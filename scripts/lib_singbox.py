import json
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Dict, Any

from lib_paths import ROOT, BIN_DIR, CONFIG_DIR, LOG_DIR
from lib_secrets import load_settings

BIN = BIN_DIR / 'sing-box.exe'


def ensure_runtime_dirs() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def is_port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def wait_port(port: int, deadline_sec: int = 18) -> bool:
    start = time.time()
    while time.time() - start < deadline_sec:
        if is_port_open('127.0.0.1', port):
            return True
        time.sleep(0.4)
    return False


def build_singbox_config(node: Dict[str, Any], socks_port: int) -> Dict[str, Any]:
    proto = (node.get('protocol') or '').lower()
    if proto not in ('vless', 'vmess', 'anytls', 'hysteria2', 'tuic', 'trojan', 'ss'):
        raise ValueError(f"Unsupported protocol for sing-box builder: {node.get('protocol')}")

    outbound = {
        'type': proto,
        'tag': 'proxy',
        'server': node['server'],
        'server_port': int(node['server_port']),
    }
    if proto in ('vless', 'vmess', 'tuic'):
        outbound['uuid'] = node['uuid']
    if proto in ('anytls', 'trojan'):
        outbound['password'] = node.get('password') or node.get('uuid')
    if proto == 'ss':
        outbound['type'] = 'shadowsocks'
        outbound['method'] = node.get('security')
        outbound['password'] = node.get('password')
    if proto == 'hysteria2':
        outbound['password'] = node.get('hy2_password') or node.get('password') or node.get('uuid')
        if node.get('obfs_password'):
            outbound['obfs'] = {'type': 'salamander', 'password': node.get('obfs_password')}
    if proto == 'tuic':
        outbound['password'] = node.get('tuic_password')
        cc = node.get('congestion_control') or ''
        if cc:
            outbound['congestion_control'] = cc.lower()
        outbound['udp_relay_mode'] = 'native'
    if proto == 'vmess':
        security = (node.get('security') or 'auto').lower()
        outbound['security'] = security if security else 'auto'
        alter_id = node.get('alter_id')
        if alter_id not in (None, '', 0, '0'):
            outbound['alter_id'] = int(alter_id)

    tls_mode = (node.get('tls_mode') or '').lower()
    if proto in ('hysteria2', 'tuic', 'anytls') and not tls_mode:
        tls_mode = 'tls'
    if proto != 'ss' and tls_mode in ('tls', 'reality'):
        tls_obj = {
            'enabled': True,
            'server_name': node.get('sni') or node.get('server'),
            'insecure': bool(node.get('insecure', False)),
        }
        alpn = [x.strip() for x in str(node.get('alpn') or '').split(',') if x.strip()]
        if alpn:
            tls_obj['alpn'] = alpn
        fp = node.get('fp') or ''
        # Hysteria2 and TUIC run TLS over QUIC. sing-box's uTLS client is for
        # TCP TLS and rejects these QUIC outbounds at connection time with
        # "unsupported usage for uTLS".
        if fp and proto not in ('hysteria2', 'tuic'):
            tls_obj['utls'] = {
                'enabled': True,
                'fingerprint': fp,
            }
        if tls_mode == 'reality':
            tls_obj['reality'] = {
                'enabled': True,
                'public_key': node.get('public_key') or '',
            }
            if node.get('short_id'):
                tls_obj['reality']['short_id'] = node.get('short_id')
        outbound['tls'] = tls_obj

    network = (node.get('network') or 'tcp').lower()
    if proto in ('hysteria2', 'tuic', 'ss'):
        pass
    elif network == 'ws':
        outbound['transport'] = {
            'type': 'ws',
            'path': node.get('path') or '/',
            'headers': {'Host': node.get('host') or node.get('server')},
        }
    elif network not in ('tcp', ''):
        raise ValueError(f'Unsupported {proto.upper()} network in current version: {network}')

    if node.get('flow'):
        outbound['flow'] = node['flow']

    return {
        'log': {'level': 'info', 'timestamp': True},
        'inbounds': [
            {
                'type': 'socks',
                'tag': 'socks-in',
                'listen': '127.0.0.1',
                'listen_port': socks_port,
            }
        ],
        'outbounds': [
            outbound,
            {'type': 'direct', 'tag': 'direct'},
            {'type': 'block', 'tag': 'block'},
        ],
        'route': {'final': 'proxy'},
    }


def resolve_singbox_binary() -> Path:
    configured = load_settings().get('singbox_path')
    return Path(configured) if configured else BIN


def start_singbox(config_path: Path, log_path: Path, binary_path: Path = None) -> subprocess.Popen:
    binary_path = Path(binary_path) if binary_path else resolve_singbox_binary()
    if not binary_path.exists():
        raise FileNotFoundError(f'sing-box not found: {binary_path}')
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logf = log_path.open('w', encoding='utf-8')
    kwargs = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}
    proc = subprocess.Popen(
        [str(binary_path), 'run', '-c', str(config_path)],
        stdout=logf,
        stderr=subprocess.STDOUT,
        cwd=str(ROOT),
        **kwargs,
    )
    proc._openclaw_logf = logf
    return proc


def stop_singbox(proc: subprocess.Popen) -> None:
    try:
        proc.terminate()
        proc.wait(timeout=8)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    logf = getattr(proc, '_openclaw_logf', None) or getattr(proc, '_proxy_audit_logf', None)
    if logf:
        try:
            logf.close()
        except Exception:
            pass


def write_config_file(config: Dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding='utf-8')
