import json
import shutil
import sqlite3
import zipfile
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
from typing import List, Dict, Any, Optional

ROOT = Path(r'E:\Openclaw_Workspace\proxy_audit')
TEMP_DIR = ROOT / 'temp'

CONFIG_TYPE_MAP = {
    1: 'vmess',
    2: 'custom',
    3: 'socks',
    4: 'shadowsocks',
    5: 'vless',
    6: 'trojan',
    7: 'hysteria2',
    8: 'tuic',
    9: 'wireguard',
    10: 'http',
    11: 'anytls',
    12: 'shadowsocksr',
}


def protocol_from_config_type(config_type: Optional[int], row: Dict[str, Any]) -> str:
    if config_type in CONFIG_TYPE_MAP:
        return CONFIG_TYPE_MAP[config_type]
    stream = (row.get('StreamSecurity') or '').lower()
    if stream == 'reality':
        return 'vless'
    return f'unknown_{config_type}'


def row_to_node(row: Dict[str, Any], sub_map: Dict[str, Dict[str, Any]], source_type: str, source_name: str) -> Dict[str, Any]:
    config_type = row.get('ConfigType')
    protocol = protocol_from_config_type(config_type, row)
    subid = row.get('Subid') or ''
    sub = sub_map.get(subid, {})
    remarks = row.get('Remarks') or f"{row.get('Address')}:{row.get('Port')}"
    tls_mode = (row.get('StreamSecurity') or '').lower()
    network = (row.get('Network') or 'tcp').lower()
    host = row.get('RequestHost') or row.get('Sni') or row.get('Address')
    path = row.get('Path') or '/'

    node = {
        'index_id': row.get('IndexId'),
        'protocol': protocol,
        'config_type': config_type,
        'remark': remarks,
        'server': row.get('Address'),
        'server_port': row.get('Port'),
        'uuid': row.get('Id'),
        'password': row.get('Id'),
        'hy2_password': row.get('Id'),
        'obfs_password': row.get('Path') or '',
        'tuic_password': row.get('Security') or '',
        'congestion_control': row.get('HeaderType') or '',
        'alter_id': row.get('AlterId'),
        'security': row.get('Security'),
        'network': network,
        'host': host,
        'path': path,
        'tls_mode': tls_mode,
        'insecure': str(row.get('AllowInsecure') or '').lower() in ('1', 'true'),
        'flow': row.get('Flow') or '',
        'sni': row.get('Sni') or row.get('Address'),
        'alpn': row.get('Alpn') or '',
        'fp': row.get('Fingerprint') or '',
        'public_key': row.get('PublicKey') or '',
        'short_id': row.get('ShortId') or '',
        'extra': row.get('Extra') or '',
        'subid': subid,
        'is_subscription': bool(row.get('IsSub')),
        'source_type': source_type,
        'source_name': source_name,
        'subscription_name': sub.get('Remarks') or '',
        'subscription_url': sub.get('Url') or '',
    }
    return node


def _read_sqlite_nodes(db_path: Path, source_type: str, source_name: str) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    sub_map = {}
    try:
        cur.execute('SELECT * FROM SubItem')
        for row in cur.fetchall():
            d = dict(row)
            sub_map[str(d.get('Id'))] = d
    except sqlite3.Error:
        pass

    cur.execute('SELECT * FROM ProfileItem')
    items = [row_to_node(dict(r), sub_map, source_type, source_name) for r in cur.fetchall()]
    conn.close()
    return items


def load_from_v2ray_db(db_path: str) -> List[Dict[str, Any]]:
    p = Path(db_path)
    return _read_sqlite_nodes(p, 'v2ray_db', p.name)


def extract_backup_and_get_db(zip_path: str) -> Path:
    zip_p = Path(zip_path)
    target = TEMP_DIR / 'backup_extract'
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_p, 'r') as zf:
        zf.extractall(target)
    candidates = list(target.rglob('guiNDB.db'))
    if not candidates:
        raise FileNotFoundError('guiNDB.db not found inside backup zip')
    return candidates[0]


def load_from_v2ray_backup(zip_path: str) -> List[Dict[str, Any]]:
    db_path = extract_backup_and_get_db(zip_path)
    return _read_sqlite_nodes(db_path, 'v2ray_backup', Path(zip_path).name)


def parse_share_link(url: str) -> Dict[str, Any]:
    url = url.strip()
    u = urlparse(url)
    if u.scheme.lower() == 'vless':
        q = parse_qs(u.query)
        return {
            'index_id': None,
            'protocol': 'vless',
            'config_type': 5,
            'remark': unquote(u.fragment) if u.fragment else f'{u.hostname}:{u.port}',
            'server': u.hostname,
            'server_port': u.port or 443,
            'uuid': u.username,
            'alter_id': 0,
            'security': q.get('encryption', ['none'])[0],
            'network': q.get('type', ['tcp'])[0].lower(),
            'host': q.get('host', [u.hostname])[0],
            'path': unquote(q.get('path', ['/'])[0]),
            'tls_mode': q.get('security', [''])[0].lower(),
            'insecure': q.get('insecure', q.get('allowInsecure', ['0']))[0] in ('1', 'true', 'True'),
            'flow': q.get('flow', [''])[0],
            'sni': q.get('sni', [u.hostname])[0],
            'alpn': q.get('alpn', [''])[0],
            'fp': q.get('fp', [''])[0],
            'public_key': q.get('pbk', [''])[0],
            'short_id': q.get('sid', [''])[0],
            'extra': '',
            'subid': '',
            'is_subscription': False,
            'source_type': 'share_link_file',
            'source_name': 'input-file',
            'subscription_name': '',
            'subscription_url': '',
        }
    if u.scheme.lower() == 'trojan':
        q = parse_qs(u.query)
        return {
            'index_id': None,
            'protocol': 'trojan',
            'config_type': 6,
            'remark': unquote(u.fragment) if u.fragment else f'{u.hostname}:{u.port}',
            'server': u.hostname,
            'server_port': u.port or 443,
            'uuid': u.username,
            'password': u.username,
            'alter_id': 0,
            'security': '',
            'network': q.get('type', ['tcp'])[0].lower(),
            'host': q.get('host', [u.hostname])[0],
            'path': unquote(q.get('path', ['/'])[0]),
            'tls_mode': q.get('security', ['tls'])[0].lower(),
            'insecure': q.get('insecure', q.get('allowInsecure', ['0']))[0] in ('1', 'true', 'True'),
            'flow': '',
            'sni': q.get('sni', [u.hostname])[0],
            'alpn': q.get('alpn', [''])[0],
            'fp': q.get('fp', [''])[0],
            'public_key': '',
            'short_id': '',
            'extra': '',
            'subid': '',
            'is_subscription': False,
            'source_type': 'share_link_file',
            'source_name': 'input-file',
            'subscription_name': '',
            'subscription_url': '',
        }
    return {
        'index_id': None,
        'protocol': u.scheme.lower(),
        'config_type': None,
        'remark': url[:80],
        'server': '',
        'server_port': None,
        'uuid': '',
        'alter_id': 0,
        'security': '',
        'network': '',
        'host': '',
        'path': '',
        'tls_mode': '',
        'insecure': False,
        'flow': '',
        'sni': '',
        'alpn': '',
        'fp': '',
        'public_key': '',
        'short_id': '',
        'extra': '',
        'subid': '',
        'is_subscription': False,
        'source_type': 'share_link_file',
        'source_name': 'input-file',
        'subscription_name': '',
        'subscription_url': '',
    }


def load_from_input_file(path: str) -> List[Dict[str, Any]]:
    p = Path(path)
    lines = [x.strip() for x in p.read_text(encoding='utf-8', errors='ignore').splitlines() if x.strip()]
    return [parse_share_link(line) for line in lines]


def filter_nodes(nodes: List[Dict[str, Any]], filter_substring: str = '', protocols: Optional[List[str]] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    out = []
    protocols = [x.lower().strip() for x in (protocols or []) if x.strip()]
    needle = (filter_substring or '').lower().strip()
    for node in nodes:
        hay = ' | '.join([
            str(node.get('remark') or ''),
            str(node.get('server') or ''),
            str(node.get('subscription_name') or ''),
            str(node.get('source_name') or ''),
        ]).lower()
        if needle and needle not in hay:
            continue
        if protocols and (node.get('protocol') or '').lower() not in protocols:
            continue
        out.append(node)
        if limit and len(out) >= limit:
            break
    return out


def describe_support(node: Dict[str, Any]) -> (bool, str):
    proto = (node.get('protocol') or '').lower()
    network = (node.get('network') or 'tcp').lower()
    tls_mode = (node.get('tls_mode') or '').lower()

    if proto == 'vless':
        if network not in ('tcp', 'ws', ''):
            return False, f'VLESS network not implemented yet: {network}'
        if tls_mode not in ('', 'tls', 'reality'):
            return False, f'VLESS tls/stream security mode not implemented yet: {tls_mode}'
        if tls_mode == 'reality' and not node.get('public_key'):
            return False, 'VLESS reality node missing public_key'
        return True, ''

    if proto == 'vmess':
        if network not in ('tcp', 'ws', ''):
            return False, f'VMess network not implemented yet: {network}'
        if tls_mode not in ('', 'tls'):
            return False, f'VMess tls/stream security mode not implemented yet: {tls_mode}'
        if not node.get('uuid'):
            return False, 'VMess node missing uuid/id'
        return True, ''

    if proto == 'anytls':
        if not node.get('server') or not node.get('server_port'):
            return False, 'AnyTLS node missing server/port'
        if not node.get('password') and not node.get('uuid'):
            return False, 'AnyTLS node missing password/id'
        if tls_mode not in ('', 'tls'):
            return False, f'AnyTLS tls mode not implemented yet: {tls_mode}'
        return True, ''

    if proto == 'hysteria2':
        if not node.get('server') or not node.get('server_port'):
            return False, 'Hysteria2 node missing server/port'
        if not node.get('hy2_password') and not node.get('password') and not node.get('uuid'):
            return False, 'Hysteria2 node missing password/id'
        if tls_mode not in ('', 'tls'):
            return False, f'Hysteria2 tls mode not implemented yet: {tls_mode}'
        return True, ''

    if proto == 'tuic':
        if not node.get('server') or not node.get('server_port'):
            return False, 'TUIC node missing server/port'
        if not node.get('uuid') or not node.get('tuic_password'):
            return False, 'TUIC node missing uuid/password'
        if tls_mode not in ('', 'tls'):
            return False, f'TUIC tls mode not implemented yet: {tls_mode}'
        return True, ''

    if proto == 'trojan':
        if network not in ('tcp', 'ws', ''):
            return False, f'Trojan network not implemented yet: {network}'
        if tls_mode not in ('', 'tls'):
            return False, f'Trojan tls mode not implemented yet: {tls_mode}'
        if not node.get('password') and not node.get('uuid'):
            return False, 'Trojan node missing password/id'
        return True, ''

    return False, f'Protocol not implemented in current formal version: {proto}'
