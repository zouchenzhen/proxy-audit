import json
import base64
import shutil
import sqlite3
import zipfile
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
from typing import List, Dict, Any, Optional

from lib_paths import TEMP_DIR

CONFIG_TYPE_MAP = {
    1: 'vmess',
    2: 'custom',
    3: 'ss',
    4: 'socks',
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


def _json_object(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, ValueError):
        return {}


def row_to_node(row: Dict[str, Any], sub_map: Dict[str, Dict[str, Any]], source_type: str, source_name: str) -> Dict[str, Any]:
    config_type = row.get('ConfigType')
    protocol = protocol_from_config_type(config_type, row)
    subid = row.get('Subid') or ''
    sub = sub_map.get(subid, {})
    remarks = row.get('Remarks') or f"{row.get('Address')}:{row.get('Port')}"
    proto_extra = _json_object(row.get('ProtoExtra'))
    transport_extra = _json_object(row.get('TransportExtra'))
    tls_mode = (row.get('StreamSecurity') or '').lower()
    if protocol in ('hysteria2', 'tuic', 'anytls') and not tls_mode:
        tls_mode = 'tls'
    network = (row.get('Network') or 'tcp').lower()
    if network == 'raw':
        network = 'tcp'
    host = row.get('RequestHost') or transport_extra.get('Host') or row.get('Sni') or row.get('Address')
    path = row.get('Path') or transport_extra.get('Path') or '/'

    legacy_id = row.get('Id') or ''
    username = row.get('Username') or ''
    stored_password = row.get('Password') or ''
    uuid_value = legacy_id or stored_password or username
    password_value = stored_password or legacy_id or username
    if protocol == 'tuic':
        uuid_value = username or legacy_id
    elif protocol == 'ss':
        password_value = stored_password or username or legacy_id

    security = row.get('Security') or ''
    if protocol == 'vmess':
        security = security or proto_extra.get('VmessSecurity') or 'auto'
    elif protocol == 'vless':
        security = security or proto_extra.get('VlessEncryption') or 'none'
    elif protocol == 'ss':
        security = proto_extra.get('SsMethod') or security

    node = {
        'index_id': row.get('IndexId'),
        'protocol': protocol,
        'config_type': config_type,
        'remark': remarks,
        'server': row.get('Address'),
        'server_port': row.get('Port'),
        'uuid': uuid_value,
        'password': password_value,
        'hy2_password': stored_password or legacy_id or username,
        'obfs_password': proto_extra.get('SalamanderPass') or '',
        'tuic_password': stored_password or row.get('Security') or '',
        'congestion_control': proto_extra.get('CongestionControl') or row.get('HeaderType') or '',
        'alter_id': row.get('AlterId') if row.get('AlterId') is not None else proto_extra.get('AlterId'),
        'security': security,
        'network': network,
        'host': host,
        'path': path,
        'tls_mode': tls_mode,
        'insecure': str(row.get('AllowInsecure') or '').lower() in ('1', 'true'),
        'flow': row.get('Flow') or proto_extra.get('Flow') or '',
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


def extract_backup_and_get_db(
    zip_path: str,
    *,
    extract_dir: Optional[Path] = None,
    max_files: Optional[int] = None,
    max_uncompressed_bytes: Optional[int] = None,
) -> Path:
    zip_p = Path(zip_path)
    target = Path(extract_dir) if extract_dir is not None else TEMP_DIR / 'backup_extract'
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_p, 'r') as zf:
        target_root = target.resolve()
        members = [member for member in zf.infolist() if not member.is_dir()]
        if max_files is not None and len(members) > max_files:
            raise ValueError(f'Backup ZIP contains more than {max_files} files')
        declared_size = sum(max(0, member.file_size) for member in members)
        if max_uncompressed_bytes is not None and declared_size > max_uncompressed_bytes:
            raise ValueError('Backup ZIP expands beyond the cloud safety limit')
        total_written = 0
        for member in members:
            destination = (target / member.filename).resolve()
            if target_root != destination and target_root not in destination.parents:
                raise ValueError(f'Unsafe path in backup ZIP: {member.filename}')
            if member.flag_bits & 0x1:
                raise ValueError('Encrypted backup ZIP files are not supported')
            unix_mode = (member.external_attr >> 16) & 0xFFFF
            if unix_mode and (unix_mode & 0o170000) == 0o120000:
                raise ValueError(f'Symbolic links are not allowed in backup ZIP: {member.filename}')
            destination.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member, 'r') as source, destination.open('wb') as output:
                while True:
                    chunk = source.read(64 * 1024)
                    if not chunk:
                        break
                    total_written += len(chunk)
                    if max_uncompressed_bytes is not None and total_written > max_uncompressed_bytes:
                        raise ValueError('Backup ZIP expands beyond the cloud safety limit')
                    output.write(chunk)
    candidates = list(target.rglob('guiNDB.db'))
    if not candidates:
        raise FileNotFoundError('guiNDB.db not found inside backup zip')
    return candidates[0]


def load_from_v2ray_backup(
    zip_path: str,
    *,
    extract_dir: Optional[Path] = None,
    max_files: Optional[int] = None,
    max_uncompressed_bytes: Optional[int] = None,
) -> List[Dict[str, Any]]:
    db_path = extract_backup_and_get_db(
        zip_path,
        extract_dir=extract_dir,
        max_files=max_files,
        max_uncompressed_bytes=max_uncompressed_bytes,
    )
    return _read_sqlite_nodes(db_path, 'v2ray_backup', Path(zip_path).name)


def _decode_b64(value: str) -> str:
    value = value.strip().replace('-', '+').replace('_', '/')
    value += '=' * (-len(value) % 4)
    return base64.b64decode(value).decode('utf-8', errors='strict')


def _base_node(protocol: str, config_type: Optional[int], source_name: str = 'input-file') -> Dict[str, Any]:
    return {
        'index_id': None,
        'protocol': protocol,
        'config_type': config_type,
        'remark': '',
        'server': '',
        'server_port': None,
        'uuid': '',
        'password': '',
        'hy2_password': '',
        'obfs_password': '',
        'tuic_password': '',
        'congestion_control': '',
        'alter_id': 0,
        'security': '',
        'network': 'tcp',
        'host': '',
        'path': '/',
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
        'source_name': source_name,
        'subscription_name': '',
        'subscription_url': '',
    }


def _bool_query(q: Dict[str, List[str]], *names: str) -> bool:
    for name in names:
        if name in q:
            return str(q[name][0]).lower() in ('1', 'true', 'yes')
    return False


def parse_share_link(url: str, source_name: str = 'input-file') -> Dict[str, Any]:
    url = url.strip()
    if url.lower().startswith('vmess://'):
        node = _base_node('vmess', 1, source_name)
        try:
            data = json.loads(_decode_b64(url.split('://', 1)[1]))
            node.update({
                'remark': data.get('ps') or f"{data.get('add')}:{data.get('port')}",
                'server': data.get('add') or '',
                'server_port': int(data.get('port') or 443),
                'uuid': data.get('id') or '',
                'alter_id': int(data.get('aid') or 0),
                'security': data.get('scy') or data.get('security') or 'auto',
                'network': (data.get('net') or 'tcp').lower(),
                'host': data.get('host') or data.get('add') or '',
                'path': data.get('path') or '/',
                'tls_mode': (data.get('tls') or '').lower(),
                'sni': data.get('sni') or data.get('host') or data.get('add') or '',
                'alpn': data.get('alpn') or '',
                'fp': data.get('fp') or '',
                'insecure': str(data.get('allowInsecure') or '').lower() in ('1', 'true'),
            })
            return node
        except Exception as exc:
            node['remark'] = 'Invalid VMess link'
            node['parse_error'] = str(exc)
            return node

    u = urlparse(url)
    scheme = u.scheme.lower()
    aliases = {'hy2': 'hysteria2'}
    protocol = aliases.get(scheme, scheme)
    config_types = {'vless': 5, 'trojan': 6, 'hysteria2': 7, 'tuic': 8, 'anytls': 11, 'ss': 4}
    node = _base_node(protocol, config_types.get(protocol), source_name)
    q = parse_qs(u.query)

    if protocol in ('vless', 'trojan', 'hysteria2', 'tuic', 'anytls'):
        username = unquote(u.username or '')
        password = unquote(u.password or '')
        node.update({
            'remark': unquote(u.fragment) if u.fragment else f'{u.hostname}:{u.port}',
            'server': u.hostname or '',
            'server_port': u.port or 443,
            'network': q.get('type', ['tcp'])[0].lower(),
            'host': q.get('host', [u.hostname or ''])[0],
            'path': unquote(q.get('path', ['/'])[0]),
            'insecure': _bool_query(q, 'insecure', 'allowInsecure', 'allow_insecure'),
            'sni': q.get('sni', [u.hostname or ''])[0],
            'alpn': q.get('alpn', [''])[0],
            'fp': q.get('fp', q.get('fingerprint', ['']))[0],
        })
        if protocol == 'vless':
            node.update({
                'uuid': username,
                'security': q.get('encryption', ['none'])[0],
                'tls_mode': q.get('security', [''])[0].lower(),
                'flow': q.get('flow', [''])[0],
                'public_key': q.get('pbk', q.get('publicKey', ['']))[0],
                'short_id': q.get('sid', q.get('shortId', ['']))[0],
            })
        elif protocol == 'trojan':
            node.update({'uuid': username, 'password': username, 'tls_mode': q.get('security', ['tls'])[0].lower()})
        elif protocol == 'hysteria2':
            auth = username if not password else f'{username}:{password}'
            node.update({
                'uuid': auth,
                'password': auth,
                'hy2_password': auth,
                'tls_mode': 'tls',
                'obfs_password': q.get('obfs-password', q.get('obfsPassword', ['']))[0],
            })
        elif protocol == 'tuic':
            node.update({
                'uuid': username,
                'password': password,
                'tuic_password': password,
                'tls_mode': 'tls',
                'congestion_control': q.get('congestion_control', q.get('congestion-control', ['']))[0],
            })
        elif protocol == 'anytls':
            auth = username if not password else f'{username}:{password}'
            node.update({'uuid': auth, 'password': auth, 'tls_mode': 'tls'})
        return node

    if scheme == 'ss':
        try:
            raw = url.split('://', 1)[1].split('#', 1)[0].split('?', 1)[0]
            if '@' not in raw:
                raw = _decode_b64(raw)
            credentials, endpoint = raw.rsplit('@', 1)
            if ':' not in credentials:
                credentials = _decode_b64(credentials)
            method, password = credentials.split(':', 1)
            endpoint_url = urlparse('ss://' + endpoint)
            node.update({
                'remark': unquote(u.fragment) if u.fragment else endpoint,
                'server': endpoint_url.hostname or '',
                'server_port': endpoint_url.port,
                'security': unquote(method),
                'password': unquote(password),
                'network': 'tcp',
            })
            return node
        except Exception as exc:
            node['remark'] = 'Invalid Shadowsocks link'
            node['parse_error'] = str(exc)
            return node

    node.update({
        'remark': unquote(u.fragment) if u.fragment else f'{scheme or "unknown"}:{u.hostname or "unparsed"}:{u.port or ""}',
        'server': u.hostname or '',
        'server_port': u.port,
    })
    return node


def load_from_input_file(path: str) -> List[Dict[str, Any]]:
    p = Path(path)
    return load_from_text(p.read_text(encoding='utf-8', errors='ignore'), p.name)


def load_from_text(text: str, source_name: str = 'pasted-links') -> List[Dict[str, Any]]:
    normalized = text.strip().lstrip('\ufeff')
    if '://' not in normalized and normalized:
        try:
            decoded = _decode_b64(''.join(normalized.split()))
            if '://' in decoded:
                normalized = decoded
        except Exception:
            pass
    lines = [
        line.strip()
        for line in normalized.splitlines()
        if line.strip() and not line.lstrip().startswith(('#', '//'))
    ]
    return [parse_share_link(line, source_name=source_name) for line in lines]


def filter_nodes(nodes: List[Dict[str, Any]], filter_substring: str = '', protocols: Optional[List[str]] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    out = []
    protocols = [x.lower().strip() for x in (protocols or []) if x.strip()]
    needle = (filter_substring or '').lower().strip()
    for node in nodes:
        hay = ' | '.join([
            str(node.get('remark') or ''),
            str(node.get('_display_server') or ''),
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

    if proto == 'ss':
        if not node.get('server') or not node.get('server_port'):
            return False, 'Shadowsocks node missing server/port'
        if not node.get('security') or not node.get('password'):
            return False, 'Shadowsocks node missing method/password'
        if network not in ('tcp', '') or tls_mode:
            return False, 'Shadowsocks plugin transport is not implemented'
        return True, ''

    return False, f'Protocol not implemented in current formal version: {proto}'
