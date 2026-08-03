import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Dict, Any, List, Tuple

ROOT = Path(r"E:/Openclaw_Workspace/proxy_audit")
RAW_DIR = ROOT / 'results' / 'raw'
REPORT_DIR = ROOT / 'results' / 'reports'

DEFAULT_RUNS = [
    ('run_20260319_201919_enhanced.json', 'vless', 'not_priority', 'vless_enhanced'),
    ('run_20260320_004342.json', 'vmess', 'watch', 'vmess_first_batch'),
    ('run_20260320_005729.json', 'anytls', 'keep', 'anytls_first_batch'),
    ('run_20260320_010628.json', 'hysteria2', 'keep', 'hysteria2_full_batch'),
]


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding='utf-8'))


def recommendation_for_row(protocol: str, node: Dict[str, Any], ipify: Dict[str, Any], default: str = 'watch') -> str:
    rec = default
    if protocol == 'vless':
        ip = ipify.get('ip')
        if node.get('remark') == 'vless-reality' and ip == '4.149.84.24':
            rec = 'keep'
        elif node.get('remark') == 'vless-reality':
            rec = 'watch'
        else:
            rec = 'not_priority'
    elif protocol == 'vmess':
        rec = 'watch'
    elif protocol in ('anytls', 'hysteria2'):
        rec = 'keep'
    elif protocol == 'tuic':
        rec = 'watch'
    elif protocol == 'trojan':
        rec = 'watch'
    return rec


def rows_from_single_raw(raw_name: str, source_tag: str = 'single_run') -> List[Dict[str, Any]]:
    p = Path(raw_name)
    if not p.is_absolute():
        p = RAW_DIR / raw_name
    d = load_json(p)
    rows = []
    for r in d.get('results') or []:
        if not r.get('success'):
            continue
        node = r.get('node') or {}
        res = r.get('result') or {}
        ipify = res.get('ipify') or {}
        ip_api = res.get('ip_api') or {}
        uni = res.get('unified') or {}
        protocol = (node.get('protocol') or 'unknown').lower()
        rows.append({
            'protocol': protocol,
            'remark': node.get('remark'),
            'server': node.get('server'),
            'server_port': node.get('server_port'),
            'exit_ip': ipify.get('ip'),
            'country': ip_api.get('country'),
            'city': ip_api.get('city'),
            'asn': ip_api.get('as'),
            'isp': ip_api.get('isp'),
            'org': ip_api.get('org'),
            'ip_type_final': uni.get('ip_type_final'),
            'risk_level_final': uni.get('risk_level_final'),
            'risk_score_final': uni.get('risk_score_final'),
            'native_ip_judgement': uni.get('native_ip_judgement'),
            'recommendation': recommendation_for_row(protocol, node, ipify),
            'source_run': source_tag,
            'raw_file': p.name,
        })
    return rows


def normalize_rows(raw_name: str, proto_label: str, recommendation_default: str, source_tag: str) -> List[Dict[str, Any]]:
    p = RAW_DIR / raw_name
    d = load_json(p)
    rows = []
    for r in d.get('results') or []:
        if not r.get('success'):
            continue
        node = r.get('node') or {}
        actual_proto = (node.get('protocol') or '').lower()
        if actual_proto != proto_label.lower():
            continue
        res = r.get('result') or {}
        ipify = res.get('ipify') or {}
        ip_api = res.get('ip_api') or {}
        uni = res.get('unified') or {}
        rec = recommendation_for_row(proto_label.lower(), node, ipify, default=recommendation_default)
        rows.append({
            'protocol': proto_label,
            'remark': node.get('remark'),
            'server': node.get('server'),
            'server_port': node.get('server_port'),
            'exit_ip': ipify.get('ip'),
            'country': ip_api.get('country'),
            'city': ip_api.get('city'),
            'asn': ip_api.get('as'),
            'isp': ip_api.get('isp'),
            'org': ip_api.get('org'),
            'ip_type_final': uni.get('ip_type_final'),
            'risk_level_final': uni.get('risk_level_final'),
            'risk_score_final': uni.get('risk_score_final'),
            'native_ip_judgement': uni.get('native_ip_judgement'),
            'recommendation': rec,
            'source_run': source_tag,
            'raw_file': raw_name,
        })
    return rows


def dedupe(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set[Tuple[Any, ...]] = set()
    out = []
    for row in rows:
        key = (
            row.get('protocol'),
            row.get('remark'),
            row.get('exit_ip'),
            row.get('server'),
            row.get('server_port'),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ['no_data'])
        writer.writeheader()
        if rows:
            writer.writerows(rows)


def parse_run_specs(items: List[str]) -> List[Tuple[str, str, str, str]]:
    specs = []
    for item in items:
        parts = item.split('|')
        if len(parts) != 4:
            raise SystemExit(f'Invalid --run spec: {item} ; expected raw_file|protocol|recommendation|source_tag')
        specs.append(tuple(parts))
    return specs


def main():
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass
    parser = argparse.ArgumentParser(description='Generate deduplicated success-node reports')
    parser.add_argument('--stamp', required=True, help='Suffix timestamp used in output filenames, e.g. 20260320_1434')
    parser.add_argument('--input-raw', help='Single raw run JSON (absolute path or filename under results/raw). Uses actual protocol per row.')
    parser.add_argument('--source-tag', default='single_run', help='Source tag used with --input-raw')
    parser.add_argument('--run', action='append', default=[], help='Custom run spec: raw_file|protocol|recommendation|source_tag ; may be repeated')
    args = parser.parse_args()

    if args.input_raw:
        rows = rows_from_single_raw(args.input_raw, source_tag=args.source_tag)
        run_specs = [('single_raw', args.input_raw, 'mixed', args.source_tag)]
    else:
        run_specs = parse_run_specs(args.run) if args.run else DEFAULT_RUNS
        rows: List[Dict[str, Any]] = []
        for raw_name, proto_label, recommendation_default, source_tag in run_specs:
            rows += normalize_rows(raw_name, proto_label, recommendation_default, source_tag)

    rows = dedupe(rows)
    shortlist = [r for r in rows if r['recommendation'] in ('keep', 'watch')]

    full_json = REPORT_DIR / f'success_nodes_full_{len(rows)}_{args.stamp}.json'
    full_csv = REPORT_DIR / f'success_nodes_full_{len(rows)}_{args.stamp}.csv'
    short_json = REPORT_DIR / f'success_nodes_shortlist_{len(shortlist)}_{args.stamp}.json'
    short_csv = REPORT_DIR / f'success_nodes_shortlist_{len(shortlist)}_{args.stamp}.csv'

    full_json.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding='utf-8')
    write_csv(full_csv, rows)
    short_json.write_text(json.dumps(shortlist, ensure_ascii=False, indent=2), encoding='utf-8')
    write_csv(short_csv, shortlist)

    print(json.dumps({
        'run_specs': run_specs,
        'full_count': len(rows),
        'short_count': len(shortlist),
        'full_json': str(full_json),
        'full_csv': str(full_csv),
        'short_json': str(short_json),
        'short_csv': str(short_csv),
    }, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
