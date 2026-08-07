import argparse
import json
import sys
import time
from pathlib import Path

from lib_ipintel import probe_ip_via_socks
from lib_report import write_csv, build_summary_rows, write_markdown_report
from lib_singbox import ensure_runtime_dirs, build_singbox_config, write_config_file, start_singbox, stop_singbox, wait_port
from lib_v2rayn import load_from_v2ray_backup, load_from_v2ray_db, load_from_input_file, filter_nodes, describe_support

from lib_paths import ROOT, RESULT_RAW, RESULT_CSV, RESULT_REPORT, CONFIG_DIR, LOG_DIR


def parse_args():
    p = argparse.ArgumentParser(description='Batch proxy audit via sing-box + v2rayN data sources')
    p.add_argument('--v2ray-backup', help='Path to v2rayN backup zip')
    p.add_argument('--v2ray-db', help='Path to v2rayN guiNDB.db')
    p.add_argument('--input-file', help='Path to txt file containing share links')
    p.add_argument('--filter-substring', default='', help='Only test nodes whose metadata contains this substring')
    p.add_argument('--protocols', default='', help='Comma-separated protocols to include, e.g. vless,vmess,hysteria2,tuic,anytls')
    p.add_argument('--limit', type=int, default=0, help='Stop after N matched nodes (0 means no limit)')
    p.add_argument('--start-port', type=int, default=21080)
    p.add_argument('--timeout', type=int, default=15)
    return p.parse_args()


def load_nodes(args):
    if args.v2ray_backup:
        return load_from_v2ray_backup(args.v2ray_backup), f'v2ray_backup:{args.v2ray_backup}'
    if args.v2ray_db:
        return load_from_v2ray_db(args.v2ray_db), f'v2ray_db:{args.v2ray_db}'
    if args.input_file:
        return load_from_input_file(args.input_file), f'input_file:{args.input_file}'
    raise SystemExit('One input source is required: --v2ray-backup or --v2ray-db or --input-file')




def _ensure_utf8_stdout():
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass


def print_progress(msg: str) -> None:
    sys.stdout.buffer.write((msg + '\n').encode('utf-8', errors='replace'))
    sys.stdout.flush()

def tail_text(path: Path, chars: int = 4000) -> str:
    try:
        return path.read_text(encoding='utf-8', errors='ignore')[-chars:]
    except Exception:
        return ''


def run_one(node, idx: int, socks_port: int, timeout: int):
    supported, reason = describe_support(node)
    safe_name = f'node_{idx:04d}'
    cfg_path = CONFIG_DIR / f'{safe_name}.json'
    log_path = LOG_DIR / f'{safe_name}.log'
    result = {
        'supported': supported,
        'success': False,
        'skip_reason': '' if supported else reason,
        'error': None,
        'node': node,
        'socks_port': socks_port,
        'config_path': str(cfg_path),
        'log_path': str(log_path),
        'result': None,
        'log_tail': '',
    }
    if not supported:
        return result

    proc = None
    try:
        config = build_singbox_config(node, socks_port)
        write_config_file(config, cfg_path)
        proc = start_singbox(cfg_path, log_path)
        if not wait_port(socks_port, deadline_sec=max(10, timeout + 3)):
            raise RuntimeError('sing-box local socks listener did not become ready in time')
        intel = probe_ip_via_socks(socks_port, timeout=timeout)
        result['success'] = True
        result['result'] = intel
        return result
    except Exception as e:
        result['error'] = repr(e)
        result['log_tail'] = tail_text(log_path)
        return result
    finally:
        if proc is not None:
            stop_singbox(proc)
            if not result['log_tail']:
                result['log_tail'] = tail_text(log_path)


def main():
    _ensure_utf8_stdout()
    args = parse_args()
    ensure_runtime_dirs()
    RESULT_RAW.mkdir(parents=True, exist_ok=True)
    RESULT_CSV.mkdir(parents=True, exist_ok=True)
    RESULT_REPORT.mkdir(parents=True, exist_ok=True)

    nodes, source_label = load_nodes(args)
    protocols = [x.strip() for x in args.protocols.split(',') if x.strip()]
    selected = filter_nodes(nodes, filter_substring=args.filter_substring, protocols=protocols, limit=(args.limit or None))

    run_id = time.strftime('%Y%m%d_%H%M%S')
    results = []
    total = len(selected)
    proto_counts = {}
    for n in selected:
        proto = (n.get('protocol') or 'unknown').lower()
        proto_counts[proto] = proto_counts.get(proto, 0) + 1

    print_progress(f'[START] source={source_label}')
    print_progress(f'[START] matched_nodes={total}')
    if proto_counts:
        parts = ', '.join(f'{k}={v}' for k, v in sorted(proto_counts.items()))
        print_progress(f'[START] protocols: {parts}')

    success_count = 0
    fail_count = 0
    skip_count = 0
    for idx, node in enumerate(selected, start=1):
        proto = node.get('protocol') or 'unknown'
        remark = node.get('remark') or '(no remark)'
        server = node.get('server') or ''
        port = node.get('server_port') or ''
        print_progress(f'[RUN] [{idx}/{total}] {proto} | {remark} | {server}:{port}')
        item = run_one(node, idx, args.start_port + idx - 1, args.timeout)
        results.append(item)
        if item.get('success'):
            success_count += 1
            exit_ip = (((item.get('result') or {}).get('ipify')) or {}).get('ip')
            print_progress(f'[OK]  [{idx}/{total}] exit_ip={exit_ip} | success={success_count} fail={fail_count} skip={skip_count}')
        elif item.get('supported'):
            fail_count += 1
            err = item.get('error') or 'unknown_error'
            print_progress(f'[FAIL][{idx}/{total}] {err} | success={success_count} fail={fail_count} skip={skip_count}')
        else:
            skip_count += 1
            reason = item.get('skip_reason') or 'unsupported'
            print_progress(f'[SKIP][{idx}/{total}] {reason} | success={success_count} fail={fail_count} skip={skip_count}')

    payload = {
        'run_id': run_id,
        'source_label': source_label,
        'args': vars(args),
        'matched_nodes': len(selected),
        'results': results,
    }
    raw_path = RESULT_RAW / f'run_{run_id}.json'
    csv_path = RESULT_CSV / f'run_{run_id}.csv'
    md_path = RESULT_REPORT / f'run_{run_id}.md'

    raw_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
    write_csv(csv_path, build_summary_rows(results))
    write_markdown_report(md_path, {'run_id': run_id, 'source_label': source_label}, results)

    summary = {
        'run_id': run_id,
        'source_label': source_label,
        'matched_nodes': len(selected),
        'supported_nodes': sum(1 for r in results if r.get('supported')),
        'successful_tests': sum(1 for r in results if r.get('success')),
        'raw_path': str(raw_path),
        'csv_path': str(csv_path),
        'md_path': str(md_path),
    }
    sys.stdout.buffer.write((json.dumps(summary, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))


if __name__ == '__main__':
    main()
