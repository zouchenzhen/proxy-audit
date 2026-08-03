import argparse
import json
import sys
import time
from pathlib import Path

from lib_ipintel import enrich_ip_profile, build_unified_profile
from lib_report import write_csv, build_summary_rows, write_markdown_report

ROOT = Path(r'E:\Openclaw_Workspace\proxy_audit')
RESULT_RAW = ROOT / 'results' / 'raw'
RESULT_CSV = ROOT / 'results' / 'csv'
RESULT_REPORT = ROOT / 'results' / 'reports'


def parse_args():
    p = argparse.ArgumentParser(description='Enhance an existing raw run with multi-source IP intel')
    p.add_argument('--input-raw', required=True)
    p.add_argument('--success-only', action='store_true', default=True)
    p.add_argument('--sleep-sec', type=float, default=0.2)
    p.add_argument('--timeout', type=int, default=15)
    return p.parse_args()


def main():
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass
    args = parse_args()
    RESULT_RAW.mkdir(parents=True, exist_ok=True)
    RESULT_CSV.mkdir(parents=True, exist_ok=True)
    RESULT_REPORT.mkdir(parents=True, exist_ok=True)

    src = Path(args.input_raw)
    payload = json.loads(src.read_text(encoding='utf-8'))
    results = payload.get('results') or []

    total_targets = 0
    success_count = 0
    fail_count = 0
    cache = {}
    for item in results:
        if args.success_only and not item.get('success'):
            continue
        exit_ip = (((item.get('result') or {}).get('ipify')) or {}).get('ip')
        ip_api = (((item.get('result') or {}).get('ip_api')) or {})
        if not exit_ip:
            continue
        total_targets += 1
        try:
            if exit_ip not in cache:
                cache[exit_ip] = enrich_ip_profile(exit_ip, timeout=args.timeout, sleep_sec=args.sleep_sec)
            enrich = cache[exit_ip]
            unified = build_unified_profile(exit_ip, ip_api, enrich.get('ipinfo') or {}, enrich.get('ip2location') or {}, enrich.get('ipqs') or {}, enrich.get('scamalytics') or {})
            item.setdefault('result', {})['ipinfo'] = enrich.get('ipinfo')
            item['result']['ip2location'] = enrich.get('ip2location')
            item['result']['ipqs'] = enrich.get('ipqs')
            item['result']['scamalytics'] = enrich.get('scamalytics')
            item['result']['intel_errors'] = enrich.get('errors') or {}
            item['result']['unified'] = unified
            if enrich.get('errors'):
                item['result']['enrich_warning'] = 'partial_source_failures'
            success_count += 1
        except Exception as e:
            item.setdefault('result', {})['enrich_error'] = repr(e)
            fail_count += 1

    run_id = payload.get('run_id') or time.strftime('%Y%m%d_%H%M%S')
    enhanced_run_id = f'{run_id}_enhanced'
    payload['enhanced_from'] = str(src)
    payload['enhanced_run_id'] = enhanced_run_id
    payload['enhanced_summary'] = {
        'total_targets': total_targets,
        'success_count': success_count,
        'fail_count': fail_count,
    }

    raw_path = RESULT_RAW / f'run_{enhanced_run_id}.json'
    csv_path = RESULT_CSV / f'run_{enhanced_run_id}.csv'
    md_path = RESULT_REPORT / f'run_{enhanced_run_id}.md'
    raw_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
    write_csv(csv_path, build_summary_rows(results))
    write_markdown_report(md_path, {'run_id': enhanced_run_id, 'source_label': payload.get('source_label')}, results)

    print(json.dumps({
        'enhanced_run_id': enhanced_run_id,
        'total_targets': total_targets,
        'success_count': success_count,
        'fail_count': fail_count,
        'raw_path': str(raw_path),
        'csv_path': str(csv_path),
        'md_path': str(md_path),
    }, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
