import csv
from pathlib import Path
from typing import Iterable, List, Dict, Any


def write_csv(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        with path.open('w', newline='', encoding='utf-8-sig') as f:
            f.write('no_data\n')
        return
    fieldnames = []
    seen = set()
    for row in rows:
        for key in row.keys():
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)
    with path.open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def build_summary_rows(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = []
    for item in results:
        node = item.get('node', {})
        ip_api = (((item.get('result') or {}).get('ip_api')) or {})
        ipinfo = (((item.get('result') or {}).get('ipinfo')) or {})
        ip2location = (((item.get('result') or {}).get('ip2location')) or {})
        ipqs = (((item.get('result') or {}).get('ipqs')) or {})
        unified = (((item.get('result') or {}).get('unified')) or {})
        rows.append({
            'remark': node.get('remark'),
            'protocol': node.get('protocol'),
            'source_type': node.get('source_type'),
            'source_name': node.get('source_name'),
            'subscription_name': node.get('subscription_name'),
            'is_subscription': node.get('is_subscription'),
            'server': node.get('server'),
            'port': node.get('server_port'),
            'network': node.get('network'),
            'tls_mode': node.get('tls_mode'),
            'sni': node.get('sni'),
            'host': node.get('host'),
            'path': node.get('path'),
            'supported': item.get('supported'),
            'success': item.get('success'),
            'skip_reason': item.get('skip_reason'),
            'error': item.get('error'),
            'exit_ip': (((item.get('result') or {}).get('ipify')) or {}).get('ip'),
            'country': ip_api.get('country'),
            'countryCode': ip_api.get('countryCode'),
            'regionName': ip_api.get('regionName'),
            'city': ip_api.get('city'),
            'isp': ip_api.get('isp'),
            'org': ip_api.get('org'),
            'asn': ip_api.get('as'),
            'asname': ip_api.get('asname'),
            'mobile': ip_api.get('mobile'),
            'proxy': ip_api.get('proxy'),
            'hosting': ip_api.get('hosting'),
            'ipinfo_country': ipinfo.get('country'),
            'ipinfo_country_code': ipinfo.get('country_code'),
            'ipinfo_asn': ipinfo.get('asn'),
            'ipinfo_as_name': ipinfo.get('as_name'),
            'ip2location_country': ip2location.get('country_name'),
            'ip2location_country_code': ip2location.get('country_code'),
            'ip2location_region': ip2location.get('region_name'),
            'ip2location_city': ip2location.get('city_name'),
            'ip2location_asn': ip2location.get('asn'),
            'ip2location_as': ip2location.get('as'),
            'ip2location_is_proxy': ip2location.get('is_proxy'),
            'ipqs_fraud_score': ipqs.get('fraud_score'),
            'ipqs_proxy': ipqs.get('proxy'),
            'ipqs_vpn': ipqs.get('vpn'),
            'ipqs_tor': ipqs.get('tor'),
            'ipqs_mobile': ipqs.get('mobile'),
            'ip_type_final': unified.get('ip_type_final'),
            'risk_score_final': unified.get('risk_score_final'),
            'risk_level_final': unified.get('risk_level_final'),
            'native_ip_judgement': unified.get('native_ip_judgement'),
            'civilian_grade': unified.get('civilian_grade'),
            'reasoning_brief': unified.get('reasoning_brief'),
            'socks_port': item.get('socks_port'),
            'config_path': item.get('config_path'),
            'log_path': item.get('log_path'),
        })
    return rows


def write_markdown_report(path: Path, meta: Dict[str, Any], results: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    total = len(results)
    success = sum(1 for x in results if x.get('success'))
    supported = sum(1 for x in results if x.get('supported'))
    unsupported = sum(1 for x in results if not x.get('supported'))
    lines = []
    lines.append('# Proxy Audit Report')
    lines.append('')
    lines.append(f"- run_id: `{meta.get('run_id')}`")
    lines.append(f"- source: `{meta.get('source_label')}`")
    lines.append(f"- total_nodes: **{total}**")
    lines.append(f"- supported_nodes: **{supported}**")
    lines.append(f"- successful_tests: **{success}**")
    lines.append(f"- unsupported_or_skipped: **{unsupported}**")
    lines.append('')
    lines.append('## Results')
    lines.append('')
    for idx, item in enumerate(results, start=1):
        node = item.get('node', {})
        result = item.get('result') or {}
        ip_api = result.get('ip_api') or {}
        unified = result.get('unified') or {}
        lines.append(f"### {idx}. {node.get('remark') or '(no remark)'}")
        lines.append(f"- protocol: `{node.get('protocol')}`")
        lines.append(f"- source_type: `{node.get('source_type')}`")
        lines.append(f"- source_name: `{node.get('source_name')}`")
        lines.append(f"- server: `{node.get('server')}:{node.get('server_port')}`")
        lines.append(f"- network: `{node.get('network')}` / tls: `{node.get('tls_mode')}`")
        lines.append(f"- supported: `{item.get('supported')}`")
        lines.append(f"- success: `{item.get('success')}`")
        if item.get('skip_reason'):
            lines.append(f"- skip_reason: `{item.get('skip_reason')}`")
        if item.get('error'):
            lines.append(f"- error: `{item.get('error')}`")
        if item.get('success'):
            lines.append(f"- exit_ip: `{(result.get('ipify') or {}).get('ip')}`")
            lines.append(f"- country/city: `{ip_api.get('country')} / {ip_api.get('city')}`")
            lines.append(f"- ASN: `{ip_api.get('as')}`")
            lines.append(f"- ISP/ORG: `{ip_api.get('isp')} / {ip_api.get('org')}`")
            lines.append(f"- ip_type_final: `{unified.get('ip_type_final')}`")
            lines.append(f"- risk: `{unified.get('risk_level_final')} / {unified.get('risk_score_final')}`")
            lines.append(f"- native_ip_judgement: `{unified.get('native_ip_judgement')}`")
            lines.append(f"- civilian_grade: `{unified.get('civilian_grade')}`")
            lines.append(f"- reasoning_brief: `{unified.get('reasoning_brief')}`")
        lines.append('')
    path.write_text('\n'.join(lines), encoding='utf-8')
