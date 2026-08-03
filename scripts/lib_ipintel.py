import json
import time
from pathlib import Path
from typing import Any, Dict, Optional

import requests

ROOT = Path(r"E:\Openclaw_Workspace\proxy_audit")
CONFIG_LOCAL = ROOT / 'config.local.json'


def load_local_config() -> Dict[str, Any]:
    if not CONFIG_LOCAL.exists():
        return {}
    return json.loads(CONFIG_LOCAL.read_text(encoding='utf-8'))


def _safe_json(resp):
    try:
        return resp.json()
    except Exception:
        try:
            return json.loads(resp.text)
        except Exception:
            return {'raw_text': resp.text}


def _session_with_socks(socks_port: Optional[int] = None) -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    if socks_port:
        proxies = {
            'http': f'socks5h://127.0.0.1:{socks_port}',
            'https': f'socks5h://127.0.0.1:{socks_port}',
        }
        session.proxies.update(proxies)
    return session


def _get_json(session: requests.Session, url: str, timeout: int, headers: Optional[Dict[str, str]] = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    resp = session.get(url, timeout=timeout, headers=headers or {}, params=params or {})
    resp.raise_for_status()
    return _safe_json(resp)


def fetch_ipinfo(ip: str, timeout: int = 15, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cfg = cfg or load_local_config()
    token = cfg.get('ipinfo_api_key')
    session = _session_with_socks(None)
    headers = {'User-Agent': 'Mozilla/5.0'}
    if token:
        return _get_json(session, f'https://api.ipinfo.io/lite/{ip}', timeout, headers=headers, params={'token': token})
    return _get_json(session, f'https://ipinfo.io/widget/demo/{ip}', timeout, headers=headers)


def fetch_ip2location(ip: str, timeout: int = 15, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cfg = cfg or load_local_config()
    key = cfg.get('ip2location_api_key')
    session = _session_with_socks(None)
    params = {'ip': ip}
    if key:
        params['key'] = key
    return _get_json(session, 'https://api.ip2location.io/', timeout, params=params)


def fetch_ipqs(ip: str, timeout: int = 15, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cfg = cfg or load_local_config()
    key = cfg.get('ipqs_api_key')
    session = _session_with_socks(None)
    if key:
        url = f'https://www.ipqualityscore.com/api/json/ip/{key}/{ip}'
        return _get_json(session, url, timeout, params={'strictness': 1, 'allow_public_access_points': 'true'})
    return _get_json(session, f'https://ipqualityscore.com/api/json/ip/demo/{ip}', timeout)


def fetch_scamalytics(ip: str, timeout: int = 15, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cfg = cfg or load_local_config()
    user = cfg.get('scamalytics_user')
    key = cfg.get('scamalytics_api_key')
    session = _session_with_socks(None)
    headers = {'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json,text/plain,*/*'}
    if user and key:
        return _get_json(session, f'https://api11.scamalytics.com/v3/{user}/', timeout, headers=headers, params={'key': key, 'ip': ip})
    return _get_json(session, f'https://scamalytics.com/ip/{ip}?output=json', timeout, headers=headers)


def classify_ip_type(ip_api: Dict[str, Any], ip2location: Dict[str, Any], ipqs: Dict[str, Any], scamalytics: Dict[str, Any]) -> str:
    mobile = any([
        bool(ip_api.get('mobile')),
        bool(ipqs.get('mobile')),
        str(ip2location.get('usage_type') or '').lower() == 'mobile',
    ])
    if mobile:
        return 'mobile'

    hosting_votes = 0
    if bool(ip_api.get('hosting')):
        hosting_votes += 1
    if bool((scamalytics.get('scamalytics') or {}).get('scamalytics_proxy', {}).get('is_datacenter')):
        hosting_votes += 1
    if str(ip2location.get('usage_type') or '').lower() in {'dch', 'data center/web hosting/transit', 'cdn'}:
        hosting_votes += 1
    if hosting_votes >= 1:
        return 'datacenter'

    proxy_votes = 0
    if bool(ip_api.get('proxy')):
        proxy_votes += 1
    if bool(ipqs.get('proxy')) or bool(ipqs.get('vpn')) or bool(ipqs.get('tor')) or bool(ipqs.get('active_vpn')):
        proxy_votes += 1
    if bool((scamalytics.get('scamalytics') or {}).get('scamalytics_proxy', {}).get('is_vpn')):
        proxy_votes += 1
    if proxy_votes >= 1:
        return 'proxy_or_transit'

    return 'residential_or_business'


def classify_native(ip_api: Dict[str, Any], ipinfo: Dict[str, Any], ip2location: Dict[str, Any]) -> str:
    reg = (ipinfo.get('country_code') or ip2location.get('country_code') or '').upper()
    geo = (ip_api.get('countryCode') or '').upper()
    if not reg or not geo:
        return '未知'
    return '原生' if reg == geo else '广播'


def classify_risk(ipqs: Dict[str, Any], scamalytics: Dict[str, Any], ip_api: Dict[str, Any]) -> Dict[str, Any]:
    scores = []
    fraud = ipqs.get('fraud_score')
    if isinstance(fraud, (int, float)):
        scores.append(int(fraud))
    scam_score = (scamalytics.get('scamalytics') or {}).get('scamalytics_score')
    if isinstance(scam_score, (int, float)):
        scores.append(int(scam_score))
    if bool(ip_api.get('proxy')):
        scores.append(65)
    if bool(ip_api.get('hosting')):
        scores.append(55)

    final = max(scores) if scores else 0
    if final >= 75:
        level = 'high'
    elif final >= 40:
        level = 'medium'
    else:
        level = 'low'
    return {'risk_score_final': final, 'risk_level_final': level}


def build_unified_profile(exit_ip: str, ip_api: Dict[str, Any], ipinfo: Dict[str, Any], ip2location: Dict[str, Any], ipqs: Dict[str, Any], scamalytics: Dict[str, Any]) -> Dict[str, Any]:
    ip_type_final = classify_ip_type(ip_api, ip2location, ipqs, scamalytics)
    native_ip_judgement = classify_native(ip_api, ipinfo, ip2location)
    risk = classify_risk(ipqs, scamalytics, ip_api)
    civilian_grade = ip_type_final in ('mobile', 'residential_or_business')

    reasons = []
    if ip_type_final == 'mobile':
        reasons.append('mobile 信号明显，按家宽级口径视为纯净')
    elif ip_type_final == 'datacenter':
        reasons.append('多源命中托管/机房特征')
    elif ip_type_final == 'proxy_or_transit':
        reasons.append('多源命中代理/中转特征')
    else:
        reasons.append('未见明显机房或代理特征')
    reasons.append(f'注册地/落地地判定：{native_ip_judgement}')
    reasons.append(f"综合风险：{risk['risk_level_final']}({risk['risk_score_final']})")

    return {
        'exit_ip': exit_ip,
        'ip_type_final': ip_type_final,
        'risk_score_final': risk['risk_score_final'],
        'risk_level_final': risk['risk_level_final'],
        'native_ip_judgement': native_ip_judgement,
        'civilian_grade': civilian_grade,
        'reasoning_brief': '；'.join(reasons),
    }


def enrich_ip_profile(exit_ip: str, timeout: int = 15, sleep_sec: float = 0.0, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cfg = cfg or load_local_config()
    out = {'ipinfo': {}, 'ip2location': {}, 'ipqs': {}, 'scamalytics': {}, 'errors': {}}
    for key, fn in [('ipinfo', fetch_ipinfo), ('ip2location', fetch_ip2location), ('ipqs', fetch_ipqs), ('scamalytics', fetch_scamalytics)]:
        try:
            out[key] = fn(exit_ip, timeout, cfg) or {}
        except Exception as e:
            out['errors'][key] = repr(e)
            out[key] = {}
        if sleep_sec:
            time.sleep(sleep_sec)
    out['unified'] = build_unified_profile(exit_ip, {}, out.get('ipinfo') or {}, out.get('ip2location') or {}, out.get('ipqs') or {}, out.get('scamalytics') or {})
    return out


def probe_ip_via_socks(socks_port: int, timeout: int = 15) -> dict:
    cfg = load_local_config()
    session = _session_with_socks(socks_port)
    ip_data = _get_json(session, 'https://api.ipify.org?format=json', timeout)
    ip = ip_data.get('ip')
    ip_api = _get_json(
        session,
        f'http://ip-api.com/json/{ip}?fields=status,message,query,country,countryCode,regionName,city,isp,org,as,asname,mobile,proxy,hosting',
        timeout,
    )
    enrich = enrich_ip_profile(ip, timeout=timeout, sleep_sec=0.15, cfg=cfg)
    unified = build_unified_profile(ip, ip_api, enrich.get('ipinfo') or {}, enrich.get('ip2location') or {}, enrich.get('ipqs') or {}, enrich.get('scamalytics') or {})
    return {
        'ipify': ip_data,
        'ip_api': ip_api,
        'ipinfo': enrich.get('ipinfo'),
        'ip2location': enrich.get('ip2location'),
        'ipqs': enrich.get('ipqs'),
        'scamalytics': enrich.get('scamalytics'),
        'intel_errors': enrich.get('errors') or {},
        'unified': unified,
    }
