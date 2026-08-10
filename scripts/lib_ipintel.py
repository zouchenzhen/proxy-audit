import json
import statistics
import threading
import time
from typing import Any, Dict, List, Optional

import requests

from lib_secrets import load_settings, normalize_secret_values, secret_id


PROVIDER_META = [
    {"id": "ip_api", "name": "IP-API", "key_field": "", "default": True},
    {"id": "ipapi_is", "name": "ipapi.is", "key_field": "", "default": True},
    {"id": "ipinfo", "name": "IPinfo", "key_field": "ipinfo_api_key", "default": True},
    {"id": "ip2location", "name": "IP2Location", "key_field": "ip2location_api_key", "default": True},
    {"id": "ipqs", "name": "IPQualityScore", "key_field": "ipqs_api_key", "default": True},
    {"id": "scamalytics", "name": "Scamalytics", "key_field": "scamalytics_api_key", "default": True},
    {"id": "abuseipdb", "name": "AbuseIPDB", "key_field": "abuseipdb_api_key", "default": False},
]
DEFAULT_PROVIDERS = [item["id"] for item in PROVIDER_META if item["default"]]
SERVICE_TARGETS = {
    "chatgpt": ("ChatGPT", "https://chatgpt.com/cdn-cgi/trace"),
    "claude": ("Claude", "https://claude.ai/cdn-cgi/trace"),
    "github": ("GitHub", "https://github.com/favicon.ico"),
    "youtube": ("YouTube", "https://www.youtube.com/generate_204"),
}


class ProviderKeyUnavailable(RuntimeError):
    pass


_KEY_POOL_LOCK = threading.Lock()
_KEY_POOL_CURSOR: Dict[str, int] = {}
_KEY_POOL_COOLDOWN: Dict[str, float] = {}


def _provider_payload_ok(data: Dict[str, Any]) -> bool:
    if data.get("success") is False:
        return False
    if data.get("error"):
        return False
    return str(data.get("status") or "").lower() not in {"error", "fail", "failed"}


def _ordered_pool_keys(field: str, cfg: Dict[str, Any]) -> List[str]:
    keys = normalize_secret_values(cfg.get(field))
    if not keys:
        return []
    now = time.time()
    with _KEY_POOL_LOCK:
        start = _KEY_POOL_CURSOR.get(field, 0) % len(keys)
        _KEY_POOL_CURSOR[field] = (start + 1) % len(keys)
        ordered = keys[start:] + keys[:start]
        available = [key for key in ordered if _KEY_POOL_COOLDOWN.get(f"{field}:{secret_id(key)}", 0) <= now]
    return available


def _cooldown_key(field: str, key: str, seconds: int = 300) -> None:
    with _KEY_POOL_LOCK:
        _KEY_POOL_COOLDOWN[f"{field}:{secret_id(key)}"] = time.time() + seconds


def _request_with_key_pool(field: str, cfg: Dict[str, Any], fetcher, fallback=None) -> Dict[str, Any]:
    configured = normalize_secret_values(cfg.get(field))
    keys = _ordered_pool_keys(field, cfg)
    if not keys:
        if configured:
            raise ProviderKeyUnavailable(f"all configured keys for {field} are cooling down")
        return fallback() if fallback else {"skipped": "missing_api_key"}
    for key in keys:
        try:
            data = fetcher(key) or {}
            if not _provider_payload_ok(data):
                raise ProviderKeyUnavailable("provider rejected the key or quota is unavailable")
            return data
        except requests.HTTPError as exc:
            status = getattr(exc.response, "status_code", None)
            if status not in {401, 402, 403, 429}:
                raise
            _cooldown_key(field, key, 600 if status == 429 else 300)
        except ProviderKeyUnavailable:
            _cooldown_key(field, key)
    raise ProviderKeyUnavailable(f"all configured keys for {field} are unavailable")


def load_local_config() -> Dict[str, Any]:
    return load_settings()


def _safe_json(resp):
    try:
        return resp.json()
    except Exception:
        try:
            return json.loads(resp.text)
        except Exception:
            return {"raw_text": resp.text[:1200]}


def _session_with_socks(socks_port: Optional[int] = None) -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": "ProxyAudit/2.0 (+local-web-ui)"})
    if socks_port:
        session.proxies.update({
            "http": f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        })
    return session


def _get_json(session: requests.Session, url: str, timeout: int, headers=None, params=None) -> Dict[str, Any]:
    resp = session.get(url, timeout=timeout, headers=headers or {}, params=params or {})
    resp.raise_for_status()
    return _safe_json(resp)


def fetch_ipinfo(ip: str, timeout: int = 15, cfg=None) -> Dict[str, Any]:
    cfg = cfg or load_local_config()
    session = _session_with_socks()
    return _request_with_key_pool(
        "ipinfo_api_key",
        cfg,
        lambda token: _get_json(session, f"https://api.ipinfo.io/lite/{ip}", timeout, params={"token": token}),
        fallback=lambda: _get_json(session, f"https://ipinfo.io/widget/demo/{ip}", timeout),
    )


def fetch_ip2location(ip: str, timeout: int = 15, cfg=None) -> Dict[str, Any]:
    cfg = cfg or load_local_config()
    session = _session_with_socks()
    return _request_with_key_pool(
        "ip2location_api_key",
        cfg,
        lambda key: _get_json(session, "https://api.ip2location.io/", timeout, params={"ip": ip, "key": key}),
        fallback=lambda: _get_json(session, "https://api.ip2location.io/", timeout, params={"ip": ip}),
    )


def fetch_ipqs(ip: str, timeout: int = 15, cfg=None) -> Dict[str, Any]:
    cfg = cfg or load_local_config()
    session = _session_with_socks()
    return _request_with_key_pool(
        "ipqs_api_key",
        cfg,
        lambda key: _get_json(session, f"https://www.ipqualityscore.com/api/json/ip/{key}/{ip}", timeout, params={"strictness": 1, "allow_public_access_points": "true"}),
        fallback=lambda: _get_json(session, f"https://ipqualityscore.com/api/json/ip/demo/{ip}", timeout),
    )


def fetch_scamalytics(ip: str, timeout: int = 15, cfg=None) -> Dict[str, Any]:
    cfg = cfg or load_local_config()
    user = cfg.get("scamalytics_user")
    headers = {"Accept": "application/json,text/plain,*/*"}
    session = _session_with_socks()
    if not user:
        return _get_json(session, f"https://scamalytics.com/ip/{ip}?output=json", timeout, headers=headers)
    return _request_with_key_pool(
        "scamalytics_api_key",
        cfg,
        lambda key: _get_json(session, f"https://api11.scamalytics.com/v3/{user}/", timeout, headers=headers, params={"key": key, "ip": ip}),
        fallback=lambda: _get_json(session, f"https://scamalytics.com/ip/{ip}?output=json", timeout, headers=headers),
    )


def fetch_ipapi_is(ip: str, timeout: int = 15, cfg=None) -> Dict[str, Any]:
    return _get_json(_session_with_socks(), "https://api.ipapi.is/", timeout, params={"q": ip})


def fetch_abuseipdb(ip: str, timeout: int = 15, cfg=None) -> Dict[str, Any]:
    cfg = cfg or load_local_config()
    session = _session_with_socks()
    data = _request_with_key_pool(
        "abuseipdb_api_key",
        cfg,
        lambda key: _get_json(
            session,
            "https://api.abuseipdb.com/api/v2/check",
            timeout,
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
        ),
    )
    return data.get("data") or data


def classify_ip_type(ip_api, ip2location, ipqs, scamalytics, ipapi_is=None) -> str:
    ipapi_is = ipapi_is or {}
    mobile = any([
        bool(ip_api.get("mobile")),
        bool(ipqs.get("mobile")),
        str(ip2location.get("usage_type") or "").lower() == "mobile",
        bool(ipapi_is.get("is_mobile")),
    ])
    if mobile:
        return "mobile"
    hosting = any([
        bool(ip_api.get("hosting")),
        bool((scamalytics.get("scamalytics") or {}).get("scamalytics_proxy", {}).get("is_datacenter")),
        str(ip2location.get("usage_type") or "").lower() in {"dch", "data center/web hosting/transit", "cdn"},
        bool(ipapi_is.get("is_datacenter")),
    ])
    if hosting:
        return "datacenter"
    proxy = any([
        bool(ip_api.get("proxy")),
        bool(ipqs.get("proxy") or ipqs.get("vpn") or ipqs.get("tor") or ipqs.get("active_vpn")),
        bool((scamalytics.get("scamalytics") or {}).get("scamalytics_proxy", {}).get("is_vpn")),
        bool(ipapi_is.get("is_proxy") or ipapi_is.get("is_vpn") or ipapi_is.get("is_tor")),
    ])
    return "proxy_or_transit" if proxy else "residential_or_business"


def classify_native(ip_api, ipinfo, ip2location) -> str:
    reg = (ipinfo.get("country_code") or ip2location.get("country_code") or "").upper()
    geo = (ip_api.get("countryCode") or "").upper()
    if not reg or not geo:
        return "未知"
    return "原生" if reg == geo else "广播"


def classify_risk(ipqs, scamalytics, ip_api, abuseipdb=None, ipapi_is=None) -> Dict[str, Any]:
    scores = []
    fraud = ipqs.get("fraud_score")
    if isinstance(fraud, (int, float)):
        scores.append(int(fraud))
    scam_score = (scamalytics.get("scamalytics") or {}).get("scamalytics_score")
    if isinstance(scam_score, (int, float)):
        scores.append(int(scam_score))
    abuse = (abuseipdb or {}).get("abuseConfidenceScore")
    if isinstance(abuse, (int, float)):
        scores.append(int(abuse))
    if ip_api.get("proxy") or (ipapi_is or {}).get("is_proxy"):
        scores.append(65)
    if ip_api.get("hosting") or (ipapi_is or {}).get("is_datacenter"):
        scores.append(55)
    final = max(scores) if scores else 0
    level = "high" if final >= 75 else "medium" if final >= 40 else "low"
    return {"risk_score_final": final, "risk_level_final": level, "source_scores": scores}


def build_unified_profile(exit_ip, ip_api, ipinfo, ip2location, ipqs, scamalytics, abuseipdb=None, ipapi_is=None) -> Dict[str, Any]:
    ip_type = classify_ip_type(ip_api, ip2location, ipqs, scamalytics, ipapi_is)
    native = classify_native(ip_api, ipinfo, ip2location)
    risk = classify_risk(ipqs, scamalytics, ip_api, abuseipdb, ipapi_is)
    civilian = ip_type in ("mobile", "residential_or_business")
    type_reason = {
        "mobile": "多源命中移动网络特征",
        "datacenter": "多源命中托管/机房特征",
        "proxy_or_transit": "多源命中代理/中转特征",
        "residential_or_business": "未见明显机房或代理特征",
    }[ip_type]
    return {
        "exit_ip": exit_ip,
        "ip_type_final": ip_type,
        "risk_score_final": risk["risk_score_final"],
        "risk_level_final": risk["risk_level_final"],
        "native_ip_judgement": native,
        "civilian_grade": civilian,
        "reasoning_brief": f"{type_reason}；注册地/落地地：{native}；综合风险：{risk['risk_level_final']}({risk['risk_score_final']})",
    }


def enrich_ip_profile(exit_ip: str, timeout: int = 15, sleep_sec: float = 0.0, cfg=None, providers=None) -> Dict[str, Any]:
    cfg = cfg or load_local_config()
    providers = list(providers or DEFAULT_PROVIDERS)
    fetchers = {
        "ipinfo": fetch_ipinfo,
        "ip2location": fetch_ip2location,
        "ipqs": fetch_ipqs,
        "scamalytics": fetch_scamalytics,
        "ipapi_is": fetch_ipapi_is,
        "abuseipdb": fetch_abuseipdb,
    }
    out = {key: {} for key in fetchers}
    out["errors"] = {}
    for key in providers:
        fn = fetchers.get(key)
        if not fn:
            continue
        try:
            out[key] = fn(exit_ip, timeout, cfg) or {}
        except Exception as exc:
            # Do not include request URLs here: some providers place the API key
            # in the URL path and requests' exception text would leak it.
            out["errors"][key] = type(exc).__name__
        if sleep_sec:
            time.sleep(sleep_sec)
    return out


def probe_quality(session: requests.Session, timeout: int, samples: int = 2) -> Dict[str, Any]:
    latencies: List[float] = []
    errors = []
    for _ in range(max(0, min(samples, 5))):
        started = time.perf_counter()
        try:
            response = session.get("https://www.gstatic.com/generate_204", timeout=timeout)
            response.raise_for_status()
            latencies.append(round((time.perf_counter() - started) * 1000, 1))
        except Exception as exc:
            errors.append(type(exc).__name__)
    jitter = round(statistics.pstdev(latencies), 1) if len(latencies) > 1 else 0.0
    return {
        "samples_ms": latencies,
        "latency_median_ms": round(statistics.median(latencies), 1) if latencies else None,
        "jitter_ms": jitter if latencies else None,
        "success_rate": round(len(latencies) / max(samples, 1) * 100, 1),
        "errors": errors,
    }


def probe_services(session: requests.Session, timeout: int, targets=None) -> Dict[str, Any]:
    output = {}
    for target in targets or []:
        if target not in SERVICE_TARGETS:
            continue
        name, url = SERVICE_TARGETS[target]
        started = time.perf_counter()
        try:
            response = session.get(url, timeout=timeout, allow_redirects=True)
            output[target] = {
                "name": name,
                "reachable": response.status_code > 0,
                "status": response.status_code,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
                "note": "仅代表端点连通，不等于账号或区域解锁",
            }
        except Exception as exc:
            output[target] = {"name": name, "reachable": False, "status": None, "error": type(exc).__name__}
    return output


def probe_ip_via_socks(socks_port: int, timeout: int = 15, providers=None, service_targets=None, quality_samples: int = 2) -> dict:
    cfg = load_local_config()
    selected = list(providers or DEFAULT_PROVIDERS)
    session = _session_with_socks(socks_port)
    started = time.perf_counter()
    ip_data = _get_json(session, "https://api.ipify.org?format=json", timeout)
    ipify_ms = round((time.perf_counter() - started) * 1000, 1)
    ip = ip_data.get("ip")
    ip_api = {}
    intel_errors = {}
    if "ip_api" in selected:
        try:
            ip_api = _get_json(
                session,
                f"http://ip-api.com/json/{ip}?fields=status,message,query,country,countryCode,regionName,city,isp,org,as,asname,mobile,proxy,hosting",
                timeout,
            )
        except Exception as exc:
            intel_errors["ip_api"] = f"{type(exc).__name__}: {exc}"
    enrich = enrich_ip_profile(ip, timeout=timeout, sleep_sec=0.08, cfg=cfg, providers=selected)
    intel_errors.update(enrich.get("errors") or {})
    unified = build_unified_profile(
        ip,
        ip_api,
        enrich.get("ipinfo") or {},
        enrich.get("ip2location") or {},
        enrich.get("ipqs") or {},
        enrich.get("scamalytics") or {},
        enrich.get("abuseipdb") or {},
        enrich.get("ipapi_is") or {},
    )
    return {
        "ipify": ip_data,
        "ipify_latency_ms": ipify_ms,
        "ip_api": ip_api,
        "ipinfo": enrich.get("ipinfo"),
        "ip2location": enrich.get("ip2location"),
        "ipqs": enrich.get("ipqs"),
        "scamalytics": enrich.get("scamalytics"),
        "ipapi_is": enrich.get("ipapi_is"),
        "abuseipdb": enrich.get("abuseipdb"),
        "intel_errors": intel_errors,
        "unified": unified,
        "quality": probe_quality(session, timeout, quality_samples),
        "services": probe_services(session, timeout, service_targets),
    }
