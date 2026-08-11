import base64
import ctypes
import hashlib
import json
import os
from ctypes import wintypes
from pathlib import Path
from typing import Any, Dict, Iterable, List

from lib_paths import ROOT


SECURE_CONFIG = ROOT / "config.secure.json"
LEGACY_CONFIG = ROOT / "config.local.json"
SECRET_FIELDS = {
    "ipapi_is_api_key",
    "ip2location_api_key",
    "ipinfo_api_key",
    "ipqs_api_key",
    "scamalytics_api_key",
    "abuseipdb_api_key",
}
ALLOWED_FIELDS = SECRET_FIELDS | {
    "scamalytics_user",
    "singbox_path",
    "xray_path",
    "default_timeout",
    "default_concurrency",
    "history_limit",
}
MAX_KEYS_PER_PROVIDER = 50
ENV_SECRET_PREFIXES = {
    "ipapi_is_api_key": "PROXY_AUDIT_IPAPI_IS_API_KEY",
    "ip2location_api_key": "PROXY_AUDIT_IP2LOCATION_API_KEY",
    "ipinfo_api_key": "PROXY_AUDIT_IPINFO_API_KEY",
    "ipqs_api_key": "PROXY_AUDIT_IPQS_API_KEY",
    "scamalytics_api_key": "PROXY_AUDIT_SCAMALYTICS_API_KEY",
    "abuseipdb_api_key": "PROXY_AUDIT_ABUSEIPDB_API_KEY",
}
ENV_PLAIN_FIELDS = {
    "scamalytics_user": "PROXY_AUDIT_SCAMALYTICS_USER",
}


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _blob(data: bytes):
    buffer = ctypes.create_string_buffer(data)
    return DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer


def _dpapi_protect(data: bytes) -> bytes:
    in_blob, in_buffer = _blob(data)
    entropy_blob, entropy_buffer = _blob(b"proxy-audit-local-config-v1")
    out_blob = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "Proxy Audit local settings",
        ctypes.byref(entropy_blob),
        None,
        None,
        0,
        ctypes.byref(out_blob),
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)


def _dpapi_unprotect(data: bytes) -> bytes:
    in_blob, in_buffer = _blob(data)
    entropy_blob, entropy_buffer = _blob(b"proxy-audit-local-config-v1")
    out_blob = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        ctypes.byref(entropy_blob),
        None,
        None,
        0,
        ctypes.byref(out_blob),
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)


def _read_secure() -> Dict[str, Any]:
    if not SECURE_CONFIG.exists():
        return {}
    wrapper = json.loads(SECURE_CONFIG.read_text(encoding="utf-8"))
    payload = base64.b64decode(wrapper.get("payload") or "")
    if wrapper.get("protected"):
        if os.name != "nt":
            raise RuntimeError("This settings file is protected by Windows DPAPI")
        payload = _dpapi_unprotect(payload)
    return json.loads(payload.decode("utf-8"))


def normalize_secret_values(value: Any) -> List[str]:
    if isinstance(value, str):
        values: Iterable[Any] = value.replace("\r", "\n").replace(",", "\n").replace(";", "\n").split("\n")
    elif isinstance(value, (list, tuple, set)):
        values = value
    else:
        values = []
    output: List[str] = []
    seen = set()
    for item in values:
        key = str(item or "").strip()
        if not key or key in seen:
            continue
        seen.add(key)
        output.append(key)
        if len(output) >= MAX_KEYS_PER_PROVIDER:
            break
    return output


def secret_id(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def secret_preview(value: str) -> Dict[str, str]:
    visible = min(6, len(value) - 4) if len(value) > 4 else 0
    return {
        "id": secret_id(value),
        "masked": "••••••••",
        "prefix": f"{value[:visible]}…" if visible else "••…",
    }


def _environment_settings() -> Dict[str, Any]:
    settings: Dict[str, Any] = {}
    for field, prefix in ENV_SECRET_PREFIXES.items():
        values: List[str] = []
        for name in [prefix, f"{prefix}S", *(f"{prefix}_{index}" for index in range(1, MAX_KEYS_PER_PROVIDER + 1))]:
            values.extend(normalize_secret_values(os.environ.get(name)))
        values = normalize_secret_values(values)
        if values:
            settings[field] = values
    for field, name in ENV_PLAIN_FIELDS.items():
        value = str(os.environ.get(name) or "").strip()
        if value:
            settings[field] = value
    return settings


def load_settings(include_legacy: bool = True, include_environment: bool = True) -> Dict[str, Any]:
    settings: Dict[str, Any] = {}
    if include_legacy and LEGACY_CONFIG.exists():
        try:
            settings.update(json.loads(LEGACY_CONFIG.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass
    try:
        settings.update(_read_secure())
    except (OSError, ValueError, RuntimeError):
        pass
    if include_environment:
        settings.update(_environment_settings())
    output = {key: value for key, value in settings.items() if key in ALLOWED_FIELDS}
    for field in SECRET_FIELDS:
        if field in output:
            output[field] = normalize_secret_values(output[field])
    return output


def save_settings(updates: Dict[str, Any], clear_fields=None, remove_key_ids=None) -> Dict[str, Any]:
    # Runtime-injected values must stay process-only and must never be copied
    # into config.secure.json when another setting is saved through the UI.
    current = load_settings(include_environment=False)
    for key in clear_fields or []:
        if key in ALLOWED_FIELDS:
            # Keep an explicit empty tombstone so a cleared value does not
            # reappear from the legacy plaintext config during migration.
            current[key] = [] if key in SECRET_FIELDS else ""
    for field, identifiers in (remove_key_ids or {}).items():
        if field not in SECRET_FIELDS:
            continue
        remove = {str(identifier) for identifier in identifiers or []}
        current[field] = [key for key in normalize_secret_values(current.get(field)) if secret_id(key) not in remove]
    for key, value in updates.items():
        if key not in ALLOWED_FIELDS or value is None or value == "":
            continue
        if key in SECRET_FIELDS:
            current[key] = normalize_secret_values(normalize_secret_values(current.get(key)) + normalize_secret_values(value))
            continue
        if key in {"default_timeout", "default_concurrency", "history_limit"}:
            value = int(value)
        current[key] = value

    raw = json.dumps(current, ensure_ascii=False).encode("utf-8")
    protected = os.name == "nt"
    payload = _dpapi_protect(raw) if protected else raw
    wrapper = {
        "version": 1,
        "protected": protected,
        "payload": base64.b64encode(payload).decode("ascii"),
    }
    temp = SECURE_CONFIG.with_suffix(".tmp")
    temp.write_text(json.dumps(wrapper, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(SECURE_CONFIG)
    return current


def public_settings() -> Dict[str, Any]:
    settings = load_settings()
    key_previews = {
        field: [secret_preview(value) for value in normalize_secret_values(settings.get(field))]
        for field in sorted(SECRET_FIELDS)
    }
    return {
        "configured": {field: bool(key_previews[field]) for field in sorted(SECRET_FIELDS)},
        "key_counts": {field: len(key_previews[field]) for field in sorted(SECRET_FIELDS)},
        "key_previews": key_previews,
        "scamalytics_user_configured": bool(settings.get("scamalytics_user")),
        "singbox_path": settings.get("singbox_path") or "",
        "xray_path": settings.get("xray_path") or "",
        "default_timeout": int(settings.get("default_timeout") or 15),
        "default_concurrency": int(settings.get("default_concurrency") or 2),
        "history_limit": max(1, min(int(settings.get("history_limit") or 10), 100)),
        "storage": "Windows DPAPI" if os.name == "nt" else "local file",
        "legacy_config_detected": LEGACY_CONFIG.exists(),
    }
