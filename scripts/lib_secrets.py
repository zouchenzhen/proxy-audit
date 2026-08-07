import base64
import ctypes
import json
import os
from ctypes import wintypes
from pathlib import Path
from typing import Any, Dict

from lib_paths import ROOT


SECURE_CONFIG = ROOT / "config.secure.json"
LEGACY_CONFIG = ROOT / "config.local.json"
SECRET_FIELDS = {
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


def load_settings(include_legacy: bool = True) -> Dict[str, Any]:
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
    return {key: value for key, value in settings.items() if key in ALLOWED_FIELDS}


def save_settings(updates: Dict[str, Any], clear_fields=None) -> Dict[str, Any]:
    current = load_settings()
    for key in clear_fields or []:
        if key in ALLOWED_FIELDS:
            # Keep an explicit empty tombstone so a cleared value does not
            # reappear from the legacy plaintext config during migration.
            current[key] = ""
    for key, value in updates.items():
        if key not in ALLOWED_FIELDS or value is None or value == "":
            continue
        if key in {"default_timeout", "default_concurrency"}:
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
    return {
        "configured": {field: bool(settings.get(field)) for field in sorted(SECRET_FIELDS)},
        "scamalytics_user_configured": bool(settings.get("scamalytics_user")),
        "singbox_path": settings.get("singbox_path") or "",
        "xray_path": settings.get("xray_path") or "",
        "default_timeout": int(settings.get("default_timeout") or 15),
        "default_concurrency": int(settings.get("default_concurrency") or 2),
        "storage": "Windows DPAPI" if os.name == "nt" else "local file",
        "legacy_config_detected": LEGACY_CONFIG.exists(),
    }
