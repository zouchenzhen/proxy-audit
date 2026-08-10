"""Privacy-safe secret scan for the full reachable Git history and worktree.

Findings report only rule, object/scope, path and line number. Matched values
are deliberately never printed because scanner output may be stored in CI logs.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
MAX_DEFAULT_BYTES = 2 * 1024 * 1024
SENSITIVE_PATH = re.compile(
    r"(?i)(?:^|/)(?:config\.(?:local|secure)\.json|\.env(?:\..*)?|guiNDB\.db|(?:input|results)/.+|[^/]*backup[^/]*\.(?:zip|db))$"
)


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]


RULES = (
    Rule("proxy-share-link", re.compile(r"(?i)\b(?:vless|vmess|trojan|ss|hysteria2?|tuic|anytls|socks5?)://[^\s\"'<>]+")),
    Rule("subscription-url", re.compile(r"(?i)https?://[^\s\"'<>]+/(?:sub(?:scription)?s?|api/v1/client/subscribe)(?:[/?.#][^\s\"'<>]*)?")),
    Rule("url-secret-query", re.compile(r"(?i)https?://[^\s\"'<>]+[?&](?:token|key|auth|password)=[^\s&\"'<>]{8,}")),
    Rule("uuid", re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")),
    Rule("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    Rule("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    Rule("openai-token", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    Rule("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    Rule("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Rule("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    Rule("url-userinfo", re.compile(r"(?i)https?://[^\s/@:]+:[^\s/@]+@[^\s/]+")),
    Rule(
        "assigned-secret",
        re.compile(
            r"(?i)\b(?:(?:[a-z0-9]+[_-])?api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd)\b"
            r"\s*[:=]\s*(?:\[\s*)?[\"']([A-Za-z0-9_./+=:@-]{8,})[\"']"
        ),
    ),
)


SAFE_MARKERS = (
    "example.com",
    "example.invalid",
    ".invalid",
    "192.0.2.",
    "198.51.100.",
    "203.0.113.",
    "safe-password",
    "new-secret",
    "legacy-secret",
    "alpha-secret-111",
    "beta-secret-222",
    "credential-must-not-leak",
    "secret-node-credential",
    "browser-acceptance-",
    "demo-us.invalid",
    "demo-jp.invalid",
)


def git(*args: str, input_data: bytes | None = None) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        input=input_data,
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(message or f"git {' '.join(args)} failed")
    return completed.stdout


def safe_placeholder(path: str, line: str, value: str) -> bool:
    lower = f"{line}\n{value}".lower()
    if any(marker in lower for marker in SAFE_MARKERS):
        return True
    if re.fullmatch(r"0{8}-0{4}-0{4}-0{4}-0{9}[0-9a-f]{3}", value, re.IGNORECASE):
        return True
    if path == "scripts/scan_git_history.py":
        return True
    return False


def text_lines(data: bytes) -> Iterable[tuple[int, str]]:
    if b"\x00" in data[:8192]:
        return ()
    text = data.decode("utf-8", errors="replace")
    return enumerate(text.splitlines(), start=1)


def scan_bytes(scope: str, path: str, data: bytes) -> list[tuple[str, str, str, int]]:
    findings: list[tuple[str, str, str, int]] = []
    if SENSITIVE_PATH.search(path.replace("\\", "/")):
        findings.append(("sensitive-path", scope, path, 0))
    for line_number, line in text_lines(data):
        for rule in RULES:
            for match in rule.pattern.finditer(line):
                value = match.group(0)
                if safe_placeholder(path, line, value):
                    continue
                findings.append((rule.name, scope, path, line_number))
    return findings


def history_blobs(max_bytes: int) -> Iterable[tuple[str, str, bytes]]:
    commits = git("rev-list", "--all").decode().splitlines()
    seen: set[tuple[str, str]] = set()
    for commit in commits:
        entries = git("ls-tree", "-r", "-z", commit).split(b"\x00")
        for entry in entries:
            if not entry:
                continue
            metadata, raw_path = entry.split(b"\t", 1)
            _mode, kind, oid = metadata.decode().split()
            if kind != "blob":
                continue
            path = raw_path.decode("utf-8", errors="replace")
            identity = (oid, path)
            if identity in seen:
                continue
            seen.add(identity)
            data = git("cat-file", "blob", oid)
            if len(data) <= max_bytes:
                yield f"git:{oid[:12]}", path, data


def worktree_files(max_bytes: int) -> Iterable[tuple[str, str, bytes]]:
    paths = git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\x00")
    for raw_path in paths:
        if not raw_path:
            continue
        path = raw_path.decode("utf-8", errors="replace")
        target = ROOT / path
        if target.is_file() and target.stat().st_size <= max_bytes:
            yield "worktree", path, target.read_bytes()


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan reachable Git history without printing secret values")
    parser.add_argument("--max-bytes", type=int, default=MAX_DEFAULT_BYTES, help="maximum blob/file size to scan")
    parser.add_argument("--no-worktree", action="store_true", help="scan committed history only")
    args = parser.parse_args()

    findings: set[tuple[str, str, str, int]] = set()
    try:
        for scope, path, data in history_blobs(max(1024, args.max_bytes)):
            findings.update(scan_bytes(scope, path, data))
        if not args.no_worktree:
            for scope, path, data in worktree_files(max(1024, args.max_bytes)):
                findings.update(scan_bytes(scope, path, data))
    except (OSError, RuntimeError) as exc:
        print(f"scan failed: {type(exc).__name__}", file=sys.stderr)
        return 2

    if findings:
        print(f"Sensitive-pattern findings: {len(findings)}")
        for rule, scope, path, line in sorted(findings):
            location = f"{path}:{line}" if line else path
            print(f"- {rule} | {scope} | {location} | value redacted")
        print("Rotate any real credential before considering a history rewrite.")
        return 1

    print("Sensitive-pattern scan passed: full reachable Git history and worktree are clean.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
