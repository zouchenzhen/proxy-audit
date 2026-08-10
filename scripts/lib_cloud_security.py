import http.client
import ipaddress
import socket
import ssl
from typing import Dict, Iterable, List, Tuple
from urllib.parse import urljoin, urlsplit


MAX_SUBSCRIPTION_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 3


def _ip_is_public(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    return bool(ip.is_global)


def resolve_public_host(hostname: str, port: int) -> List[str]:
    clean = str(hostname or "").strip().rstrip(".")
    if not clean:
        raise ValueError("Missing host")
    try:
        direct = ipaddress.ip_address(clean.split("%", 1)[0])
        addresses = [str(direct)]
    except ValueError:
        try:
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(clean, port, type=socket.SOCK_STREAM)})
        except socket.gaierror as error:
            raise ValueError("Host cannot be resolved") from error
    if not addresses or any(not _ip_is_public(address) for address in addresses):
        raise ValueError("Private, loopback, reserved, or metadata-network targets are not allowed")
    return sorted(addresses, key=lambda item: (":" in item, item))


def pin_public_node(node: Dict) -> Dict:
    pinned = dict(node)
    original = str(node.get("server") or "").strip()
    port = int(node.get("server_port") or 0)
    addresses = resolve_public_host(original, port)
    if not node.get("sni") and not _looks_like_ip(original):
        pinned["sni"] = original
    if (node.get("network") or "").lower() == "ws" and not node.get("host") and not _looks_like_ip(original):
        pinned["host"] = original
    pinned["_display_server"] = original
    pinned["server"] = addresses[0]
    return pinned


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.split("%", 1)[0])
        return True
    except ValueError:
        return False


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, pinned_ip: str, timeout: int):
        super().__init__(host, port=port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, pinned_ip: str, timeout: int):
        super().__init__(host, port=port, timeout=timeout, context=ssl.create_default_context())
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        raw = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def _read_limited(response: http.client.HTTPResponse, limit: int) -> bytes:
    declared = response.getheader("Content-Length")
    if declared and int(declared) > limit:
        raise ValueError("Subscription response exceeds 2 MB")
    body = response.read(limit + 1)
    if len(body) > limit:
        raise ValueError("Subscription response exceeds 2 MB")
    return body


def fetch_public_subscription(url: str, timeout: int = 15) -> str:
    current = str(url or "").strip()
    for _ in range(MAX_REDIRECTS + 1):
        parsed = urlsplit(current)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Subscription URL must use public HTTP or HTTPS")
        if parsed.username or parsed.password or parsed.fragment:
            raise ValueError("Subscription URL must not contain credentials or fragments")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        pinned_ip = resolve_public_host(parsed.hostname, port)[0]
        connection_cls = _PinnedHTTPSConnection if parsed.scheme == "https" else _PinnedHTTPConnection
        connection = connection_cls(parsed.hostname, port, pinned_ip, timeout)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        try:
            connection.request("GET", path, headers={
                "Host": parsed.netloc,
                "User-Agent": "ProxyAudit-Cloud/2.3",
                "Accept": "text/plain,application/octet-stream;q=0.8,*/*;q=0.2",
            })
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                location = response.getheader("Location")
                response.read(1024)
                if not location:
                    raise ValueError("Subscription redirect has no destination")
                current = urljoin(current, location)
                continue
            if not 200 <= response.status < 300:
                raise ValueError(f"Subscription server returned HTTP {response.status}")
            body = _read_limited(response, MAX_SUBSCRIPTION_BYTES)
            charset = response.headers.get_content_charset() or "utf-8"
            return body.decode(charset, errors="replace")
        finally:
            connection.close()
    raise ValueError("Subscription redirected too many times")
