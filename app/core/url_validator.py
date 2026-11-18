"""URL validation and SSRF protection for SecureSight AI.

Before any scan, the target URL must pass validate_target_url().
It rejects:
  - non-http/https schemes (file://, ftp://, ...)
  - URLs containing usernames/passwords
  - unusual ports
  - localhost and internal hostnames
  - hostnames that RESOLVE to private/internal IP addresses
"""

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443, 8080, 8443}
BLOCKED_HOSTNAMES = {"localhost"}
BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home", ".corp")


class UnsafeURLError(ValueError):
    """Raised when a URL is invalid or not safe to scan."""


@dataclass
class ValidatedTarget:
    """The result of a successful validation."""

    url: str
    scheme: str
    hostname: str
    port: int
    ip_addresses: list[str] = field(default_factory=list)


def normalize_url(raw_url: str) -> str:
    """Clean up user input. Adds https:// if no scheme was typed."""
    if raw_url is None:
        raise UnsafeURLError("Please enter a URL.")

    url = raw_url.strip()
    if not url:
        raise UnsafeURLError("Please enter a URL.")
    if len(url) > MAX_URL_LENGTH:
        raise UnsafeURLError("The URL is too long.")
    if any(ch.isspace() or ord(ch) < 32 for ch in url):
        raise UnsafeURLError("The URL contains invalid characters.")

    if "://" not in url:
        url = "https://" + url
    return url


def is_blocked_ip(ip_string: str) -> bool:
    """Return True if the IP is NOT a normal public internet address."""
    ip = ipaddress.ip_address(ip_string)

    # Treat IPv4 addresses wrapped in IPv6 (::ffff:127.0.0.1) as IPv4.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    # is_global is False for private, loopback, link-local (169.254.x.x),
    # shared (100.64.x.x), reserved and unspecified (0.0.0.0) addresses.
    return (not ip.is_global) or ip.is_multicast


def resolve_host(hostname: str, port: int) -> list[str]:
    """Return every IP address a hostname resolves to."""
    # If the hostname is already an IP address, no DNS lookup is needed.
    try:
        return [str(ipaddress.ip_address(hostname))]
    except ValueError:
        pass

    try:
        results = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        raise UnsafeURLError(f"Could not resolve the hostname '{hostname}'.")

    addresses = []
    for result in results:
        ip = result[4][0].split("%")[0]  # strip IPv6 scope id if present
        if ip not in addresses:
            addresses.append(ip)
    return addresses


def validate_target_url(raw_url: str) -> ValidatedTarget:
    """Validate a user-supplied URL. Raises UnsafeURLError if unsafe."""
    url = normalize_url(raw_url)

    try:
        parsed = urlparse(url)
        port = parsed.port  # raises ValueError for invalid ports
    except ValueError:
        raise UnsafeURLError("The URL is not formatted correctly.")

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsafeURLError("Only http:// and https:// URLs are allowed.")

    if parsed.username or parsed.password:
        raise UnsafeURLError("URLs containing usernames or passwords are not allowed.")

    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        raise UnsafeURLError("The URL does not contain a hostname.")

    if port is None:
        port = 443 if scheme == "https" else 80
    if port not in ALLOWED_PORTS:
        raise UnsafeURLError(
            f"Port {port} is not allowed. Allowed ports: {sorted(ALLOWED_PORTS)}."
        )

    if hostname in BLOCKED_HOSTNAMES or hostname.endswith(BLOCKED_SUFFIXES):
        raise UnsafeURLError("Scanning localhost or internal hostnames is not allowed.")

    ip_addresses = resolve_host(hostname, port)
    if not ip_addresses:
        raise UnsafeURLError(f"Could not resolve the hostname '{hostname}'.")

    # Every resolved address must be public. One private address is enough to block.
    for ip in ip_addresses:
        if is_blocked_ip(ip):
            raise UnsafeURLError(
                f"Blocked: '{hostname}' points to a private or internal address ({ip})."
            )

    clean_url = urlunparse(parsed._replace(scheme=scheme, fragment=""))
    return ValidatedTarget(
        url=clean_url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        ip_addresses=ip_addresses,
    )