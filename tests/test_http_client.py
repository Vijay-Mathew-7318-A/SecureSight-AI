import ipaddress
import types

import pytest
import requests

from app.core import url_validator
from app.core.url_validator import UnsafeURLError
from app.scanner.http_client import (
    FetchError,
    SafeHttpClient,
    extract_set_cookie_headers,
)

PRIVATE_HOSTS = {"evil.example.org": ["10.1.2.3"]}


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    """IP addresses resolve to themselves; hostnames resolve to a public IP
    unless listed in PRIVATE_HOSTS."""

    def fake_resolve(host, port):
        try:
            return [str(ipaddress.ip_address(host))]
        except ValueError:
            return PRIVATE_HOSTS.get(host, ["93.184.216.34"])

    monkeypatch.setattr(url_validator, "resolve_host", fake_resolve)


# ---------- fake response helpers ----------
class FakeRawHeaders:
    def __init__(self, cookies):
        self._cookies = cookies

    def getlist(self, name):
        return list(self._cookies) if name.lower() == "set-cookie" else []


class FakeRaw:
    def __init__(self, cookies=None, peer_ip=None):
        self.headers = FakeRawHeaders(cookies or [])
        if peer_ip:
            sock = types.SimpleNamespace(getpeername=lambda: (peer_ip, 443))
            self._connection = types.SimpleNamespace(sock=sock)


class FakeResponse:
    def __init__(self, status=200, headers=None, body=b"", cookies=None, peer_ip=None):
        self.status_code = status
        self.headers = headers or {}
        self.encoding = "utf-8"
        self.raw = FakeRaw(cookies, peer_ip)
        self.closed = False
        self._body = body

    def iter_content(self, chunk_size=8192):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i : i + chunk_size]

    def close(self):
        self.closed = True


def make_client(responses, **kwargs):
    """responses maps URL -> list of FakeResponse/Exception, used in order."""
    client = SafeHttpClient(timeout=5, max_redirects=3, **kwargs)
    client.calls = []

    def fake_send(url, verify):
        client.calls.append((url, verify))
        item = responses[url].pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    client._send = fake_send
    return client


# ---------- tests ----------
def test_fetch_simple_page():
    resp = FakeResponse(
        200, {"Content-Type": "text/html", "X-Frame-Options": "DENY"}, b"<html>hi</html>"
    )
    client = make_client({"https://example.com": [resp]})
    result = client.fetch("example.com")
    assert result.status_code == 200
    assert result.final_url == "https://example.com"
    assert result.headers["x-frame-options"] == "DENY"
    assert "hi" in result.body_text
    assert result.tls_verified is True
    assert result.redirect_chain == []
    assert result.body_truncated is False
    assert resp.closed is True


def test_follows_redirect_and_records_chain():
    client = make_client(
        {
            "https://example.com": [FakeResponse(301, {"Location": "/home"})],
            "https://example.com/home": [FakeResponse(200, {}, b"ok")],
        }
    )
    result = client.fetch("example.com")
    assert result.final_url == "https://example.com/home"
    assert len(result.redirect_chain) == 1
    assert result.redirect_chain[0].status_code == 301


def test_collects_set_cookie_from_every_hop():
    client = make_client(
        {
            "https://example.com": [
                FakeResponse(302, {"Location": "/next"}, cookies=["a=1; Path=/"])
            ],
            "https://example.com/next": [
                FakeResponse(200, {}, b"", cookies=["b=2; Secure; HttpOnly"])
            ],
        }
    )
    result = client.fetch("example.com")
    assert result.set_cookie_headers == ["a=1; Path=/", "b=2; Secure; HttpOnly"]


def test_redirect_to_private_ip_is_blocked():
    client = make_client(
        {"https://example.com": [FakeResponse(302, {"Location": "http://192.168.1.10/admin"})]}
    )
    with pytest.raises(UnsafeURLError, match="Blocked redirect"):
        client.fetch("example.com")
    assert len(client.calls) == 1  # the private address was never requested


def test_redirect_to_hostname_resolving_to_private_ip_is_blocked():
    client = make_client(
        {"https://example.com": [FakeResponse(302, {"Location": "https://evil.example.org/"})]}
    )
    with pytest.raises(UnsafeURLError, match="Blocked redirect"):
        client.fetch("example.com")


def test_redirect_to_unsafe_scheme_is_blocked():
    client = make_client(
        {"https://example.com": [FakeResponse(302, {"Location": "ftp://example.com/file"})]}
    )
    with pytest.raises(UnsafeURLError):
        client.fetch("example.com")


def test_too_many_redirects():
    loop = [FakeResponse(302, {"Location": "/loop"}) for _ in range(5)]
    client = make_client(
        {
            "https://example.com": [FakeResponse(302, {"Location": "/loop"})],
            "https://example.com/loop": loop,
        }
    )
    with pytest.raises(FetchError, match="Too many redirects"):
        client.fetch("example.com")


def test_bad_certificate_retries_without_verification():
    client = make_client(
        {
            "https://example.com": [
                requests.exceptions.SSLError("certificate verify failed"),
                FakeResponse(200, {}, b"page"),
            ]
        }
    )
    result = client.fetch("example.com")
    assert client.calls == [("https://example.com", True), ("https://example.com", False)]
    assert result.tls_verified is False
    assert "certificate verify failed" in result.tls_error
    assert result.status_code == 200


def test_timeout_becomes_fetch_error():
    client = make_client({"https://example.com": [requests.exceptions.ConnectTimeout("t")]})
    with pytest.raises(FetchError, match="did not respond"):
        client.fetch("example.com")


def test_connection_error_becomes_fetch_error():
    client = make_client({"https://example.com": [requests.exceptions.ConnectionError("x")]})
    with pytest.raises(FetchError, match="Could not connect"):
        client.fetch("example.com")


def test_large_body_is_truncated():
    client = make_client(
        {"https://example.com": [FakeResponse(200, {}, b"a" * 500)]}, max_body_bytes=100
    )
    result = client.fetch("example.com")
    assert len(result.body_text) == 100
    assert result.body_truncated is True


def test_http_site_has_no_tls_status():
    client = make_client({"http://example.com": [FakeResponse(200, {}, b"plain")]})
    result = client.fetch("http://example.com")
    assert result.tls_verified is None


def test_connection_to_private_peer_ip_is_detected():
    resp = FakeResponse(200, {}, b"secret", peer_ip="10.0.0.5")
    client = make_client({"https://example.com": [resp]})
    with pytest.raises(UnsafeURLError, match="private or internal"):
        client.fetch("example.com")
    assert resp.closed is True


def test_extract_set_cookie_falls_back_to_single_header():
    fake = types.SimpleNamespace(
        raw=types.SimpleNamespace(headers={}), headers={"Set-Cookie": "x=1"}
    )
    assert extract_set_cookie_headers(fake) == ["x=1"]


def test_unsafe_start_url_is_never_requested():
    client = make_client({})
    with pytest.raises(UnsafeURLError):
        client.fetch("localhost")
    assert client.calls == []