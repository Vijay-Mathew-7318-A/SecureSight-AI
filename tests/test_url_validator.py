import socket

import pytest

from app.core import url_validator
from app.core.url_validator import (
    UnsafeURLError,
    is_blocked_ip,
    validate_target_url,
)


def test_adds_https_when_scheme_missing():
    result = validate_target_url("8.8.8.8")
    assert result.url == "https://8.8.8.8"
    assert result.scheme == "https"
    assert result.port == 443


def test_keeps_http_scheme():
    result = validate_target_url("http://8.8.8.8")
    assert result.scheme == "http"
    assert result.port == 80


@pytest.mark.parametrize("bad", ["", "   "])
def test_rejects_empty_input(bad):
    with pytest.raises(UnsafeURLError):
        validate_target_url(bad)


@pytest.mark.parametrize(
    "bad",
    ["ftp://example.com", "file:///etc/passwd", "gopher://example.com"],
)
def test_rejects_non_http_schemes(bad):
    with pytest.raises(UnsafeURLError):
        validate_target_url(bad)


@pytest.mark.parametrize(
    "bad",
    [
        "localhost",
        "http://localhost:8080",
        "127.0.0.1",
        "10.0.0.5",
        "192.168.1.1",
        "172.16.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "[::1]",
        "http://[::1]/",
        "100.64.0.1",
    ],
)
def test_blocks_local_and_private_targets(bad):
    with pytest.raises(UnsafeURLError):
        validate_target_url(bad)


def test_rejects_credentials_in_url():
    with pytest.raises(UnsafeURLError):
        validate_target_url("https://user:pass@example.com")


@pytest.mark.parametrize("bad", ["https://example.com:22", "https://example.com:99999"])
def test_rejects_bad_ports(bad):
    with pytest.raises(UnsafeURLError):
        validate_target_url(bad)


def test_rejects_whitespace_inside_url():
    with pytest.raises(UnsafeURLError):
        validate_target_url("https://exa mple.com")


def test_blocks_hostname_that_resolves_to_private_ip(monkeypatch):
    monkeypatch.setattr(url_validator, "resolve_host", lambda h, p: ["10.0.0.8"])
    with pytest.raises(UnsafeURLError):
        validate_target_url("https://sneaky.example.com")


def test_blocks_if_any_resolved_ip_is_private(monkeypatch):
    monkeypatch.setattr(
        url_validator, "resolve_host", lambda h, p: ["93.184.216.34", "192.168.0.5"]
    )
    with pytest.raises(UnsafeURLError):
        validate_target_url("https://mixed.example.com")


def test_accepts_hostname_resolving_to_public_ip(monkeypatch):
    monkeypatch.setattr(url_validator, "resolve_host", lambda h, p: ["93.184.216.34"])
    result = validate_target_url("https://example.com/path?x=1")
    assert result.hostname == "example.com"
    assert result.ip_addresses == ["93.184.216.34"]


def test_dns_failure_is_rejected(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(url_validator.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(UnsafeURLError):
        validate_target_url("https://does-not-exist.example")


def test_is_blocked_ip_allows_public_address():
    assert is_blocked_ip("8.8.8.8") is False