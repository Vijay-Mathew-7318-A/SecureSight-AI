import ssl
import types
from datetime import datetime, timedelta, timezone

import pytest

from app.core.url_validator import ValidatedTarget
from app.scanner import https_ssl
from app.scanner.http_client import FetchError
from app.scanner.https_ssl import (
    CertificateInfo,
    HttpsProbe,
    _build_probe_urls,
    analyze_certificate,
    analyze_https,
    classify_verify_code,
    fetch_certificate_info,
    info_from_cert,
    run_https_ssl_checks,
)

NOW = datetime(2026, 11, 18, tzinfo=timezone.utc)
TARGET = ValidatedTarget(
    url="https://example.com/login?x=1",
    scheme="https",
    hostname="example.com",
    port=443,
    ip_addresses=["93.184.216.34"],
)


def valid_info(days):
    return CertificateInfo(
        hostname="example.com",
        status="valid",
        tls_version="TLSv1.3",
        not_after=NOW + timedelta(days=days, hours=1),
        issuer="Example CA",
    )


def ids(findings):
    return {f.check_id for f in findings}


class FakeClient:
    def __init__(self, results):
        self.results = results
        self.urls = []

    def fetch(self, url):
        self.urls.append(url)
        item = self.results[url]
        if isinstance(item, Exception):
            raise item
        return item


# ---------- certificate analysis ----------
def test_valid_certificate_far_from_expiry():
    findings = analyze_certificate(valid_info(90), NOW)
    assert ids(findings) == {"tls-certificate-ok"}
    assert findings[0].severity.value == "Informational"


@pytest.mark.parametrize(
    "days, severity",
    [(3, "High"), (7, "High"), (10, "Medium"), (14, "Medium"), (25, "Low"), (30, "Low")],
)
def test_expiring_certificate_severity(days, severity):
    findings = analyze_certificate(valid_info(days), NOW)
    assert ids(findings) == {"cert-expiring-soon"}
    assert findings[0].severity.value == severity


def test_certificate_past_expiry_date_is_reported_as_expired():
    findings = analyze_certificate(valid_info(-2), NOW)
    assert ids(findings) == {"cert-expired"}


@pytest.mark.parametrize(
    "problem, check_id, severity",
    [
        ("expired", "cert-expired", "High"),
        ("hostname_mismatch", "cert-hostname-mismatch", "High"),
        ("self_signed", "cert-self-signed", "High"),
        ("untrusted_chain", "cert-untrusted-chain", "Medium"),
        ("other", "cert-verification-failed", "Medium"),
    ],
)
def test_invalid_certificate_problems(problem, check_id, severity):
    info = CertificateInfo(
        hostname="example.com", status="invalid", problem=problem, detail="details"
    )
    findings = analyze_certificate(info, NOW)
    assert ids(findings) == {check_id}
    assert findings[0].severity.value == severity
    assert findings[0].evidence == "details"


def test_certificate_error_status_produces_no_findings():
    info = CertificateInfo(hostname="example.com", status="error", detail="boom")
    assert analyze_certificate(info, NOW) == []


@pytest.mark.parametrize(
    "code, problem",
    [(10, "expired"), (62, "hostname_mismatch"), (18, "self_signed"),
     (20, "untrusted_chain"), (999, "other")],
)
def test_classify_verify_codes(code, problem):
    assert classify_verify_code(code) == problem


def test_info_from_cert_parses_dates_and_names():
    cert = {
        "notAfter": "Jan  1 00:00:00 2030 GMT",
        "notBefore": "Jan  1 00:00:00 2029 GMT",
        "issuer": ((("organizationName", "Example CA"),), (("commonName", "Example CA R3"),)),
        "subject": ((("commonName", "example.com"),),),
    }
    info = info_from_cert("example.com", cert, "TLSv1.3")
    assert info.status == "valid"
    assert info.not_after.year == 2030
    assert info.issuer == "Example CA / Example CA R3"
    assert info.subject == "example.com"


# ---------- HTTPS / HTTP analysis ----------
def test_https_unavailable_but_http_works():
    probe = HttpsProbe(https_reachable=False, https_error="refused", http_reachable=True)
    assert ids(analyze_https(probe)) == {"https-unavailable"}


def test_http_without_redirect_to_https():
    probe = HttpsProbe(
        https_reachable=True,
        http_reachable=True,
        http_final_url="http://example.com",
        http_redirects_to_https=False,
    )
    assert ids(analyze_https(probe)) == {"http-no-https-redirect"}


def test_http_redirecting_to_https_has_no_findings():
    probe = HttpsProbe(
        https_reachable=True,
        http_reachable=True,
        http_final_url="https://example.com",
        http_redirects_to_https=True,
    )
    assert analyze_https(probe) == []


def test_https_only_site_has_no_findings():
    probe = HttpsProbe(https_reachable=True, http_reachable=False)
    assert analyze_https(probe) == []


# ---------- full flow with fakes ----------
def test_run_checks_full_flow():
    client = FakeClient(
        {
            "https://example.com/login?x=1": types.SimpleNamespace(
                final_url="https://example.com/login?x=1"
            ),
            "http://example.com/login?x=1": types.SimpleNamespace(
                final_url="http://example.com/login?x=1"
            ),
        }
    )
    findings, notes = run_https_ssl_checks(
        TARGET, client=client, cert_fetcher=lambda host, ips: valid_info(90), now=NOW
    )
    assert ids(findings) == {"http-no-https-redirect", "tls-certificate-ok"}
    assert notes == []
    assert client.urls == [
        "https://example.com/login?x=1",
        "http://example.com/login?x=1",
    ]


def test_run_skips_certificate_check_when_https_unreachable():
    client = FakeClient(
        {
            "https://example.com/login?x=1": FetchError("Could not connect to the website."),
            "http://example.com/login?x=1": types.SimpleNamespace(
                final_url="http://example.com/login?x=1"
            ),
        }
    )
    calls = []

    def cert_fetcher(host, ips):
        calls.append(host)
        return valid_info(90)

    findings, _ = run_https_ssl_checks(TARGET, client=client, cert_fetcher=cert_fetcher, now=NOW)
    assert ids(findings) == {"https-unavailable"}
    assert calls == []


def test_run_when_site_unreachable_adds_note():
    error = FetchError("Could not connect to the website.")
    client = FakeClient(
        {"https://example.com/login?x=1": error, "http://example.com/login?x=1": error}
    )
    findings, notes = run_https_ssl_checks(TARGET, client=client, now=NOW)
    assert findings == []
    assert "could not be reached" in notes[0]


def test_run_adds_note_when_certificate_cannot_be_read():
    client = FakeClient(
        {
            "https://example.com/login?x=1": types.SimpleNamespace(final_url="https://example.com"),
            "http://example.com/login?x=1": FetchError("closed"),
        }
    )
    broken = CertificateInfo(hostname="example.com", status="error", detail="timed out")
    findings, notes = run_https_ssl_checks(
        TARGET, client=client, cert_fetcher=lambda h, i: broken, now=NOW
    )
    assert findings == []
    assert "could not be read" in notes[0]


def test_probe_urls_bracket_ipv6():
    target = ValidatedTarget(
        url="https://[2001:4860:4860::8888]/",
        scheme="https",
        hostname="2001:4860:4860::8888",
        port=443,
        ip_addresses=["2001:4860:4860::8888"],
    )
    https_url, http_url = _build_probe_urls(target)
    assert https_url == "https://[2001:4860:4860::8888]/"
    assert http_url == "http://[2001:4860:4860::8888]/"


# ---------- network function safety (no real connections) ----------
def test_certificate_fetch_never_connects_to_private_ip(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("must not connect to a private address")

    monkeypatch.setattr(https_ssl.socket, "create_connection", boom)
    info = fetch_certificate_info("internal.example", ["10.0.0.1"])
    assert info.status == "error"


def test_certificate_fetch_classifies_verification_error(monkeypatch):
    def fake_connect(*args, **kwargs):
        exc = ssl.SSLCertVerificationError(1, "verify failed")
        exc.verify_code = 10
        exc.verify_message = "certificate has expired"
        raise exc

    monkeypatch.setattr(https_ssl.socket, "create_connection", fake_connect)
    info = fetch_certificate_info("example.com", ["93.184.216.34"], timeout=2)
    assert info.status == "invalid"
    assert info.problem == "expired"
    assert "expired" in info.detail