"""HTTPS availability and TLS certificate checks.

Network functions (fetch_certificate_info, probe_https_and_http) gather facts.
Analysis functions (analyze_https, analyze_certificate) turn facts into Findings.
The analysis functions need no network, which makes them easy to test.

Scope: standard ports 80 and 443 of the target host. NOT covered here:
weak ciphers/protocol versions, certificate revocation, HSTS (headers check).
"""

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.core.config import get_settings
from app.core.url_validator import UnsafeURLError, ValidatedTarget, is_blocked_ip
from app.scanner.http_client import FetchError, SafeHttpClient
from app.scanner.models import Finding, Severity

CHECK_NAME = "HTTPS and TLS certificate"
COVERS = ("A04:2025",)  # OWASP categories this check contributes to

# OpenSSL verification error codes -> our simple problem names
VERIFY_CODE_PROBLEMS = {
    10: "expired",
    62: "hostname_mismatch",
    64: "hostname_mismatch",
    18: "self_signed",
    19: "self_signed",
    2: "untrusted_chain",
    20: "untrusted_chain",
    21: "untrusted_chain",
}


@dataclass
class CertificateInfo:
    """What we learned from the TLS handshake."""

    hostname: str
    status: str  # "valid", "invalid" or "error" (could not read at all)
    tls_version: str = ""
    problem: str = ""  # for "invalid": expired, hostname_mismatch, self_signed, ...
    detail: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    issuer: str = ""
    subject: str = ""


@dataclass
class HttpsProbe:
    """Results of requesting the site over HTTPS and over HTTP."""

    https_reachable: bool = False
    https_error: str = ""
    http_reachable: bool = False
    http_error: str = ""
    http_final_url: str = ""
    http_redirects_to_https: bool | None = None  # None = HTTP not reachable


# ----------------------------------------------------------------- certificate
def classify_verify_code(code) -> str:
    return VERIFY_CODE_PROBLEMS.get(code, "other")


def _names_to_text(rdns) -> str:
    flat = {}
    for rdn in rdns or ():
        for key, value in rdn:
            flat[key] = value
    parts = (flat.get("organizationName"), flat.get("commonName"))
    return " / ".join(p for p in parts if p)


def _cert_date(cert: dict, key: str):
    try:
        seconds = ssl.cert_time_to_seconds(cert[key])
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (KeyError, ValueError):
        return None


def info_from_cert(hostname: str, cert: dict, tls_version: str) -> CertificateInfo:
    """Build CertificateInfo from the dict returned by ssl's getpeercert()."""
    return CertificateInfo(
        hostname=hostname,
        status="valid",
        tls_version=tls_version or "",
        not_before=_cert_date(cert, "notBefore"),
        not_after=_cert_date(cert, "notAfter"),
        issuer=_names_to_text(cert.get("issuer")),
        subject=_names_to_text(cert.get("subject")),
    )


def fetch_certificate_info(hostname, ip_addresses, port=443, timeout=None) -> CertificateInfo:
    """Read the certificate by connecting ONLY to already-validated public IPs."""
    timeout = timeout if timeout is not None else get_settings().request_timeout
    context = ssl.create_default_context()  # verifies certificate AND hostname
    last_error = "No public IP address available to connect to."

    for ip in ip_addresses:
        if is_blocked_ip(ip):
            continue
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls:
                    return info_from_cert(hostname, tls.getpeercert(), tls.version())
        except ssl.SSLCertVerificationError as exc:
            message = getattr(exc, "verify_message", "") or str(exc)
            return CertificateInfo(
                hostname=hostname,
                status="invalid",
                problem=classify_verify_code(getattr(exc, "verify_code", None)),
                detail=message[:300],
            )
        except (ssl.SSLError, OSError) as exc:
            last_error = f"{type(exc).__name__}: {str(exc)[:200]}"
            continue

    return CertificateInfo(hostname=hostname, status="error", detail=last_error)


PROBLEM_FINDINGS = {
    "expired": (
        "cert-expired",
        "TLS certificate has expired",
        Severity.HIGH,
        "The website's certificate is past its expiry date. Browsers show a full-page "
        "warning and users cannot be sure they are talking to the real site.",
        "Renew the certificate immediately. Set up automatic renewal (for example "
        "Let's Encrypt with certbot, or your hosting provider's managed certificates).",
    ),
    "hostname_mismatch": (
        "cert-hostname-mismatch",
        "Certificate does not match the website name",
        Severity.HIGH,
        "The certificate was issued for a different domain name than the one being "
        "visited, so browsers will warn users.",
        "Get a certificate that includes this exact domain name (and www. if used), "
        "then install it on the server.",
    ),
    "self_signed": (
        "cert-self-signed",
        "Self-signed certificate",
        Severity.HIGH,
        "The certificate was not issued by a trusted certificate authority, so "
        "browsers cannot verify the site's identity.",
        "Replace it with a certificate from a trusted authority. Free options such "
        "as Let's Encrypt exist.",
    ),
    "untrusted_chain": (
        "cert-untrusted-chain",
        "Certificate chain is not trusted or is incomplete",
        Severity.MEDIUM,
        "The certificate could not be linked to a trusted authority. Common causes "
        "are a missing intermediate certificate on the server. It can also happen "
        "when a network or antivirus program intercepts HTTPS on the scanning machine.",
        "Install the full certificate chain (including intermediates) on the server, "
        "then re-scan from a different network to rule out local interception.",
    ),
    "other": (
        "cert-verification-failed",
        "Certificate verification failed",
        Severity.MEDIUM,
        "The certificate failed verification for a reason not covered by the more "
        "specific checks.",
        "Check the certificate with an online SSL checker, fix the reported problem, "
        "and re-scan.",
    ),
}


def _problem_finding(problem: str, evidence: str) -> Finding:
    check_id, title, severity, description, remediation = PROBLEM_FINDINGS.get(
        problem, PROBLEM_FINDINGS["other"]
    )
    return Finding(
        check_id=check_id,
        title=title,
        severity=severity,
        owasp_category="A04:2025",
        description=description,
        remediation=remediation,
        evidence=evidence,
    )


def analyze_certificate(info: CertificateInfo, now: datetime | None = None) -> list[Finding]:
    """Turn certificate facts into findings."""
    now = now or datetime.now(timezone.utc)

    if info.status == "error":
        return []  # nothing reliable to report; the caller adds a note
    if info.status == "invalid":
        return [_problem_finding(info.problem, info.detail)]

    if info.not_after is not None:
        days = (info.not_after - now).days
        expiry_text = info.not_after.strftime("%Y-%m-%d")

        if days < 0:
            return [_problem_finding("expired", f"Certificate expired on {expiry_text}.")]

        severity = None
        if days <= 7:
            severity = Severity.HIGH
        elif days <= 14:
            severity = Severity.MEDIUM
        elif days <= 30:
            severity = Severity.LOW
        if severity is not None:
            return [
                Finding(
                    check_id="cert-expiring-soon",
                    title=f"TLS certificate expires in {days} days",
                    severity=severity,
                    owasp_category="A04:2025",
                    description="The certificate is close to its expiry date. If it is "
                    "not renewed in time, visitors will see security warnings.",
                    remediation="Renew the certificate now and enable automatic renewal "
                    "with monitoring/alerts so this does not happen again.",
                    evidence=f"Expires on {expiry_text} ({days} days remaining). "
                    f"Issuer: {info.issuer or 'unknown'}.",
                )
            ]
        evidence = (
            f"Valid until {expiry_text} ({days} days remaining). "
            f"Issuer: {info.issuer or 'unknown'}. TLS version: {info.tls_version or 'unknown'}."
        )
    else:
        evidence = f"Certificate verified. TLS version: {info.tls_version or 'unknown'}."

    return [
        Finding(
            check_id="tls-certificate-ok",
            title="TLS certificate is valid",
            severity=Severity.INFORMATIONAL,
            owasp_category="A04:2025",
            description="The certificate is trusted, matches the website name and is "
            "not close to expiry.",
            remediation="No action needed. Keep automatic renewal enabled.",
            evidence=evidence,
        )
    ]


# ------------------------------------------------------------------ HTTPS/HTTP
def _build_probe_urls(target: ValidatedTarget) -> tuple[str, str]:
    host = f"[{target.hostname}]" if ":" in target.hostname else target.hostname
    parsed = urlparse(target.url)
    suffix = parsed.path or ""
    if parsed.query:
        suffix += "?" + parsed.query
    return f"https://{host}{suffix}", f"http://{host}{suffix}"


def probe_https_and_http(target: ValidatedTarget, client: SafeHttpClient) -> HttpsProbe:
    https_url, http_url = _build_probe_urls(target)
    probe = HttpsProbe()

    try:
        client.fetch(https_url)
        probe.https_reachable = True
    except (FetchError, UnsafeURLError) as exc:
        probe.https_error = str(exc)

    try:
        result = client.fetch(http_url)
        probe.http_reachable = True
        probe.http_final_url = result.final_url
        probe.http_redirects_to_https = result.final_url.lower().startswith("https://")
    except (FetchError, UnsafeURLError) as exc:
        probe.http_error = str(exc)

    return probe


def analyze_https(probe: HttpsProbe) -> list[Finding]:
    findings = []

    if not probe.https_reachable and probe.http_reachable:
        findings.append(
            Finding(
                check_id="https-unavailable",
                title="HTTPS is not available",
                severity=Severity.HIGH,
                owasp_category="A04:2025",
                description="The website answered over plain HTTP but could not be "
                "reached over HTTPS. Data sent over HTTP (logins, forms, cookies) can "
                "be read or changed by anyone on the network path.",
                remediation="Install a TLS certificate and enable HTTPS on port 443. "
                "Then redirect all HTTP traffic to HTTPS.",
                evidence=f"HTTPS request failed: {probe.https_error}",
            )
        )
    elif probe.https_reachable and probe.http_reachable:
        if probe.http_redirects_to_https is False:
            findings.append(
                Finding(
                    check_id="http-no-https-redirect",
                    title="HTTP does not redirect to HTTPS",
                    severity=Severity.MEDIUM,
                    owasp_category="A04:2025",
                    description="HTTPS works, but visitors who use the plain HTTP "
                    "address stay on an unencrypted connection.",
                    remediation="Configure the server to redirect all HTTP requests to "
                    "HTTPS with a permanent (301) redirect.",
                    evidence=f"The HTTP request ended at {probe.http_final_url} "
                    "without switching to HTTPS.",
                )
            )
    return findings


# ---------------------------------------------------------------- entry point
def run_https_ssl_checks(target, client=None, cert_fetcher=None, now=None):
    """Run all HTTPS/TLS checks. Returns (findings, notes)."""
    client = client or SafeHttpClient()
    cert_fetcher = cert_fetcher or fetch_certificate_info
    findings: list[Finding] = []
    notes: list[str] = []

    probe = probe_https_and_http(target, client)
    findings.extend(analyze_https(probe))

    if not probe.https_reachable and not probe.http_reachable:
        notes.append(
            "The website could not be reached over HTTP or HTTPS, so HTTPS and "
            "certificate checks were skipped."
        )

    if probe.https_reachable:
        info = cert_fetcher(target.hostname, target.ip_addresses)
        if info.status == "error":
            notes.append(f"The TLS certificate could not be read: {info.detail}")
        else:
            findings.extend(analyze_certificate(info, now))

    return findings, notes