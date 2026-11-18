"""HTTP security header analysis.

analyze_headers() takes a dictionary of response headers (names in lowercase)
and returns (findings, notes). It makes no network requests.

Scope: headers of ONE page (the final page after redirects). Other pages of the
same site may send different headers. The Content-Security-Policy analysis is a
simplified review, not a full policy evaluator.
"""

import re

from app.scanner.models import Finding, Severity

CHECK_NAME = "HTTP security headers"
COVERS = ("A02:2025",)  # OWASP categories this check contributes to

HSTS_MIN_MAX_AGE = 15_552_000  # 180 days, in seconds
VERSION_PATTERN = re.compile(r"\d+\.\d+")
DISCLOSURE_HEADERS = ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator")


def _clip(text: str, limit: int = 200) -> str:
    return text if len(text) <= limit else text[:limit] + "..."


def _finding(check_id, title, severity, description, remediation, evidence) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        severity=severity,
        owasp_category="A02:2025",
        description=description,
        remediation=remediation,
        evidence=evidence,
    )


# ------------------------------------------------------------------- parsers
def parse_csp(value: str) -> dict[str, list[str]]:
    """Turn a CSP header into {directive: [sources]}. First occurrence wins."""
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name not in directives:
            directives[name] = tokens[1:]
    return directives


def parse_hsts_max_age(value: str):
    """Return the max-age number from an HSTS header, or None if unusable."""
    for part in value.split(";"):
        part = part.strip()
        if part.lower().startswith("max-age"):
            _, _, raw = part.partition("=")
            raw = raw.strip().strip('"')
            if raw.isdigit():
                return int(raw)
    return None


def csp_weaknesses(directives: dict[str, list[str]]) -> list[str]:
    """List the reasons a (present) CSP gives weak protection against script injection."""
    script_sources = directives.get("script-src") or directives.get("default-src")
    if script_sources is None:
        return ["it does not restrict where scripts can load from (no script-src or default-src)"]

    lowered = [s.lower() for s in script_sources]
    has_nonce_or_hash = any(
        s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in lowered
    )
    strict_dynamic = "'strict-dynamic'" in lowered

    problems = []
    if "'unsafe-inline'" in lowered and not (has_nonce_or_hash or strict_dynamic):
        problems.append("it allows inline scripts ('unsafe-inline')")
    if "'unsafe-eval'" in lowered:
        problems.append("it allows eval() ('unsafe-eval')")
    if "*" in lowered:
        problems.append("it allows scripts from any host (*)")
    if not strict_dynamic and any(s in ("http:", "https:", "data:") for s in lowered):
        problems.append("it allows scripts from very broad sources (http:, https: or data:)")
    return problems


# -------------------------------------------------------------------- checks
def _check_hsts(headers) -> list[Finding]:
    value = headers.get("strict-transport-security")
    fix = (
        "Send this header on every HTTPS response: "
        "Strict-Transport-Security: max-age=31536000; includeSubDomains. "
        "Test with a short max-age first. Do not add 'preload' until you have read "
        "about it, because it is hard to undo."
    )

    if value is None:
        evidence = "The Strict-Transport-Security header is not present."
    else:
        max_age = parse_hsts_max_age(value)
        if max_age:  # a positive number
            if max_age >= HSTS_MIN_MAX_AGE:
                return []
            return [
                _finding(
                    "hsts-short-max-age",
                    "HSTS max-age is short",
                    Severity.LOW,
                    "HSTS is enabled, but the browser remembers it for a short time, "
                    "so users are unprotected again soon after their last visit.",
                    fix,
                    f"Header value: {_clip(value)} (recommended: at least {HSTS_MIN_MAX_AGE} seconds).",
                )
            ]
        evidence = f"The header is present but its max-age is missing, invalid or zero: {_clip(value)}"

    return [
        _finding(
            "missing-hsts",
            "HTTP Strict Transport Security (HSTS) is not enabled",
            Severity.MEDIUM,
            "Without HSTS, a browser can be tricked into using plain HTTP on the first "
            "request, which lets an attacker on the network read or change traffic.",
            fix,
            evidence,
        )
    ]


def _check_csp(headers):
    """Returns (findings, parsed_csp_directives)."""
    value = headers.get("content-security-policy")
    if value is None:
        evidence = "No enforced Content-Security-Policy header was found."
        if headers.get("content-security-policy-report-only") is not None:
            evidence += (
                " A Content-Security-Policy-Report-Only header exists, but "
                "report-only mode only reports problems and blocks nothing."
            )
        return (
            [
                _finding(
                    "missing-csp",
                    "Content-Security-Policy header is missing",
                    Severity.MEDIUM,
                    "A Content Security Policy tells the browser which sources of scripts "
                    "and other content are allowed. It is a strong second line of defense "
                    "against cross-site scripting (XSS).",
                    "Add a Content-Security-Policy header. Start with "
                    "Content-Security-Policy-Report-Only to see what would break, then "
                    "enforce a policy such as: default-src 'self'; frame-ancestors 'self'.",
                    evidence,
                )
            ],
            {},
        )

    directives = parse_csp(value)
    problems = csp_weaknesses(directives)
    if not problems:
        return [], directives

    return (
        [
            _finding(
                "weak-csp",
                "Content-Security-Policy is weak",
                Severity.LOW,
                "A CSP is present, but it leaves gaps that reduce its protection "
                "against injected scripts.",
                "Remove 'unsafe-inline', 'unsafe-eval' and wildcard sources from "
                "script-src. Use nonces or hashes for necessary inline scripts and "
                "list only the hosts you really need.",
                "Problems: " + "; ".join(problems) + f". Policy: {_clip(value)}",
            )
        ],
        directives,
    )


def _check_content_type_options(headers) -> list[Finding]:
    value = headers.get("x-content-type-options")
    if value is not None and value.split(",")[0].strip().lower() == "nosniff":
        return []
    evidence = (
        "The X-Content-Type-Options header is not present."
        if value is None
        else f"Header value is '{_clip(value, 100)}', but 'nosniff' is expected."
    )
    return [
        _finding(
            "missing-x-content-type-options",
            "X-Content-Type-Options header is missing",
            Severity.LOW,
            "Without 'nosniff', some browsers may guess a file's type and treat "
            "uploaded or user-controlled content as a script.",
            "Add the header: X-Content-Type-Options: nosniff",
            evidence,
        )
    ]


def _has_clickjacking_protection(headers, directives) -> bool:
    xfo = headers.get("x-frame-options", "").split(",")[0].strip().lower()
    if xfo in ("deny", "sameorigin"):
        return True
    ancestors = [s.lower() for s in directives.get("frame-ancestors", [])]
    return bool(ancestors) and "*" not in ancestors


def _clickjacking_finding(headers) -> Finding:
    xfo = headers.get("x-frame-options")
    evidence = "Neither X-Frame-Options nor a CSP frame-ancestors directive was found."
    if xfo is not None:
        evidence = (
            f"X-Frame-Options is '{_clip(xfo, 100)}', which does not protect "
            "(only DENY and SAMEORIGIN do), and no CSP frame-ancestors directive was found."
        )
    return _finding(
        "missing-clickjacking-protection",
        "No clickjacking protection",
        Severity.MEDIUM,
        "Other websites can load this page inside a hidden frame and trick visitors "
        "into clicking buttons without realizing it (clickjacking).",
        "Add a CSP header with frame-ancestors 'self' (or 'none'). For older browsers "
        "you can also send: X-Frame-Options: SAMEORIGIN",
        evidence,
    )


def _check_referrer_policy(headers) -> list[Finding]:
    value = headers.get("referrer-policy")
    if value is None:
        return [
            _finding(
                "missing-referrer-policy",
                "Referrer-Policy header is missing",
                Severity.INFORMATIONAL,
                "The site does not say how much of its address to share with other "
                "sites. Modern browsers already default to a fairly safe behavior, so "
                "the risk is small.",
                "Add the header: Referrer-Policy: strict-origin-when-cross-origin",
                "The Referrer-Policy header is not present.",
            )
        ]
    last_policy = value.split(",")[-1].strip().lower()
    if last_policy in ("unsafe-url", "no-referrer-when-downgrade"):
        return [
            _finding(
                "unsafe-referrer-policy",
                "Referrer-Policy leaks full page addresses",
                Severity.LOW,
                "This policy sends the full address of the page (including its path "
                "and query string) to other websites, which can expose private details.",
                "Use a stricter policy: Referrer-Policy: strict-origin-when-cross-origin",
                f"Header value: {_clip(value, 100)}",
            )
        ]
    return []


def _check_permissions_policy(headers) -> list[Finding]:
    if headers.get("permissions-policy") is not None:
        return []
    return [
        _finding(
            "missing-permissions-policy",
            "Permissions-Policy header is missing",
            Severity.INFORMATIONAL,
            "The site does not restrict which browser features (camera, microphone, "
            "location and others) its pages may use.",
            "Add a Permissions-Policy header that disables features you do not use, "
            "for example: Permissions-Policy: camera=(), microphone=(), geolocation=()",
            "The Permissions-Policy header is not present.",
        )
    ]


def _check_information_disclosure(headers) -> list[Finding]:
    found = []
    server = headers.get("server", "")
    if server and VERSION_PATTERN.search(server):
        found.append(f"server: {_clip(server, 100)}")
    for name in DISCLOSURE_HEADERS:
        if name in headers:
            found.append(f"{name}: {_clip(headers[name], 100)}")

    if not found:
        return []
    return [
        _finding(
            "server-info-disclosure",
            "Server reveals software details",
            Severity.LOW,
            "Headers announce which software (and sometimes which version) the "
            "server runs. This does not break anything by itself, but it helps "
            "attackers look for known weaknesses.",
            "Configure the web server and framework to hide version numbers and "
            "technology headers (for example 'server_tokens off' in nginx, "
            "'ServerTokens Prod' in Apache, or removing X-Powered-By).",
            "; ".join(found),
        )
    ]


# --------------------------------------------------------------- entry points
def analyze_headers(headers: dict, is_https: bool, status_code: int = 200):
    """Analyze response headers. Returns (findings, notes)."""
    headers = {name.lower(): value for name, value in headers.items()}
    findings: list[Finding] = []
    notes: list[str] = []

    if status_code >= 400:
        notes.append(
            f"The final response had status {status_code}; headers on error pages "
            "can differ from headers on normal pages."
        )

    content_type = headers.get("content-type", "").lower()
    is_page = (not content_type) or ("html" in content_type)

    if is_https:
        findings.extend(_check_hsts(headers))
    else:
        notes.append(
            "HSTS was not checked because the final page was served over HTTP "
            "(browsers ignore HSTS on plain HTTP)."
        )

    findings.extend(_check_content_type_options(headers))
    findings.extend(_check_information_disclosure(headers))

    if is_page:
        csp_findings, directives = _check_csp(headers)
        findings.extend(csp_findings)
        if not _has_clickjacking_protection(headers, directives):
            findings.append(_clickjacking_finding(headers))
        findings.extend(_check_referrer_policy(headers))
        findings.extend(_check_permissions_policy(headers))
    else:
        notes.append(
            "Page-level headers (CSP, framing, Referrer-Policy, Permissions-Policy) "
            "were not checked because the response is not HTML."
        )

    return findings, notes


def run_header_checks(fetch_result):
    """Run the header checks on a FetchResult. Returns (findings, notes)."""
    is_https = fetch_result.final_url.lower().startswith("https://")
    return analyze_headers(fetch_result.headers, is_https, fetch_result.status_code)