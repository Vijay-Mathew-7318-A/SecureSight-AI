import types

import pytest

from app.scanner.headers import analyze_headers, parse_csp, run_header_checks

GOOD = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=()",
    "content-type": "text/html; charset=utf-8",
}


def good(changes=None, remove=()):
    headers = dict(GOOD)
    headers.update(changes or {})
    for name in remove:
        headers.pop(name, None)
    return headers


def ids(findings):
    return {f.check_id for f in findings}


def test_good_headers_have_no_findings():
    findings, notes = analyze_headers(GOOD, True)
    assert findings == []
    assert notes == []


def test_all_headers_missing_on_html_https_page():
    findings, _ = analyze_headers({"content-type": "text/html"}, True)
    assert ids(findings) == {
        "missing-hsts",
        "missing-csp",
        "missing-x-content-type-options",
        "missing-clickjacking-protection",
        "missing-referrer-policy",
        "missing-permissions-policy",
    }


def test_missing_header_severities():
    findings, _ = analyze_headers({"content-type": "text/html"}, True)
    severity = {f.check_id: f.severity.value for f in findings}
    assert severity["missing-hsts"] == "Medium"
    assert severity["missing-csp"] == "Medium"
    assert severity["missing-x-content-type-options"] == "Low"
    assert severity["missing-clickjacking-protection"] == "Medium"
    assert severity["missing-referrer-policy"] == "Informational"
    assert severity["missing-permissions-policy"] == "Informational"


def test_hsts_is_skipped_over_http():
    findings, notes = analyze_headers({"content-type": "text/html"}, False)
    assert "missing-hsts" not in ids(findings)
    assert any("HSTS" in note for note in notes)


@pytest.mark.parametrize(
    "value, expect_finding",
    [
        ("max-age=300", True),
        ("max-age=15551999", True),
        ("max-age=15552000", False),
    ],
)
def test_hsts_max_age_boundary(value, expect_finding):
    findings, _ = analyze_headers(good({"strict-transport-security": value}), True)
    assert (ids(findings) == {"hsts-short-max-age"}) is expect_finding
    if not expect_finding:
        assert findings == []


@pytest.mark.parametrize("value", ["max-age=0", "includeSubDomains", "max-age=abc"])
def test_hsts_unusable_values_count_as_missing(value):
    findings, _ = analyze_headers(good({"strict-transport-security": value}), True)
    assert ids(findings) == {"missing-hsts"}


@pytest.mark.parametrize(
    "policy",
    [
        "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
        "default-src 'self' 'unsafe-eval'; frame-ancestors 'none'",
        "script-src *; frame-ancestors 'none'",
        "img-src 'self'; frame-ancestors 'none'",
        "script-src 'self' https:; frame-ancestors 'none'",
    ],
)
def test_weak_csp_detected(policy):
    findings, _ = analyze_headers(good({"content-security-policy": policy}), True)
    assert ids(findings) == {"weak-csp"}
    assert findings[0].severity.value == "Low"


def test_csp_with_nonce_is_not_weak():
    policy = "script-src 'nonce-abc123' 'unsafe-inline'; frame-ancestors 'none'"
    findings, _ = analyze_headers(good({"content-security-policy": policy}), True)
    assert findings == []


def test_report_only_csp_is_not_enforced():
    headers = good(
        {"content-security-policy-report-only": "default-src 'self'"},
        remove=["content-security-policy"],
    )
    findings, _ = analyze_headers(headers, True)
    assert ids(findings) == {"missing-csp", "missing-clickjacking-protection"}
    csp_finding = next(f for f in findings if f.check_id == "missing-csp")
    assert "report-only" in csp_finding.evidence.lower()


def test_x_frame_options_protects_without_frame_ancestors():
    headers = good(
        {"content-security-policy": "default-src 'self'", "x-frame-options": "DENY"}
    )
    findings, _ = analyze_headers(headers, True)
    assert findings == []


@pytest.mark.parametrize("value", ["ALLOW-FROM https://x.com", "foo"])
def test_obsolete_or_invalid_x_frame_options_do_not_protect(value):
    headers = good(
        {"content-security-policy": "default-src 'self'", "x-frame-options": value}
    )
    findings, _ = analyze_headers(headers, True)
    assert ids(findings) == {"missing-clickjacking-protection"}


def test_frame_ancestors_wildcard_does_not_protect():
    headers = good({"content-security-policy": "default-src 'self'; frame-ancestors *"})
    findings, _ = analyze_headers(headers, True)
    assert ids(findings) == {"missing-clickjacking-protection"}


@pytest.mark.parametrize(
    "value, expected",
    [
        ("nosniff", set()),
        ("NoSniff", set()),
        ("sniff", {"missing-x-content-type-options"}),
    ],
)
def test_nosniff_value_handling(value, expected):
    findings, _ = analyze_headers(good({"x-content-type-options": value}), True)
    assert ids(findings) == expected


@pytest.mark.parametrize("value", ["unsafe-url", "no-referrer-when-downgrade"])
def test_unsafe_referrer_policy(value):
    findings, _ = analyze_headers(good({"referrer-policy": value}), True)
    assert ids(findings) == {"unsafe-referrer-policy"}


@pytest.mark.parametrize(
    "name, value, expect_finding",
    [
        ("server", "nginx/1.18.0", True),
        ("server", "Apache", False),
        ("server", "cloudflare", False),
        ("x-powered-by", "Express", True),
        ("x-aspnet-version", "4.0.30319", True),
    ],
)
def test_information_disclosure_headers(name, value, expect_finding):
    findings, _ = analyze_headers(good({name: value}), True)
    expected = {"server-info-disclosure"} if expect_finding else set()
    assert ids(findings) == expected


def test_error_status_adds_a_note():
    findings, notes = analyze_headers(GOOD, True, 503)
    assert findings == []
    assert any("503" in note for note in notes)


def test_non_html_response_skips_page_checks():
    findings, notes = analyze_headers({"content-type": "application/json"}, True)
    assert ids(findings) == {"missing-hsts", "missing-x-content-type-options"}
    assert any("HTML" in note for note in notes)


def test_run_header_checks_over_https():
    fetch = types.SimpleNamespace(
        headers=GOOD, final_url="https://example.com", status_code=200
    )
    assert run_header_checks(fetch) == ([], [])


def test_run_header_checks_over_http_skips_hsts():
    fetch = types.SimpleNamespace(
        headers={"content-type": "text/html"},
        final_url="http://example.com",
        status_code=200,
    )
    findings, _ = run_header_checks(fetch)
    assert "missing-hsts" not in ids(findings)


def test_every_finding_has_explanation_fix_and_evidence():
    findings, _ = analyze_headers(
        {"content-type": "text/html", "server": "nginx/1.18.0"}, True
    )
    assert findings
    for finding in findings:
        assert finding.description
        assert finding.remediation
        assert finding.evidence
        assert finding.owasp_category == "A02:2025"


def test_parse_csp_lowercases_names_and_first_directive_wins():
    assert parse_csp("Script-Src 'self'; script-src *") == {"script-src": ["'self'"]}