import types

import pytest

from app.scanner.cookies import (
    analyze_cookies,
    classify_cookie,
    parse_set_cookie,
    run_cookie_checks,
)

GOOD_SESSION = "sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"


def ids(findings):
    return {f.check_id for f in findings}


def severity_of(findings, check_id):
    return next(f.severity.value for f in findings if f.check_id == check_id)


# ---------- parsing ----------
def test_parse_set_cookie_reads_attributes():
    cookie = parse_set_cookie(
        "sessionid=abc; Path=/; Domain=example.com; Secure; HttpOnly; "
        "SameSite=Strict; Max-Age=3600"
    )
    assert cookie.name == "sessionid"
    assert cookie.secure is True
    assert cookie.httponly is True
    assert cookie.samesite == "strict"
    assert cookie.path == "/"
    assert cookie.domain == "example.com"
    assert cookie.persistent is True
    assert cookie.kind == "session"


def test_parsed_cookie_does_not_keep_the_value():
    cookie = parse_set_cookie("sessionid=SECRET; Path=/")
    assert not hasattr(cookie, "value")


@pytest.mark.parametrize("header", ["", "novalue", "=abc", "   ; Secure"])
def test_parse_rejects_invalid_headers(header):
    assert parse_set_cookie(header) is None


@pytest.mark.parametrize(
    "name, kind",
    [
        ("PHPSESSID", "session"),
        ("JSESSIONID", "session"),
        ("connect.sid", "session"),
        ("auth_token", "session"),
        ("jwt", "session"),
        ("csrftoken", "csrf"),
        ("XSRF-TOKEN", "csrf"),
        ("theme", "other"),
        ("_ga", "other"),
        ("lang", "other"),
    ],
)
def test_classify_cookie_names(name, kind):
    assert classify_cookie(name) == kind


# ---------- analysis ----------
def test_good_cookie_has_no_findings():
    findings, notes = analyze_cookies([GOOD_SESSION])
    assert findings == []
    assert any("1 cookie checked" in note for note in notes)


def test_no_cookies_adds_a_note():
    findings, notes = analyze_cookies([])
    assert findings == []
    assert "No cookies" in notes[0]


def test_session_cookie_missing_secure_is_medium():
    findings, _ = analyze_cookies(["sessionid=abc; Path=/; HttpOnly; SameSite=Lax"])
    assert ids(findings) == {"cookie-missing-secure"}
    assert severity_of(findings, "cookie-missing-secure") == "Medium"


def test_other_cookie_missing_secure_is_low():
    findings, _ = analyze_cookies(["theme=dark; Path=/; HttpOnly; SameSite=Lax"])
    assert ids(findings) == {"cookie-missing-secure"}
    assert severity_of(findings, "cookie-missing-secure") == "Low"


def test_session_cookie_missing_httponly_is_medium():
    findings, _ = analyze_cookies(["sessionid=abc; Path=/; Secure; SameSite=Lax"])
    assert ids(findings) == {"cookie-missing-httponly"}
    assert severity_of(findings, "cookie-missing-httponly") == "Medium"


def test_other_cookie_missing_httponly_is_informational():
    findings, _ = analyze_cookies(["theme=dark; Secure; SameSite=Lax"])
    assert ids(findings) == {"cookie-missing-httponly"}
    assert severity_of(findings, "cookie-missing-httponly") == "Informational"


def test_csrf_cookie_is_exempt_from_httponly():
    findings, _ = analyze_cookies(["csrftoken=abc; Secure; SameSite=Lax"])
    assert findings == []


def test_session_cookie_missing_samesite_is_low():
    findings, _ = analyze_cookies(["sessionid=abc; Secure; HttpOnly"])
    assert ids(findings) == {"cookie-missing-samesite"}
    assert severity_of(findings, "cookie-missing-samesite") == "Low"


def test_other_cookie_missing_samesite_is_informational():
    findings, _ = analyze_cookies(["theme=dark; Secure; HttpOnly"])
    assert ids(findings) == {"cookie-missing-samesite"}
    assert severity_of(findings, "cookie-missing-samesite") == "Informational"


def test_invalid_samesite_value_counts_as_missing():
    findings, _ = analyze_cookies(["sessionid=abc; Secure; HttpOnly; SameSite=Sometimes"])
    assert ids(findings) == {"cookie-missing-samesite"}


def test_samesite_none_without_secure():
    findings, _ = analyze_cookies(["sessionid=abc; HttpOnly; SameSite=None"])
    assert ids(findings) == {"cookie-missing-secure", "cookie-samesite-none-insecure"}
    assert severity_of(findings, "cookie-samesite-none-insecure") == "Low"


def test_samesite_none_with_secure_on_session_cookie_is_informational():
    findings, _ = analyze_cookies(["sessionid=abc; Secure; HttpOnly; SameSite=None"])
    assert ids(findings) == {"cookie-samesite-none"}
    assert severity_of(findings, "cookie-samesite-none") == "Informational"


def test_samesite_none_with_secure_on_other_cookie_has_no_finding():
    findings, _ = analyze_cookies(["ads=1; Secure; HttpOnly; SameSite=None"])
    assert findings == []


@pytest.mark.parametrize(
    "header, expect_violation",
    [
        ("__Host-id=1; Secure; HttpOnly; SameSite=Lax; Path=/", False),
        ("__Host-id=1; Secure; HttpOnly; SameSite=Lax; Path=/app", True),
        ("__Host-id=1; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=example.com", True),
        ("__Host-id=1; HttpOnly; SameSite=Lax; Path=/", True),
        ("__Secure-id=1; Secure; HttpOnly; SameSite=Lax", False),
        ("__Secure-id=1; HttpOnly; SameSite=Lax", True),
    ],
)
def test_cookie_prefix_rules(header, expect_violation):
    findings, _ = analyze_cookies([header])
    assert ("cookie-prefix-violation" in ids(findings)) is expect_violation


def test_findings_group_several_cookies_into_one():
    findings, _ = analyze_cookies(
        ["sessionid=a; HttpOnly; SameSite=Lax", "theme=dark; HttpOnly; SameSite=Lax"]
    )
    assert ids(findings) == {"cookie-missing-secure"}
    assert len(findings) == 1
    assert severity_of(findings, "cookie-missing-secure") == "Medium"
    evidence = findings[0].evidence
    assert "sessionid" in evidence and "theme" in evidence


def test_duplicate_cookie_last_one_wins():
    findings, notes = analyze_cookies(
        ["sessionid=a; Path=/", "sessionid=b; Path=/; Secure; HttpOnly; SameSite=Lax"]
    )
    assert findings == []
    assert any("1 cookie checked" in note for note in notes)


def test_unreadable_header_is_noted_and_skipped():
    findings, notes = analyze_cookies(["garbage", GOOD_SESSION])
    assert findings == []
    assert any("could not be read" in note for note in notes)


def test_cookie_values_never_appear_in_output():
    findings, notes = analyze_cookies(["sessionid=SUPERSECRETVALUE; Path=/"])
    assert findings
    everything = " ".join(
        [f.evidence + f.description + f.remediation + f.title for f in findings] + notes
    )
    assert "SUPERSECRETVALUE" not in everything


def test_long_cookie_lists_are_shortened():
    headers = [f"c{i}=1" for i in range(12)]
    findings, _ = analyze_cookies(headers)
    secure = next(f for f in findings if f.check_id == "cookie-missing-secure")
    assert "and 2 more" in secure.evidence


def test_run_cookie_checks_uses_fetch_result():
    fetch = types.SimpleNamespace(set_cookie_headers=["sessionid=abc; Path=/"])
    findings, _ = run_cookie_checks(fetch)
    assert "cookie-missing-secure" in ids(findings)


def test_every_finding_has_explanation_fix_and_evidence():
    findings, _ = analyze_cookies(["sessionid=abc; Path=/"])
    assert findings
    for finding in findings:
        assert finding.description
        assert finding.remediation
        assert finding.evidence
        assert finding.owasp_category == "A02:2025"