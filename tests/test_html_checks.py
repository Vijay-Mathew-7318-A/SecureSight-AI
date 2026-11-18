import types

import pytest

from app.scanner.html_checks import analyze_html, run_html_checks

URL = "https://example.com/"


def check(html, url=URL, content_type="text/html; charset=utf-8", truncated=False):
    return analyze_html(html, url, content_type, truncated)


def ids(findings):
    return {f.check_id for f in findings}


def one(findings, check_id):
    return next(f for f in findings if f.check_id == check_id)


# ---------- baseline ----------
def test_clean_https_page_has_no_findings():
    html = (
        '<html><head><title>Home</title><script src="/app.js"></script>'
        '<link rel="stylesheet" href="/site.css"></head><body><img src="/logo.png">'
        '<form action="/login" method="post"><input type="password" name="p"></form>'
        "</body></html>"
    )
    findings, notes = check(html)
    assert findings == []
    assert notes == []


# ---------- mixed content ----------
def test_mixed_content_active_script():
    findings, _ = check('<script src="http://example.com/a.js"></script>')
    assert ids(findings) == {"mixed-content-active"}
    assert one(findings, "mixed-content-active").severity.value == "Medium"


def test_mixed_content_passive_image():
    findings, _ = check('<img src="http://example.com/a.png">')
    assert ids(findings) == {"mixed-content-passive"}
    assert one(findings, "mixed-content-passive").severity.value == "Low"


def test_mixed_content_ignored_on_http_page():
    findings, _ = check('<script src="http://example.com/a.js"></script>', url="http://example.com/")
    assert findings == []


def test_protocol_relative_and_relative_urls_are_not_mixed_content():
    html = '<script src="//example.com/x.js"></script><img src="pics/a.png">'
    findings, _ = check(html)
    assert findings == []


def test_plain_links_are_not_mixed_content():
    findings, _ = check('<a href="http://other.com/">link</a>')
    assert findings == []


def test_insecure_stylesheet_is_active_mixed_content():
    findings, _ = check('<link rel="stylesheet" href="http://example.com/s.css">')
    assert ids(findings) == {"mixed-content-active"}


def test_insecure_iframe_is_active_mixed_content():
    findings, _ = check('<iframe src="http://example.com/frame"></iframe>')
    assert ids(findings) == {"mixed-content-active"}


def test_several_insecure_resources_are_grouped_into_one_finding():
    html = '<script src="http://example.com/a.js"></script><script src="http://example.com/b.js"></script>'
    findings, _ = check(html)
    assert len(findings) == 1
    assert "a.js" in findings[0].evidence and "b.js" in findings[0].evidence


# ---------- subresource integrity ----------
def test_external_script_without_sri():
    findings, _ = check('<script src="https://cdn.other.net/lib.js"></script>')
    assert ids(findings) == {"external-script-no-sri"}
    assert one(findings, "external-script-no-sri").severity.value == "Low"
    assert "cdn.other.net" in findings[0].evidence


def test_external_script_with_sri_is_fine():
    html = '<script src="https://cdn.other.net/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script>'
    findings, _ = check(html)
    assert findings == []


def test_same_site_subdomain_is_not_third_party():
    findings, _ = check(
        '<script src="https://cdn.example.com/a.js"></script>', url="https://www.example.com/"
    )
    assert findings == []


def test_external_stylesheet_without_sri_is_informational():
    findings, _ = check('<link rel="stylesheet" href="https://cdn.other.net/s.css">')
    assert ids(findings) == {"external-stylesheet-no-sri"}
    assert findings[0].severity.value == "Informational"


def test_google_fonts_stylesheet_is_exempt():
    findings, _ = check('<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto">')
    assert findings == []


def test_query_strings_are_not_shown_in_evidence():
    findings, _ = check('<script src="https://cdn.other.net/a.js?token=SECRET123"></script>')
    assert ids(findings) == {"external-script-no-sri"}
    assert "SECRET123" not in findings[0].evidence
    assert "cdn.other.net/a.js" in findings[0].evidence


# ---------- forms ----------
def test_password_form_on_http_page():
    html = '<form action="/login" method="post"><input type="password" name="p"></form>'
    findings, _ = check(html, url="http://example.com/")
    assert ids(findings) == {"password-form-over-http"}
    assert findings[0].severity.value == "High"


def test_password_field_outside_form_on_http_page():
    findings, _ = check('<input type="password" name="p">', url="http://example.com/")
    assert ids(findings) == {"password-form-over-http"}


def test_password_form_using_get():
    html = '<form action="/login"><input type="password" name="p"></form>'
    findings, _ = check(html)
    assert ids(findings) == {"password-form-uses-get"}
    assert findings[0].severity.value == "Medium"
    assert findings[0].evidence == "Forms with a password field that use GET: 1."


def test_form_posting_to_http_is_medium():
    html = '<form action="http://example.com/s" method="post"><input name="q"></form>'
    findings, _ = check(html)
    assert ids(findings) == {"form-posts-to-http"}
    assert findings[0].severity.value == "Medium"


def test_form_with_password_posting_to_http_is_high():
    html = '<form action="http://example.com/s" method="post"><input type="password" name="p"></form>'
    findings, _ = check(html)
    assert ids(findings) == {"form-posts-to-http"}
    assert findings[0].severity.value == "High"


# ---------- directory listing ----------
def test_directory_listing():
    html = (
        "<html><head><title>Index of /backup</title></head><body>"
        '<h1>Index of /backup</h1><a href="/">Parent Directory</a></body></html>'
    )
    findings, _ = check(html)
    assert ids(findings) == {"directory-listing"}
    assert findings[0].severity.value == "Medium"


# ---------- error details ----------
@pytest.mark.parametrize(
    "body, label",
    [
        ('Traceback (most recent call last):\n  File "app.py", line 3, in <module>', "Python traceback"),
        ("Exception in thread main\n\tat com.example.App.main(App.java:42)", "Java stack trace"),
        (
            "<b>Warning</b>: Undefined variable $x in <b>/var/www/html/index.php</b> on line <b>12</b>",
            "PHP error message with file path",
        ),
        ("Server Error in '/' Application.", ".NET stack trace or error page"),
        ("TypeError: x\n    at Object.<anonymous> (/app/server.js:10:15)", "Node.js stack trace"),
        ("You have an error in your SQL syntax; check the manual", "SQL error message"),
        ("ORA-00933: SQL command not properly ended", "SQL error message"),
        ("The debugger caught an exception in your WSGI application.", "Framework debug mode page"),
    ],
)
def test_error_details_detected(body, label):
    findings, _ = check(body)
    assert ids(findings) == {"error-details-exposed"}
    assert label in findings[0].evidence


def test_debug_mode_page_is_high_and_normal_errors_are_medium():
    debug, _ = check("The debugger caught an exception in your WSGI application.")
    normal, _ = check("ORA-00933: SQL command not properly ended")
    assert debug[0].severity.value == "High"
    assert normal[0].severity.value == "Medium"


def test_error_details_found_in_json_response():
    findings, notes = check(
        '{"error": "Traceback (most recent call last): boom"}', content_type="application/json"
    )
    assert ids(findings) == {"error-details-exposed"}
    assert any("not HTML" in note for note in notes)


def test_normal_text_is_not_an_error_leak():
    findings, _ = check("<p>Warning: our store closes early in December.</p>")
    assert findings == []


# ---------- generator and libraries ----------
def test_generator_with_version():
    findings, _ = check('<meta name="generator" content="WordPress 6.2.1">')
    assert ids(findings) == {"generator-version-disclosure"}
    assert findings[0].severity.value == "Low"


def test_generator_without_version_is_ignored():
    findings, _ = check('<meta name="generator" content="Hugo">')
    assert findings == []


def test_library_versions_detected():
    html = (
        '<script src="/js/jquery-1.12.4.min.js"></script>'
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/3.3.7/js/bootstrap.min.js" '
        'integrity="sha384-x" crossorigin="anonymous"></script>'
    )
    findings, _ = check(html)
    assert ids(findings) == {"library-versions-detected"}
    finding = findings[0]
    assert finding.severity.value == "Informational"
    assert "jquery 1.12.4" in finding.evidence
    assert "bootstrap 3.3.7" in finding.evidence
    assert "does not check" in finding.description


def test_unversioned_library_is_ignored():
    findings, _ = check('<script src="/js/jquery.min.js"></script>')
    assert findings == []


# ---------- skipping and notes ----------
def test_non_text_response_is_skipped():
    findings, notes = check("xxxx", content_type="image/png")
    assert findings == []
    assert "skipped" in notes[0]


def test_empty_body_adds_note():
    findings, notes = check("   ")
    assert findings == []
    assert "empty" in notes[0]


def test_truncated_page_adds_note():
    findings, notes = check("<html></html>", truncated=True)
    assert findings == []
    assert any("Only the first part" in note for note in notes)


# ---------- entry point and quality ----------
def test_run_html_checks_uses_fetch_result():
    fetch = types.SimpleNamespace(
        body_text='<script src="http://example.com/a.js"></script>',
        final_url="https://example.com/",
        headers={"content-type": "text/html"},
        body_truncated=False,
    )
    findings, _ = run_html_checks(fetch)
    assert ids(findings) == {"mixed-content-active"}


def test_every_finding_has_explanation_fix_and_evidence():
    html = (
        '<html><head><meta name="generator" content="WordPress 6.2.1">'
        '<script src="http://example.com/a.js"></script>'
        '<script src="https://cdn.other.net/jquery-1.12.4.min.js"></script>'
        '<link rel="stylesheet" href="https://cdn.other.net/s.css"></head>'
        '<body><img src="http://example.com/i.png">'
        '<form action="http://example.com/login"><input type="password"></form></body></html>'
    )
    findings, _ = check(html)
    assert ids(findings) == {
        "mixed-content-active",
        "mixed-content-passive",
        "external-script-no-sri",
        "external-stylesheet-no-sri",
        "form-posts-to-http",
        "password-form-uses-get",
        "generator-version-disclosure",
        "library-versions-detected",
    }
    for finding in findings:
        assert finding.description
        assert finding.remediation
        assert finding.evidence


def test_malformed_html_does_not_crash():
    findings, notes = check('<div <<>> <script src="http://example.com/a.js" <form action=')
    assert isinstance(findings, list)
    assert isinstance(notes, list)