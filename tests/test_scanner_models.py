import pytest

from app.scanner.models import OWASP_TOP_10, Finding, ScanResult, Severity


def make_finding(title="Example", severity=Severity.LOW, category="A02:2025"):
    return Finding(
        check_id="example",
        title=title,
        severity=severity,
        owasp_category=category,
        description="desc",
        remediation="fix it",
    )


def test_owasp_list_has_ten_categories():
    assert len(OWASP_TOP_10) == 10


def test_finding_rejects_unknown_owasp_category():
    with pytest.raises(ValueError):
        make_finding(category="A99:2025")


def test_finding_to_dict_uses_text_severity_and_owasp_name():
    data = make_finding(severity=Severity.MEDIUM).to_dict()
    assert data["severity"] == "Medium"
    assert data["owasp_name"] == "Security Misconfiguration"


def test_findings_are_sorted_most_severe_first():
    result = ScanResult(target_url="https://example.com")
    result.add_finding(make_finding("L", Severity.LOW))
    result.add_finding(make_finding("C", Severity.CRITICAL))
    result.add_finding(make_finding("M", Severity.MEDIUM))
    assert [f.title for f in result.sorted_findings()] == ["C", "M", "L"]


def test_severity_counts_always_include_every_level():
    result = ScanResult(target_url="https://example.com")
    result.add_finding(make_finding(severity=Severity.HIGH))
    counts = result.severity_counts()
    assert counts == {
        "Critical": 0,
        "High": 1,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }


def test_scan_result_to_dict_shape():
    result = ScanResult(target_url="https://example.com")
    result.add_finding(make_finding())
    data = result.to_dict()
    assert data["total_findings"] == 1
    assert data["findings"][0]["title"] == "Example"
    assert data["owasp_edition"] == "2025"