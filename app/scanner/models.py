"""Data structures shared by every scanner check.

A check looks at the target website and produces zero or more Finding objects.
All findings for one scan are collected in a ScanResult.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    """How serious a finding is. The value is the text shown to users."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


# Most severe first. Used for sorting and for the dashboard summary.
SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFORMATIONAL,
]
SEVERITY_RANK = {severity: rank for rank, severity in enumerate(SEVERITY_ORDER)}

# OWASP Top 10, 2025 edition. Verify names at https://owasp.org/Top10/2025/
# Note: SSRF (A10 in 2021) was merged into A01 Broken Access Control in 2025.
OWASP_EDITION = "2025"
OWASP_TOP_10 = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Logging & Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}


@dataclass
class Finding:
    """One security observation about the target website."""

    check_id: str            # short machine name, e.g. "missing-hsts"
    title: str               # short heading shown in the dashboard
    severity: Severity
    owasp_category: str      # a key of OWASP_TOP_10, e.g. "A02:2025"
    description: str         # what the problem is, in simple words
    remediation: str         # how to fix it
    evidence: str = ""       # what we actually observed (header value, date...)

    def __post_init__(self):
        if self.owasp_category not in OWASP_TOP_10:
            raise ValueError(f"Unknown OWASP category: {self.owasp_category}")

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "owasp_category": self.owasp_category,
            "owasp_name": OWASP_TOP_10[self.owasp_category],
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
        }


@dataclass
class ScanResult:
    """Everything produced by one scan of one website."""

    target_url: str
    final_url: str = ""
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    findings: list[Finding] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def sorted_findings(self) -> list[Finding]:
        """Findings ordered from most to least severe."""
        return sorted(
            self.findings, key=lambda f: (SEVERITY_RANK[f.severity], f.title)
        )

    def severity_counts(self) -> dict[str, int]:
        """Number of findings per severity. Every level is always present."""
        counts = {severity.value: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "target_url": self.target_url,
            "final_url": self.final_url,
            "scanned_at": self.scanned_at,
            "owasp_edition": OWASP_EDITION,
            "checks_run": self.checks_run,
            "notes": self.notes,
            "severity_counts": self.severity_counts(),
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }