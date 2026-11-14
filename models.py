from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class TestCase:
    case_id: str
    principal: str
    resource_type: str
    resource_id: str
    tenant_id: str
    sensitivity: str
    method: str
    path: str
    expected: str
    vulnerability: str
    headers: dict[str, str] = field(default_factory=dict)
    query: dict[str, str] = field(default_factory=dict)
    payload: dict[str, Any] | None = None
    write: bool = False


@dataclass
class TestResult:
    case: TestCase
    status_code: int | None
    verdict: str
    finding: dict[str, Any] | None
    evidence: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "case": asdict(self.case),
            "status_code": self.status_code,
            "verdict": self.verdict,
            "finding": self.finding,
            "evidence": self.evidence,
        }


@dataclass
class ScanReport:
    scan_id: str
    status: str
    mode: str
    total_tests: int
    passed_tests: int
    inconclusive_tests: int
    findings: list[dict[str, Any]]
    results: list[TestResult]
    risk_score: int
    findings_by_severity: dict[str, int]
    leaks_by_vulnerability: dict[str, int]

    def as_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "status": self.status,
            "mode": self.mode,
            "total_tests": self.total_tests,
            "passed_tests": self.passed_tests,
            "inconclusive_tests": self.inconclusive_tests,
            "finding_count": len(self.findings),
            "leak_count": sum(
                finding["verdict"] in ("PROVEN LEAK", "LEAK")
                for finding in self.findings
            ),
            "risk_score": self.risk_score,
            "findings_by_severity": self.findings_by_severity,
            "leaks_by_vulnerability": self.leaks_by_vulnerability,
            "findings": self.findings,
            "results": [result.as_dict() for result in self.results],
        }
