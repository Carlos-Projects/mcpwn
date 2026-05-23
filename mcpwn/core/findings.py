from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Literal

Severity = Literal["critical", "high", "medium", "low", "info"]


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    attack_type: str
    target: str
    description: str
    detail: str
    recommendation: str
    evidence: dict = field(default_factory=dict)


@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "findings": [asdict(f) for f in self.findings],
            "metadata": self.metadata,
        }

    @property
    def summary(self) -> dict:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return {
            "total": len(self.findings),
            "by_severity": counts,
        }