"""Data shared by every part of the tool."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Ordered so that comparisons like `sev >= Severity.HIGH` work."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except (KeyError, AttributeError):
            raise ValueError(f"unknown severity: {value!r}") from None

    @classmethod
    def from_cvss(cls, score: float) -> Severity:
        """Map a CVSS base score to a severity, using the FIRST bands."""
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Finding:
    tool: str
    severity: Severity
    rule: str
    message: str
    file: str = ""
    line: int = 0
    category: str = "code"  # code | secret | dependency | config | runtime
    language: str = ""
    snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "severity": self.severity.label,
            "rule": self.rule,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "category": self.category,
            "language": self.language,
            "snippet": self.snippet,
        }


# Why a tool did or did not produce results. A tool that failed must never
# look like a tool that found nothing, so the status is always reported.
OK = "ok"
SKIPPED = "skipped"  # nothing to do for this folder (not a problem)
UNAVAILABLE = "unavailable"  # tool missing: the check did NOT happen
ERROR = "error"  # tool ran and failed: the check did NOT happen


@dataclass
class ToolResult:
    name: str
    status: str
    detail: str = ""
    findings: list[Finding] = field(default_factory=list)
    seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "findings": len(self.findings),
            "seconds": round(self.seconds, 2),
        }
