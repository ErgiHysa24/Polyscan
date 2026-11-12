"""SARIF 2.1.0 output (OASIS standard): the format GitHub code scanning, DefectDojo, SonarQube and most
IDEs read.

One SARIF "run" per tool. A tool that did not run correctly is not left out: its run says
`executionSuccessful: false` with the reason, so a reader of the SARIF file cannot mistake a failed
check for a clean one (the same rule as every other polyscan report).

`security-severity` is the number GitHub uses to show critical / high / medium / low; CWE ids become
tags in GitHub's form `external/cwe/cwe-89`. Paths are relative to the scanned folder.
"""

from __future__ import annotations

import json
import re

from . import __version__
from .models import OK, SKIPPED, Severity
from .scanner import ScanResult

SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}
# GitHub: >= 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low
SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "2.0", Severity.INFO: "0.0"}
URL = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)


def _uri(path: str) -> str:
    path = path.replace("\\", "/")
    if URL.match(path):
        return path  # a site scan: the finding is at a URL
    return path[2:] if path.startswith("./") else path  # (not lstrip: ".github/x" must keep its dot)


def _location(f) -> list[dict]:
    if not f.file:
        return []
    loc = {"physicalLocation": {"artifactLocation": {"uri": _uri(f.file)}}}
    if f.line and f.line > 0 and not URL.match(f.file):
        loc["physicalLocation"]["region"] = {"startLine": int(f.line)}
    return [loc]


def _tags(f) -> list[str]:
    tags = ["security", f.category]
    tags += [f"external/cwe/cwe-{c.split('-')[1]}" for c in f.cwe.split(",") if c.startswith("CWE-")]
    return tags


def to_sarif(result: ScanResult) -> str:
    runs = []
    for t in result.tools:
        rules: dict[str, dict] = {}
        results = []
        for f in t.findings:
            rule_id = f.rule or "polyscan-finding"
            rule = rules.setdefault(rule_id, {
                "id": rule_id, "shortDescription": {"text": (" ".join(f.message.split()) or rule_id)[:200]},
                "properties": {"tags": _tags(f), "security-severity": SECURITY_SEVERITY[f.severity]},
            })  # fmt: skip
            # a rule keeps the highest severity of its results
            if float(SECURITY_SEVERITY[f.severity]) > float(rule["properties"]["security-severity"]):
                rule["properties"]["security-severity"] = SECURITY_SEVERITY[f.severity]
            res = {
                "ruleId": rule_id, "level": LEVEL[f.severity], "message": {"text": " ".join(f.message.split()) or rule_id},
                "locations": _location(f), "properties": {"severity": f.severity.label, "category": f.category},
            }  # fmt: skip
            if f.language:
                res["properties"]["language"] = f.language
            results.append(res)
        invocation = {"executionSuccessful": t.status in (OK, SKIPPED)}
        if t.status != OK:
            invocation["toolExecutionNotifications"] = [{
                "level": "note" if t.status == SKIPPED else "error",
                "message": {"text": f"{t.status}: {t.detail or 'no detail'}"[:1000]},
            }]  # fmt: skip
        runs.append({
            "tool": {"driver": {"name": t.name, "informationUri": "https://github.com/ErgiHysa24/Polyscan",
                                "semanticVersion": __version__, "rules": list(rules.values())}},
            "invocations": [invocation],
            "results": results,
            "properties": {"polyscan": {"status": t.status, "kind": result.kind}},
        })  # fmt: skip
    return json.dumps({"$schema": SCHEMA, "version": "2.1.0", "runs": runs}, indent=2, ensure_ascii=False)
