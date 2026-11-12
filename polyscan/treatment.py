"""Risk treatment: what the team DECIDED to do about each risk, kept in a file under version control.

A risk register is not finished when the risks are scored. ISO 27005 and NIST SP 800-30 / 800-39
both continue with the *response*: for each risk someone chooses to

    mitigate  - fix it (owner and a due date),
    accept    - live with it for a while (owner, reason, and an expiry date: acceptance is never forever),
    transfer  - give it to someone else (insurer, hosting provider, a vendor fix),
    avoid     - remove the feature or component that causes it,

and tools may be wrong, so a finding can also be marked **false-positive** (with the reason, so the
decision can be reviewed later). The file looks like this (JSON, so no extra library is needed):

    {
      "version": 1,
      "decisions": [
        {"rule": "CVE-2026-69246", "file": "php/composer.lock",
         "decision": "accept", "owner": "Mario Rossi", "justification": "only used in the test suite",
         "expires": "2026-12-31"},
        {"rule": "B608", "file": "app/reports/*.py", "decision": "false-positive",
         "owner": "Mario Rossi", "justification": "the query text is a constant, the value is a placeholder"},
        {"rule": "polyscan-sql-*", "decision": "mitigate", "owner": "team backend", "due": "2026-12-15",
         "status": "in-progress", "ticket": "#42"}
      ]
    }

Matching: `rule`, `file` and `tool` are shell-style patterns (`*`, `?`); a missing field matches
everything, but every decision needs at least `rule` or `file` (a decision that matches *all*
findings is almost always a mistake). The first decision that matches a finding wins.

What polyscan does with it, and why:
  * false positives leave the register but are LISTED, with who decided and why (audit trail);
  * an accepted risk stays in the register as "accepted" and no longer fails `--fail-on`, until the
    acceptance expires: then it counts again and a warning says so;
  * mitigate / transfer / avoid keep the risk active (it is still there until the retest says it is
    gone); past the due date a warning says it is overdue;
  * a decision that matches nothing is reported: the problem may be fixed, or the pattern is wrong;
  * an entry with "decision": "todo" is a placeholder (see `polyscan risk --decisions-template`).

The file is data: it is validated field by field and nothing in it is executed.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from .models import Finding

DECISIONS = ("mitigate", "accept", "transfer", "avoid", "false-positive", "todo")
STATUSES = ("open", "in-progress", "done")
KEYS = {"rule", "file", "tool", "decision", "owner", "justification", "expires", "due", "status", "ticket", "note"}
MAX_BYTES = 2 * 1024 * 1024
MAX_TEXT = 500


@dataclass
class Decision:
    index: int  # position in the file, 1-based: used in messages and to keep groups apart
    decision: str
    rule: str = ""
    file: str = ""
    tool: str = ""
    owner: str = ""
    justification: str = ""
    expires: date | None = None
    due: date | None = None
    status: str = "open"
    ticket: str = ""
    note: str = ""
    matched: int = 0

    def matches(self, f: Finding) -> bool:
        for pattern, value in ((self.rule, f.rule), (self.file, f.file), (self.tool, f.tool)):
            if pattern and not fnmatch.fnmatchcase(value, pattern):
                return False
        return True

    def label(self) -> str:
        what = ", ".join(f"{k}={v}" for k, v in (("rule", self.rule), ("file", self.file), ("tool", self.tool)) if v)
        return f"decision #{self.index} ({what})"

    def state(self, today: date) -> str:
        """accepted | acceptance-expired | planned | overdue | done | false-positive | todo"""
        if self.decision == "accept":
            return "acceptance-expired" if self.expires and self.expires < today else "accepted"
        if self.decision in ("mitigate", "transfer", "avoid"):
            if self.status == "done":
                return "done"
            return "overdue" if self.due and self.due < today else "planned"
        return self.decision

    def to_dict(self, today: date) -> dict:
        d = {
            "decision": self.decision, "state": self.state(today), "owner": self.owner, "justification": self.justification,
            "expires": self.expires.isoformat() if self.expires else None, "due": self.due.isoformat() if self.due else None,
            "status": self.status, "ticket": self.ticket, "note": self.note,
            "match": {k: v for k, v in (("rule", self.rule), ("file", self.file), ("tool", self.tool)) if v},
            "entry": self.index,
        }  # fmt: skip
        return d


@dataclass
class Plan:
    """All decisions of one file, and what happened when they were applied."""

    path: str
    decisions: list[Decision] = field(default_factory=list)
    today: date = field(default_factory=date.today)
    false_positives: list[tuple[Finding, Decision]] = field(default_factory=list)  # filled by split()

    def decision_for(self, f: Finding) -> Decision | None:
        for d in self.decisions:
            if d.decision != "todo" and d.matches(f):
                return d
        return None

    def warnings(self) -> list[str]:
        out = []
        for d in self.decisions:
            if d.decision == "todo":
                continue
            if not d.matched:
                out.append(f"{d.label()} matches no finding: the problem may be fixed, or the pattern is wrong")
            elif d.state(self.today) == "acceptance-expired":
                out.append(f"{d.label()}: the acceptance expired on {d.expires} - the risk counts again until someone decides")
            elif d.state(self.today) == "done":
                out.append(f"{d.label()} is marked done, but the scan still finds it ({d.matched}x): the fix did not work or is not deployed")
            elif d.state(self.today) == "overdue":
                out.append(f"{d.label()}: the {d.decision} was due on {d.due} and is not done ({d.owner})")
        todo = sum(d.decision == "todo" for d in self.decisions)
        if todo:
            out.append(f"{todo} decision(s) still marked 'todo' in {self.path}")
        return out


def _date(value, where: str) -> date | None:
    if value in (None, ""):
        return None
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        raise ValueError(f"{where}: dates are written YYYY-MM-DD, not {str(value)[:30]!r}") from None


def _text(item: dict, key: str, where: str) -> str:
    value = item.get(key, "")
    if not isinstance(value, str):
        raise ValueError(f"{where}: {key} must be text")
    if len(value) > MAX_TEXT:
        raise ValueError(f"{where}: {key} is longer than {MAX_TEXT} characters")
    return value.strip()


def parse(data, path: str = "decisions", today: date | None = None) -> Plan:
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("decisions"), list):
        raise ValueError(f'{path}: expected {{"version": 1, "decisions": [...]}}')
    plan = Plan(path, today=today or date.today())
    for n, item in enumerate(data["decisions"], 1):
        where = f"{path}, decision #{n}"
        if not isinstance(item, dict):
            raise ValueError(f"{where}: must be an object")
        unknown = set(item) - KEYS
        if unknown:
            raise ValueError(f"{where}: unknown field(s) {sorted(unknown)} (allowed: {sorted(KEYS)})")
        kind = _text(item, "decision", where)
        if kind not in DECISIONS:
            raise ValueError(f"{where}: decision must be one of {list(DECISIONS)}")
        d = Decision(
            index=n, decision=kind, rule=_text(item, "rule", where), file=_text(item, "file", where),
            tool=_text(item, "tool", where), owner=_text(item, "owner", where),
            justification=_text(item, "justification", where), expires=_date(item.get("expires"), where),
            due=_date(item.get("due"), where), status=_text(item, "status", where) or "open",
            ticket=_text(item, "ticket", where), note=_text(item, "note", where),
        )  # fmt: skip
        if not (d.rule or d.file):
            raise ValueError(f"{where}: give at least a rule or a file pattern (a decision for everything is almost always a mistake)")
        if d.status not in STATUSES:
            raise ValueError(f"{where}: status must be one of {list(STATUSES)}")
        if kind != "todo" and not d.owner:
            raise ValueError(f"{where}: every decision needs an owner (who is responsible for it)")
        if kind in ("accept", "false-positive", "transfer", "avoid") and not d.justification:
            raise ValueError(f"{where}: '{kind}' needs a justification")
        if kind == "accept" and not d.expires:
            raise ValueError(f"{where}: an accepted risk needs an expiry date ('expires'): acceptance is reviewed, not forever")
        if kind == "mitigate" and not d.due:
            raise ValueError(f"{where}: a mitigation needs a due date ('due')")
        plan.decisions.append(d)
    return plan


def load(path: str, today: date | None = None) -> Plan:
    p = Path(path)
    try:
        if p.stat().st_size > MAX_BYTES:
            raise ValueError(f"{path}: file is too large for a decisions file")
        data = json.loads(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"{path}: cannot read the file ({exc.strerror or exc})") from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: not valid JSON (line {exc.lineno})") from None
    return parse(data, path, today)


def split(findings: list[Finding], plan: Plan | None) -> tuple[list[tuple[Finding, Decision | None]], list[tuple[Finding, Decision]]]:
    """(findings that stay in the register with their decision, findings removed as false positives)."""
    kept, removed = [], []
    for f in findings:
        d = plan.decision_for(f) if plan else None
        if d:
            d.matched += 1
        if d and d.decision == "false-positive":
            removed.append((f, d))
        else:
            kept.append((f, d))
    if plan:
        plan.false_positives = removed
    return kept, removed


def template(risks) -> str:
    """A decisions file with one 'todo' entry per risk, ready to be filled in."""
    entries = []
    for r in risks:
        entries.append({
            "rule": r.rule, "decision": "todo", "owner": "", "justification": "",
            "note": f"{r.id} {r.level} (score {r.score}): {r.title[:120]}",
        })  # fmt: skip
    return json.dumps({"version": 1, "decisions": entries}, indent=2, ensure_ascii=False) + "\n"
