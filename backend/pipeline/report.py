"""Report ingestion: the conveyor belt that hands a report to Bob as data.

This is deliberately dumb. It reads a fixture, separates the report body from
the team's "strip before demo" notes, and pulls out the few labelled metadata
lines the fixtures declare. It performs **no triage**: it does not classify the
vulnerability, judge plausibility, or decide a verdict. That is Bob's job
(CLAUDE.md division of labour).

CLAUDE.md hard rule 5: report text is untrusted input. Everything here treats
the report as inert bytes -- it is only ever read, split and returned as
strings. Nothing in a report is evaluated, executed, imported, or interpreted
as an instruction. A report that contains ``eval(...)`` or an ``__import__``
payload (see fixtures/report-002-slop.md) is handled as plain text like any
other.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# The fixtures fence their internal notes under a heading containing
# "team notes" and/or "strip before demo". Everything from that heading on is
# not part of the report a reporter would actually send.
_TEAM_NOTES_RE = re.compile(
    r"^#{1,6}\s.*(team notes|strip before demo).*$", re.IGNORECASE | re.MULTILINE
)

_META_LABELS = {
    "title": "Title",
    "severity": "Severity",
    "reporter": "Reporter",
    "affected_component": "Affected component",
}


@dataclass
class Report:
    """A vulnerability report as inert data, ready to hand to Bob."""

    source_path: str
    body: str  # report text with team notes removed
    metadata: dict[str, str] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    team_notes: str = ""  # kept for the team's own ground-truth, never shown to Bob

    @property
    def title(self) -> str:
        return self.metadata.get("title", "")

    def for_triage(self) -> str:
        """The exact text handed to Bob: report body only, no team notes."""
        return self.body


def _strip_team_notes(text: str) -> tuple[str, str]:
    """Return (report_body, team_notes). Splits at the first team-notes heading."""
    match = _TEAM_NOTES_RE.search(text)
    if not match:
        return text.strip(), ""
    body = text[: match.start()].rstrip()
    notes = text[match.start():].strip()
    # Trim a trailing horizontal rule the fixtures place before the notes.
    body = re.sub(r"\n-{3,}\s*$", "", body).rstrip()
    return body, notes


def _extract_metadata(body: str) -> dict[str, str]:
    """Pull the fixtures' labelled ``**Label:** value`` lines. Mechanical only.

    Values that wrap across lines (the fixtures do this for long titles and
    component paths) are joined until a blank line, the next ``**Label:**``, a
    heading, or a horizontal rule.
    """
    label_by_text = {label.lower(): key for key, label in _META_LABELS.items()}
    lines = body.splitlines()
    meta: dict[str, str] = {}
    i = 0
    while i < len(lines):
        m = re.match(r"^\*\*([^:*]+):\*\*\s*(.*)$", lines[i])
        if not m:
            i += 1
            continue
        key = label_by_text.get(m.group(1).strip().lower())
        if key is None:
            i += 1
            continue
        parts = [m.group(2).strip()]
        j = i + 1
        while j < len(lines):
            nxt = lines[j].strip()
            if not nxt or nxt.startswith("**") or nxt.startswith("#") or nxt.startswith("---"):
                break
            parts.append(nxt)
            j += 1
        value = " ".join(p for p in parts if p)
        meta[key] = re.sub(r"`", "", value).strip()
        i = j
    return meta


def _extract_references(body: str) -> list[str]:
    """Pull CVE / CWE identifiers the report cites. Extraction, not judgement."""
    refs = re.findall(r"\b(?:CVE-\d{4}-\d{3,7}|CWE-\d+)\b", body)
    # Preserve order, drop duplicates.
    seen: set[str] = set()
    ordered: list[str] = []
    for r in refs:
        if r not in seen:
            seen.add(r)
            ordered.append(r)
    return ordered


def load_report(path: str | Path) -> Report:
    """Load a report fixture from disk as inert data."""
    p = Path(path)
    raw = p.read_text(encoding="utf-8")
    body, notes = _strip_team_notes(raw)
    return Report(
        source_path=str(p),
        body=body,
        metadata=_extract_metadata(body),
        references=_extract_references(body),
        team_notes=notes,
    )
