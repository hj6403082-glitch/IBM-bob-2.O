"""The frozen verdict contract shared by Bob, the UI and the demo.

CLAUDE.md conventions: keep the verdict schema stable once frozen --
``VERDICT``, ``CONFIDENCE``, ``EVIDENCE`` (list of ``file:line``), ``ACTION``.
The UI and the demo both read this shape.

This module defines the *container and its validation only*. The verdict
*content* -- which value applies to a given report, and the evidence behind it
-- is Bob's to decide (CLAUDE.md division of labour). Nothing here classifies a
report or picks a verdict.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    """The four verdicts Bob may emit (docs/security-triage-mode.md, Phase 3)."""

    CONFIRMED = "CONFIRMED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    NOT_A_VULNERABILITY = "NOT_A_VULNERABILITY"
    FABRICATED = "FABRICATED"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ``file:line`` -- path, colon, line number. Evidence entries must cite a
# concrete location so the maintainer can jump straight to it.
_EVIDENCE_RE = re.compile(r"^.+:\d+(?:-\d+)?$")
# A location reference appearing anywhere in an entry (e.g. real verdicts write
# "requests/sessions.py:327 -- root cause ...", not a bare file:line).
_LOC_RE = re.compile(r"[\w./\\-]+\.\w+:\d+(?:-\d+)?")


class VerdictSchemaError(ValueError):
    """Raised when a verdict payload does not conform to the frozen schema."""


@dataclass(frozen=True)
class TriageVerdict:
    """A validated verdict record. Produced by Bob, consumed by the rails."""

    verdict: Verdict
    confidence: Confidence
    evidence: list[str]
    action: str
    # Free-form supporting detail Bob may attach (root cause, notes). Optional
    # and never required by the contract.
    detail: str = ""

    def __post_init__(self) -> None:
        validate_verdict(asdict(self))

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        d["confidence"] = self.confidence.value
        return d

    def to_json(self, **kwargs: Any) -> str:
        return json.dumps(self.to_dict(), indent=2, **kwargs)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TriageVerdict":
        validate_verdict(data)
        return cls(
            verdict=Verdict(data["verdict"]),
            confidence=Confidence(str(data["confidence"]).lower()),
            evidence=list(data["evidence"]),
            action=str(data["action"]),
            detail=str(data.get("detail", "")),
        )


def validate_verdict(data: dict[str, Any], *, require_evidence: bool = True) -> None:
    """Validate a verdict payload against the frozen schema. Structure only.

    Raises :class:`VerdictSchemaError` describing the first problem found.
    """
    if not isinstance(data, dict):
        raise VerdictSchemaError(f"verdict must be a mapping, got {type(data).__name__}")

    missing = {"verdict", "confidence", "evidence", "action"} - set(data)
    if missing:
        raise VerdictSchemaError(f"missing required field(s): {sorted(missing)}")

    # Accept either raw strings or enum members (normalise to the string value).
    verdict_value = getattr(data["verdict"], "value", data["verdict"])
    confidence_value = str(getattr(data["confidence"], "value", data["confidence"])).lower()

    valid_verdicts = {v.value for v in Verdict}
    if verdict_value not in valid_verdicts:
        raise VerdictSchemaError(
            f"verdict {data['verdict']!r} not one of {sorted(valid_verdicts)}"
        )

    valid_conf = {c.value for c in Confidence}
    if confidence_value not in valid_conf:
        raise VerdictSchemaError(
            f"confidence {data['confidence']!r} not one of {sorted(valid_conf)}"
        )

    evidence = data["evidence"]
    if not isinstance(evidence, list) or not all(isinstance(e, str) for e in evidence):
        raise VerdictSchemaError("evidence must be a list of strings")

    # CONFIRMED must point at real code (Phase 3/4): at least one entry has to
    # be a concrete file:line location so the maintainer can jump to it. Other
    # entries, and all evidence on the other verdicts (e.g. FABRICATED cites
    # what is *absent*), are free-form prose and never rejected.
    if require_evidence and verdict_value == Verdict.CONFIRMED.value:
        if not any(_EVIDENCE_RE.match(e.strip()) or _LOC_RE.search(e) for e in evidence):
            raise VerdictSchemaError(
                "CONFIRMED verdict requires at least one entry citing a file:line "
                "location (e.g. requests/sessions.py:327 -- root cause ...)"
            )

    if not str(data["action"]).strip():
        raise VerdictSchemaError("action must be a non-empty string")


def parse_verdict_block(text: str) -> dict[str, Any]:
    """Parse Bob's plain-text ``VERDICT:``/``CONFIDENCE:``/``EVIDENCE:``/``ACTION:``
    trailer (docs/security-triage-mode.md output format) into a dict.

    This is a mechanical text reader for Bob's own output -- it makes no
    judgement and invents nothing. Returns a dict suitable for
    :func:`validate_verdict` / :meth:`TriageVerdict.from_dict`.
    """
    fields: dict[str, Any] = {}
    lines = text.splitlines()
    i = 0
    current_key: str | None = None
    evidence: list[str] = []
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        m = re.match(r"^(VERDICT|CONFIDENCE|EVIDENCE|ACTION)\s*:\s*(.*)$", stripped)
        if m:
            key = m.group(1).lower()
            value = m.group(2).strip()
            current_key = key
            if key == "evidence":
                if value:
                    evidence.append(value.lstrip("- ").strip())
            else:
                fields[key] = value
        elif current_key == "evidence" and stripped.startswith("-"):
            evidence.append(stripped.lstrip("- ").strip())
        elif (current_key == "action" and stripped and "action" in fields
              and not stripped.startswith(("#", "```", "---"))):
            fields["action"] = (fields["action"] + " " + stripped).strip()
        i += 1
    fields["evidence"] = [e for e in evidence if e]
    return fields
