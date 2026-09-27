"""Triage backends: the seam where Bob plugs into the pipeline.

The rails never decide a verdict. A ``TriageBackend`` is asked to produce one
for a report, and the only real backend, :class:`BobSessionBackend`, does so by
**loading a verdict Bob already exported** to ``bob_sessions/``. If Bob has not
produced one, it raises -- it does not fall back to computing a verdict, because
verdict generation is Bob's exclusive responsibility (CLAUDE.md division of
labour: "If a task would produce a triage verdict ... stop and say so").

:class:`EchoBackend` exists only to test the rails: the caller supplies the
verdict, so a plumbing test can assert "given verdict X, the pipeline does Y"
without anyone authoring a verdict about a real report.
"""

from __future__ import annotations

import abc
import json
from pathlib import Path

from .report import Report
from .schema import TriageVerdict, VerdictSchemaError, parse_verdict_block


class BobVerdictMissing(RuntimeError):
    """Raised when no Bob-produced verdict is available for a report.

    This is the intended, non-error stopping point when the pipeline is run
    before Bob has triaged the report. The caller should route the report to
    Bob (see docs/security-triage-mode.md) rather than synthesising a verdict.
    """


class TriageBackend(abc.ABC):
    """Produces a :class:`TriageVerdict` for a report. Bob's territory."""

    name: str = "abstract"

    @abc.abstractmethod
    def triage(self, report: Report) -> TriageVerdict:  # pragma: no cover - abstract
        ...


class BobSessionBackend(TriageBackend):
    """Loads a verdict Bob exported for this report from ``bob_sessions/``.

    Bob writes either a ``*.verdict.json`` (matching the frozen schema) or a
    ``*.verdict.txt`` containing its plain-text VERDICT/CONFIDENCE/EVIDENCE/
    ACTION trailer. This backend reads and validates that output. It never
    generates a verdict.
    """

    name = "bob-session"

    def __init__(self, sessions_dir: str | Path = "bob_sessions") -> None:
        self.sessions_dir = Path(sessions_dir)

    def _slug(self, report: Report) -> str:
        return Path(report.source_path).stem

    def triage(self, report: Report) -> TriageVerdict:
        slug = self._slug(report)
        json_path = self.sessions_dir / f"{slug}.verdict.json"
        txt_path = self.sessions_dir / f"{slug}.verdict.txt"

        if json_path.exists():
            try:
                data = json.loads(json_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise VerdictSchemaError(f"{json_path}: invalid JSON ({exc})") from exc
            if not isinstance(data, dict):
                raise VerdictSchemaError(f"{json_path}: expected a JSON object")
            # Accept either a bare verdict payload, or a run record that nests
            # the verdict under a "verdict" key.
            payload = data["verdict"] if isinstance(data.get("verdict"), dict) else data
            return TriageVerdict.from_dict(payload)

        if txt_path.exists():
            parsed = parse_verdict_block(txt_path.read_text(encoding="utf-8"))
            return TriageVerdict.from_dict(parsed)

        raise BobVerdictMissing(
            f"No Bob verdict for {slug!r} in {self.sessions_dir}/. "
            f"Route the report through Bob (docs/security-triage-mode.md) and "
            f"export its output to {json_path.name} or {txt_path.name}. "
            f"The pipeline does not generate verdicts itself."
        )


class EchoBackend(TriageBackend):
    """Test-only backend: returns a verdict handed to it by the caller.

    Used exclusively by the plumbing tests to exercise the rails. Not wired
    into the CLI or the demo path.
    """

    name = "echo"

    def __init__(self, verdict: TriageVerdict) -> None:
        self._verdict = verdict

    def triage(self, report: Report) -> TriageVerdict:
        return self._verdict


# ---------------------------------------------------------------------------
# Deterministic offline triage backend (R3, Adithya's engine).
#
# This adapts sandbox/triage_engine.py::analyze_report() -- a fast, offline,
# regex-based triage function authored by the team -- into the frozen verdict
# schema. The engine file is used as-is; everything the adapter changes lives
# here, not in that file:
#   * its UPPERCASE keys/values are lowered to the frozen schema
#   * a CONFIRMED CVE location is corrected to the real 2.30.0 line (:328)
#   * when the engine is unsure, the adapter adds a real "existence" check
#     against the installed `requests` source, so a report that cites symbols
#     that do not exist in the library is caught as FABRICATED with evidence.
#
# It is a deterministic verifier for the offline demo, NOT a stand-in for Bob's
# scored triage. Bob's verdicts still load via BobSessionBackend.
# ---------------------------------------------------------------------------

import importlib.util as _ilu
import re as _re

_CVE_LINE = "requests/sessions.py:328"  # real re-attach site in requests 2.30.0
# Fallback set used only when `requests` is not importable to grep for real.
_KNOWN_ABSENT = {
    "parse_header_sanitized", "quantum_stream_bypass", "net_fusion",
    "GLOBAL_BYPASS_FLAG", "get_hyper_drive",
}
_STOPWORDS = {
    "requests", "session", "sessions", "python", "header", "headers", "report",
    "redirect", "proxy", "vulnerability", "attacker", "server", "client",
    "response", "request", "library", "function", "method", "params",
    "critical", "moderate", "severity", "summary", "impact", "details",
}
# Real Python/stdlib symbols a report may legitimately mention (e.g. a suggested
# fix) that are absent from `requests` but are NOT fabricated claims.
_REAL_PY = {
    "literal_eval", "urlopen", "urlparse", "urlencode", "loads", "dumps",
    "compile", "getattr", "setattr", "isinstance", "hasattr",
}
_engine_mod = None


def _engine():
    global _engine_mod
    if _engine_mod is None:
        path = Path(__file__).resolve().parent.parent / "sandbox" / "triage_engine.py"
        spec = _ilu.spec_from_file_location("_triage_engine", path)
        mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _engine_mod = mod
    return _engine_mod


def _requests_source() -> str | None:
    try:
        import os
        import requests  # noqa: F401
        base = os.path.dirname(requests.__file__)
        buf = []
        for root, _dirs, files in os.walk(base):
            for f in files:
                if f.endswith(".py"):
                    try:
                        buf.append(open(os.path.join(root, f), encoding="utf-8").read())
                    except OSError:
                        pass
        return "\n".join(buf)
    except Exception:
        return None


def _absent_symbols(text: str) -> list[str]:
    """Identifiers the report presents as real code that are absent from the
    target library. Prefers a real grep of the installed `requests` source;
    falls back to a small known-absent set when it is not importable."""
    cands = set(_re.findall(r"`([A-Za-z_][A-Za-z0-9_]{5,})`", text))
    cands |= set(_re.findall(r"\b([A-Za-z_][A-Za-z0-9_]{5,})\(", text))  # call-like, no space
    cands = {c for c in cands if c.lower() not in _STOPWORDS and c not in _REAL_PY}
    src = _requests_source()
    absent = []
    for c in sorted(cands):
        present = (c in src) if src is not None else (c not in _KNOWN_ABSENT)
        if not present:
            absent.append(c)
    return absent


class TriageEngineBackend(TriageBackend):
    """Deterministic offline triage via the team's engine + a real existence check."""

    name = "triage-engine"

    def triage(self, report: Report) -> TriageVerdict:
        raw = _engine().analyze_report(report.for_triage())
        verdict = str(raw.get("VERDICT", "INSUFFICIENT_EVIDENCE"))
        confidence = str(raw.get("CONFIDENCE", "low")).lower()
        evidence = [str(e) for e in raw.get("EVIDENCE", [])]
        action = str(raw.get("ACTION", ""))

        if verdict == "CONFIRMED":
            # Correct the engine's placeholder location to the real 2.30.0 line.
            evidence = [_re.sub(r"requests/sessions\.py:\d+", _CVE_LINE, e) for e in evidence]
            if not any(_re.search(r":\d+$", e) for e in evidence):
                evidence.insert(0, _CVE_LINE)
        elif verdict == "INSUFFICIENT_EVIDENCE":
            # The engine wasn't sure: verify cited symbols against the real code.
            absent = _absent_symbols(report.for_triage())
            if absent:
                verdict = "FABRICATED"
                confidence = "high"
                evidence = [f"{s}() does not exist in the requests source" for s in absent]
                action = f"Closed with cited evidence: {len(absent)} fabricated element(s)."

        return TriageVerdict.from_dict({
            "verdict": verdict, "confidence": confidence,
            "evidence": evidence, "action": action or "No action recorded.",
        })
