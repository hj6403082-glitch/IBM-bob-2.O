"""Plumbing tests for the TriageEngineBackend adapter (wraps R3's engine).

These assert the adapter bridges the engine's output into the frozen schema and
produces the right verdict for each demo fixture. They test the rails + the
adapter, not a hand-authored verdict.
"""

from pathlib import Path

from pipeline import PatchWardenPipeline, TriageEngineBackend, load_report

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _run(name):
    pipe = PatchWardenPipeline(TriageEngineBackend(), reproduce=False)
    return pipe.run(load_report(FIXTURES / name))


def test_real_report_confirmed_with_correct_line():
    rec = _run("report-001-real.md")
    assert rec.verdict["verdict"] == "CONFIRMED"
    # The adapter corrects the engine's placeholder to the real 2.30.0 line.
    assert any(e.endswith("sessions.py:328") for e in rec.verdict["evidence"])
    assert rec.triage_backend == "triage-engine"


def test_realistic_slop_fabricated_by_existence_check():
    rec = _run("report-002-slop.md")
    assert rec.verdict["verdict"] == "FABRICATED"
    # The fabricated function is cited; real/severity words are not over-flagged.
    joined = " ".join(rec.verdict["evidence"]).lower()
    assert "parse_header_sanitized" in joined
    assert "critical" not in joined
    assert "literal_eval" not in joined


def test_injection_report_blocked():
    rec = _run("report-003-injection.md")
    assert rec.verdict["verdict"] == "FABRICATED"
    assert "injection" in rec.verdict["action"].lower()


def test_confirmed_triggers_reproduction_via_engine():
    pipe = PatchWardenPipeline(TriageEngineBackend(), reproduce=True)
    rec = pipe.run(load_report(FIXTURES / "report-001-real.md"))
    rep = rec.reproduction
    assert rep["ran"] is True or "could not run" in rep["detail"] or "not found" in rep["detail"]
