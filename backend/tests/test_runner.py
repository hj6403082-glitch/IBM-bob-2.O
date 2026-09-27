"""Plumbing tests for the pipeline runner, backends and export. Not a security
test -- verdicts here are fixtures supplied to the rails, not judgements about
real reports."""

import json
from pathlib import Path

import pytest

from pipeline import (
    BobSessionBackend,
    BobVerdictMissing,
    Confidence,
    EchoBackend,
    PatchWardenPipeline,
    TriageVerdict,
    Verdict,
    export_run,
    load_report,
    rebuild_ui_index,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _verdict(kind: Verdict, evidence=None) -> TriageVerdict:
    return TriageVerdict(
        verdict=kind,
        confidence=Confidence.HIGH,
        evidence=evidence or (["requests/sessions.py:319"] if kind == Verdict.CONFIRMED else []),
        action="test",
    )


def test_non_confirmed_does_not_reproduce():
    backend = EchoBackend(_verdict(Verdict.FABRICATED, evidence=["nope"]))
    record = PatchWardenPipeline(backend).run(FIXTURES / "report-002-slop.md")
    assert record.verdict["verdict"] == "FABRICATED"
    assert record.reproduction["ran"] is False


def test_confirmed_triggers_reproduction():
    backend = EchoBackend(_verdict(Verdict.CONFIRMED))
    record = PatchWardenPipeline(backend, reproduce=True).run(
        FIXTURES / "report-001-real.md"
    )
    # The rails must *attempt* the sandbox rig on CONFIRMED. Whether it
    # reproduces depends on the installed requests version and openssl; the
    # wiring is what this test asserts.
    rep = record.reproduction
    assert rep["ran"] is True or "could not run" in rep["detail"] or "not found" in rep["detail"]


def test_reproduce_flag_off_skips_rig():
    backend = EchoBackend(_verdict(Verdict.CONFIRMED))
    record = PatchWardenPipeline(backend, reproduce=False).run(
        FIXTURES / "report-001-real.md"
    )
    assert record.reproduction["ran"] is False


def test_bob_backend_missing_verdict_raises(tmp_path):
    backend = BobSessionBackend(sessions_dir=tmp_path)
    with pytest.raises(BobVerdictMissing, match="does not generate verdicts"):
        PatchWardenPipeline(backend).run(FIXTURES / "report-001-real.md")


def test_bob_backend_loads_exported_json(tmp_path):
    report = load_report(FIXTURES / "report-001-real.md")
    slug = Path(report.source_path).stem
    payload = {
        "verdict": "CONFIRMED",
        "confidence": "high",
        "evidence": ["requests/sessions.py:319"],
        "action": "reproduced; patch drafted",
    }
    (tmp_path / f"{slug}.verdict.json").write_text(json.dumps(payload))
    backend = BobSessionBackend(sessions_dir=tmp_path)
    record = PatchWardenPipeline(backend, reproduce=False).run(report)
    assert record.verdict["verdict"] == "CONFIRMED"
    assert record.triage_backend == "bob-session"


def test_bob_backend_loads_nested_record_json(tmp_path):
    # A file that nests the verdict under a "verdict" key (run-record shape)
    # must load the same as a bare verdict payload.
    report = load_report(FIXTURES / "report-001-real.md")
    slug = Path(report.source_path).stem
    record = {
        "report_title": "whatever",
        "verdict": {
            "verdict": "CONFIRMED",
            "confidence": "high",
            "evidence": ["requests/sessions.py:319"],
            "action": "reproduced",
        },
    }
    (tmp_path / f"{slug}.verdict.json").write_text(json.dumps(record))
    backend = BobSessionBackend(sessions_dir=tmp_path)
    got = PatchWardenPipeline(backend, reproduce=False).run(report)
    assert got.verdict["verdict"] == "CONFIRMED"


def test_bob_backend_rejects_bad_json(tmp_path):
    from pipeline import VerdictSchemaError
    report = load_report(FIXTURES / "report-001-real.md")
    slug = Path(report.source_path).stem
    (tmp_path / f"{slug}.verdict.json").write_text("{ not valid json ")
    backend = BobSessionBackend(sessions_dir=tmp_path)
    with pytest.raises(VerdictSchemaError, match="invalid JSON"):
        PatchWardenPipeline(backend, reproduce=False).run(report)


def test_bob_backend_loads_text_trailer(tmp_path):
    report = load_report(FIXTURES / "report-002-slop.md")
    slug = Path(report.source_path).stem
    (tmp_path / f"{slug}.verdict.txt").write_text(
        "VERDICT: FABRICATED\n"
        "CONFIDENCE: high\n"
        "EVIDENCE:\n  - parse_header_sanitized() does not exist\n"
        "ACTION: closed with evidence\n"
    )
    backend = BobSessionBackend(sessions_dir=tmp_path)
    record = PatchWardenPipeline(backend, reproduce=False).run(report)
    assert record.verdict["verdict"] == "FABRICATED"


def test_export_and_ui_index_roundtrip(tmp_path):
    backend = EchoBackend(_verdict(Verdict.NOT_A_VULNERABILITY, evidence=["intended"]))
    record = PatchWardenPipeline(backend, reproduce=False).run(
        FIXTURES / "report-002-slop.md"
    )
    out = export_run(record, sessions_dir=tmp_path)
    assert out.exists()
    ui_data = tmp_path / "runs.json"
    rebuild_ui_index(sessions_dir=tmp_path, ui_data_path=ui_data)
    data = json.loads(ui_data.read_text())
    assert len(data["runs"]) == 1
    assert data["runs"][0]["verdict"]["verdict"] == "NOT_A_VULNERABILITY"
