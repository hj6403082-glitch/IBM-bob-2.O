"""Plumbing tests for report ingestion. Not a security test.

These assert the conveyor belt behaves: team notes are withheld from Bob,
labelled metadata and references are extracted, and report text is handled as
inert data (never executed).
"""

from pathlib import Path

from pipeline.report import load_report

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_real_report_metadata_and_refs():
    r = load_report(FIXTURES / "report-001-real.md")
    assert "Proxy credentials leak" in r.title
    assert "CVE-2023-32681" in r.references
    assert "CWE-200" in r.references


def test_team_notes_are_stripped_from_triage_text():
    r = load_report(FIXTURES / "report-001-real.md")
    # The demo checklist requires fixtures to be stripped of team notes before
    # they reach Bob. The loader enforces that.
    assert r.team_notes  # notes are captured for the team...
    assert "Ground truth" in r.team_notes
    assert "Ground truth" not in r.for_triage()  # ...but never handed to Bob
    assert "strip before demo" not in r.for_triage().lower()


def test_slop_report_payload_is_inert_text():
    r = load_report(FIXTURES / "report-002-slop.md")
    body = r.for_triage()
    # The slop report contains an eval()/__import__ payload as *text*. Loading
    # the report must never execute it; it is only ever returned as a string.
    assert "__import__('os').system('id')" in body  # present verbatim, as data
    assert "parse_header_sanitized" in body
    # team notes enumerating the four falsehoods are withheld from Bob
    assert "good negative test" not in body.lower()


def test_slop_report_references_include_unrelated_cve():
    r = load_report(FIXTURES / "report-002-slop.md")
    assert "CVE-2024-38472" in r.references
    assert "CWE-94" in r.references


def test_wrapped_metadata_values_are_joined():
    # The slop fixture wraps both the title and the component across two lines.
    # Extraction must join them rather than truncate at the first line.
    r = load_report(FIXTURES / "report-002-slop.md")
    assert r.title.endswith("requests")  # "...header parsing in `requests`"
    assert "parse_header_sanitized" in r.metadata["affected_component"]
    assert r.metadata["affected_component"].startswith("requests/utils.py")
