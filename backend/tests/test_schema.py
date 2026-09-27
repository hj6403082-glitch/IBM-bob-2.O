"""Plumbing tests for the frozen verdict schema. Not a security test."""

import pytest

from pipeline.schema import (
    Confidence,
    TriageVerdict,
    Verdict,
    VerdictSchemaError,
    parse_verdict_block,
    validate_verdict,
)


def test_confirmed_verdict_roundtrips():
    v = TriageVerdict(
        verdict=Verdict.CONFIRMED,
        confidence=Confidence.HIGH,
        evidence=["requests/sessions.py:319"],
        action="reproduced with failing test",
    )
    again = TriageVerdict.from_dict(v.to_dict())
    assert again == v
    assert again.to_dict()["verdict"] == "CONFIRMED"


def test_missing_field_rejected():
    with pytest.raises(VerdictSchemaError, match="missing required field"):
        validate_verdict({"verdict": "CONFIRMED", "confidence": "high"})


def test_unknown_verdict_value_rejected():
    with pytest.raises(VerdictSchemaError, match="not one of"):
        validate_verdict(
            {"verdict": "MAYBE", "confidence": "high", "evidence": [], "action": "x"}
        )


def test_confirmed_requires_evidence():
    with pytest.raises(VerdictSchemaError, match="CONFIRMED verdict requires"):
        validate_verdict(
            {"verdict": "CONFIRMED", "confidence": "high", "evidence": [], "action": "x"}
        )


def test_fabricated_may_have_no_locations():
    # FABRICATED cites what is absent, so zero file:line entries is valid.
    validate_verdict(
        {
            "verdict": "FABRICATED",
            "confidence": "high",
            "evidence": ["parse_header_sanitized() does not exist"],
            "action": "closed with evidence",
        }
    )


def test_malformed_location_rejected():
    with pytest.raises(VerdictSchemaError, match="file:line"):
        validate_verdict(
            {
                "verdict": "CONFIRMED",
                "confidence": "low",
                "evidence": ["requests/sessions.py:not-a-line"],
                "action": "x",
            }
        )


def test_parse_bob_text_block():
    block = """
    Some preamble Bob printed.

    VERDICT: FABRICATED
    CONFIDENCE: high
    EVIDENCE:
      - parse_header_sanitized() does not exist in this repository
      - no eval() call in header handling
    ACTION: closed with evidence; no maintainer time spent
    """
    parsed = parse_verdict_block(block)
    assert parsed["verdict"] == "FABRICATED"
    assert parsed["confidence"] == "high"
    assert len(parsed["evidence"]) == 2
    v = TriageVerdict.from_dict(parsed)
    assert v.verdict == Verdict.FABRICATED
