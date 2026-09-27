"""Integration check: the pipeline consumes R1 Ultra v3's rig when available.

R1 needs the origin.local / destination.local hostnames mapped to 127.0.0.1
(see r1ultra/README.md). When they aren't set up, the pipeline falls back to
the lite sandbox rig, so this test skips rather than fails.
"""

import shutil
import socket
from pathlib import Path

import pytest

from pipeline import Confidence, PatchWardenPipeline, TriageVerdict, Verdict
from pipeline.backends import EchoBackend

R1_DIR = Path(__file__).resolve().parent.parent / "r1ultra"
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _hosts_ok():
    try:
        socket.gethostbyname("origin.local")
        socket.gethostbyname("destination.local")
        return True
    except OSError:
        return False


@pytest.mark.skipif(not R1_DIR.exists(), reason="r1ultra subproject not present")
@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl required for R1 TLS cert")
@pytest.mark.skipif(not _hosts_ok(), reason="origin.local/destination.local not mapped to 127.0.0.1")
def test_pipeline_uses_r1_rig_and_reproduces():
    verdict = TriageVerdict(
        verdict=Verdict.CONFIRMED, confidence=Confidence.HIGH,
        evidence=["requests/sessions.py:328"], action="verify with R1",
    )
    rec = PatchWardenPipeline(EchoBackend(verdict), reproduce=True).run(
        FIXTURES / "report-001-real.md"
    )
    rep = rec.reproduction
    assert rep["ran"] is True
    # On the pinned vulnerable requests 2.30.0, R1 must report the leak.
    assert rep["engine"] == "r1-ultra-v3"
    assert rep["reproduced"] is True
    assert rep["run_id"]
