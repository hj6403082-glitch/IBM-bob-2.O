"""The PatchWarden pipeline rails.

Flow:  load report  ->  Bob triage (via backend)  ->  validate verdict  ->
       if CONFIRMED, run the offline sandbox reproduction rig  ->  RunRecord.

What the rails do NOT do (Bob's territory, CLAUDE.md division of labour):
decide the verdict, analyse root cause, author the patch, author the
regression test, or open the PR. Those appear in the record only as fields Bob
fills in and exports; the runner never creates them.

The reproduction step is Claude's (the sandbox rig, CLAUDE.md). It runs only to
*corroborate* a verdict Bob has already reached CONFIRMED -- it does not decide
anything.
"""

from __future__ import annotations

import datetime as _dt
import importlib.util
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .backends import BobVerdictMissing, TriageBackend
from .report import Report, load_report
from .schema import TriageVerdict, Verdict

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SANDBOX_DIR = _REPO_ROOT / "sandbox"


@dataclass
class ReproResult:
    ran: bool
    reproduced: bool | None = None
    detail: str = ""
    engine: str = "lite"          # "r1-ultra-v3" when R1's rig produced it
    run_id: str | None = None     # R1 run_id, when available


@dataclass
class RunRecord:
    """Everything one report produced, in the frozen shape the UI reads."""

    report_path: str
    report_title: str
    report_references: list[str]
    triage_backend: str
    verdict: dict[str, Any]  # TriageVerdict.to_dict()
    reproduction: dict[str, Any]  # ReproResult as dict
    created_at: str
    # Bob's Phase-5 artefacts, filled in by Bob's export (not by the runner).
    patch_ref: str | None = None
    pull_request_url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_R1_DIR = _REPO_ROOT / "r1ultra"


def _hosts_resolve() -> bool:
    """R1 addresses origin.local / destination.local; both must resolve."""
    import socket
    try:
        socket.gethostbyname("origin.local")
        socket.gethostbyname("destination.local")
        return True
    except OSError:
        return False


def _run_r1_probe() -> ReproResult | None:
    """Prefer R1 Ultra v3's evidence-producing rig. Returns None (→ fall back to
    the lite rig) when R1 isn't present, its hostnames aren't set up, or it
    can't establish a trustworthy result (UNEXPECTED_FAILURE)."""
    demo = _R1_DIR / "scripts" / "run_demo.py"
    if not demo.exists() or not _hosts_resolve():
        return None
    import json
    import os
    import subprocess
    import tempfile
    try:
        env = dict(os.environ, PYTHONPATH=str(_R1_DIR),
                   R1_ARTIFACT_DIR=tempfile.mkdtemp(prefix="r1-run-"))
        proc = subprocess.run([sys.executable, "scripts/run_demo.py"],
                              cwd=str(_R1_DIR), env=env, capture_output=True,
                              text=True, timeout=90)
        data = json.loads(proc.stdout)
    except Exception:  # pragma: no cover - environment/tooling issues
        return None
    status = data.get("status")
    run_id = data.get("run_id")
    if status == "CONFIRMED_VULNERABLE":
        return ReproResult(ran=True, reproduced=True, engine="r1-ultra-v3",
                           run_id=run_id,
                           detail="R1 CONFIRMED_VULNERABLE — credential observed at the "
                                  "redirected HTTPS destination; SHA-256 evidence manifest written")
    if status == "FIXED":
        return ReproResult(ran=True, reproduced=False, engine="r1-ultra-v3",
                           run_id=run_id, detail="R1 FIXED — destination did not receive Proxy-Authorization")
    return None  # UNEXPECTED_FAILURE → fall back to the lite rig


def _run_sandbox_probe() -> ReproResult:
    """Run the reproduction. Prefers R1 Ultra v3's rig (real runtime traffic +
    evidence manifest); falls back to the lite sandbox/rig.py when R1 is not
    available in this environment.
    """
    r1 = _run_r1_probe()
    if r1 is not None:
        return r1
    rig_path = _SANDBOX_DIR / "rig.py"
    if not rig_path.exists():
        return ReproResult(ran=False, detail="sandbox/rig.py not found")
    try:
        spec = importlib.util.spec_from_file_location("_patchwarden_rig", rig_path)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        result = module.run_probe()
    except Exception as exc:  # pragma: no cover - environment/tooling issues
        return ReproResult(ran=False, detail=f"rig could not run: {exc!r}")
    if result.errors:
        return ReproResult(
            ran=True, reproduced=False, detail=f"rig errors: {result.errors}"
        )
    detail = (
        f"requests {result.requests_version}: destination received "
        f"Proxy-Authorization={result.dest_proxy_auth!r}"
    )
    return ReproResult(ran=True, reproduced=result.leaked, detail=detail)


class PatchWardenPipeline:
    """Runs a report through the rails using a pluggable triage backend."""

    def __init__(self, backend: TriageBackend, *, reproduce: bool = True) -> None:
        self.backend = backend
        self.reproduce = reproduce

    def run(self, report: Report | str | Path) -> RunRecord:
        if not isinstance(report, Report):
            report = load_report(report)

        # Bob decides the verdict. The runner only asks and validates.
        verdict: TriageVerdict = self.backend.triage(report)

        repro = ReproResult(ran=False, detail="not run")
        if self.reproduce and verdict.verdict == Verdict.CONFIRMED:
            repro = _run_sandbox_probe()

        return RunRecord(
            report_path=report.source_path,
            report_title=report.title,
            report_references=report.references,
            triage_backend=self.backend.name,
            verdict=verdict.to_dict(),
            reproduction=asdict(repro),
            created_at=_dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        )


__all__ = [
    "PatchWardenPipeline",
    "RunRecord",
    "ReproResult",
    "BobVerdictMissing",
]
