"""PatchWarden pipeline rails.

Claude Code owns this plumbing (ingestion, verdict schema/validation,
orchestration, export, UI). Bob owns the security judgement it plugs into:
triage verdicts, root-cause analysis, patch, regression test and PR.
See ../CLAUDE.md for the division of labour.
"""

from .backends import (
    BobSessionBackend,
    BobVerdictMissing,
    EchoBackend,
    TriageBackend,
    TriageEngineBackend,
)
from .export import export_run, rebuild_ui_index
from .report import Report, load_report
from .runner import PatchWardenPipeline, ReproResult, RunRecord
from .schema import (
    Confidence,
    TriageVerdict,
    Verdict,
    VerdictSchemaError,
    parse_verdict_block,
    validate_verdict,
)

__all__ = [
    "BobSessionBackend",
    "BobVerdictMissing",
    "EchoBackend",
    "TriageBackend",
    "TriageEngineBackend",
    "PatchWardenPipeline",
    "ReproResult",
    "RunRecord",
    "Report",
    "load_report",
    "Confidence",
    "TriageVerdict",
    "Verdict",
    "VerdictSchemaError",
    "parse_verdict_block",
    "validate_verdict",
    "export_run",
    "rebuild_ui_index",
]
