"""CLI for the PatchWarden rails.

    python -m pipeline run fixtures/*.md --export            # offline engine (default)
    python -m pipeline run fixtures/*.md --backend bob       # use Bob's exported verdicts
    python -m pipeline show fixtures/report-002-slop.md      # ingestion only, no triage

``run`` uses the offline deterministic triage engine by default
(--backend engine), so it works out of the box. With --backend bob it instead
loads Bob's exported verdicts (bob_sessions/<slug>.verdict.json or .txt) and
never invents one -- route the report through Bob first
(docs/security-triage-mode.md).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .backends import BobSessionBackend, BobVerdictMissing, TriageEngineBackend
from .schema import VerdictSchemaError
from .export import export_run, rebuild_ui_index
from .report import load_report
from .runner import PatchWardenPipeline


def _cmd_show(args: argparse.Namespace) -> int:
    for path in args.reports:
        report = load_report(path)
        print(f"# {path}")
        print(f"  title      : {report.title}")
        print(f"  severity   : {report.metadata.get('severity', '-')}")
        print(f"  component  : {report.metadata.get('affected_component', '-')}")
        print(f"  references : {', '.join(report.references) or '-'}")
        print(f"  team notes : {'present (withheld from Bob)' if report.team_notes else 'none'}")
        print()
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    backend = (TriageEngineBackend() if args.backend == "engine"
               else BobSessionBackend(args.sessions_dir))
    pipeline = PatchWardenPipeline(backend, reproduce=not args.no_reproduce)
    exit_code = 0
    for path in args.reports:
        report = load_report(path)
        print(f"# {path}  ({report.title})")
        try:
            record = pipeline.run(report)
        except BobVerdictMissing as exc:
            print(f"  PENDING BOB: {exc}")
            print()
            exit_code = 2
            continue
        except VerdictSchemaError as exc:
            slug = path.stem
            print(f"  TEMPLATE NOT FILLED: {args.sessions_dir}/{slug}.verdict.txt "
                  f"still has placeholders. Paste Bob's verdict in ({exc}).")
            print()
            exit_code = 2
            continue
        v = record.verdict
        print(f"  VERDICT   : {v['verdict']}  (confidence: {v['confidence']})")
        print(f"  EVIDENCE  : {len(v['evidence'])} item(s)")
        for e in v["evidence"]:
            print(f"              - {e}")
        print(f"  ACTION    : {v['action']}")
        rep = record.reproduction
        if rep["ran"]:
            status = "reproduced" if rep["reproduced"] else "NOT reproduced"
            print(f"  REPRODUCE : {status} -- {rep['detail']}")
        if args.export:
            out = export_run(record, args.sessions_dir)
            print(f"  exported  : {out}")
        print()
    if args.export:
        ui = rebuild_ui_index(args.sessions_dir)
        print(f"UI index rebuilt: {ui}")
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pipeline", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_show = sub.add_parser("show", help="ingest a report and print it (no triage)")
    p_show.add_argument("reports", nargs="+", type=Path)
    p_show.set_defaults(func=_cmd_show)

    p_run = sub.add_parser("run", help="run reports through the rails using Bob verdicts")
    p_run.add_argument("reports", nargs="+", type=Path)
    p_run.add_argument("--backend", choices=["engine", "bob"], default="engine",
                       help="engine: offline deterministic triage (default); bob: load Bob's exported verdicts")
    p_run.add_argument("--sessions-dir", default="bob_sessions", type=Path)
    p_run.add_argument("--export", action="store_true", help="write run records + UI index")
    p_run.add_argument("--no-reproduce", action="store_true", help="skip the sandbox rig")
    p_run.set_defaults(func=_cmd_run)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
