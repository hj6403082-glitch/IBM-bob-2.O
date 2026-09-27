# pipeline/ — PatchWarden rails

The orchestration that carries a report from ingestion to a rendered verdict.
This is Claude Code's lane: scaffolding, harness plumbing, export and UI. The
**security judgement plugs in here but is Bob's** — triage verdicts, root-cause
analysis, patch, regression test and PR (see `../CLAUDE.md`).

```
report fixture
    │  pipeline.report.load_report()      ← ingestion (inert data; strips team notes)
    ▼
TriageBackend.triage(report)             ← Bob's verdict (BobSessionBackend loads
    │                                        what Bob exported; never computed here)
    ▼
pipeline.schema.validate_verdict()       ← frozen contract check
    │
    ├─ if CONFIRMED → R1 Ultra v3 rig (r1ultra/, real traffic + r1.v2 evidence)
    │                 ↳ falls back to the lite sandbox/rig.py when R1's
    │                   origin.local/destination.local hosts aren't set up
    ▼
RunRecord → bob_sessions/<slug>.run.json → ui/runs.json → dashboard
```

## The Bob seam

`pipeline/backends.py` defines `TriageBackend`, with two production backends:

- **`TriageEngineBackend`** (default) — the deterministic **offline** engine
  (R3, `sandbox/triage_engine.py`): regex prompt-injection defense + a real
  existence check of cited symbols against the installed `requests` source.
  Great for a reliable live demo. It is a verifier the pipeline runs, **not** a
  stand-in for Bob's scored triage.
- **`BobSessionBackend`** — **loads** a verdict Bob exported to `bob_sessions/`
  (`<slug>.verdict.json` or `.verdict.txt`). If none exists it raises
  `BobVerdictMissing` and stops; it never synthesises a verdict.

`EchoBackend` exists only for the plumbing tests.

## Use

```bash
# ingest and print a report (no triage)
python -m pipeline show fixtures/report-001-real.md

# run reports using Bob's exported verdicts; reproduce CONFIRMED ones; export
python -m pipeline run fixtures/*.md --export
```

`run` exits non-zero with `PENDING BOB` for any report Bob has not yet triaged.

## What is NOT here (Bob's territory)

No verdict logic, no root-cause analysis, no patch authoring, no regression-test
authoring, no PR creation. Those are produced by Bob and exported to
`bob_sessions/`; the rails only validate, corroborate (via the sandbox rig),
record and display them.

## Modules

| Module | Role |
|---|---|
| `report.py` | Mechanical report loader. Treats report text as inert data (CLAUDE.md hard rule 5). |
| `schema.py` | Frozen verdict contract + validator + Bob-text-trailer parser. |
| `backends.py` | The Bob seam: `TriageBackend`, `BobSessionBackend`, `EchoBackend`. |
| `runner.py` | Orchestrator. Runs the sandbox rig on `CONFIRMED`. Builds `RunRecord`. |
| `export.py` | Writes run records to `bob_sessions/` and rebuilds `ui/runs.json`. |
| `__main__.py` | CLI (`python -m pipeline …`). |

Tests for these rails live in `../tests/` (plumbing only — the security
reproduction test is `../sandbox/test_proxy_auth_leak.py`).
