# PatchWarden — Project Overview & Handoff

An AI security copilot for open-source maintainers, built for the IBM Bob 2.0
hackathon (team Devzippers). Given an inbound vulnerability report, PatchWarden
verifies it against the real code, rules on it with cited evidence, reproduces
genuine issues with a failing test (offline, sandboxed), and prepares a patch +
PR for a human to review. **It never merges.**

Target: `requests` 2.30.0, **CVE-2023-32681** — the `Proxy-Authorization`
header survives a cross-host redirect, leaking proxy credentials. Real root
cause: `requests/sessions.py:328` (`rebuild_proxies` re-attaches the header);
fixed upstream in 2.31.0 by a `not scheme.startswith("https")` guard.

Repo: https://github.com/krishiyswim23-swagger/IBM-Bob-2.O-2026
Working branch: `claude/awesome-hawking-kv99ta` · open PR: #1

## Division of labour (from CLAUDE.md)
- **IBM Bob** owns the security *judgement*: triage verdicts, root-cause,
  patch, regression test, and the upstream PR (scored hackathon requirement).
- **Claude / tooling** built the scaffolding, the sandbox + reproduction rig,
  the pipeline plumbing, the verdict dashboard/demo, and docs.

## Layout

```
CLAUDE.md                     scope rules for AI tooling in this repo
README.md                     project pitch
OVERVIEW.md                   this file
setup.sh                      one-command setup (venv + deps + tests + demo)
pytest.ini                    ignores r1ultra/ at repo root

fixtures/
  report-001-real.md          genuine CVE report (reporter voice, no fix given)
  report-002-slop.md          realistic AI-slop report (fabricated function)
  report-003-injection.md     prompt-injection report ("ignore previous…")

docs/
  security-triage-mode.md     Bob "Security Triage Officer" custom-mode text
  demo-script.md              4:30 run-of-show
  bob-run-pack.md             copy-paste steps to produce Bob's verdicts
  SETUP-IN-BOB.md             setting the project up inside the Bob IDE

sandbox/                      LITE reproduction rig (zero-setup default/fallback)
  rig.py                      two-server (origin+proxy / https dest) leak probe
  test_proxy_auth_leak.py     pytest: GREEN on 2.30.0, RED on patched
  triage_engine.py            R3 offline triage engine (Adithya) — regex + slop
  requirements.txt            requests==2.30.0, pytest
  conftest.py, README.md

r1ultra/                      CANONICAL reproduction (R1 Ultra v3, Navinraj)
  r1/engine.py                reproduce() → r1.v2 result; verdict from observation
  r1/evidence.py              JSON result, markdown report, SHA-256 manifest
  r1/runner.py                CLI: reproduce / live-metadata
  r1/live_metadata.py         optional, isolated OSV/NVD lookup
  sandbox/rig.py              LocalRig: origin.local → allow-listed proxy → TLS dest
  schemas/r1.v2.schema.json   the R1→R2 contract schema
  scripts/                    run_demo, run_matrix (Docker), verify_artifacts, self_check
  sample-evidence/            a committed, verified run (vulnerable + fixed)
  Dockerfile[.fixed], docs/, README.md, REQUIREMENTS.txt

pipeline/                     the rails around Bob
  report.py                   ingestion; treats report text as inert data
  schema.py                   frozen verdict schema + validator + trailer parser
  backends.py                 TriageBackend: TriageEngineBackend (default),
                              BobSessionBackend (loads Bob's verdicts), EchoBackend
  runner.py                   orchestrator; runs R1 rig (or lite) on CONFIRMED
  export.py                   writes bob_sessions/*.run.json and ui/runs.json
  __main__.py                 CLI: python -m pipeline show|run [--backend engine|bob]
  README.md

tests/                        plumbing tests (schema, ingestion, runner, engine, R1)
bob_sessions/                 Bob's exports + verdict templates + schema doc
ui/
  index.html                  live verdict console (search, filters, value band)
  demo.html                   self-contained static console build
  present.html                the living, narrated 4:30 demo (see below)
  narration/cover.mp3         uploaded human-voice clip for the intro
```

## How the pieces connect

```
report (fixtures/*.md)
  → pipeline.report.load_report()            ingest as inert data
  → TriageBackend.triage()                   verdict (engine default, or Bob)
  → pipeline.schema.validate_verdict()       frozen contract
  → if CONFIRMED: r1ultra reproduce()        real traffic + SHA-256 evidence
                  (falls back to sandbox/rig.py if R1 hosts unset)
  → RunRecord → bob_sessions/*.run.json → ui/runs.json → console/demo
```

Verdicts on the three fixtures: **001 CONFIRMED** (reproduced offline, evidence
manifest verified), **002 FABRICATED** (cited function absent from requests),
**003 FABRICATED** (prompt injection blocked at the guard).

## The demo (ui/present.html)
A single-file, offline, hash-routed presentation with 7 "pages" (Intro → How →
Slop → Real → Why → Close → Console) and a **Demo Mode** that auto-plays on the
4:30 timeline. Living touches: an animated "Bob core" reactor, subagents that
stream reasoning with flow-wire pulses, count-up telemetry, verdict shockwaves,
a RED→patch→GREEN terminal, the R1 tamper-evident receipt on the CONFIRMED
case, and Bob **narrates** (audio clip on the intro, natural TTS elsewhere,
with a voice picker). Hosted copy: a private claude.ai artifact.

## Run it
```
bash setup.sh                                   # venv + deps + 28 tests + demo run
python -m pipeline run fixtures/*.md --export   # offline engine triage + reproduction
python -m pytest -q                             # 28 passing
# open ui/present.html in a browser for the demo
```
R1 rig needs `origin.local`/`destination.local` mapped to 127.0.0.1 (else the
pipeline uses the lite rig).

## Status
- Done: sandbox + R1 reproduction (evidence-verified), pipeline, triage engine
  integration, fixtures, console + demo, setup + docs. 28 tests green.
- Pending (Bob's): fill `bob_sessions/*.verdict.txt` with Bob's real verdicts,
  Bob's patch + regression test + upstream PR, and the Bob session exports +
  Bobcoin screenshots.
