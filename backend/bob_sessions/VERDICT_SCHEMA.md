# Verdict export schema

How Bob hands a verdict to the pipeline rails. The rails **read** these files;
they never write a verdict (CLAUDE.md division of labour).

For each triaged report `fixtures/<slug>.md`, Bob exports its verdict here as
either of:

- `<slug>.verdict.json` — the frozen schema below, **or**
- `<slug>.verdict.txt` — Bob's plain-text trailer (the `VERDICT:` / `CONFIDENCE:` /
  `EVIDENCE:` / `ACTION:` block from `docs/security-triage-mode.md`).

The pipeline validates whichever it finds (`pipeline/schema.py`).

## Frozen JSON shape

```json
{
  "verdict": "CONFIRMED",
  "confidence": "high",
  "evidence": ["requests/sessions.py:319"],
  "action": "reproduced with failing test; patch drafted for maintainer review",
  "detail": "optional free-form root-cause notes"
}
```

| Field | Type | Rules |
|---|---|---|
| `verdict` | string | One of `CONFIRMED`, `INSUFFICIENT_EVIDENCE`, `NOT_A_VULNERABILITY`, `FABRICATED`. |
| `confidence` | string | One of `high`, `medium`, `low`. |
| `evidence` | list of string | Each supporting point. Location citations must be `file:line` (or `file:line-line`). `CONFIRMED` requires at least one entry. `FABRICATED` typically cites what is *absent*. |
| `action` | string | What Bob did, or what the reporter must supply. Non-empty. |
| `detail` | string | Optional. Root-cause narrative, notes for the maintainer. |

## Run records

After the pipeline runs a report it writes `<slug>.run.json` here — the verdict
above plus the offline reproduction result and report metadata. That is the
file the dashboard aggregates (`python -m pipeline run … --export` rebuilds
`ui/runs.json`). Run records are generated artefacts.

## What still belongs in this directory (judging requirement)

See `README.md`: exported Bob task-session reports and Bobcoin consumption
screenshots, named `NN-short-description.md`. The `.verdict.*` / `.run.json`
files are the machine-readable companions to those human-readable exports.
