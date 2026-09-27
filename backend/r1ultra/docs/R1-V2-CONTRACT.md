# R1 → R2 Integration Contract: `r1.v2`

## Required artifact set
- `r1-result.json`
- `r1-report.md`
- `evidence-manifest.sha256.json`
- optional `live-cve-metadata.json`

## Status semantics
- `CONFIRMED_VULNERABLE`: runtime Requests traffic caused the runtime-generated proxy credential to be observed at the redirected HTTPS destination.
- `FIXED`: the identical flow completed successfully and the destination did not receive `Proxy-Authorization`.
- `UNEXPECTED_FAILURE`: an infrastructure, health, dependency, TLS, execution, or invariant condition prevented a trustworthy result.

R2 MUST NOT convert `UNEXPECTED_FAILURE` into a security verdict.

## Evidence integrity
Every run has a random `run_id`. Secrets are never persisted; only SHA-256 fingerprints are emitted. The manifest hashes generated evidence files. R2 should verify the manifest before consuming the result. `scripts/verify_artifacts.py` additionally rejects stale/unexpected files in an artifact directory and requires the vulnerable and fixed runs to carry different `run_id`s.

## Offline boundary
Reproduction does not contact OSV, NVD, GitHub, or other Internet services. Live metadata is a separate optional operation. The host mapping for `origin.local`/`destination.local` is supplied at `docker run` time via `--add-host` (see README.md); the image itself does not modify `/etc/hosts`.
