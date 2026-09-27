# PatchWarden R1 Ultra v3 — Sandbox & Reproduction

R1 is an evidence-producing, offline reproduction boundary for CVE-2023-32681 in Requests.
The canonical engine performs real runtime traffic:

`origin.local → local allow-listed proxy → destination.local`

The destination records the actual request headers. The security result is derived from that observation.

## R1 guarantees

- Exact vulnerable fixture dependency: `requests==2.30.0`.
- Runtime-generated synthetic proxy credentials; no real secrets.
- Runtime-allocated ports.
- Runtime-generated local TLS certificate.
- Origin/proxy/destination health gates before reproduction.
- Reproduction works with Docker `--network none`.
- No Internet dependency for the reproduction path.
- Result is derived from destination observation, never from a hardcoded verdict.
- `UNEXPECTED_FAILURE` is distinct from a security result.
- Non-root container execution.
- Versioned R1→R2 `r1.v2` contract and JSON schema.
- SHA-256 evidence manifest.
- Optional live OSV/NVD metadata is isolated from reproduction.
- Artifact verification compares the actual vulnerable and fixed evidence directories.

## One-shot validation (recommended for demo dry-runs)

```bash
python scripts/run_full_validation.py --runs 3
```

This builds both images (`Dockerfile`, then `Dockerfile.fixed` on top of it),
runs the security-invariant pytest in each (RED on vulnerable, GREEN on
fixed), runs the vulnerable/fixed matrix into `artifacts-vulnerable/` and
`artifacts-fixed/`, and runs `scripts/verify_artifacts.py` — repeated
`--runs` times. This is the command that satisfies the "three clean
consecutive runs" stability gate before recording the demo video; the
individual steps below exist for debugging a failure it reports.

## Runtime host mapping

Docker image builds do not modify `/etc/hosts`.

Provide the two local names at runtime:

```powershell
docker run --rm --network none `
  --add-host origin.local:127.0.0.1 `
  --add-host destination.local:127.0.0.1 `
  patchwarden-r1
```

For host-side artifact persistence, mount an output directory and set `R1_ARTIFACT_DIR`:

```powershell
docker run --rm --network none `
  --add-host origin.local:127.0.0.1 `
  --add-host destination.local:127.0.0.1 `
  -e R1_ARTIFACT_DIR=/patchwarden/artifacts `
  -v "${PWD}/artifacts-vulnerable:/patchwarden/artifacts" `
  patchwarden-r1
```

## Vulnerable baseline

The authoritative R1 baseline is `requests==2.30.0`.

Run the security-invariant test inside the vulnerable container:

```bash
python -m pytest -q
```

The test is intentionally expected to be **RED** on the vulnerable baseline. That failure is evidence that `Proxy-Authorization` reached the redirected HTTPS destination.

## Fixed comparison

`Dockerfile.fixed` builds from the R1 image and installs a patched Requests release for the comparison environment.

The same test must become **GREEN**, and:

```bash
python scripts/run_demo.py
```

must classify the runtime observation as `FIXED`.

R1 never declares a result solely from a version string.

## Evidence layout

The final R1 handoff expects:

```text
artifacts-vulnerable/
├── r1-result.json
├── r1-report.md
└── evidence-manifest.sha256.json

artifacts-fixed/
├── r1-result.json
├── r1-report.md
└── evidence-manifest.sha256.json
```

The verifier reads those actual files and validates:

- `r1.v2` structure
- runtime status
- health checks
- security observation
- runtime credential fingerprint relationship
- SHA-256 manifest integrity
- vulnerable → fixed transition

Run:

```powershell
python .\scripts\verify_artifacts.py
```

## Self-check

```powershell
python .\scripts\self_check.py
```

## Live metadata

```bash
python scripts/fetch_live_metadata.py
```

Live metadata can be unavailable. That never changes the offline reproduction result.

## R2 boundary

R2 consumes the machine-readable `r1.v2` result and evidence artifacts. R2 should not reach into the sandbox implementation to determine whether the vulnerability reproduced.

`UNEXPECTED_FAILURE` must never be converted into a security verdict.


## Live data and zero-fabrication rule

PatchWarden uses a strict two-plane design:

```text
LIVE EXTERNAL PLANE                         OFFLINE REPRODUCTION
OSV + NVD + PyPI                            Docker / network-none
       |                                             |
       v                                             v
current metadata + provenance                 actual runtime behavior
       |                                             |
       +-------------------+-------------------------+
                           v
                    auditable evidence
```

External facts are fetched at run time. The project does not manufacture current CVE/package data. Live metadata includes source URLs, retrieval timestamps, HTTP status and raw API responses. If a source is unavailable or disagrees with the requested target, the result is explicitly `UNAVAILABLE` or `MISMATCH`; no fake fallback is used.

Run the live preflight with:

```bash
python scripts/live_preflight.py --package requests --version 2.30.0 --cve CVE-2023-32681
```

The security reproduction remains offline and does not depend on live APIs. The target version is a fixed experimental input; the observed vulnerability state is determined by the actual sandbox execution.

See `docs/LIVE-DATA-POLICY.md` for the complete rule.

