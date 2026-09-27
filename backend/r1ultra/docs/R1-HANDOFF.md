# R1 Handoff — PatchWarden R1 Ultra v3

R1 supplies the disposable, offline reproduction environment for the PatchWarden pipeline.

## R1 owner

- Navinraj

## Target

- CVE: `CVE-2023-32681`
- Package: `requests`
- Vulnerable baseline: `2.30.0`

## Reproduction boundary

The canonical reproduction is fully local:

```text
local HTTP origin
      ↓
allow-listed local proxy
      ↓
cross-host redirect
      ↓
local HTTPS destination
```

The sandbox uses runtime-generated synthetic credentials, runtime-allocated ports, and a runtime-generated local TLS certificate.

No real credentials or external target are used.

## R1 → R2 contract

R2 consumes the machine-readable `r1.v2` result rather than reaching into the sandbox implementation.

The canonical evidence directories are:

```text
artifacts-vulnerable/
artifacts-fixed/
```

Each contains:

```text
r1-result.json
r1-report.md
evidence-manifest.sha256.json
```

Produced by `scripts/run_full_validation.py` (full offline Docker build +
RED/GREEN pytest + matrix + verify, recommended) or `scripts/run_matrix.py`
directly if the images are already built. Verified by
`scripts/verify_artifacts.py`. Host mapping for `origin.local` /
`destination.local` is supplied at `docker run` time via `--add-host`, not
baked into the image — see README.md.

## Security lifecycle

### Vulnerable baseline

`requests==2.30.0`

Expected state:

```text
CONFIRMED_VULNERABLE
Proxy-Authorization present at destination
runtime credential fingerprint matches
```

The security-invariant pytest is intentionally RED on this baseline.

### Fixed comparison

The fixed environment uses the patched Requests version actually installed in that environment.

Expected state:

```text
FIXED
Proxy-Authorization absent at destination
no observed credential fingerprint
```

The same security-invariant pytest is GREEN.

## Failure semantics

`UNEXPECTED_FAILURE` means that the infrastructure/test run did not establish a trustworthy security result.

It must never be interpreted as either vulnerable or fixed.

## Evidence integrity

R1 produces:

- machine-readable `r1-result.json`
- human-readable `r1-report.md`
- SHA-256 `evidence-manifest.sha256.json`

The verifier checks the actual files and refuses inconsistent or missing evidence.

## Offline rule

The reproduction does not depend on OSV, NVD, the public internet, or live external hosts.

`python scripts/fetch_live_metadata.py` is optional metadata collection only.

## R2 handoff

R2 may consume:

1. `r1-result.json`
2. `r1-report.md`
3. the SHA-256 manifest
4. the R1 v2 contract

R2 should not depend on internal sandbox implementation details.
