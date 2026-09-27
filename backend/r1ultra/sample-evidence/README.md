# R1 sample evidence (committed snapshot)

A real, verified run of R1 Ultra v3 — proof the reproduction works end to end,
so reviewers can see it without running anything. Regenerate anytime with the
matrix below.

- `vulnerable/` — requests **2.30.0** → **CONFIRMED_VULNERABLE**
  (Proxy-Authorization reached the redirected HTTPS destination; credential
  fingerprint matched).
- `fixed/` — requests **2.31.0** → **FIXED** (destination did not receive it).

Each folder has the `r1.v2` result, the human-readable report, and a SHA-256
evidence manifest. `scripts/verify_artifacts.py` validates both runs and the
vulnerable→fixed security transition.

## Regenerate (no Docker)
Map the R1 hostnames first (`127.0.0.1 origin.local` / `destination.local`), then:
```
PYTHONPATH=. R1_ARTIFACT_DIR=./artifacts-vulnerable python scripts/run_demo.py   # in a requests==2.30.0 env
PYTHONPATH=. R1_ARTIFACT_DIR=./artifacts-fixed      python scripts/run_demo.py   # in a requests>=2.31.0 env
python scripts/verify_artifacts.py
```
(Or `scripts/run_matrix.py` with the two Docker images.)
