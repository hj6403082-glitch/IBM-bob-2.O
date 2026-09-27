# R1 Upgrade Notes

Implemented upgrades in this package:

- generated Python cache files removed
- artifact directories are recreated for every reproduction run
- Requests version classification is explicit for 2.30.0 and 2.31.0
- artifact verifier checks canonical files, stale files, hashes, versions, and distinct run IDs
- `.gitignore` and `.dockerignore` exclude generated artifacts and caches
- `scripts/run_full_validation.py` automates Docker build, RED/GREEN pytest proof, matrix verification, and artifact verification

Docker execution still needs to be performed on a Docker-enabled machine before claiming runtime validation.
