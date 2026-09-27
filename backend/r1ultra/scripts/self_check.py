from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

required_files = [
    "Dockerfile",
    "Dockerfile.fixed",
    "REQUIREMENTS.txt",
    "r1/engine.py",
    "r1/runner.py",
    "sandbox/rig.py",
    "schemas/r1.v2.schema.json",
    "docs/R1-V2-CONTRACT.md",
    "docs/R1-HANDOFF.md",
    "scripts/verify_artifacts.py",
    "scripts/run_full_validation.py",
        "scripts/live_preflight.py",
        "docs/LIVE-DATA-POLICY.md",
]

for relative in required_files:
    path = ROOT / relative
    assert path.is_file(), f"missing required file: {relative}"

dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
assert "/etc/hosts" not in dockerfile, "Dockerfile must not modify /etc/hosts during build"

requirements = (ROOT / "REQUIREMENTS.txt").read_text(encoding="utf-8")
assert "requests==2.30.0" in requirements, "vulnerable Requests pin missing"

schema = json.loads((ROOT / "schemas/r1.v2.schema.json").read_text(encoding="utf-8"))
assert schema["properties"]["schema"]["const"] == "r1.v2"
assert schema["properties"]["status"]["enum"] == [
    "CONFIRMED_VULNERABLE",
    "FIXED",
    "UNEXPECTED_FAILURE",
]
target_required = set(schema["properties"]["target"]["required"])
assert target_required == {
    "cve_id",
    "package",
    "expected_vulnerable_version",
    "observed_version",
}

handoff = (ROOT / "docs/R1-HANDOFF.md").read_text(encoding="utf-8")
assert "R1 Ultra v3" in handoff
assert "artifacts-vulnerable/" in handoff
assert "artifacts-fixed/" in handoff

ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
assert "__pycache__/" in ignore
assert "artifacts-vulnerable/" in ignore
assert "artifacts-fixed/" in ignore

dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
assert "artifacts-vulnerable/" in dockerignore
assert "artifacts-fixed/" in dockerignore

print("R1 project self-check: OK")
