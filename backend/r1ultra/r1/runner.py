from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path

from r1.engine import reproduce
from r1.evidence import environment, write_json, write_manifest, write_report
from r1.live_metadata import fetch_live

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = Path(os.environ.get("R1_ARTIFACT_DIR", ROOT / "artifacts"))


def _prepare_artifact_dir() -> None:
    if ARTIFACTS.exists():
        if ARTIFACTS.is_file():
            raise RuntimeError(f"artifact path is a file: {ARTIFACTS}")
        shutil.rmtree(ARTIFACTS)
    ARTIFACTS.mkdir(parents=True, exist_ok=False)


def run_reproduction() -> int:
    _prepare_artifact_dir()
    result = reproduce()
    result["environment"] = environment()
    result["artifacts"] = {
        "result": "r1-result.json",
        "report": "r1-report.md",
        "manifest": "evidence-manifest.sha256.json",
    }

    write_json(ARTIFACTS / "r1-result.json", result)
    write_report(ARTIFACTS / "r1-report.md", result)
    write_manifest(ARTIFACTS, ARTIFACTS / "evidence-manifest.sha256.json")
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in ("CONFIRMED_VULNERABLE", "FIXED") else 2


def live_metadata() -> int:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    data = fetch_live("requests", "2.30.0", "CVE-2023-32681")
    write_json(ARTIFACTS / "live-cve-metadata.json", data)
    print(json.dumps(data, indent=2))
    return 0 if data["status"] == "OK" else 3


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["reproduce", "live-metadata"])
    args = parser.parse_args()
    return run_reproduction() if args.command == "reproduce" else live_metadata()


if __name__ == "__main__":
    raise SystemExit(main())
