#!/usr/bin/env python3
"""Run a real-time metadata preflight without changing the offline test."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r1.live_metadata import fetch_live

p=argparse.ArgumentParser()
p.add_argument("--package", required=True)
p.add_argument("--version", required=True)
p.add_argument("--cve", required=True)
a=p.parse_args()
result=fetch_live(a.package, a.version, a.cve)
print(json.dumps(result, indent=2))
raise SystemExit(0 if result["status"] == "OK" else 3)
