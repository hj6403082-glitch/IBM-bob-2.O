from __future__ import annotations

"""
Run the canonical R1 reproduction in isolated Docker environments.

Usage:
  python scripts/run_matrix.py --vulnerable-image patchwarden-r1 \
      --fixed-image patchwarden-r1-fixed

The runner does not infer security state from a version string. Each image must
execute the real R1 engine and write its runtime evidence to a separate host
directory. The final transition is checked from those actual result files.
"""

import argparse
import json
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_container(image: str, output_dir: Path) -> None:
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)

    command = [
        "docker", "run", "--rm",
        "--network", "none",
        "--add-host", "origin.local:127.0.0.1",
        "--add-host", "destination.local:127.0.0.1",
        "-e", "R1_ARTIFACT_DIR=/patchwarden/artifacts",
        "-v", f"{output_dir.resolve()}:/patchwarden/artifacts",
        image,
    ]
    completed = subprocess.run(command, cwd=ROOT)
    if completed.returncode not in (0, 2):
        raise SystemExit(
            f"container failed unexpectedly for {image!r}: exit {completed.returncode}"
        )


def load_result(path: Path) -> dict:
    result_path = path / "r1-result.json"
    if not result_path.is_file():
        raise SystemExit(f"missing runtime result: {result_path}")
    return json.loads(result_path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vulnerable-image", default="patchwarden-r1")
    parser.add_argument("--fixed-image", default="patchwarden-r1-fixed")
    parser.add_argument("--vulnerable-output", default="artifacts-vulnerable")
    parser.add_argument("--fixed-output", default="artifacts-fixed")
    args = parser.parse_args()

    vulnerable_dir = ROOT / args.vulnerable_output
    fixed_dir = ROOT / args.fixed_output

    run_container(args.vulnerable_image, vulnerable_dir)
    run_container(args.fixed_image, fixed_dir)

    vulnerable = load_result(vulnerable_dir)
    fixed = load_result(fixed_dir)

    if vulnerable.get("status") != "CONFIRMED_VULNERABLE":
        raise SystemExit(
            f"vulnerable image did not establish CONFIRMED_VULNERABLE: "
            f"{vulnerable.get('status')!r}"
        )
    if fixed.get("status") != "FIXED":
        raise SystemExit(
            f"fixed image did not establish FIXED: {fixed.get('status')!r}"
        )

    vo = vulnerable["observation"]
    fo = fixed["observation"]

    if vo.get("proxy_authorization_present") is not True:
        raise SystemExit("vulnerable evidence does not show destination credential observation")
    if fo.get("proxy_authorization_present") is not False:
        raise SystemExit("fixed evidence still shows destination credential observation")

    print("R1 MATRIX: VERIFIED")
    print(f"  vulnerable Requests: {vulnerable['target']['observed_version']}")
    print(f"  vulnerable status: {vulnerable['status']}")
    print(f"  fixed Requests: {fixed['target']['observed_version']}")
    print(f"  fixed status: {fixed['status']}")
    print("  security transition: credential reached destination → did not reach destination")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
