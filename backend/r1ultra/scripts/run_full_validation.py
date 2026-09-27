from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOST_ARGS = [
    "--network", "none",
    "--add-host", "origin.local:127.0.0.1",
    "--add-host", "destination.local:127.0.0.1",
]


def run(label: str, command: list[str], expected: set[int] | None = None) -> None:
    print(f"\n=== {label} ===")
    print("$ " + " ".join(command))
    completed = subprocess.run(command, cwd=ROOT)
    allowed = expected if expected is not None else {0}
    if completed.returncode not in allowed:
        raise SystemExit(f"{label} failed with exit code {completed.returncode}; expected {sorted(allowed)}")


def pytest_in_container(image: str, expected_exit: int, label: str) -> None:
    run(
        label,
        ["docker", "run", "--rm", *HOST_ARGS, "--entrypoint", "python", image, "-m", "pytest", "-q"],
        {expected_exit},
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the complete PatchWarden R1 validation flow.")
    parser.add_argument("--vulnerable-image", default="patchwarden-r1")
    parser.add_argument("--fixed-image", default="patchwarden-r1-fixed")
    parser.add_argument("--runs", type=int, default=1)
    args = parser.parse_args()

    if args.runs < 1:
        raise SystemExit("--runs must be >= 1")

    run("Docker availability", ["docker", "version"])
    run("Build vulnerable image", ["docker", "build", "-t", args.vulnerable_image, "."])
    run(
        "Build fixed image",
        [
            "docker", "build",
            "-f", "Dockerfile.fixed",
            "--build-arg", f"BASE_IMAGE={args.vulnerable_image}:latest",
            "-t", args.fixed_image, ".",
        ],
    )

    for index in range(1, args.runs + 1):
        print(f"\n######## VALIDATION RUN {index}/{args.runs} ########")
        pytest_in_container(args.vulnerable_image, 1, "Vulnerable pytest — expected RED")
        pytest_in_container(args.fixed_image, 0, "Fixed pytest — expected GREEN")

        run(
            "R1 vulnerable/fixed matrix",
            [sys.executable, "scripts/run_matrix.py", "--vulnerable-image", args.vulnerable_image, "--fixed-image", args.fixed_image],
        )
        run("R1 artifact verification", [sys.executable, "scripts/verify_artifacts.py"])

    print(f"\nFULL R1 VALIDATION: PASS ({args.runs} run(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
