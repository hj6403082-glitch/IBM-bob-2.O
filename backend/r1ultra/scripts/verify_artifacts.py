from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNS = {
    "vulnerable": ROOT / "artifacts-vulnerable",
    "fixed": ROOT / "artifacts-fixed",
}
VULNERABLE_VERSION = "2.30.0"
FIXED_VERSION = "2.31.0"
ALLOWED_STATUSES = {"CONFIRMED_VULNERABLE", "FIXED", "UNEXPECTED_FAILURE"}
REQUIRED_RESULT_KEYS = {
    "schema", "run_id", "generated_at", "status", "target",
    "environment", "health", "observation", "errors", "artifacts",
}
REQUIRED_TARGET_KEYS = {
    "cve_id", "package", "expected_vulnerable_version", "observed_version",
}
REQUIRED_OBSERVATION_KEYS = {
    "proxy_authorization_present",
    "expected_credential_fingerprint",
    "observed_credential_fingerprint",
    "credential_match",
}
EXPECTED_FILES = {"r1-result.json", "r1-report.md", "evidence-manifest.sha256.json"}
OPTIONAL_FILES = {"live-cve-metadata.json"}


def fail(message: str) -> None:
    raise SystemExit(f"R1 ARTIFACT VERIFICATION: FAILED\n{message}")


def load_json(path: Path) -> dict:
    if not path.is_file():
        fail(f"missing file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"invalid JSON: {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"expected JSON object: {path}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_run(label: str, directory: Path) -> dict:
    result_path = directory / "r1-result.json"
    report_path = directory / "r1-report.md"
    manifest_path = directory / "evidence-manifest.sha256.json"

    if not directory.is_dir():
        fail(f"{label}: missing artifact directory: {directory}")
    for required in (result_path, report_path, manifest_path):
        if not required.is_file():
            fail(f"{label}: missing required artifact: {required.name}")

    result = load_json(result_path)
    manifest = load_json(manifest_path)

    missing = REQUIRED_RESULT_KEYS - result.keys()
    if missing:
        fail(f"{label}: result missing keys: {sorted(missing)}")
    if result["schema"] != "r1.v2":
        fail(f"{label}: unexpected schema: {result['schema']!r}")
    if result["status"] not in ALLOWED_STATUSES:
        fail(f"{label}: unexpected status: {result['status']!r}")
    if not result["run_id"] or not result["generated_at"]:
        fail(f"{label}: run_id/generated_at must be populated")
    if result["errors"]:
        fail(f"{label}: runtime errors are present: {result['errors']}")

    target = result["target"]
    missing_target = REQUIRED_TARGET_KEYS - target.keys()
    if missing_target:
        fail(f"{label}: target missing keys: {sorted(missing_target)}")
    if target["package"] != "requests":
        fail(f"{label}: unexpected package: {target['package']!r}")
    if target["cve_id"] != "CVE-2023-32681":
        fail(f"{label}: unexpected CVE: {target['cve_id']!r}")
    if target["expected_vulnerable_version"] != VULNERABLE_VERSION:
        fail(f"{label}: unexpected vulnerable baseline")

    environment = result["environment"]
    if environment.get("requests_version") != target["observed_version"]:
        fail(f"{label}: environment Requests version does not match target observed_version")

    health = result["health"]
    for component in ("origin", "destination", "proxy"):
        if component not in health:
            fail(f"{label}: missing health component: {component}")
        if health[component].get("ok") is not True:
            fail(f"{label}: health check failed: {component}: {health[component]}")

    observation = result["observation"]
    missing_observation = REQUIRED_OBSERVATION_KEYS - observation.keys()
    if missing_observation:
        fail(f"{label}: observation missing keys: {sorted(missing_observation)}")

    manifest_files = manifest.get("files")
    if not isinstance(manifest_files, list) or not manifest_files:
        fail(f"{label}: manifest.files is not a non-empty list")

    seen = set()
    for item in manifest_files:
        relative = item.get("path")
        expected = item.get("sha256")
        if not isinstance(relative, str) or not relative or not isinstance(expected, str) or not expected:
            fail(f"{label}: malformed manifest entry: {item!r}")
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            fail(f"{label}: unsafe manifest path: {relative!r}")
        if relative in seen:
            fail(f"{label}: duplicate manifest path: {relative!r}")
        seen.add(relative)
        if relative == manifest_path.name:
            fail(f"{label}: manifest must not hash itself")
        path = directory / relative_path
        if not path.is_file():
            fail(f"{label}: manifest references missing file: {path}")
        actual = sha256_file(path)
        if actual != expected:
            fail(f"{label}: hash mismatch for {path}: expected {expected}, got {actual}")

    actual_files = {
        p.relative_to(directory).as_posix()
        for p in directory.rglob("*")
        if p.is_file()
    }
    allowed_files = EXPECTED_FILES | OPTIONAL_FILES
    unexpected = actual_files - allowed_files
    if unexpected:
        fail(f"{label}: unexpected/stale artifact files: {sorted(unexpected)}")
    missing_from_manifest = (EXPECTED_FILES - {manifest_path.name}) - seen
    if missing_from_manifest:
        fail(f"{label}: required artifacts missing from manifest: {sorted(missing_from_manifest)}")
    if not seen.issubset(allowed_files - {manifest_path.name}):
        fail(f"{label}: manifest contains unsupported artifact paths: {sorted(seen - allowed_files)}")

    artifact_paths = result["artifacts"]
    if artifact_paths.get("result") != "r1-result.json" or artifact_paths.get("report") != "r1-report.md" or artifact_paths.get("manifest") != "evidence-manifest.sha256.json":
        fail(f"{label}: result.artifacts does not match canonical artifact names")

    return result


def main() -> int:
    results = {label: verify_run(label, directory) for label, directory in RUNS.items()}
    vulnerable = results["vulnerable"]
    fixed = results["fixed"]

    if vulnerable["status"] != "CONFIRMED_VULNERABLE":
        fail(f"vulnerable run status is {vulnerable['status']!r}")
    if fixed["status"] != "FIXED":
        fail(f"fixed run status is {fixed['status']!r}")
    if vulnerable["target"]["observed_version"] != VULNERABLE_VERSION:
        fail("vulnerable run has the wrong Requests version")
    if fixed["target"]["observed_version"] != FIXED_VERSION:
        fail("fixed run has the wrong Requests version")
    if vulnerable["run_id"] == fixed["run_id"]:
        fail("vulnerable and fixed runs must have different run IDs")

    vo = vulnerable["observation"]
    fo = fixed["observation"]
    if vo["proxy_authorization_present"] is not True:
        fail("vulnerable run did not observe Proxy-Authorization at destination")
    if vo["credential_match"] is not True:
        fail("vulnerable run did not match the runtime-generated credential")
    if not vo["observed_credential_fingerprint"]:
        fail("vulnerable run has no observed credential fingerprint")
    if vo["observed_credential_fingerprint"] != vo["expected_credential_fingerprint"]:
        fail("vulnerable observed/expected credential fingerprints differ")

    if fo["proxy_authorization_present"] is not False:
        fail("fixed run still observed Proxy-Authorization at destination")
    if fo["credential_match"] is not False:
        fail("fixed run unexpectedly reports a credential match")
    if fo["observed_credential_fingerprint"] is not None:
        fail("fixed run contains an observed credential fingerprint")

    print("R1 ARTIFACT VERIFICATION: OK")
    print()
    print("VULNERABLE RUN")
    print(f"  status: {vulnerable['status']}")
    print(f"  Requests: {vulnerable['target']['observed_version']}")
    print(f"  Proxy-Authorization at destination: {vo['proxy_authorization_present']}")
    print(f"  Credential match: {vo['credential_match']}")
    print()
    print("FIXED RUN")
    print(f"  status: {fixed['status']}")
    print(f"  Requests: {fixed['target']['observed_version']}")
    print(f"  Proxy-Authorization at destination: {fo['proxy_authorization_present']}")
    print(f"  Credential match: {fo['credential_match']}")
    print()
    print("SECURITY TRANSITION: VERIFIED")
    print("  vulnerable → credential reached destination")
    print("  fixed      → credential did not reach destination")
    print()
    print("All manifest SHA-256 hashes: VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
