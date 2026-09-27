from __future__ import annotations

import hashlib
import os

import requests

from sandbox.rig import LocalRig
from r1.evidence import utc_now

EXPECTED_CVE = "CVE-2023-32681"
PACKAGE = "requests"
VULNERABLE_VERSION = "2.30.0"
FIXED_VERSION = "2.31.0"
SUPPORTED_VERSIONS = {VULNERABLE_VERSION, FIXED_VERSION}


def _result() -> dict:
    return {
        "schema": "r1.v2",
        "run_id": os.urandom(12).hex(),
        "generated_at": utc_now(),
        "status": "UNEXPECTED_FAILURE",
        "target": {
            "cve_id": EXPECTED_CVE,
            "package": PACKAGE,
            "expected_vulnerable_version": VULNERABLE_VERSION,
            "observed_version": requests.__version__,
        },
        "health": {},
        "observation": {},
        "errors": [],
    }


def reproduce() -> dict:
    rig = None
    result = _result()
    observed_version = requests.__version__

    if observed_version not in SUPPORTED_VERSIONS:
        result["errors"].append({
            "type": "UnsupportedVersion",
            "message": (
                f"R1 supports only Requests {VULNERABLE_VERSION} "
                f"and {FIXED_VERSION}; observed {observed_version}"
            ),
        })
        return result

    try:
        rig = LocalRig()
        rig.start()
        result["health"] = rig.health()

        if not all(item.get("ok") is True for item in result["health"].values()):
            raise RuntimeError("one or more rig health checks failed")

        proxies = {
            "http": f"http://{rig.credentials.user}:{rig.credentials.password}@127.0.0.1:{rig.proxy.port}",
            "https": f"http://{rig.credentials.user}:{rig.credentials.password}@127.0.0.1:{rig.proxy.port}",
        }

        for key in (
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
            "http_proxy", "https_proxy", "all_proxy",
        ):
            os.environ.pop(key, None)

        response = requests.get(
            f"http://origin.local:{rig.origin_port}/start",
            proxies=proxies,
            allow_redirects=True,
            verify=False,
            timeout=5,
        )

        line, headers, received = rig.observation.snapshot()
        observed = headers.get("Proxy-Authorization")
        observed_fingerprint = (
            hashlib.sha256(observed.encode()).hexdigest() if observed else None
        )
        credential_match = observed == rig.credentials.authorization if observed else False

        result["observation"] = {
            "http_status": response.status_code,
            "final_url": response.url,
            "destination_request_line": line,
            "destination_received_at": received,
            "proxy_authorization_present": observed is not None,
            "expected_credential_fingerprint": rig.credentials.fingerprint,
            "observed_credential_fingerprint": observed_fingerprint,
            "credential_match": credential_match,
        }

        if response.status_code != 200:
            raise RuntimeError(f"destination returned HTTP {response.status_code}")

        if observed_version == VULNERABLE_VERSION:
            if credential_match:
                result["status"] = "CONFIRMED_VULNERABLE"
            else:
                result["errors"].append({
                    "type": "InvariantMismatch",
                    "message": "Pinned vulnerable version did not reproduce the expected security-invariant violation",
                })
        elif observed_version == FIXED_VERSION:
            if observed is None and not credential_match:
                result["status"] = "FIXED"
            else:
                result["errors"].append({
                    "type": "InvariantMismatch",
                    "message": "Fixed comparison version still exposed Proxy-Authorization at the destination",
                })

    except Exception as exc:
        result["status"] = "UNEXPECTED_FAILURE"
        result["errors"].append({"type": type(exc).__name__, "message": str(exc)})
    finally:
        if rig is not None:
            rig.close()

    if result["errors"] and result["status"] == "UNEXPECTED_FAILURE":
        return result
    if result["status"] == "UNEXPECTED_FAILURE" and not result["errors"]:
        result["errors"].append({
            "type": "InvariantMismatch",
            "message": "The controlled reproduction completed without establishing a supported security result",
        })
    return result
