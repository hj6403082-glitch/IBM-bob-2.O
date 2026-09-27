"""Live external vulnerability/package metadata.

This module is deliberately separate from the offline reproduction. It never
creates synthetic vulnerability facts. Every external fact is fetched at run
time from official/public APIs and stored with its source URL and retrieval
 timestamp. If a source cannot be reached, the result says UNAVAILABLE.
"""
from __future__ import annotations

import datetime as dt
import os
from urllib.parse import quote
import requests

OSV_QUERY = os.environ.get("PATCHWARDEN_OSV_QUERY_URL", "https://api.osv.dev/v1/query")
OSV_VULN = os.environ.get("PATCHWARDEN_OSV_VULN_URL", "https://api.osv.dev/v1/vulns")
NVD_CVE = os.environ.get("PATCHWARDEN_NVD_CVE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
PYPI_PROJECT = os.environ.get("PATCHWARDEN_PYPI_PROJECT_URL", "https://pypi.org/pypi")


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _get_json(url: str, *, timeout=(3, 10), headers=None) -> dict:
    r = requests.get(url, timeout=timeout, headers=headers or {"User-Agent": "PatchWarden-R1/live-metadata"})
    r.raise_for_status()
    return r.json()


def _source(url: str, data=None, error=None, http_status=None) -> dict:
    item = {"url": url, "retrieved_at": _utc_now()}
    if http_status is not None:
        item["http_status"] = http_status
    if data is not None:
        item["data"] = data
    if error is not None:
        item["status"] = "UNAVAILABLE"
        item["error"] = error
    return item


def fetch_live(package: str, version: str, cve_id: str) -> dict:
    """Fetch live OSV, NVD and PyPI evidence for one target.

    The supplied package/version/CVE identify the experiment; they are not
    presented as live facts. Live sources independently verify them.
    """
    started = _utc_now()
    result = {
        "schema": "r1.live.v1",
        "retrieved_at": started,
        "status": "UNAVAILABLE",
        "query": {"package": package, "version": version, "cve_id": cve_id},
        "sources": {},
        "derived": {},
        "errors": [],
    }
    timeout = (3, 10)

    # OSV: query the exact package/version, then retrieve the CVE record.
    try:
        r = requests.post(
            OSV_QUERY,
            json={"package": {"name": package, "ecosystem": "PyPI"}, "version": version},
            timeout=timeout,
            headers={"User-Agent": "PatchWarden-R1/live-metadata", "Content-Type": "application/json"},
        )
        r.raise_for_status()
        osv_version = r.json()
        result["sources"]["osv_package_version"] = _source(OSV_QUERY, osv_version, http_status=r.status_code)
    except Exception as exc:
        result["sources"]["osv_package_version"] = _source(OSV_QUERY, error=f"{type(exc).__name__}: {exc}")
        result["errors"].append("OSV package/version query unavailable")
        osv_version = {}

    try:
        osv_url = f"{OSV_VULN.rstrip('/')}/{quote(cve_id, safe='')}"
        osv_cve = _get_json(osv_url, timeout=timeout)
        result["sources"]["osv_cve"] = _source(osv_url, osv_cve, http_status=200)
    except Exception as exc:
        result["sources"]["osv_cve"] = _source(f"{OSV_VULN.rstrip('/')}/{quote(cve_id, safe='')}", error=f"{type(exc).__name__}: {exc}")
        result["errors"].append("OSV CVE record unavailable")
        osv_cve = {}

    # NVD: independent current CVE record.
    try:
        nvd_url = f"{NVD_CVE}?cveId={quote(cve_id, safe='')}"
        nvd = _get_json(nvd_url, timeout=timeout, headers={"User-Agent": "PatchWarden-R1/live-metadata"})
        result["sources"]["nvd"] = _source(nvd_url, nvd, http_status=200)
    except Exception as exc:
        result["sources"]["nvd"] = _source(NVD_CVE, error=f"{type(exc).__name__}: {exc}")
        result["errors"].append("NVD CVE record unavailable")
        nvd = {}

    # PyPI: current project/release metadata, including latest release.
    pypi_url = f"{PYPI_PROJECT.rstrip('/')}/{quote(package, safe='')}/json"
    try:
        pypi = _get_json(pypi_url, timeout=timeout, headers={"User-Agent": "PatchWarden-R1/live-metadata"})
        result["sources"]["pypi_project"] = _source(pypi_url, pypi, http_status=200)
    except Exception as exc:
        result["sources"]["pypi_project"] = _source(pypi_url, error=f"{type(exc).__name__}: {exc}")
        result["errors"].append("PyPI project metadata unavailable")
        pypi = {}

    vulns = osv_version.get("vulns") or []
    osv_ids = {v.get("id") for v in vulns if isinstance(v, dict)}
    cve_match = cve_id in osv_ids or any(cve_id in str(v) for v in vulns)
    pypi_info = pypi.get("info") or {}
    pypi_latest = pypi_info.get("version")
    releases = pypi.get("releases") or {}
    result["derived"] = {
        "osv_exact_version_contains_cve": bool(cve_match),
        "osv_exact_version_vulnerability_ids": sorted(x for x in osv_ids if x),
        "pypi_latest_version": pypi_latest,
        "pypi_requested_version_exists": version in releases,
        "osv_cve_record_id": osv_cve.get("id"),
        "nvd_cve_count": len(nvd.get("vulnerabilities") or []),
    }

    if result["sources"].get("osv_package_version", {}).get("data") and result["sources"].get("osv_cve", {}).get("data") and result["sources"].get("pypi_project", {}).get("data"):
        if result["derived"]["osv_cve_record_id"] == cve_id and result["derived"]["osv_exact_version_contains_cve"] and result["derived"]["pypi_requested_version_exists"]:
            result["status"] = "OK"
        else:
            result["status"] = "MISMATCH"
            result["errors"].append("Live sources do not independently confirm the requested package/version/CVE relationship")
    return result
