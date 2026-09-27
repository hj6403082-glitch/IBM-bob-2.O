"""Regression test for CVE-2023-32681 — asserts the SECURE outcome.

This test must:
  - PASS  on the patched code  (requests 2.30.0 + the https-guard fix,
          or any requests >= 2.31.0)
  - FAIL  on the unpatched requests 2.30.0

Complement to sandbox/test_proxy_auth_leak.py (which asserts the *insecure*
outcome and therefore passes only on the vulnerable version).
"""

from __future__ import annotations

import shutil

import pytest

from rig import EXPECTED_LEAK_HEADER, TwoServerRig


@pytest.fixture()
def probe_result():
    if shutil.which("openssl") is None:
        pytest.skip("openssl CLI not available to generate the sandbox TLS cert")
    with TwoServerRig() as rig:
        yield rig.probe()


def test_proxy_authorization_is_stripped_on_cross_host_redirect(probe_result):
    """Proxy-Authorization must NOT reach the https destination after a
    cross-host redirect.  This is the regression assertion: if the https guard
    in rebuild_proxies is absent, the header leaks and this test fails.
    """
    assert not probe_result.errors, (
        f"rig error before reaching the destination: {probe_result.errors}"
    )
    assert probe_result.final_status == 200, (
        f"expected the redirect to resolve to 200, got {probe_result.final_status}"
    )

    leaked = probe_result.dest_proxy_auth
    assert leaked is None, (
        f"CVE-2023-32681 reproduced: requests {probe_result.requests_version} "
        "forwarded Proxy-Authorization to the https destination after a "
        "cross-host redirect. "
        f"Destination received: {leaked!r} (expected: None). "
        "Root cause: rebuild_proxies() in sessions.py re-attaches the header "
        "without checking whether the redirect target scheme is 'https'. "
        "Fix: guard the header attachment with "
        "'if not scheme.startswith(\"https\") and username and password'."
    )


def test_proxy_legitimately_saw_the_header_on_connect(probe_result):
    """Sanity check: the CONNECT request to the proxy must still carry the
    header (that is its legitimate, expected use on every version)."""
    assert probe_result.connect_proxy_auth == EXPECTED_LEAK_HEADER, (
        "proxy did not receive Proxy-Authorization on CONNECT; the rig is "
        f"misconfigured (saw {probe_result.connect_proxy_auth!r})"
    )
