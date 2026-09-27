"""Reproduction test for CVE-2023-32681.

Runs the two-server rig (``rig.py``) and asserts that the destination server
receives the ``Proxy-Authorization`` header that the proxy credentials
produced -- i.e. that proxy credentials leak across the redirect.

Expected outcome by version (this is the point of a reproduction test):

    requests == 2.30.0  -> GREEN  (the header leaks; assertion holds)
    requests >= 2.31.0  -> RED    (the header is stripped; assertion fails)

So this test failing is the signal that the target version is patched. Pin
``requests==2.30.0`` (see requirements.txt) to see it pass.

This is the reproduction rig asserting insecure behaviour (CLAUDE.md hard
rule 3). It is deliberately *not* the regression test that ships with a fix:
that test -- the one that must pass on the patched version -- is authored by
IBM Bob and exported to bob_sessions/ (CLAUDE.md division of labour).
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


def test_proxy_authorization_leaks_to_destination(probe_result):
    """Server B must NOT see Proxy-Authorization. On requests 2.30.0 it does."""
    assert not probe_result.errors, (
        f"rig error before reaching the destination: {probe_result.errors}"
    )
    assert probe_result.final_status == 200, (
        f"expected the redirect to resolve to 200, got {probe_result.final_status}"
    )

    leaked = probe_result.dest_proxy_auth
    assert leaked is not None, (
        "Proxy-Authorization did NOT reach the destination -- this build of "
        f"requests ({probe_result.requests_version}) strips it across the "
        "redirect, so CVE-2023-32681 does not reproduce here. That means the "
        "target is PATCHED (>= 2.31.0). Pin requests==2.30.0 to reproduce."
    )
    assert leaked == EXPECTED_LEAK_HEADER, (
        "destination received a Proxy-Authorization header, but not the value "
        f"derived from the proxy credentials: got {leaked!r}, expected "
        f"{EXPECTED_LEAK_HEADER!r}"
    )


def test_proxy_legitimately_saw_the_header_on_connect(probe_result):
    """Sanity check: the proxy itself always sees the header on the CONNECT
    request. That is the header's legitimate use and must hold on every
    version, so it isolates the leak in the test above to the destination."""
    assert probe_result.connect_proxy_auth == EXPECTED_LEAK_HEADER, (
        "proxy did not receive Proxy-Authorization on CONNECT; the rig is "
        f"misconfigured (saw {probe_result.connect_proxy_auth!r})"
    )
