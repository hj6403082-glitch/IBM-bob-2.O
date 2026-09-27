from __future__ import annotations

import os
import requests
import urllib3

from sandbox.rig import LocalRig

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def test_proxy_authorization_does_not_reach_destination():
    rig = LocalRig()
    try:
        rig.start()
        health = rig.health()
        assert all(item["ok"] for item in health.values())
        proxies = {
            "http": f"http://{rig.credentials.user}:{rig.credentials.password}@127.0.0.1:{rig.proxy.port}",
            "https": f"http://{rig.credentials.user}:{rig.credentials.password}@127.0.0.1:{rig.proxy.port}",
        }
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            os.environ.pop(key, None)
        response = requests.get(
            f"http://origin.local:{rig.origin_port}/start",
            proxies=proxies,
            allow_redirects=True,
            verify=False,
            timeout=5,
        )
        assert response.status_code == 200
        _, headers, _ = rig.observation.snapshot()
        leaked = headers.get("Proxy-Authorization")
        print(f"Observed at destination: Proxy-Authorization present={leaked is not None}")
        assert leaked is None, "Proxy-Authorization reached the redirected HTTPS destination"
    finally:
        rig.close()
