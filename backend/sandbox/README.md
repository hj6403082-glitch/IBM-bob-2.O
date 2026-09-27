# sandbox/ — CVE-2023-32681 reproduction rig (lite / fallback)

> **The canonical reproduction is R1 Ultra v3 in [`../r1ultra/`](../r1ultra/README.md)** —
> real origin→proxy→destination traffic, health gates, a versioned `r1.v2`
> result and a SHA-256 evidence manifest. The pipeline uses R1 when its
> `origin.local`/`destination.local` hosts are mapped, and falls back to this
> lightweight two-server rig otherwise. This rig stays as the zero-setup default
> so `pytest sandbox/` and the demo work anywhere.

---


Offline, two-server reproduction of **CVE-2023-32681**: `requests` < 2.31.0
leaks the `Proxy-Authorization` header to the destination host when a request
is redirected to an `https` target, disclosing proxy credentials.

This directory is the **reproduction rig** — it stands up a disposable local
environment and asserts that the insecure behaviour occurs. It does not triage,
patch, or open a PR; that work goes through IBM Bob (see `../CLAUDE.md`).

## What it does

Two local servers only, everything bound to `127.0.0.1`, no external network:

| Server | Role |
|---|---|
| **A** | HTTP origin. `GET /start` → `301` redirect to `https://<B>/dest`. Also doubles as the **CONNECT proxy** the client is configured to use. |
| **B** | HTTPS destination. Records the headers it receives **inside the tunnel** — i.e. what the redirect target actually sees. |

The client session is configured with a credentialed proxy URL
(`http://proxyuser:…@A`). Those credentials are what make `requests` generate
the `Proxy-Authorization` header — the rig never sets the header by hand. The
credentials are synthetic sandbox demo values, not a real secret.

## The mechanism

On a redirect, `requests/sessions.py::Session.rebuild_proxies` re-derives
`Proxy-Authorization` from the proxy URL and re-attaches it to the
**destination-bound** request:

```python
# 2.30.0 (vulnerable)
if username and password:
    headers["Proxy-Authorization"] = _basic_auth_str(username, password)

# 2.31.0 (patched) — guard added
if not scheme.startswith("https") and username and password:
    headers["Proxy-Authorization"] = _basic_auth_str(username, password)
```

When the redirect target is `https`, the request travels inside the proxy's
`CONNECT` tunnel. On 2.30.0 the re-attached header rides through the tunnel and
reaches server B. The 2.31.0 guard suppresses it for `https` targets.

The proxy legitimately seeing the header on the `CONNECT` line is expected on
every version — the **leak** is the *second* copy that reaches the destination.

## Run it

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt        # pins requests==2.30.0

python rig.py                          # standalone demo, prints LEAK / no leak
pytest -v                              # the reproduction test
```

Requires the `openssl` CLI (used to generate a throwaway self-signed cert for
server B at runtime, into a temp dir that is deleted on teardown — no key or
cert material is committed).

## The test

`test_proxy_auth_leak.py` asserts that server B receives the
`Proxy-Authorization` header. By version:

| `requests` | `pytest` result |
|---|---|
| **2.30.0** (pinned) | **green** — the header leaks; assertion holds |
| **2.31.0+** (patched) | **red** — the header is stripped; assertion fails |

So this test going **red is the signal that the target is patched**. That is
the intended behaviour of a reproduction test: it is red everywhere except on
the vulnerable version.

> This is the reproduction assertion (`../CLAUDE.md` hard rule 3). It is **not**
> the regression test that ships with a fix — the test that must *pass* on the
> patched version is authored by IBM Bob and exported to `bob_sessions/`
> (division of labour in `../CLAUDE.md`).

## Files

| File | Purpose |
|---|---|
| `rig.py` | The two-server rig + `run_probe()` + standalone demo (`python rig.py`). |
| `test_proxy_auth_leak.py` | The pytest reproduction test. |
| `conftest.py` | Makes `rig` importable from any invocation dir. |
| `requirements.txt` | Pins `requests==2.30.0` and `pytest`. |
