# Session Log 06: Pull Request Draft (CVE-2023-32681)

Prepared by Bob. PatchWarden proposes; the maintainer decides. **Never merged.**

---

**Title:** `fix(sessions): strip Proxy-Authorization on https redirect targets (CVE-2023-32681)`

## Summary
When a `requests` session using a credentialed proxy follows a cross-scheme
redirect to an `https` URL, the proxy credentials are silently forwarded to the
destination host. The user has no indication this happened.

## Root cause
`Session.rebuild_proxies()` re-derives `Proxy-Authorization` from the proxy URL on
every redirect and re-attaches it unconditionally (`requests/sessions.py:327`). For
`https` redirects the request travels inside the proxy's CONNECT tunnel, so the
header reaches the origin server rather than being consumed by the proxy.

## Fix
A single `scheme` guard before re-attaching the header (`sessions.py:327`):

```python
# Before (vulnerable):
if username and password:
    headers["Proxy-Authorization"] = _basic_auth_str(username, password)

# After (patched):
if not scheme.startswith("https") and username and password:
    headers["Proxy-Authorization"] = _basic_auth_str(username, password)
```

## Regression test
`sandbox/test_proxy_auth_no_leak_regression.py` — asserts `Proxy-Authorization`
does not reach the destination after a cross-host https redirect. Passes on patched
code; fails on unpatched 2.30.0. Requires the `openssl` CLI; skips cleanly when absent.

## Maintainer checklist
- Confirm the CONNECT path: for `https` proxying, `Proxy-Authorization` is still sent
  on the CONNECT request (handled by urllib3) — this patch does not affect that leg.
- Confirm no callers set `scheme` to a non-URL-scheme alias; the guard
  `not scheme.startswith("https")` is correct.
- Run the sandbox rig (`python sandbox/rig.py`, or `r1ultra/`) on a host with
  `openssl` to see the before/after live.

_This matches the upstream 2.31.0 fix. Do not merge without human sign-off._
