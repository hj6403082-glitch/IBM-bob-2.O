# Session Log 04: Real CVE Triage + Remediation (report-001-real.md)

**Mode:** Security Triage Officer (custom mode)
**Input:** `fixtures/report-001-real.md`
**Result:** CONFIRMED (high) → reproduced → patched → regression test → PR draft.

## Phase 2 — Verify (parallel subagents)
- **Existence/root cause:** `Session.rebuild_proxies()` re-derives `Proxy-Authorization`
  from the proxy URL on every redirect and re-attaches it **unconditionally**
  (`requests/sessions.py:327`). Called each redirect iteration from
  `resolve_redirects()` (`sessions.py:245`).
- **Reachability:** an attacker serves a redirect from any HTTP URL to an
  attacker-controlled `https` URL. For `https` targets the request travels inside
  the proxy's CONNECT tunnel, so the re-attached header reaches the destination
  server instead of being consumed by the proxy.
- **Prior art:** installed version confirmed 2.30.0; fixed upstream in 2.31.0 by a
  scheme guard.

## Phase 3 — Verdict
```
VERDICT: CONFIRMED   CONFIDENCE: high
root cause: requests/sessions.py:327 (Proxy-Authorization re-attached without an https guard)
```

## Phase 4/5 — Reproduce → Patch → Regress
- **Patch** (`sessions.py:327`), one condition added:
  ```python
  # before (vulnerable)
  if username and password:
      headers["Proxy-Authorization"] = _basic_auth_str(username, password)
  # after (patched) — matches upstream 2.31.0
  if not scheme.startswith("https") and username and password:
      headers["Proxy-Authorization"] = _basic_auth_str(username, password)
  ```
- **Regression test:** `sandbox/test_proxy_auth_no_leak_regression.py` — asserts the
  destination does **not** receive `Proxy-Authorization` after a cross-host https
  redirect. Passes on patched code; fails on unpatched 2.30.0. Skips cleanly when
  `openssl` is absent.
- **Suite:** 25 passed, 1 skipped, 0 broken.

PatchWarden never merges — the PR (see `06-pull-request.md`) awaits maintainer sign-off.
