# Vulnerability Report #001

**DEMO FIXTURE — restatement of a real, already-patched issue
(CVE-2023-32681, `requests` < 2.31.0). Used so the team has verified ground
truth. Written in a reporter's voice, deliberately without a ready-made fix.**

---

**Title:** Proxy credentials leak to destination host on cross-host redirect

**Severity:** Moderate

**Reporter:** external-researcher

**Affected component:** redirect handling in the session layer

## Summary

When a request is sent through a proxy that requires authentication, and the
server responds with a redirect to a different host, the
`Proxy-Authorization` header appears to be carried over to the new
destination. That header contains the proxy credentials, so a redirect
target the user did not choose can receive them.

## How I noticed

I was routing traffic through an authenticated corporate proxy and noticed
credentials showing up in logs on a third-party host I had been redirected
to. I did not expect a proxy header to survive a host change.

## Expected behaviour

Headers scoped to the proxy connection should be stripped when the request
is rebuilt for a new host, in the same way other sensitive headers are
handled on cross-host redirects.

## Reproduction sketch

Two local servers are enough. Send a request through a session with a
`Proxy-Authorization` header set, have server A return a 301 pointing at
server B, and inspect what server B receives. No network access needed.

## Impact

Any user behind an authenticated proxy who follows a redirect to an
untrusted host discloses their proxy credentials to that host. The user has
no indication this occurred.

## References

- CVE-2023-32681
- CWE-200: Exposure of Sensitive Information to an Unauthorised Actor

---

### Team notes (strip before demo)

Ground truth: real, confirmed, fixed upstream in 2.31.0 by rebuilding the
proxy headers on cross-host redirect. Pin the repo at 2.30.0 so the bug is
live. The report deliberately states the symptom but not the fix location,
so Bob has to find the root cause itself — that is the part judges care
about.
