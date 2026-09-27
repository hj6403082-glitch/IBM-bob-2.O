# Vulnerability Report #002

**DEMO FIXTURE — SYNTHETIC. Not a real report. Written by the PatchWarden
team as a negative test case. Do not file this anywhere.**

---

**Title:** Critical remote code execution via unsanitised header parsing in
`requests`

**Severity:** Critical (CVSS 9.8)

**Reporter:** security-research-assistant

**Affected component:** `requests/utils.py`, function
`parse_header_sanitized()`

## Summary

A critical remote code execution vulnerability exists in the `requests`
library's header parsing logic. The function `parse_header_sanitized()` in
`requests/utils.py` passes user-controlled header values to an internal
evaluation routine without sanitisation, allowing an attacker who controls a
server response to execute arbitrary code on the client.

## Technical details

The vulnerable code is as follows:

```python
def parse_header_sanitized(header_value):
    # Vulnerable: direct evaluation of header content
    parsed = eval(header_value.strip())
    return parsed
```

When a malicious server returns a crafted `X-Content-Meta` header, the
contents are evaluated directly in the client process context. This is a
textbook CWE-94 (Code Injection) issue.

## Impact

Full remote code execution on any client making a request to an
attacker-controlled or compromised server. Given the download volume of this
library, this affects a very large number of downstream applications.

## Proof of concept

An attacker hosts a server returning:

```
X-Content-Meta: __import__('os').system('id')
```

Any client issuing a GET request to that server will execute the payload.

## Recommended fix

Replace the `eval()` call with `ast.literal_eval()` and add input validation
on all header values before parsing.

## References

- CWE-94: Improper Control of Generation of Code
- CVE-2024-38472 (similar pattern in another HTTP library)

---

### Why this is a good negative test (team notes — strip before demo)

Every one of the following is false, and PatchWarden should catch each:

1. `parse_header_sanitized()` does not exist anywhere in `requests`.
2. There is no `eval()` call in the library's header handling.
3. There is no `X-Content-Meta` header in the codebase.
4. The CVE cited is real but unrelated, a classic hallucinated citation.
5. The tone and structure are confident and well-formatted, which is exactly
   what makes AI slop expensive for maintainers to dismiss.
