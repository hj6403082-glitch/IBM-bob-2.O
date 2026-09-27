# PatchWarden R1 — Runtime Reproduction Report

- Run ID: `928b170c610e267d273c2ddb`
- Status: **FIXED**
- Generated UTC: `2026-09-25T22:24:42.407155Z`
- Target: `CVE-2023-32681`
- Observed Requests: `2.31.0`

## Runtime observation

- Final HTTP status: `200`
- Final URL: `https://destination.local:53241/final`
- Destination received Proxy-Authorization: `False`
- Credential match: `False`
- Destination request: `GET /final HTTP/1.1`

## Health gates

- origin: `True` (302)
- destination: `True` (200)
- proxy: `True` (44007)

## Result semantics

`CONFIRMED_VULNERABLE` is emitted only when the live destination observed the runtime-generated credential on the redirected request.
`FIXED` is emitted only when the destination completed the same flow without the prohibited header.
`UNEXPECTED_FAILURE` means no trustworthy security conclusion was established.

No observed security result is hardcoded or fabricated.
