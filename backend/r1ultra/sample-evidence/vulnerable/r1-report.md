# PatchWarden R1 — Runtime Reproduction Report

- Run ID: `ce52461dd24a97e886cb66e5`
- Status: **CONFIRMED_VULNERABLE**
- Generated UTC: `2026-09-25T22:24:41.231434Z`
- Target: `CVE-2023-32681`
- Observed Requests: `2.30.0`

## Runtime observation

- Final HTTP status: `200`
- Final URL: `https://destination.local:45433/final`
- Destination received Proxy-Authorization: `True`
- Credential match: `True`
- Destination request: `GET /final HTTP/1.1`

## Health gates

- origin: `True` (302)
- destination: `True` (200)
- proxy: `True` (37041)

## Result semantics

`CONFIRMED_VULNERABLE` is emitted only when the live destination observed the runtime-generated credential on the redirected request.
`FIXED` is emitted only when the destination completed the same flow without the prohibited header.
`UNEXPECTED_FAILURE` means no trustworthy security conclusion was established.

No observed security result is hardcoded or fabricated.
