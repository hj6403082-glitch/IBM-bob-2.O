# PatchWarden — 100% Live External Data Policy

PatchWarden separates **live external facts** from the **offline security reproduction**.

## No fabricated external facts

The project must never display a hardcoded CVE description, severity, current package version, latest release, advisory state, or external-source result as though it were current data.

Live external metadata is fetched at execution time from public APIs and recorded with:

- source URL
- retrieval timestamp
- HTTP status when available
- raw source response
- derived fields used by the demo

Current integrations:

- OSV.dev vulnerability API
- NVD CVE 2.0 API
- PyPI JSON API

The official API documentation confirms these are live API interfaces for vulnerability/package metadata. See the project references in the submission notes.

## Offline reproduction remains offline

The reproduction itself must stay independent of those services. `docker run --network none` is still used for the security test. Live metadata is an evidence/preflight stage, not a dependency of the local exploit-behavior test.

## Fixed experiment configuration is not fake data

The R1 target may define an experiment such as:

```text
CVE-2023-32681
requests 2.30.0
comparison: requests 2.31.0
```

Those values identify the controlled test. They are not claimed to be current external facts. The live preflight independently verifies the relationship before a live-data-backed demo/report uses it.

## Failure behavior

If a live source is unavailable or contradicts the requested target, PatchWarden must report:

```text
UNAVAILABLE
```

or

```text
MISMATCH
```

It must not substitute sample values.
