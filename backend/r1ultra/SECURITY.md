# Security boundary

R1 is intentionally a local defensive reproduction fixture. It uses only loopback services, runtime-generated synthetic credentials, an allow-listed proxy, and a short-lived test certificate. It does not contain real credentials, live exploit payloads, or Internet-dependent reproduction logic.

Do not replace the synthetic credential with a real secret. Keep the offline Docker network boundary (`--network none`) when executing the reproduction fixture or the validation runner. Host name resolution for `origin.local`/`destination.local` is supplied at container run time via `--add-host`; the image itself never modifies `/etc/hosts`.
