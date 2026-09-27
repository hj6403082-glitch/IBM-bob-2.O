# PatchWarden — ready-to-run integrated project

Complete editable source: organic animated dashboard, floating bottom dock, and the integrated vulnerability-triage backend from the supplied ZIP.

## Windows

1. Install **Python 3.11 or newer** from https://www.python.org/downloads/ if needed. Enable **Add Python to PATH** during installation.
2. Extract this ZIP completely; do not run from inside the compressed folder.
3. Double-click **Start-PatchWarden.cmd**.
4. On the first launch, dependencies install into a local `.venv` folder. The browser opens automatically when the server is ready.

## macOS / Linux

Install Python 3.11+ if needed, extract the ZIP, open a terminal in this folder, and run:

```sh
sh start.sh
```

On Linux, your Python installation may require the OS's `python3-venv` package to create a virtual environment.

## Using the app

Open **http://127.0.0.1:4173/#scan** on the same computer. Keep the launch terminal running. Press **Ctrl+C** to stop it.

The **Triage** view opens by default. Select a bundled report and click **Run triage**. Results and run history persist locally in `state/`, created automatically on first use. The **Fleet** and **Rollouts** tabs in the dock are an explicitly labelled UI simulation, not backend data.

**Node.js is not required** with these launchers. An optional Node launcher remains available as `node preview.cjs` after Python setup.

Internet access is needed for the first dependency installation. Optional Google Fonts also load online; system-font fallbacks work without them. The report verifier and local reproduction do not require internet access after setup.

## Local reproduction prerequisite

The fresh sandbox reproduction uses **OpenSSL** for a temporary local TLS certificate.

- **Windows:** Install Git for Windows from https://git-scm.com/downloads/win using its standard location. PatchWarden automatically finds its bundled OpenSSL. Alternatively, put OpenSSL on PATH.
- **macOS / Linux:** Make sure `openssl version` works in a terminal.

If OpenSSL is absent, the dashboard and report verifier still work. Uncheck **Local reproduction**, or install OpenSSL and rerun. A missing harness dependency is shown as “Not run,” never as a successful reproduction.

## Troubleshooting

- **Port already in use:** close an older PatchWarden launch window, or use `python start.py --port 4175` (macOS/Linux: `python3 start.py --port 4175`) and open the printed URL.
- **Browser did not open:** copy the URL printed in the terminal into your browser.
- **Setup/download failed:** confirm internet access and retry. Dependencies are pinned in `requirements.txt`.
- **Python not found:** install Python 3.11+ and reopen your terminal.
- **Prepare without starting:** `python start.py --setup-only`.
- **Start without opening a browser:** `python start.py --no-browser`.

## What is connected

- Bundled real, fabricated, and prompt-injection report fixtures.
- Fresh deterministic offline verification against Requests 2.30.0.
- Optional localhost-only reproduction of the supplied CVE scenario.
- Imported Bob session verdicts, explicitly distinguished from fresh verification.
- Custom report text/file input, saved run history, JSON downloads, and SHA-256 checks.
- Archived R1 vulnerable/fixed evidence, checked against its original manifests.
- The original supplied presentation at `/legacy/present.html`.

Fleet assets, deployment controls, and fleet compliance remain a UI simulation. The backend is a narrowly scoped report verifier, not a general-purpose AI model or production patch deployer. Imported Bob action text does not mean this app applies patches or creates pull requests. No live Bob service is called.

Requests 2.30.0 is deliberately pinned as the vulnerable reproduction target. Keep it inside this project's isolated environment. Sandbox evidence uses synthetic credentials and loopback servers. The service is for local use, not public hosting.

The supplied archive's optional narration MP3 is absent. The original presentation is included as provided. Live R1 Ultra requires its separate Python 3.11/hostname setup; this app uses the lite localhost harness and separately verifies archived R1 evidence.

## Source map

- `dist/`: all HTML, CSS, JavaScript, organic canvas animation, dock, and triage UI.
- `backend/`: supplied pipeline, fixtures, Bob exports, sandbox rigs, original UI, evidence, docs, and tests.
- `service.py`: loopback API and static file server.
- `worker.py`: isolated pipeline invocation adapter.
- `start.py`, `Start-PatchWarden.cmd`, `start.sh`: portable setup and launch.
- `tests/test_service.py`: API integration tests.
- `requirements.txt`: Python dependencies.

Machine-specific virtual environments, private run history, caches, and hosting configuration are intentionally excluded. They are not required source files.

## Validation

The integrated source passed 7 API tests and 27 supplied pipeline tests; 3 environment-dependent tests were skipped. Tests cover reproduction, all three fixtures, imported Bob provenance, persistence, tamper detection, and request boundaries.

After setup, run:

```text
.venv\Scripts\python.exe -m pytest tests/test_service.py -q
```

On macOS/Linux use `.venv/bin/python`. The secure-outcome regression test included in the backend is intentionally expected to fail against the unpatched 2.30.0 target; it is not part of the passing plumbing suite.
