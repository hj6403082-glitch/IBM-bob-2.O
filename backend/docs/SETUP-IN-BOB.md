# Setting up PatchWarden in the IBM Bob IDE

Step-by-step to get the project running in Bob and produce the graded verdicts.
Commands are given for **PowerShell (Windows)** and **macOS/Linux**.

## 1. Sign in and open the project
1. In the **IBM BOB** panel, click **Log in to Bob** (or start the free trial).
2. Open the repo folder in Bob. If it isn't cloned yet, open a terminal
   (**Terminal → New Terminal**) and clone it, then check out the branch that
   has all the work:

   ```powershell
   git clone https://github.com/krishiyswim23-swagger/IBM-Bob-2.O-2026
   cd IBM-Bob-2.O-2026
   git checkout claude/awesome-hawking-kv99ta
   ```
   Then **File → Open Folder…** and pick that folder.

## 2. Set up Python + dependencies
Requires Python 3.11 and `openssl` on PATH.

**macOS/Linux (or Git Bash):**
```bash
bash setup.sh
```

**Windows PowerShell:**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r sandbox\requirements.txt
python -m pytest -q
python -m pipeline run fixtures\report-001-real.md fixtures\report-002-slop.md fixtures\report-003-injection.md --export
```
You should see **28 tests pass** and three verdicts printed (1 confirmed, 2 fabricated).

## 3. Create the "Security Triage Officer" custom mode
1. In the Bob panel, open **Bob Settings** (bottom-right status bar) or the panel's
   **⋯ / gear** menu, and find **Custom Modes → New**.
2. Name it **Security Triage Officer**.
3. Paste the entire contents of [`security-triage-mode.md`](security-triage-mode.md)
   as the mode definition. Save.
4. Export this Bob session → `bob_sessions/02-custom-mode-creation.md`.

## 4. Triage the three reports (one Bob task each)
For each fixture, start a task **in Security Triage Officer mode** and paste the
prompt from [`bob-run-pack.md`](bob-run-pack.md) §2 with the report body.
Expected: `001` → CONFIRMED, `002` → FABRICATED, `003` → FABRICATED (injection).

Save each verdict trailer into the matching template (already created):
- `bob_sessions/report-001-real.verdict.txt`
- `bob_sessions/report-002-slop.verdict.txt`
- `bob_sessions/report-003-injection.verdict.txt`

Then run the pipeline on Bob's verdicts:
```
python -m pipeline run fixtures/*.md --backend bob --export
```

## 5. Remediate the confirmed one (Bob, agent mode)
Ask Bob to patch `requests/sessions.py::rebuild_proxies` (add the
`not scheme.startswith("https")` guard), turn `sandbox/test_proxy_auth_leak.py`
into a regression test (RED before, GREEN after), and open a PR — **never merge**.
Export sessions → `bob_sessions/05-patch-and-regression.md`, `06-pull-request.md`.

## 6. Judging exports
Fill the checklist in [`../bob_sessions/README.md`](../bob_sessions/README.md):
the session `.md` exports and the **Bobcoin consumption screenshots**.

---

### Troubleshooting
- **`openssl` not found** → install it (Windows: `winget install ShiningLight.OpenSSL`
  or use Git's openssl) and reopen the terminal. The lite rig needs it for the TLS cert.
- **Tests can't import `pipeline`** → run from the repo root, and make sure the venv is active.
- **R1 rig shows `UNEXPECTED_FAILURE`** → the `origin.local`/`destination.local`
  hosts aren't mapped; the pipeline falls back to the lite rig automatically.
  To use R1 directly, add both to your hosts file pointing at `127.0.0.1`.
