#!/usr/bin/env bash
# PatchWarden one-command setup (macOS / Linux / Git Bash).
# Creates a venv, installs the pinned deps, runs the tests, and does a demo run.
set -e
cd "$(dirname "$0")"

echo "==> Python venv"
python3 -m venv .venv 2>/dev/null || python -m venv .venv
# shellcheck disable=SC1091
if [ -f .venv/bin/activate ]; then . .venv/bin/activate; else . .venv/Scripts/activate; fi

echo "==> Installing dependencies (requests==2.30.0, pytest)"
python -m pip install -U pip >/dev/null
python -m pip install -r sandbox/requirements.txt

echo "==> Running the test suite"
python -m pytest -q

echo "==> Pipeline demo (offline triage engine + reproduction)"
python -m pipeline run \
  fixtures/report-001-real.md \
  fixtures/report-002-slop.md \
  fixtures/report-003-injection.md --export || true

cat <<'DONE'

==> Setup complete.

Next:
  - Open ui/present.html in a browser for the demo (or serve ui/ for the live console).
  - Run Bob per docs/bob-run-pack.md, then:
        python -m pipeline run fixtures/*.md --backend bob --export

Optional (rigorous R1 rig instead of the lite fallback): map the R1 hostnames
  echo "127.0.0.1 origin.local"      | sudo tee -a /etc/hosts
  echo "127.0.0.1 destination.local" | sudo tee -a /etc/hosts
DONE
