#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
if ! command -v python3 >/dev/null 2>&1; then
  echo 'Install Python 3.11 or newer, then run this launcher again.'
  exit 1
fi
exec python3 start.py "$@"
