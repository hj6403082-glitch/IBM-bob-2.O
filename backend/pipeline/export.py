"""Export run records to bob_sessions/ and to the UI's data file.

The exporter writes what the pipeline observed (Bob's verdict + the sandbox
reproduction result) into a stable JSON shape. It is plumbing: it serialises;
it does not decide anything.
"""

from __future__ import annotations

import json
from pathlib import Path

from .runner import RunRecord

_REPO_ROOT = Path(__file__).resolve().parent.parent


def export_run(record: RunRecord, sessions_dir: str | Path = "bob_sessions") -> Path:
    """Write one run record to bob_sessions/<slug>.run.json. Returns the path."""
    sessions = Path(sessions_dir)
    sessions.mkdir(parents=True, exist_ok=True)
    slug = Path(record.report_path).stem
    out = sessions / f"{slug}.run.json"
    out.write_text(json.dumps(record.to_dict(), indent=2) + "\n", encoding="utf-8")
    return out


def rebuild_ui_index(
    sessions_dir: str | Path = "bob_sessions",
    ui_data_path: str | Path | None = None,
) -> Path:
    """Collect every ``*.run.json`` in bob_sessions/ into ui/runs.json.

    The dashboard reads that single file. Example/placeholder records
    (``*.example.json``) are ignored.
    """
    sessions = Path(sessions_dir)
    ui_data = Path(ui_data_path) if ui_data_path else _REPO_ROOT / "ui" / "runs.json"
    ui_data.parent.mkdir(parents=True, exist_ok=True)

    runs = []
    for path in sorted(sessions.glob("*.run.json")):
        try:
            runs.append(json.loads(path.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            continue
    ui_data.write_text(json.dumps({"runs": runs}, indent=2) + "\n", encoding="utf-8")
    return ui_data
