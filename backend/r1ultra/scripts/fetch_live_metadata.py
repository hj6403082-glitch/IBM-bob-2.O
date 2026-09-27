from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r1.runner import live_metadata
raise SystemExit(live_metadata())
