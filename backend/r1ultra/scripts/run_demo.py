from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r1.runner import run_reproduction
raise SystemExit(run_reproduction())
