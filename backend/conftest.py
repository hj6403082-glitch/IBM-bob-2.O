"""Put the repo root on sys.path so ``import pipeline`` works from any invocation."""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
