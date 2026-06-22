"""
pytest conftest.py — ShieldNet Pipeline B Tests
Ensures the project root is on sys.path so that `pipeline_b.*` and `backend.*`
imports resolve correctly regardless of where pytest is invoked from.
"""
import sys
from pathlib import Path

# Insert the project root at the front of sys.path
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
