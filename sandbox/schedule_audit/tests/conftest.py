import sys
from pathlib import Path

# Make the repository root importable so `import sandbox.schedule_audit`
# works regardless of the directory pytest is invoked from.
ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
