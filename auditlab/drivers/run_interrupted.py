import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import run  # noqa: E402

WS = Path(sys.argv[1]).resolve()
WHEEL = WS / "auditlab/wheelhouse/auditdemo-1.0.0-py3-none-any.whl"
TARGET = WS / "auditlab/targets/interrupted"
TRACE = WS / "auditlab/evidence/interrupted.trace.jsonl"

run(WHEEL, TARGET, TRACE, abort=True, interpreter=sys.executable)
print("interrupted: install completed without interruption (unexpected)")
