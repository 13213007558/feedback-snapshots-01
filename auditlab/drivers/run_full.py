import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import run  # noqa: E402

WS = Path(sys.argv[1]).resolve()
WHEEL = WS / "auditlab/wheelhouse/auditdemo-1.0.0-py3-none-any.whl"
TARGET = WS / "auditlab/targets/full"
TRACE = WS / "auditlab/evidence/full.trace.jsonl"

run(WHEEL, TARGET, TRACE, abort=False, interpreter=sys.executable)
print("full: install completed without interruption")
