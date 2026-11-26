import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import run  # noqa: E402
WS = Path(sys.argv[1]).resolve()
WHEEL = WS / "auditlab/wheelhouse/auditdemo-1.0.0-py3-none-any.whl"
TARGET = WS / "auditlab/targets/partial-record"
TRACE = WS / "auditlab/evidence/partial-record.trace.jsonl"
run(WHEEL, TARGET, TRACE, abort=False, interpreter=sys.executable)
# Drop the data.txt row from the committed RECORD, leaving the file itself intact.
rec = TARGET / "purelib/auditdemo-1.0.0.dist-info/RECORD"
lines = rec.read_text(encoding="utf-8").splitlines()
kept = [ln for ln in lines if not ln.startswith("auditdemo/data.txt,")]
rec.write_text("\n".join(kept) + "\n", encoding="utf-8")
print("partial-record: removed data.txt row from", rec)
