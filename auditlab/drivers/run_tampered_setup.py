import shutil, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import run  # noqa: E402
WS = Path(sys.argv[1]).resolve()
WHEEL = WS / "auditlab/wheelhouse/auditdemo-1.0.0-py3-none-any.whl"
TARGET = WS / "auditlab/targets/tampered"
TRACE = WS / "auditlab/evidence/tampered.trace.jsonl"
run(WHEEL, TARGET, TRACE, abort=False, interpreter=sys.executable)
# Tamper after commit: modify an installed module without updating any RECORD.
victim = TARGET / "purelib/auditdemo/core.py"
with victim.open("a", encoding="utf-8") as fh:
    fh.write("\n# UNAUTHORIZED_POST_INSTALL_EDIT\n")
print("tampered: appended marker to", victim)
