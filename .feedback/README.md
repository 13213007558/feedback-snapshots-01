# Local preparation: uefi

Python 3.12.11. Install with `uv venv --python 3.12 .venv` and `uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .`.
Run `.venv/bin/python .feedback/baseline.py`. The script runs the existing tests listed below, without modifying their assertions or application code.

Baseline scope: existing unittest discovery in tests.
Original upstream: https://github.com/theopolis/uefi-firmware-parser, commit 4942c4865da22000f4bb484830e26019ec061498.
