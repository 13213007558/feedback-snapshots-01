# Local preparation: asn1tools

Python 3.12.11. Install with `uv venv --python 3.12 .venv` and `uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .`.
Run `.venv/bin/python .feedback/baseline.py`. The script runs the existing tests listed below, without modifying their assertions or application code.

Baseline scope: ['tests/test_ber.py', 'tests/test_der.py', 'tests/test_per.py', 'tests/test_uper.py', 'tests/test_oer.py', 'tests/test_constraints_checker.py'].
Original upstream: https://github.com/eerimoq/asn1tools, commit 3fdf723dca5efe077e7e2ef0f3d33f791af0e511.
