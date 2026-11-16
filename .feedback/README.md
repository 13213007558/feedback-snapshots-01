# Local preparation: pycrate

Python 3.12.11. Install with `uv venv --python 3.12 .venv` and `uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .`.
Run `.venv/bin/python .feedback/baseline.py`. The script runs the existing tests listed below, without modifying their assertions or application code.

Baseline scope: ['test/test_core.py', 'test/test_asn1rt.py', 'test/test_mobile.py'].
Original upstream: https://github.com/pycrate-org/pycrate, commit 7f5590f4f03a029c6699bb6dad28a7ada55d9929.

Fast baseline selection: ['-m', 'pytest', '-o', 'addopts=', '-q', 'test/test_core.py', 'test/test_asn1rt.py', 'test/test_mobile.py', '-k', 'not perf']. The earlier broader baseline passed; its log and timings are retained in the local batch preparation receipts.
