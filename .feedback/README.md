# Local preparation: ratchet

Python 3.12.11. Install with `uv venv --python 3.12 .venv` and `uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .`.
Run `.venv/bin/python .feedback/baseline.py`. The script runs the existing tests listed below, without modifying their assertions or application code.

Baseline scope: ['tests'].
Original upstream: https://github.com/Syndace/python-doubleratchet, commit 9ef33939048e7a09d76ce96232645717a5073c47.

Fast baseline selection: ['-m', 'pytest', '-o', 'addopts=', '-q', 'tests/test_double_ratchet.py::test_migrations', 'tests/test_kdf_chain.py', 'tests/test_symmetric_key_ratchet.py', 'tests/test_recommended_kdfs.py', 'tests/test_recommended_aeads.py', '--asyncio-mode=auto']. The earlier broader baseline passed; its log and timings are retained in the local batch preparation receipts.

Final fast command: ['-m', 'pytest', '-o', 'addopts=', '-q', 'tests/test_double_ratchet.py::test_migrations', 'tests/test_kdf_chain.py', 'tests/test_symmetric_key_ratchet.py', '--asyncio-mode=auto'].
