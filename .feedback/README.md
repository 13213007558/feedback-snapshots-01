# Local preparation: imap

Python 3.12.11. Install with `uv venv --python 3.12 .venv` and `uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .`.
Run `.venv/bin/python .feedback/baseline.py`. The script runs the existing tests listed below, without modifying their assertions or application code.

Baseline scope: ['tests/test_aioimaplib.py', 'tests/test_aioimaplib_clocked.py', 'tests/test_utils.py'].
Original upstream: https://github.com/iroco-co/aioimaplib, commit f1b3a1e3ae1916d3c3ba93d54220a5d081ecf945.

Final fast command: ['-m', 'pytest', '-o', 'addopts=', '-q', 'tests/test_aioimaplib_clocked.py', 'tests/test_aioimaplib_capabilities.py', 'tests/test_utils.py', '--asyncio-mode=auto'].
The broad integration run has two existing IDLE batching assertion failures and two SSL fixture failures against removed pyOpenSSL APIs. These are retained in the local preparation log, outside the deterministic fast scope; no test assertions were changed.
