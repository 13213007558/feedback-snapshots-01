# Local preparation: dns

Python 3.12.11. Install with `uv venv --python 3.12 .venv` and `uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .`.
Run `.venv/bin/python .feedback/baseline.py`. The script runs the existing tests listed below, without modifying their assertions or application code.

Baseline scope: ['tests/test_message.py', 'tests/test_name.py', 'tests/test_tsig.py', 'tests/test_edns.py'].
Original upstream: https://github.com/rthalley/dnspython, commit aaf79b283345d169c692b5659609093c5a6f45b1.
