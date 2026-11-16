# Local preparation: waitress

Python 3.12.11. Install with `uv venv --python 3.12 .venv` and `uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .`.
Run `.venv/bin/python .feedback/baseline.py`. The script runs the existing tests listed below, without modifying their assertions or application code.

Baseline scope: ['tests/test_parser.py', 'tests/test_receiver.py', 'tests/test_channel.py', 'tests/test_task.py', 'tests/test_proxy_headers.py'].
Original upstream: https://github.com/Pylons/waitress, commit 2b43237e9caa66f906d0f652f2519cc79ef969a5.
