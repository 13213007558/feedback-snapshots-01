# Local preparation: srp

Python 3.12.11. Install with `uv venv --python 3.12 .venv` and `uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .`.
Run `.venv/bin/python .feedback/baseline.py`. The script runs the existing tests listed below, without modifying their assertions or application code.

Baseline scope: pure-Python SRP mutual-authentication and wrong-password smoke check; native ctypes backend is optional.
Original upstream: https://github.com/cocagne/pysrp, commit 2f0211d7965290664af1537a0164dbb82a7270ff.
