# Local preparation: ndn

Python 3.12.11. Install with `uv venv --python 3.12 .venv` and `uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .`.
Run `.venv/bin/python .feedback/baseline.py`. The script runs the existing tests listed below, without modifying their assertions or application code.

Baseline scope: ['tests/encoding', 'tests/security'].
Original upstream: https://github.com/named-data/python-ndn, commit 150eb16681e324f0e17110eb6fb276d034a5916f.
