# Local preparation: dncil

Python 3.12.11. Install with `uv venv --python 3.12 .venv` and `uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .`.
Run `.venv/bin/python .feedback/baseline.py`. The script runs the existing tests listed below, without modifying their assertions or application code.

Baseline scope: ['tests'].
Original upstream: https://github.com/mandiant/dncil, commit d174a3664767db00d8ee2a0652af9e7275119334.
