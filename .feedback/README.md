# Local preparation: dnfile

Python 3.12.11. Install with `uv venv --python 3.12 .venv` and `uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .`.
Run `.venv/bin/python .feedback/baseline.py`. The script runs the existing tests listed below, without modifying their assertions or application code.

Baseline scope: ['tests'].
Original upstream: https://github.com/malwarefrank/dnfile, commit bde05f174e10cc3df72eee45ff7189c1d9e2a28b.

Initialize the fixed test-data gitlink with `git submodule update --init --recursive` against the upstream origin before tests.
