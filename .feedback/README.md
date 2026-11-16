# Local preparation: plyara

Python 3.12.11. Install with `uv venv --python 3.12 .venv` and `uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .`.
Run `.venv/bin/python .feedback/baseline.py`. The script runs the existing tests listed below, without modifying their assertions or application code.

Baseline scope: ['tests/test_core.py', 'tests/test_utils.py'].
Original upstream: https://github.com/plyara/plyara, commit 0103fed8f19a11be7fc60f88bba5422b8d7bbbb3.

Initialize the fixed test-data gitlink with `git submodule update --init --recursive` against the upstream origin before tests.
