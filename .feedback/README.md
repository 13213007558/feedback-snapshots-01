# Local preparation: opcua

Python 3.12.11. Install with `uv venv --python 3.12 .venv` and `uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .`.
Run `.venv/bin/python .feedback/baseline.py`. The script runs the existing tests listed below, without modifying their assertions or application code.

Baseline scope: ['tests/test_unit.py', 'tests/test_session_authentication.py', 'tests/test_relative_path.py', 'tests/test_uaerrors.py'].
Original upstream: https://github.com/FreeOpcUa/opcua-asyncio, commit e506dc6bc63c13176a9ede78b905ca9ca0a2523f.

Initialize the fixed test-data gitlink with `git submodule update --init --recursive` against the upstream origin before tests.
