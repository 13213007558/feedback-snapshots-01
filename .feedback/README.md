# Local preparation: sasl

Python 3.10. Install with `uv venv --python 3.10 .venv` and `uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .`.
Run `.venv/bin/python .feedback/baseline.py`. The script runs the existing tests listed below, without modifying their assertions or application code.

Baseline scope: ['tests/test_aiosasl.py', 'tests/test_stringprep.py', 'tests/test_unicode_version.py'].
Original upstream: https://github.com/horazont/aiosasl, commit c3289212eff0bc4dbd087a342bc3ca478311a821.

Python 3.10 is intentional: upstream tests still use asyncio.coroutine, removed in Python 3.12. The portable baseline excludes the optional pyOpenSSL integration.

Python 3.10 is intentional: upstream tests still use asyncio.coroutine, removed in Python 3.12. The portable baseline excludes the optional pyOpenSSL integration.
