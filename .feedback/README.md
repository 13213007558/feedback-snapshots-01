# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest --noconftest --asyncio-mode=auto -o asyncio_default_fixture_loop_scope=function -q tests/test_credentials.py tests/test_utils.py -k 'no_race_condition or uses_httpx_fetcher_by_default or ref_counted_session_rolls_back'
```
