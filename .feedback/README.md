# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o asyncio_default_fixture_loop_scope=function tests/test_add_option_filter.py tests/test_add_option_backtrace.py tests/test_contextualize.py tests/test_configure.py
```
