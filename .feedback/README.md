# Local development setup

Python 3.13

Run from the repository root:

```sh
uv venv --python 3.13 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -o addopts= -q tests/test_sessions.py tests/test_routing.py tests/wrappers/test_request.py
```
