# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= csp/tests/test_middleware.py csp/tests/test_decorators.py csp/tests/test_checks.py csp/tests/test_contrib.py
```
