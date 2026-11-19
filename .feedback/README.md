# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q tests/test_deserialization.py tests/test_decorators.py tests/test_error_store.py tests/test_schema.py
```
