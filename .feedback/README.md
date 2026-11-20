# Local development setup

Python 3.13

Run from the repository root:

```sh
uv venv --python 3.13 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q referencing/tests/test_core.py referencing/tests/test_retrieval.py referencing/tests/test_jsonschema.py
```
