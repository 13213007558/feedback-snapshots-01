# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q tests/test_engine.py tests/test_model_bind.py tests/test_session.py tests/test_record_queries.py
```
