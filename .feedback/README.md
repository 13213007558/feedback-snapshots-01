# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q joblib/test/test_store_backends.py joblib/test/test_memory.py joblib/test/test_numpy_pickle.py -k 'not joblib_format_compatibility and not future_version'
```
