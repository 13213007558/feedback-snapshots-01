# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q fsspec/tests/test_spec.py fsspec/tests/test_config.py fsspec/tests/test_caches.py fsspec/tests/test_dircache.py
```
