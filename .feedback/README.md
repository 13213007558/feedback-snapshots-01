# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q tests/test_30_mdstore.py tests/test_32_cache.py tests/test_38_metadata_filter.py tests/test_41_response.py
```
