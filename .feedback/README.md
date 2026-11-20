# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q tests/unit/test_manager.py tests/unit/test_download.py tests/unit/test_copies.py tests/unit/test_upload.py tests/unit/test_delete.py
```
