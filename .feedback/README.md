# Local development setup

Python 3.10

Run from the repository root:

```sh
uv venv --python 3.10 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q tests/test_mountfs.py tests/test_multifs.py tests/test_permissions.py tests/test_move.py
```
