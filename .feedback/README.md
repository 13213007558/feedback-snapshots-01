# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q tests/test_downscoped.py tests/test_pluggable.py tests/test_external_account.py tests/test_impersonated_credentials.py
```
