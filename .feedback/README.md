# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q tests/unit/test_client.py tests/unit/test_endpoint.py tests/unit/auth/test_signers.py tests/unit/test_tokens.py
```
