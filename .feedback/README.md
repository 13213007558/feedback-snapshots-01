# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q tests/core/test_oauth2/test_authorization_session.py tests/flask/test_oauth2/test_introspection_endpoint.py tests/flask/test_oauth2/test_revocation_endpoint.py
```
