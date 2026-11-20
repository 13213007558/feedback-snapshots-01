# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q tests/oauth2/rfc6749/endpoints/test_introspect_endpoint.py tests/oauth2/rfc6749/endpoints/test_revocation_endpoint.py tests/openid/connect/core/endpoints/test_userinfo_endpoint.py tests/openid/connect/core/grant_types/test_refresh_token.py
```
