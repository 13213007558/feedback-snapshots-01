# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q jupyterhub/tests/test_scopes.py -k 'test_scope_constructor or test_scope_precendence or test_scope_check or test_scope_filters or test_scope_parse_server_name or test_intersect_expanded_scopes'
```
