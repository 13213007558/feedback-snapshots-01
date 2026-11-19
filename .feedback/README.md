# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q tests/unit/test_network_auth.py tests/unit/test_network_session.py tests/unit/test_search_scope.py tests/unit/resolution_resolvelib/test_dependency_provenance_policy.py -k 'not non_existent_domain'
```
