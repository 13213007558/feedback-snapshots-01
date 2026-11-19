# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q guardian/testapp/tests/test_backends.py guardian/testapp/tests/test_core.py guardian/testapp/tests/test_shortcuts.py guardian/testapp/tests/test_direct_rel.py
```
