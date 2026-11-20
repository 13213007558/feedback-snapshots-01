# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q pymysql/tests/test_auth_state_machine.py pymysql/tests/test_err.py pymysql/tests/test_converters.py
```
