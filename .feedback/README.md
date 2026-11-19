# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q t/unit/test_serialization.py t/unit/test_connection.py t/unit/test_messaging.py -k 'not accept__content_disallowed'
```
