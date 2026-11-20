# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python manage.py test tests.test_attempts tests.test_handlers tests.test_login tests.test_signals --noinput
```
