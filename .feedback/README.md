# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q tests/property/test_pyenv_cfg.py tests/tasks/test_fetch_url.py tests/virtualenv/util/path/test_win.py
```
