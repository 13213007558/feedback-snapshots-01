# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q --ds=tests.settings tests/test_s3.py tests/test_utils.py tests/test_azure.py tests/test_sftp.py
```
