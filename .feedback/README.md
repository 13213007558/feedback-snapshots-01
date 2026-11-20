# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q tests/unit/sign_test.py tests/unit/get_object_test.py tests/unit/put_object_test.py tests/unit/rdma_test.py
```
