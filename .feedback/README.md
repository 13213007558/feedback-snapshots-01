# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q tests/functional/data_masking/required_dependencies/test_erase_data_masking.py tests/unit/idempotency/test_dynamodb_persistence.py
```
