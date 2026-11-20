# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt
.venv/bin/python -m pytest -q tests/brokers/test_inmemory.py tests/brokers/test_multi_broker.py tests/scheduler/test_merge_funcs.py tests/serializers/test_json_serializer.py
```
