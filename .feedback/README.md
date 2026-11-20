# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e opentelemetry-api -e opentelemetry-semantic-conventions -e opentelemetry-sdk -e tests/opentelemetry-test-utils
.venv/bin/python -m pytest -q opentelemetry-sdk/tests/trace/test_sampling.py opentelemetry-sdk/tests/metrics/test_exemplarreservoir.py opentelemetry-sdk/tests/logs/test_log_limits.py opentelemetry-sdk/tests/shared_internal/test_batch_processor.py
```
