# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= netaddr/tests/ip/test_ip_sets.py netaddr/tests/ip/test_ip_v4_v6_conversions.py
```
