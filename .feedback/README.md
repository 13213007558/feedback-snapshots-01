# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q test/unit/verify/test_policy.py test/unit/verify/test_verifier.py test/unit/internal/test_trust.py test/unit/test_dsse.py
```
