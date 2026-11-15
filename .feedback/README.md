# Local preparation

Python 3.12. Requirements pin the dependencies used in the successful baseline, including the existing test runner. Tests run locally without external services.

## Install

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

## Existing quick tests

```sh
.venv/bin/python -m pytest -q -o addopts= tests --ignore=tests/sqlite3/test_sqlcipher.py --benchmark-disable --ignore=tests/ese/ntds/test_benchmark.py -k 'not test_all_memberships and not test_large_db'
```

Observed successful source baseline: 7.424 seconds (wall time, not a performance requirement).
The full source suite also passed in 31.516 seconds. The quick command omits SQLCipher and large membership/database benchmarks; the -k selection is intentional.

Only preparation metadata was added. The application and existing tests remain at the recorded upstream commit.
