# Local preparation

Python 3.12. Requirements pin the dependencies used in the successful baseline, including the existing test runner. Tests run locally without external services. The baseline wrapper puts the active interpreter on PATH for CLI subprocess checks.

## Install

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

## Existing quick tests

```sh
.venv/bin/python .feedback/baseline.py
```

Observed successful source baseline: 4.711 seconds (wall time, not a performance requirement).

Only preparation metadata was added. The application and existing tests remain at the recorded upstream commit.
