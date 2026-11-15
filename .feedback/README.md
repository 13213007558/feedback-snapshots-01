# Local preparation

Python 3.12. Requirements pin the dependencies used in the successful baseline, including the existing test runner. Tests run locally without external services.

## Install

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

## Existing quick tests

```sh
.venv/bin/python -m pytest -q -o addopts= tests/crypto tests/luks/test_metadata.py tests/bde/test_eow.py
```

Observed successful source baseline: 3.715 seconds (wall time, not a performance requirement).
This command selects the existing quick suite. It does not claim full-suite coverage. Run additional existing tests relevant to a change.

Only preparation metadata was added. The application and existing tests remain at the recorded upstream commit.
