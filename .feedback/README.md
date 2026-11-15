# Local preparation

Python 3.12. Existing dependencies and pytest are pinned. No application source or upstream test was modified.

All existing local tests are included.

## Install

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

## Existing baseline

```sh
.venv/bin/python -m pytest -q -o addopts= tests
```

Observed successful wall time: 0.579 seconds.
