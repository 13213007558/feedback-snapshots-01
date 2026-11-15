# Local preparation

Python 3.12. Existing dependencies and pytest are pinned. No application source or upstream test was modified.

The existing CLI smoke test writes fixed /tmp/example.docx and /tmp/example_password.docx paths and cannot run safely across independent simultaneous copies. The parallel quick baseline runs the existing library tests, explicitly excluding tests/test_cli.py. The original complete source suite passed sequentially in 4.711 seconds. To run that CLI smoke test, serialize it and put the active virtualenv on PATH.

## Install

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

## Existing baseline

```sh
.venv/bin/python .feedback/baseline.py
```

Observed successful wall time: 3.487 seconds.
