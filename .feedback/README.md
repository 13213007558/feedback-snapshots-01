# Local preparation

Python 3.12. Existing dependencies and pytest are pinned. No application source or upstream test was modified.

The software suite excludes tests/device and the optional PCSC module. No authenticator, USB device, browser or external service is required.

## Install

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

## Existing baseline

```sh
.venv/bin/python -m pytest -q tests --ignore=tests/device --ignore=tests/test_pcsc.py
```

Observed successful wall time: 2.565 seconds.
