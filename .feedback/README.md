# Local preparation

Python 3.12. Existing dependencies and pytest are pinned. No application source or upstream test was modified.

The quick suite selects the existing VMFS layout and JBOSF tests. Full LVM/content/sparse suite also passed in 43.276 seconds; its evidence is retained locally.

## Install

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

## Existing baseline

```sh
.venv/bin/python -m pytest -q -o addopts= tests -k 'not huge and not lvm_basic and not lvm_span and not content and not sparse'
```

Observed successful wall time: 7.880 seconds.
