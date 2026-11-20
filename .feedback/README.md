# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q tests/test_dataset.py tests/test_filereader.py tests/test_fileset.py -k 'not constrained_to_fileset_root'
```
