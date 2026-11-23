# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= -W ignore::pytest.PytestUnknownMarkWarning tests/cache/test_region.py -k 'test_set_get or test_multi_creator or test_replace_backend_config'
```
