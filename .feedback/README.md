# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -c 'import os, sys, pytest; os.environ['"'"'AWS_EC2_METADATA_DISABLED'"'"']='"'"'true'"'"'; raise SystemExit(pytest.main(sys.argv[1:]))' -q -o addopts= test/unit
```
