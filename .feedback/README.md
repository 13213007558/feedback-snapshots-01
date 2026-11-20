# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -c 'from pathlib import Path; from tempfile import TemporaryDirectory; from tox.run import run; import os; root=os.getcwd(); p=TemporaryDirectory(); os.chdir(p.name); Path('"'"'tox.ini'"'"').write_text('"'"'[tox]\nenv_list = alpha,beta\n[testenv]\ncommands = python --version\n'"'"'); raise SystemExit(run(['"'"'list'"'"','"'"'-q'"'"']))'
```
