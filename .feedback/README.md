# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -c 'from pathlib import Path; from twine import settings; from twine.repository import Repository; s=settings.Settings(repository='"'"'pypi'"'"', username='"'"'fixture'"'"', password='"'"'local'"'"', non_interactive=True); assert s.repository_config.get('"'"'repository'"'"'); r=Repository(s.repository_config['"'"'repository'"'"'], '"'"'fixture'"'"', '"'"'local'"'"'); r.close(); print('"'"'Local repository configuration and session exercised'"'"')'
```
