# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -c 'from kr8s._config import KubeConfig; import anyio; c={'"'"'current-context'"'"':'"'"'a'"'"','"'"'contexts'"'"':[{'"'"'name'"'"':'"'"'a'"'"','"'"'context'"'"':{'"'"'cluster'"'"':'"'"'x'"'"'}}],'"'"'clusters'"'"':[{'"'"'name'"'"':'"'"'x'"'"','"'"'cluster'"'"':{'"'"'server'"'"':'"'"'https://example.invalid'"'"'}}], '"'"'users'"'"':[]}; k=KubeConfig(c); assert k.get(pointer='"'"'/current-context'"'"') == '"'"'a'"'"'; assert k.get_context('"'"'a'"'"')['"'"'cluster'"'"'] == '"'"'x'"'"'; print('"'"'KubeConfig current context and cluster passed'"'"')'
```
