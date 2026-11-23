# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt
.venv/bin/python -c 'from pathlib import Path; import msgpack; from msgpack import fallback; assert Path(msgpack.__file__).resolve().is_relative_to(Path.cwd()); data={'"'"'item'"'"':[1,2]}; assert fallback.unpackb(fallback.Packer().pack(data), raw=False)==data; print('"'"'Local pure-Python MessagePack round-trip passed'"'"')'
```
