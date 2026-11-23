# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -c 'from python_socks.sync import Proxy; p=Proxy.from_url('"'"'socks5://127.0.0.1:8050'"'"'); assert p._proxy_host=='"'"'127.0.0.1'"'"' and p._proxy_port==8050; print('"'"'Proxy address parsed without opening a socket'"'"')'
```
