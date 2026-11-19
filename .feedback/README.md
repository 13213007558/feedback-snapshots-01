# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q test_opensearchpy/test_client/test_normalize_hosts.py test_opensearchpy/test_connection/test_requests_http_connection.py test_opensearchpy/test_connection/test_urllib3_http_connection.py -o asyncio_default_fixture_loop_scope=function test_opensearchpy/test_async/test_aiohttp.py::TestAIOHttp::test_default
```
