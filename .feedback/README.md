# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q test/unit/test_caches.py test/unit/test_caches_local.py test/unit/test_streaming_client_stream_decryptor.py test/unit/test_providers_kms_master_key_provider.py
```
