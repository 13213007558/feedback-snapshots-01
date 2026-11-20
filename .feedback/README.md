# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q s3fs/tests/test_get_file_options.py s3fs/tests/test_version_info_pages.py s3fs/tests/test_custom_error_handler.py s3fs/tests/test_utils.py
```
