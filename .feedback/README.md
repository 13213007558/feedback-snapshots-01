# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o asyncio_default_fixture_loop_scope=function --ds=tests.projects.regular.settings tests/apps/account/test_login.py tests/apps/account/test_change_email.py tests/apps/account/test_reauthentication.py tests/apps/mfa/base/test_trust.py tests/apps/headless/tokens/test_jwttokenstrategy.py tests/apps/headless/usersessions/test_activity.py
```
