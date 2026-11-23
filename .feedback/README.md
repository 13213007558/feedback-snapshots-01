# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -c 'import flask_security; from flask_security.password_util import PasswordUtil; from flask_security.tokens import RefreshTokenForm; assert flask_security.Security and callable(PasswordUtil.normalize) and RefreshTokenForm; print('"'"'Flask-Security integration imports passed'"'"')'
```
