# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -c 'from readme_renderer.rst import render; s=render(chr(10).join(['"'"'Example'"'"','"'"'======='"'"','"'"''"'"','"'"'Ordinary **text**.'"'"'])); assert s and '"'"'<strong>text</strong>'"'"' in s; print('"'"'Local RST document rendered'"'"')'
```
