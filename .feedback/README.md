# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -c 'import yaml; p=chr(10).join(['"'"'---'"'"','"'"'name: a'"'"','"'"'---'"'"','"'"'name: b'"'"']); assert list(yaml.safe_load_all(p))==[{'"'"'name'"'"':'"'"'a'"'"'},{'"'"'name'"'"':'"'"'b'"'"'}]; x={'"'"'data'"'"':[1,2,3]}; assert yaml.safe_load(yaml.safe_dump(x))==x; print('"'"'Safe load, dump, and stream loading passed'"'"')'
```
