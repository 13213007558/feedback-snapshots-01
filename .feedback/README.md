# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -c 'from sqlalchemy import create_engine, inspect, Column, Integer; from alembic.migration import MigrationContext; from alembic.operations import Operations; e=create_engine('"'"'sqlite://'"'"'); c=e.connect(); a=Operations(MigrationContext.configure(c)); a.create_table('"'"'events'"'"',Column('"'"'id'"'"',Integer,primary_key=True)); assert inspect(c).get_table_names()==['"'"'events'"'"']; print('"'"'Alembic operations applied to in-memory SQLite'"'"')'
```
