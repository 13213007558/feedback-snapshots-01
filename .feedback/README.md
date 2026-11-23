# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -c 'import xlsxwriter, io, zipfile; b=io.BytesIO(); w=xlsxwriter.Workbook(b); s=w.add_worksheet(); s.write_string('"'"'A1'"'"','"'"'plain'"'"'); w.close(); assert b'"'"'plain'"'"' in zipfile.ZipFile(b).read('"'"'xl/sharedStrings.xml'"'"'); print('"'"'Spreadsheet created entirely in memory'"'"')'
```
