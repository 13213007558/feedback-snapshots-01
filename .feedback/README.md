# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -c 'from django.conf import settings; settings.configure(INSTALLED_APPS=['"'"'crispy_forms'"'"'],CRISPY_TEMPLATE_PACK='"'"'bootstrap4'"'"',SECRET_KEY='"'"'local-fixture'"'"'); import django; django.setup(); from crispy_forms.helper import FormHelper; from crispy_forms.layout import Layout, Field; h=FormHelper(); h.layout=Layout(Field('"'"'name'"'"')); assert len(h.layout.fields)==1; print('"'"'Form helper and layout initialized locally'"'"')'
```
