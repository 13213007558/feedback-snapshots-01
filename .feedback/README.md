# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e nats
.venv/bin/python -c 'from nats.aio.msg import Msg; from nats.js.api import ConsumerConfig; c=ConsumerConfig(durable_name='"'"'demo'"'"',ack_wait=3); assert c.as_dict()['"'"'ack_wait'"'"']==3000000000 and Msg(None,subject='"'"'help.test'"'"',data=b'"'"'ok'"'"').data==b'"'"'ok'"'"'; print('"'"'JetStream options and local message exercised'"'"')'
```
