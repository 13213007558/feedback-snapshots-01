---
order: 11
---

# Taskiq message format

Taskiq doesn't force you to use any specific message format. We define a default message format,
but you can use any format you want.

The default message format is:


::: tabs

@tab example

```json
{
    "task_name": "my_project.module1.task",
    "args": [1, 2, 3],
    "kwargs": {"a": 1, "b": 2, "c": 3},
    "labels": {
        "label1": "value1",
        "label2": "value2"
    }
}
```

@tab json schema

```json
{
  "properties": {
    "task_id": {
      "title": "Task Id",
      "type": "string"
    },
    "task_name": {
      "title": "Name of the task",
      "type": "string"
    },
    "labels": {
      "title": "Additional labels",
      "type": "object"
    },
    "args": {
      "items": {},
      "title": "Arguments",
      "type": "array"
    },
    "kwargs": {
      "title": "Keyword arguments",
      "type": "object"
    }
  },
  "required": [
    "task_id",
    "task_name",
    "labels",
    "args",
    "kwargs"
  ],
  "type": "object"
}
```

:::

But this can be easily changed by creating your own implementation of the TaskiqFormatter class or TaskiqSerializer class.


### Serializers

Serializers define the format of the message but not the structure. For example, if you want to use msgpack or ORJson to serialize your message, you should update the serializer of your broker.

By default, Taskiq uses JSON serializer. But we also have some implementations of other serializers:

* ORJSONSerializer - faster [JSON implementation](https://pypi.org/project/orjson/). Also, it supports datetime and UUID serialization.
* MSGPackSerializer - [MsgPack](https://pypi.org/project/msgpack/) format serializer. It might be useful to send less data over the network.
* CBORSerializer - [CBOR](https://pypi.org/project/cbor2/) format serializer. It also has a smaller size than JSON.

To define your own serializer, you have to subclass the TaskiqSerializer class and implement `dumpb` and `loadb` methods. You can take a look at the existing implementations from the `taskiq.serializers` module.

To install taskiq with libraries for non-JSON serializers, you should install taskiq with extras.

::: tabs

@tab orjson

```bash
pip install "taskiq[orjson]"
```

@tab msgpack

```bash
pip install "taskiq[msgpack]"
```

@tab cbor

```bash
pip install "taskiq[cbor]"
```

:::


After that, you can use your preferred serializer in your project like this:

::: tabs

@tab orjson

```python
from taskiq import InMemoryBroker
from taskiq.serializers import ORJSONSerializer

broker = InMemoryBroker().with_serializer(ORJSONSerializer())
```

@tab msgpack

```python
from taskiq import InMemoryBroker
from taskiq.serializers import MSGPackSerializer

broker = InMemoryBroker().with_serializer(MSGPackSerializer())
```

@tab cbor

```python
from taskiq import InMemoryBroker
from taskiq.serializers import CBORSerializer

broker = InMemoryBroker().with_serializer(CBORSerializer())
```

:::



### Formatters

Formatters define the format of the message. It might be useful if you'd like to send a task to a celery worker for a different project. You can do it in serializer as well, but formatters give you correct type hints.

By default we use a formatter that dumps the message to dict and serializes it using serializer. But you can define your own formatter to send a message in any format you want. To define a new formatter, you have to subclass the TaskiqFormatter class and implement `dumps` and `loads` methods.
As an example, you can take a look at the `JSONFormatter` from `taskiq.formatters` implementation.


### Channel-bound formats

A single worker may consume queues whose producers are on different
message versions during a migration. Instead of one broker-wide
`formatter`, the receiver can pick a formatter from the formats approved
for the channel a delivery came from.

Declare a `ChannelFormatPolicy` and install it on the broker:

```python
from taskiq import ChannelFormat, ChannelFormatPolicy
from taskiq.formatters.json_formatter import JSONFormatter
from taskiq.formatters.proxy_formatter import ProxyFormatter

broker.with_channel_formats(
    ChannelFormatPolicy(
        channels={
            # Legacy producer: still approved during the migration.
            "legacy": (ChannelFormat(ProxyFormatter(broker), legacy=True),),
            # Upgraded producer.
            "upgraded": (ChannelFormat(JSONFormatter()),),
        },
        default_channel="upgraded",
    ),
)
```

The selection works like this:

- The receiver reads the policy **once** per delivery, before parsing, and
  captures the channel, version, formatter and policy generation. Parsing,
  dependency resolution, task execution, result saving and acknowledgement
  all use that same decision.
- Only the formats approved for the delivery's channel are considered. A
  formatter's `matches()` method reports whether a payload belongs to its
  exact wire version; a truthful match wins and is never re-tried with
  another formatter. Formatters with no opinion (`matches()` returns
  `None`) are ordered by declaration, so selection is deterministic.
- A payload approved for one channel is **rejected** on a channel that does
  not approve it, even if the other formatter could parse it. Selection is
  never decided by "did parsing succeed".
- A delivery with no channel, when there is no `default_channel`, or from a
  channel that is not configured, is rejected as `unknown-channel`.
- A parse error stops the delivery (`parse-error`): no fallback formatter,
  no task lookup, no dependency expansion, no result. If the delivery is
  ackable it is acknowledged so the broker stops redelivering it.

Rejections are logged with the channel, the approved versions, the selected
version and the policy generation. Pass `on_format_rejected` to a
`Receiver` to record them, and `on_format_selected` to record the decision
taken for each accepted delivery.

#### Reloading the policy

`with_channel_formats()` replaces the whole policy atomically and bumps its
generation. Because each delivery captures the policy it started with, a
reload that happens while a message is being parsed does not change that
message: it keeps its formatter, executes its business target, saves its
result and acknowledges under the old generation. Messages received after
the reload follow only the new policy.

During a transition keep the old formats in the channel while both
producers are active, then reload with a policy that lists only the
upgraded formats. The old payloads are then rejected with
`format-mismatch` instead of being silently parsed by the new formatter.

`MultiBroker` tags every merged delivery with the routing label it was
read from, so channel-bound formats work for multi-queue workers without
extra wiring.
