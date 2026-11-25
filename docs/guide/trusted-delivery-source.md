---
order: 12
---

# Trusted delivery source

Taskiq workers can consume several delivery channels at once, for example
with the [`MultiBroker`](../available-components/brokers.md#multibroker) or
by running more than one receiver in the same process. Every channel may
deliver a message with the same task name, but not every channel should be
allowed to run every task.

Message **labels** are not suitable for that decision: they are created by
the sender, travel over the wire and can be modified by any middleware with
a `pre_execute` hook. A task that opens a database connection must decide
whether it may do so based on the channel that actually delivered the
message, not on a value inside the payload.

## Binding a task to its sources

Pass the `allowed_sources` keyword to the task decorator. It accepts one
broker or a tuple of brokers and is never serialized into a message.

```python
from taskiq import MultiBroker
from taskiq_aio_pika import AioPikaBroker

internal_broker = AioPikaBroker("amqp://guest:guest@internal:5672/")
public_broker = AioPikaBroker("amqp://guest:guest@public:5672/")

broker = MultiBroker(
    routing={"internal": internal_broker, "public": public_broker},
)


@broker.task(allowed_sources=(internal_broker,))
async def connect_to_database() -> None:
    ...
```

A delivery of `connect_to_database` that arrives through `public_broker`
is rejected. The rejection is stored as a task result with a
`SourceNotAuthorizedError`; the task body and every dependency are skipped,
and the message is acknowledged.

Tasks without `allowed_sources` keep working exactly as before on every
channel. `allowed_sources` can also be used with `broker.register_task`.

## What the receiver checks

The receiver resolves the delivery channel before deserialization and
before middlewares run:

- `MultiBroker` wraps every delivery in `SourcedMessage`, so the receiver
  knows which inner broker produced it.
- Any other broker is its own source.

The resulting `ReceiveContext` is bound to the context variable of the
execution and captures the receiving broker, the actual source, and the
task identity. The check happens before `pre_execute` hooks and before the
dependency graph is resolved, so middleware cannot grant access by adding
or rewriting labels, and a task that is rejected never opens a connection.

## Using the context in dependencies

The context is available through `Context.receive_context`, through the
`ReceiveContext` dependency, or directly through `get_receive_context()`.
It is immutable and stays consistent across asynchronous code and tasks
that run in a thread pool.

```python
from collections.abc import AsyncGenerator

from taskiq import Context, ReceiveContext, TaskiqDepends


async def get_connection(
    receive_context: ReceiveContext = TaskiqDepends(),
) -> AsyncGenerator[Connection, None]:
    receive_context.require_source(internal_broker)
    connection = await open_connection()
    try:
        yield connection
    except Exception:
        await connection.rollback()
        raise
    else:
        await connection.commit()
    finally:
        await connection.close()
```

`require_source` raises `SourceNotAuthorizedError` if the delivery did not
come from one of the approved brokers. `matches` also accepts the broker
that accepted a composite delivery, which is useful when a whole
`MultiBroker` is approved rather than its inner brokers.

Because the context is a context variable, it is restored when the delivery
finishes, including after a business exception. The next delivery starts
with its own context and can never observe the previous one.

## Middleware labels still work

`allowed_sources` is not a label. Middlewares can continue to add ordinary
labels in `pre_send` or `pre_execute` for logging, routing or retry
bookkeeping without affecting authorization. Changing labels that look
security related does not change the decision either.
