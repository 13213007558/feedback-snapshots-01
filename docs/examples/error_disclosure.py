"""Configurable error disclosure -- runnable example.

Run it with::

    python docs/examples/error_disclosure.py

The same schema is exercised three ways:

1. a *non-null* field whose resolver throws an internal error,
2. a selection of *sibling* fields where one raises a public validation error
   while the others still resolve, and
3. a *subscription* whose event stream mixes healthy events with failures.

In every case the client only receives a safe error category plus the response
``path`` (and the agreed extension fields), while the original exception is handed
to an internal logging callback.
"""

from __future__ import annotations

import asyncio
import json
from itertools import count

from graphql import (
    DisclosureMode,
    ErrorDisclosurePolicy,
    GraphQLField,
    GraphQLInt,
    GraphQLNonNull,
    GraphQLObjectType,
    GraphQLSchema,
    GraphQLString,
    PublicGraphQLError,
    execute,
    parse,
    subscribe,
)
from graphql.pyutils import SimplePubSub, is_awaitable


# --------------------------------------------------------------------------- #
# Schema: a Sensor with a nullable label and a non-null reading.
# --------------------------------------------------------------------------- #


class SecretDatabaseError(RuntimeError):
    """An internal fault whose details must never reach a public client."""


def resolve_label(sensor, info):
    # A configured label resolves normally; otherwise the application reports an
    # expected, user-facing validation error that it approves for disclosure.
    if "label" in sensor:
        return sensor["label"]
    raise PublicGraphQLError(
        "Label is not configured for this sensor.",
        path=None,
        extensions={"code": "LABEL_MISSING", "field": "label"},
    )


def resolve_reading(sensor, info):
    # A cached reading resolves normally; a cache miss hits the failing database.
    if "reading" in sensor:
        return sensor["reading"]
    # Unexpected resolver failure: note the message contains a sensitive DSN.
    raise SecretDatabaseError(
        "connect failed: postgres://user:pw@10.0.0.5/metrics timeout"
    )


sensor_type = GraphQLObjectType(
    "Sensor",
    {
        "id": GraphQLField(GraphQLNonNull(GraphQLString)),
        "label": GraphQLField(GraphQLString, resolve=resolve_label),
        # Non-null: a failure here cannot be returned as ``reading: null`` and
        # therefore bubbles up and nulls the whole ``sensor`` object.
        "reading": GraphQLField(GraphQLNonNull(GraphQLInt), resolve=resolve_reading),
    },
)

pubsub = SimplePubSub()


async def resolve_sensor_event(event, info):
    """Unwrap the published source event for per-event execution.

    ``SimplePubSub`` hands the resolver a future that resolves to the published,
    field-keyed payload; awaiting it yields the sensor object on which the nested
    ``label``/``reading`` resolvers then run, exactly as in a query.
    """
    value = event
    while asyncio.isfuture(value) or asyncio.iscoroutine(value):
        value = await value
    return value["sensorEvent"]


schema = GraphQLSchema(
    query=GraphQLObjectType(
        "Query",
        {
            "sensor": GraphQLField(
                sensor_type, resolve=lambda root, info: {"id": "sensor-42"}
            )
        },
    ),
    subscription=GraphQLObjectType(
        "Subscription",
        {
            "sensorEvent": GraphQLField(
                sensor_type,
                # ``subscribe`` produces the source stream; ``resolve`` unwraps each
                # published event so the nested Sensor resolvers can execute.
                resolve=resolve_sensor_event,
                subscribe=lambda root, info: pubsub.get_subscriber(
                    lambda sensor: {"sensorEvent": sensor}
                ),
            )
        },
    ),
)


# --------------------------------------------------------------------------- #
# Policy configuration: strict by default, with an internal logging handler.
# --------------------------------------------------------------------------- #

error_ids = count(1)
internal_log: list[str] = []


def log_internal_error(error):
    """Receive the *original* exception for internal handling/logging."""
    original = policy.original_error(error)
    internal_log.append(
        f"{type(original).__name__ if original else 'GraphQLError'}: "
        f"{original or error.message} at path={error.path}"
    )


policy = ErrorDisclosurePolicy(
    mode=DisclosureMode.STRICT,
    on_internal_error=log_internal_error,
    error_id_factory=lambda: f"evt-{next(error_ids)}",
)


def show(title, payload):
    print(f"\n=== {title} ===")
    print(json.dumps(payload, indent=2, ensure_ascii=False))


# --------------------------------------------------------------------------- #
# 1 & 2. Query: non-null field failure and sibling public validation error.
# --------------------------------------------------------------------------- #


def run_query():
    document = parse(
        """
        {
          sensor {
            id
            label
            reading
          }
        }
        """
    )
    result = execute(schema, document)

    # Internal view: the unmasked result still carries every GraphQLError.
    show("internal ExecutionResult.errors (for the server only)", result.formatted)

    # Public view: sanitized through the disclosure policy.
    show("public response (strict policy)", policy.disclose_result(result))


# --------------------------------------------------------------------------- #
# 3. Subscription: healthy and failing events on one stream.
# --------------------------------------------------------------------------- #


async def run_subscription():
    document = parse(
        """
        subscription {
          sensorEvent {
            id
            label
            reading
          }
        }
      """
    )
    result = subscribe(schema, document)
    if is_awaitable(result):
        result = await result

    published = [
        {"id": "sensor-1"},  # nested label/reading resolvers fail
        {"id": "sensor-2", "reading": 21, "label": "boiler"},  # healthy event
    ]

    # Wrap the raw response stream once; every event is sanitized on the way out.
    stream = policy.disclose_subscription(result)

    async def next_event(payload):
        # Start consuming so the subscriber is waiting, then publish the event.
        pending = asyncio.create_task(stream.__anext__())
        await asyncio.sleep(0)
        pubsub.emit(payload)
        return await pending

    public_events = [await next_event(published[0]), await next_event(published[1])]
    await stream.aclose()

    show("public subscription events", public_events)
    show("internal log of original exceptions", internal_log)


async def main():
    run_query()
    await run_subscription()
    print("\nInternal handlers saw the real exceptions; clients never did.")


if __name__ == "__main__":
    asyncio.run(main())
