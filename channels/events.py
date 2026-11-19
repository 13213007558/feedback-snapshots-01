from copy import deepcopy
from dataclasses import dataclass

from asgiref.sync import async_to_sync

from .consumer import AsyncConsumer, SyncConsumer
from .db import database_sync_to_async
from .exceptions import InvalidSubscription, UnknownEventFieldError
from .layers import get_channel_layer

# Marker stored in a field trie to show that the whole subtree at that path
# (the value as it appears in the event, however deep) is part of the selection.
_FULL_SUBTREE = object()


def _build_field_trie(field_paths):
    """
    Builds a nested-dict trie from dotted field paths. A terminal node maps to
    ``_FULL_SUBTREE`` meaning the value at that path is taken wholesale.
    """
    trie = {}
    for path in field_paths:
        if not isinstance(path, str) or not path or path.startswith("."):
            raise InvalidSubscription(
                "Field paths must be non-empty strings, got %r" % (path,)
            )
        parts = path.split(".")
        if any(part == "" for part in parts):
            raise InvalidSubscription(
                "Field paths cannot contain empty segments, got %r" % (path,)
            )
        node = trie
        for part in parts[:-1]:
            child = node.get(part)
            if child is _FULL_SUBTREE:
                # A prefix already selected the whole subtree; this path is
                # redundant rather than conflicting, so nothing more is needed.
                node = None
                break
            if child is None:
                child = {}
                node[part] = child
            node = child
        if node is not None:
            node.setdefault(parts[-1], _FULL_SUBTREE)
    return trie


def _copy_path(value, node):
    """
    Copies only the keys of ``value`` that the trie ``node`` selects. Missing
    keys and keys whose event value is not a mapping where deeper fields were
    declared are skipped. Nested mappings that end up selecting nothing are
    pruned rather than emitted as empty dicts.
    """
    result = {}
    for key, selection in node.items():
        if key not in value:
            continue
        if selection is _FULL_SUBTREE:
            result[key] = deepcopy(value[key])
        else:
            nested = value[key]
            if isinstance(nested, dict):
                copied = _copy_path(nested, selection)
                if copied:
                    result[key] = copied
    return result


def project_event(event, fields):
    """
    Returns a projection of ``event`` containing only the selected fields.

    ``fields`` is either ``None`` (the legacy default: the complete event is
    returned, deep-copied so subscribers can never mutate each other's data)
    or a list of dotted field paths such as ``["id", "actor.name"]``. The
    routing ``type`` key is always retained, because the consumer needs it to
    dispatch the event to a handler.
    """
    if fields is None:
        return deepcopy(event)

    if not isinstance(fields, (list, tuple)) or not fields:
        raise InvalidSubscription(
            "fields must be a non-empty list of field paths, got %r" % (fields,)
        )
    if not all(isinstance(path, str) for path in fields):
        raise InvalidSubscription("Every field path must be a string: %r" % (fields,))

    projected = {}
    if "type" in event:
        projected["type"] = event["type"]

    trie = _build_field_trie(fields)
    projected.update(_copy_path(event, trie))
    return projected


def _assert_no_unknown_fields(value, node, path):
    """
    Recursively asserts that every key of the mapping ``value`` is reachable
    through the trie ``node``. A key selected wholesale terminates the check
    for that subtree.
    """
    for key in value:
        if key == "type":
            continue
        if key not in node:
            full_path = "%s.%s" % (path, key) if path else key
            raise UnknownEventFieldError(
                "Event contains undeclared field %r" % full_path
            )
        selection = node[key]
        if selection is not _FULL_SUBTREE:
            nested = value[key]
            if isinstance(nested, dict):
                _assert_no_unknown_fields(
                    nested, selection, "%s.%s" % (path, key) if path else key
                )


def assert_event_allowed(event, fields):
    """
    Raises ``UnknownEventFieldError`` if ``event`` carries any field that a
    strict subscription (``reject_unknown=True``) did not declare. A
    subscription without a field selection accepts every field.
    """
    if fields is None:
        return
    trie = _build_field_trie(fields)
    _assert_no_unknown_fields(event, trie, "")


@dataclass
class Subscription:
    """
    A consumer's declaration of the events it wants and the fields it is
    willing to receive.

    - ``topic``: routing key the event is published under.
    - ``channel_name``: channel layer channel the projected event is sent to.
    - ``fields``: dotted field paths the consumer accepts, or ``None`` to keep
      receiving the complete event (the backwards-compatible default).
    - ``reject_unknown``: when true, publishing an event containing fields not
      covered by ``fields`` raises ``UnknownEventFieldError`` instead of
      silently dropping them.
    """

    topic: str
    channel_name: str
    fields: list = None
    reject_unknown: bool = False

    def __post_init__(self):
        if not isinstance(self.topic, str) or not self.topic:
            raise InvalidSubscription("topic must be a non-empty string")
        if not isinstance(self.channel_name, str) or not self.channel_name:
            raise InvalidSubscription("channel_name must be a non-empty string")
        if self.fields is not None:
            if not isinstance(self.fields, (list, tuple)) or not self.fields:
                raise InvalidSubscription(
                    "fields must be None or a non-empty list of field paths"
                )
            # Validate the paths eagerly so a bad declaration fails at
            # subscription time rather than on the first published event.
            _build_field_trie(self.fields)
        if not isinstance(self.reject_unknown, bool):
            raise InvalidSubscription("reject_unknown must be a boolean")


class EventBroker:
    """
    Fan-out broker layered on top of a channel layer.

    Publishers call :meth:`publish` with a topic and an event. Every
    :class:`Subscription` on that topic receives its own deep-copied
    projection of the event, so two subscriptions with different field
    selections can consume the same message without one altering what the
    other's handler sees.
    """

    def __init__(self, channel_layer=None):
        self.channel_layer = (
            channel_layer if channel_layer is not None else get_channel_layer()
        )
        if self.channel_layer is None:
            raise InvalidSubscription(
                "An EventBroker requires a configured channel layer"
            )
        # topic -> {channel_name: Subscription}
        self._subscriptions = {}

    async def subscribe(self, subscription):
        if not isinstance(subscription, Subscription):
            raise InvalidSubscription(
                "subscribe() expects a Subscription instance"
            )
        self.channel_layer.require_valid_topic_name(subscription.topic)
        self.channel_layer.require_valid_channel_name(subscription.channel_name)
        self._subscriptions.setdefault(subscription.topic, {})[
            subscription.channel_name
        ] = subscription

    async def unsubscribe(self, topic, channel_name):
        subscribers = self._subscriptions.get(topic)
        if subscribers is not None:
            subscribers.pop(channel_name, None)
            if not subscribers:
                self._subscriptions.pop(topic, None)

    async def publish(self, topic, event):
        if not isinstance(event, dict):
            raise TypeError("event must be a dict")
        self.channel_layer.require_valid_topic_name(topic)

        subscribers = list(self._subscriptions.get(topic, {}).values())
        if not subscribers:
            return

        # Project for every subscriber before delivering anything. A strict
        # subscription rejecting an unknown field therefore fails the whole
        # publish and no subscriber receives a partial fan-out.
        deliveries = []
        for subscription in subscribers:
            if subscription.reject_unknown:
                assert_event_allowed(event, subscription.fields)
            projected = project_event(event, subscription.fields)
            deliveries.append((subscription.channel_name, projected))

        for channel_name, projected in deliveries:
            await self.channel_layer.send(channel_name, projected)


class AsyncEventConsumer(AsyncConsumer):
    """
    Consumer base class that joins field-level event subscriptions before
    normal message dispatch begins and leaves them again on shutdown.

    Subclasses set ``event_subscriptions`` to a list of dictionaries with the
    :class:`Subscription` keyword arguments, or call :meth:`subscribe` from a
    handler to join dynamically. A subscription without ``fields`` keeps the
    complete event, so existing consumers behave exactly as before.
    """

    event_broker = None
    event_subscriptions = None

    @classmethod
    def get_event_broker(cls):
        if cls.event_broker is None:
            cls.event_broker = EventBroker()
        return cls.event_broker

    async def join_event_subscriptions(self):
        if self.event_subscriptions:
            broker = self.get_event_broker()
            for declaration in self.event_subscriptions:
                await broker.subscribe(
                    Subscription(channel_name=self.channel_name, **declaration)
                )

    async def leave_event_subscriptions(self):
        if self.event_subscriptions and getattr(self, "channel_name", None):
            broker = self.get_event_broker()
            for declaration in self.event_subscriptions:
                await broker.unsubscribe(
                    declaration["topic"], self.channel_name
                )

    async def subscribe(self, topic, fields=None, reject_unknown=False):
        broker = self.get_event_broker()
        await broker.subscribe(
            Subscription(
                topic=topic,
                channel_name=self.channel_name,
                fields=fields,
                reject_unknown=reject_unknown,
            )
        )

    async def unsubscribe(self, topic):
        await self.get_event_broker().unsubscribe(topic, self.channel_name)


class SyncEventConsumer(SyncConsumer):
    """
    Synchronous counterpart of :class:`AsyncEventConsumer`. Handlers are
    plain blocking methods. Lifecycle hooks stay coroutines (the shared
    ``__call__`` awaits them) and talk to the broker directly; only the
    handler-facing subscribe helpers wrap the broker for blocking code.
    """

    event_broker = None
    event_subscriptions = None

    @classmethod
    def get_event_broker(cls):
        if cls.event_broker is None:
            cls.event_broker = EventBroker()
        return cls.event_broker

    async def join_event_subscriptions(self):
        if self.event_subscriptions:
            broker = self.get_event_broker()
            for declaration in self.event_subscriptions:
                await broker.subscribe(
                    Subscription(channel_name=self.channel_name, **declaration)
                )

    async def leave_event_subscriptions(self):
        if self.event_subscriptions and getattr(self, "channel_name", None):
            broker = self.get_event_broker()
            for declaration in self.event_subscriptions:
                await broker.unsubscribe(
                    declaration["topic"], self.channel_name
                )

    @database_sync_to_async
    def subscribe(self, topic, fields=None, reject_unknown=False):
        async_to_sync(self.get_event_broker().subscribe)(
            Subscription(
                topic=topic,
                channel_name=self.channel_name,
                fields=fields,
                reject_unknown=reject_unknown,
            )
        )

    @database_sync_to_async
    def unsubscribe(self, topic):
        async_to_sync(self.get_event_broker().unsubscribe)(
            topic, self.channel_name
        )
