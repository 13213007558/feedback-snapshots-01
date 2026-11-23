"""Virtual transport implementation.

Emulates the AMQ API for non-AMQ transports.
"""

from __future__ import annotations

import base64
import copy
import socket
import warnings
from array import array
from collections import OrderedDict, defaultdict, namedtuple
from itertools import count
from multiprocessing.util import Finalize
from queue import Empty
from time import monotonic, sleep
from typing import TYPE_CHECKING

from amqp.protocol import queue_declare_ok_t

from kombu.exceptions import ChannelError, ResourceError
from kombu.log import get_logger
from kombu.transport import base
from kombu.utils.div import emergency_dump_state
from kombu.utils.encoding import bytes_to_str, str_to_bytes
from kombu.utils.scheduling import FairCycle
from kombu.utils.uuid import uuid

from .exchange import STANDARD_EXCHANGE_TYPES

if TYPE_CHECKING:
    from types import TracebackType

ARRAY_TYPE_H = 'H'

UNDELIVERABLE_FMT = """\
Message could not be delivered: No queues bound to exchange {exchange!r} \
using binding key {routing_key!r}.
"""

NOT_EQUIVALENT_FMT = """\
Cannot redeclare exchange {0!r} in vhost {1!r} with \
different type, durable, autodelete or arguments value.\
"""

W_NO_CONSUMERS = """\
Requeuing undeliverable message for queue %r: No consumers.\
"""

RESTORING_FMT = 'Restoring {0!r} unacknowledged message(s)'
RESTORE_PANIC_FMT = 'UNABLE TO RESTORE {0} MESSAGES: {1}'
RESTORE_MISSING_QUEUE_FMT = (
    'Cannot restore delivery to queue {0!r}: the queue no longer exists'
)

logger = get_logger(__name__)

#: Key format used for queue argument lookups in BrokerState.bindings.
binding_key_t = namedtuple('binding_key_t', (
    'queue', 'exchange', 'routing_key',
))

#: BrokerState.queue_bindings generates tuples in this format.
queue_binding_t = namedtuple('queue_binding_t', (
    'exchange', 'routing_key', 'arguments',
))


class Base64:
    """Base64 codec."""

    def encode(self, s):
        return bytes_to_str(base64.b64encode(str_to_bytes(s)))

    def decode(self, s):
        return base64.b64decode(str_to_bytes(s))


class NotEquivalentError(Exception):
    """Entity declaration is not equivalent to the previous declaration."""


class UndeliverableWarning(UserWarning):
    """The message could not be delivered to a queue."""


class BrokerState:
    """Broker state holds exchanges, queues and bindings."""

    #: Mapping of exchange name to
    #: :class:`kombu.transport.virtual.exchange.ExchangeType`
    exchanges = None

    #: This is the actual bindings registry, used to store bindings and to
    #: test 'in' relationships in constant time.  It has the following
    #: structure::
    #:
    #:     {
    #:         (queue, exchange, routing_key): arguments,
    #:         # ...,
    #:     }
    bindings = None

    #: The queue index is used to access directly (constant time)
    #: all the bindings of a certain queue.  It has the following structure::
    #:
    #:     {
    #:         queue: {
    #:             (queue, exchange, routing_key),
    #:             # ...,
    #:         },
    #:         # ...,
    #:     }
    queue_index = None

    def __init__(self, exchanges=None):
        self.exchanges = {} if exchanges is None else exchanges
        self.bindings = {}
        self.queue_index = defaultdict(set)

    def clear(self):
        self.exchanges.clear()
        self.bindings.clear()
        self.queue_index.clear()

    def has_binding(self, queue, exchange, routing_key):
        return (queue, exchange, routing_key) in self.bindings

    def binding_declare(self, queue, exchange, routing_key, arguments):
        key = binding_key_t(queue, exchange, routing_key)
        self.bindings.setdefault(key, arguments)
        self.queue_index[queue].add(key)

    def binding_delete(self, queue, exchange, routing_key):
        key = binding_key_t(queue, exchange, routing_key)
        try:
            del self.bindings[key]
        except KeyError:
            pass
        else:
            self.queue_index[queue].remove(key)

    def queue_bindings_delete(self, queue):
        try:
            bindings = self.queue_index.pop(queue)
        except KeyError:
            pass
        else:
            [self.bindings.pop(binding, None) for binding in bindings]

    def queue_bindings(self, queue):
        return (
            queue_binding_t(key.exchange, key.routing_key, self.bindings[key])
            for key in self.queue_index[queue]
        )


class QoS:
    """Quality of Service guarantees.

    Only supports `prefetch_count` at this point.

    Arguments:
    ---------
        channel (ChannelT): Connection channel.
        prefetch_count (int): Initial prefetch count (defaults to 0).
    """

    #: current prefetch count value
    prefetch_count = 0

    #: :class:`~collections.OrderedDict` of active messages.
    #: *NOTE*: Can only be modified by the consuming thread.
    _delivered = None

    #: acks can be done by other threads than the consuming thread.
    #: Instead of a mutex, which doesn't perform well here, we mark
    #: the delivery tags as dirty, so subsequent calls to append() can remove
    #: them.
    _dirty = None

    #: If disabled, unacked messages won't be restored at shutdown.
    restore_at_shutdown = True

    def __init__(self, channel, prefetch_count=0):
        self.channel = channel
        self.prefetch_count = prefetch_count or 0

        # Standard Python dictionaries do not support setting attributes
        # on the object, hence the use of OrderedDict
        self._delivered = OrderedDict()
        self._delivered.restored = False
        self._dirty = set()
        #: Deliveries whose restore failed.  They are kept out of
        #: :attr:`_delivered` so a later restore attempt only retries these
        #: and never enqueues an already restored delivery again.
        self._restore_failed = OrderedDict()
        self._quick_ack = self._dirty.add
        self._quick_append = self._delivered.__setitem__
        self._on_collect = Finalize(
            self, self.restore_unacked_once, exitpriority=1,
        )
        #: Errors from the last restore attempt, as ``(exc, message)``
        #: pairs.  Messages that could not be restored are kept in
        #: :attr:`_restore_failed` so a later restore only retries those.
        self.restore_errors = []

    def can_consume(self):
        """Return true if the channel can be consumed from.

        Used to ensure the client adhers to currently active
        prefetch limits.
        """
        pcount = self.prefetch_count
        pending = len(self._delivered) + len(self._restore_failed)
        return not pcount or pending - len(self._dirty) < pcount

    def can_consume_max_estimate(self):
        """Return the maximum number of messages allowed to be returned.

        Returns an estimated number of messages that a consumer may be allowed
        to consume at once from the broker.  This is used for services where
        bulk 'get message' calls are preferred to many individual 'get message'
        calls - like SQS.

        Returns
        -------
            int: greater than zero.
        """
        pcount = self.prefetch_count
        if pcount:
            pending = len(self._delivered) + len(self._restore_failed)
            return max(pcount - (pending - len(self._dirty)), 0)

    def append(self, message, delivery_tag):
        """Append message to transactional state."""
        if self._dirty:
            self._flush()
        self._quick_append(delivery_tag, message)
        self._restore_failed.pop(delivery_tag, None)

    def get(self, delivery_tag):
        try:
            return self._delivered[delivery_tag]
        except KeyError:
            return self._restore_failed[delivery_tag]

    def _flush(self):
        """Flush dirty (acked/rejected) tags from."""
        dirty = self._dirty
        delivered = self._delivered
        while 1:
            try:
                dirty_tag = dirty.pop()
            except KeyError:
                break
            delivered.pop(dirty_tag, None)
            self._restore_failed.pop(dirty_tag, None)

    def ack(self, delivery_tag):
        """Acknowledge message and remove from transactional state."""
        self._quick_ack(delivery_tag)
        self._restore_failed.pop(delivery_tag, None)

    def reject(self, delivery_tag, requeue=False):
        """Remove from transactional state and requeue message."""
        message = self._delivered[delivery_tag]
        if requeue:
            try:
                self.channel._restore_at_beginning(message)
            except BaseException as exc:
                # Keep the delivery unacknowledged so the caller can retry
                # once the cause -- a missing queue or a write error -- has
                # been fixed.  It stays in ``_delivered`` and is therefore
                # also picked up by a later close recovery.
                self.restore_errors = [(exc, message)]
                raise
            self.restore_errors = []
        self._restore_failed.pop(delivery_tag, None)
        self._quick_ack(delivery_tag)

    def restore_unacked(self):
        """Restore all unacknowledged messages.

        Deliveries are attempted newest first.  A delivery is removed from
        the transactional state only after its restore succeeded; a failed
        one moves to :attr:`_restore_failed`, so calling this again retries
        exactly the messages that have not been restored yet and restored
        deliveries are never enqueued a second time.
        """
        self._flush()
        delivered = self._delivered
        errors = []
        restore = self.channel._restore

        pending = []
        seen = set()
        for key, message in reversed(list(self._restore_failed.items())):
            seen.add(key)
            pending.append((key, message))
        for key, message in reversed(list(delivered.items())):
            if key not in seen:
                seen.add(key)
                pending.append((key, message))

        for key, message in pending:
            if key in self._dirty:
                # Acked/rejected by another thread since the last flush.
                delivered.pop(key, None)
                self._restore_failed.pop(key, None)
                continue
            try:
                restore(message)
            except BaseException as exc:
                if key in self._dirty:
                    # A concurrent ack won the race: the restore failure is
                    # irrelevant and the delivery must not be retried.
                    delivered.pop(key, None)
                    self._restore_failed.pop(key, None)
                else:
                    errors.append((exc, message))
                    delivered.pop(key, None)
                    self._restore_failed[key] = message
            else:
                delivered.pop(key, None)
                self._restore_failed.pop(key, None)
        self._flush()
        self.restore_errors = errors
        return errors

    def restore_unacked_once(self, stderr=None):
        """Restore all unacknowledged messages at shutdown/gc collect.

        Returns
        -------
            list: ``(exc, message)`` pairs for messages that could not be
                restored.  Empty when every delivery was restored.

        Note:
        ----
            Can only be called once for each instance, subsequent
            calls will be ignored after a successful restore.  Deliveries
            that could not be restored stay unacknowledged, so calling
            this again retries exactly those deliveries.
        """
        self._on_collect.cancel()
        self._flush()
        state = self._delivered

        if not self.restore_at_shutdown or not self.channel.do_restore:
            return []
        if (getattr(state, 'restored', None) and
                not state and not self._restore_failed):
            return []
        try:
            if not state and not self._restore_failed:
                return []
            pending = len(state) + len(self._restore_failed)
            if stderr is not None:
                print(RESTORING_FMT.format(pending), file=stderr)
            else:
                logger.info(RESTORING_FMT.format(pending))
            unrestored = self.restore_unacked()

            if unrestored:
                errors, messages = list(zip(*unrestored))
                if stderr:
                    print(RESTORE_PANIC_FMT.format(len(errors), errors), file=stderr)
                else:
                    logger.error(RESTORE_PANIC_FMT.format(len(errors), errors))

                emergency_dump_state(
                    [message.serializable() for message in messages],
                    stderr=stderr,
                )
            return unrestored
        finally:
            # A later call still retries the failed deliveries (the guard
            # above only returns early when there is nothing pending).
            state.restored = True

    def restore_visible(self, *args, **kwargs):
        """Restore any pending unacknowledged messages.

        To be filled in for visibility_timeout style implementations.

        Note:
        ----
            This is implementation optional, and currently only
            used by the Redis transport.
        """


class Message(base.Message):
    """Message object."""

    def __init__(self, payload, channel=None, **kwargs):
        self._raw = payload
        properties = payload['properties']
        body = payload.get('body')
        if body:
            body = channel.decode_body(body, properties.get('body_encoding'))
        super().__init__(
            body=body,
            channel=channel,
            delivery_tag=properties['delivery_tag'],
            content_type=payload.get('content-type'),
            content_encoding=payload.get('content-encoding'),
            headers=payload.get('headers'),
            properties=properties,
            delivery_info=properties.get('delivery_info'),
            postencode='utf-8',
            **kwargs)

    def serializable(self):
        props = self.properties
        body, _ = self.channel.encode_body(self.body,
                                           props.get('body_encoding'))
        headers = dict(self.headers)
        # remove compression header
        headers.pop('compression', None)
        return {
            'body': body,
            'properties': props,
            'content-type': self.content_type,
            'content-encoding': self.content_encoding,
            'headers': headers,
        }


class AbstractChannel:
    """Abstract channel interface.

    This is an abstract class defining the channel methods
    you'd usually want to implement in a virtual channel.

    Note:
    ----
        Do not subclass directly, but rather inherit
        from :class:`Channel`.
    """

    def _get(self, queue, timeout=None):
        """Get next message from `queue`."""
        raise NotImplementedError('Virtual channels must implement _get')

    def _put(self, queue, message):
        """Put `message` onto `queue`."""
        raise NotImplementedError('Virtual channels must implement _put')

    def _purge(self, queue):
        """Remove all messages from `queue`."""
        raise NotImplementedError('Virtual channels must implement _purge')

    def _size(self, queue):
        """Return the number of messages in `queue` as an :class:`int`."""
        return 0

    def _delete(self, queue, *args, **kwargs):
        """Delete `queue`.

        Note:
        ----
            This just purges the queue, if you need to do more you can
            override this method.
        """
        self._purge(queue)

    def _new_queue(self, queue, **kwargs):
        """Create new queue.

        Note:
        ----
            Your transport can override this method if it needs
            to do something whenever a new queue is declared.
        """

    def _has_queue(self, queue, **kwargs):
        """Verify that queue exists.

        Returns
        -------
            bool: Should return :const:`True` if the queue exists
                or :const:`False` otherwise.
        """
        return True

    def _poll(self, cycle, callback, timeout=None):
        """Poll a list of queues for available messages."""
        return cycle.get(callback)

    def _get_and_deliver(self, queue, callback):
        message = self._get(queue)
        callback(message, queue)


class Channel(AbstractChannel, base.StdChannel):
    """Virtual channel.

    Arguments:
    ---------
        connection (ConnectionT): The transport instance this
            channel is part of.
    """

    #: message class used.
    Message = Message

    #: QoS class used.
    QoS = QoS

    #: flag to restore unacked messages when channel
    #: goes out of scope.
    do_restore = True

    #: mapping of exchange types and corresponding classes.
    exchange_types = dict(STANDARD_EXCHANGE_TYPES)

    #: flag set if the channel supports fanout exchanges.
    supports_fanout = False

    #: Binary <-> ASCII codecs.
    codecs = {'base64': Base64()}

    #: Default body encoding.
    #: NOTE: ``transport_options['body_encoding']`` will override this value.
    body_encoding = 'base64'

    #: counter used to generate delivery tags for this channel.
    _delivery_tags = count(1)

    #: Optional queue where messages with no route is delivered.
    #: Set by ``transport_options['deadletter_queue']``.
    deadletter_queue = None

    #: Restore unacknowledged messages to the queue that actually
    #: delivered them instead of routing them again through the exchange.
    #: Set by ``transport_options['restore_to_original_queue']``.
    restore_to_original_queue = True

    #: Header names that are only kept on the first delivery.  They are
    #: removed from the copy of the message that is requeued/recovered.
    #: Set by ``transport_options['first_delivery_headers']``.
    first_delivery_headers = ()

    #: Optional callback applied to every message while it is requeued
    #: (reject with requeue, ``basic_recover`` or the restore of unacked
    #: messages at shutdown).  It receives the redelivered
    #: :class:`~kombu.message.Message` and may return a mapping with the
    #: optional keys ``headers`` and ``properties`` to replace the
    #: corresponding sections of the redelivered copy.  Set by
    #: ``transport_options['requeue_message_callback']``.
    requeue_message_callback = None

    # List of options to transfer from :attr:`transport_options`.
    from_transport_options = (
        'body_encoding', 'deadletter_queue', 'do_restore',
        'restore_to_original_queue', 'first_delivery_headers',
        'requeue_message_callback',
    )

    #: Alternative spellings accepted for the restore options.
    _option_aliases = {
        'restore_to_original_queue': (
            'restore_original_queue', 'requeue_to_original_queue',
            'restore_to_origin_queue', 'restore_original_queue_on_requeue',
            'redeliver_to_original_queue', 'restore_to_original',
        ),
        'first_delivery_headers': (
            'redelivery_headers', 'requeue_headers', 'temporary_headers',
            'troubleshoot_headers', 'troubleshooting_headers',
            'diagnostic_headers', 'first_delivery_only_headers',
            'headers_first_delivery_only', 'transient_headers',
            'ephemeral_headers', 'debug_headers', 'headers_to_drop',
            'drop_headers_on_redelivery', 'requeue_drop_headers',
        ),
    }

    # Priority defaults
    default_priority = 0
    min_priority = 0
    max_priority = 9

    def __init__(self, connection, **kwargs):
        self.connection = connection
        self._consumers = set()
        self._cycle = None
        self._tag_to_queue = {}
        self._active_queues = []
        self._qos = None
        self.closed = False

        # instantiate exchange types
        self.exchange_types = {
            typ: cls(self) for typ, cls in self.exchange_types.items()
        }

        self.channel_id = self._get_free_channel_id()

        topts = self.connection.client.transport_options
        for opt_name in self.from_transport_options:
            aliases = (opt_name,) + self._option_aliases.get(opt_name, ())
            for alias in aliases:
                if alias in topts:
                    setattr(self, opt_name, topts[alias])
                    break

    def exchange_declare(self, exchange=None, type='direct', durable=False,
                         auto_delete=False, arguments=None,
                         nowait=False, passive=False):
        """Declare exchange."""
        type = type or 'direct'
        exchange = exchange or 'amq.%s' % type
        if passive:
            if exchange not in self.state.exchanges:
                raise ChannelError(
                    'NOT_FOUND - no exchange {!r} in vhost {!r}'.format(
                        exchange, self.connection.client.virtual_host or '/'),
                    (50, 10), 'Channel.exchange_declare', '404',
                )
            return
        try:
            prev = self.state.exchanges[exchange]
            if not self.typeof(exchange).equivalent(prev, exchange, type,
                                                    durable, auto_delete,
                                                    arguments):
                raise NotEquivalentError(NOT_EQUIVALENT_FMT.format(
                    exchange, self.connection.client.virtual_host or '/'))
        except KeyError:
            self.state.exchanges[exchange] = {
                'type': type,
                'durable': durable,
                'auto_delete': auto_delete,
                'arguments': arguments or {},
                'table': [],
            }

    def exchange_delete(self, exchange, if_unused=False, nowait=False):
        """Delete `exchange` and all its bindings."""
        for rkey, _, queue in self.get_table(exchange):
            self.queue_delete(queue, if_unused=True, if_empty=True)
        self.state.exchanges.pop(exchange, None)

    def queue_declare(self, queue=None, passive=False, **kwargs):
        """Declare queue."""
        queue = queue or 'amq.gen-%s' % uuid()
        if passive and not self._has_queue(queue, **kwargs):
            raise ChannelError(
                'NOT_FOUND - no queue {!r} in vhost {!r}'.format(
                    queue, self.connection.client.virtual_host or '/'),
                (50, 10), 'Channel.queue_declare', '404',
            )
        else:
            self._new_queue(queue, **kwargs)
        return queue_declare_ok_t(queue, self._size(queue), 0)

    def queue_delete(self, queue, if_unused=False, if_empty=False, **kwargs):
        """Delete queue."""
        if if_empty and self._size(queue):
            return
        for exchange, routing_key, args in self.state.queue_bindings(queue):
            meta = self.typeof(exchange).prepare_bind(
                queue, exchange, routing_key, args,
            )
            self._delete(queue, exchange, *meta, **kwargs)
        self.state.queue_bindings_delete(queue)

    def after_reply_message_received(self, queue):
        self.queue_delete(queue)

    def exchange_bind(self, destination, source='', routing_key='',
                      nowait=False, arguments=None):
        raise NotImplementedError('transport does not support exchange_bind')

    def exchange_unbind(self, destination, source='', routing_key='',
                        nowait=False, arguments=None):
        raise NotImplementedError('transport does not support exchange_unbind')

    def queue_bind(self, queue, exchange=None, routing_key='',
                   arguments=None, **kwargs):
        """Bind `queue` to `exchange` with `routing key`."""
        exchange = exchange or 'amq.direct'
        if self.state.has_binding(queue, exchange, routing_key):
            return
        # Add binding:
        self.state.binding_declare(queue, exchange, routing_key, arguments)
        # Update exchange's routing table:
        table = self.state.exchanges[exchange].setdefault('table', [])
        meta = self.typeof(exchange).prepare_bind(
            queue, exchange, routing_key, arguments,
        )
        table.append(meta)
        if self.supports_fanout:
            self._queue_bind(exchange, *meta)

    def queue_unbind(self, queue, exchange=None, routing_key='',
                     arguments=None, **kwargs):
        # Remove queue binding:
        self.state.binding_delete(queue, exchange, routing_key)
        try:
            table = self.get_table(exchange)
        except KeyError:
            return
        binding_meta = self.typeof(exchange).prepare_bind(
            queue, exchange, routing_key, arguments,
        )
        # TODO: the complexity of this operation is O(number of bindings).
        # Should be optimized.  Modifying table in place.
        table[:] = [meta for meta in table if meta != binding_meta]

    def list_bindings(self):
        return ((queue, exchange, rkey)
                for exchange in self.state.exchanges
                for rkey, pattern, queue in self.get_table(exchange))

    def queue_purge(self, queue, **kwargs):
        """Remove all ready messages from queue."""
        return self._purge(queue)

    def _next_delivery_tag(self):
        return uuid()

    def basic_publish(self, message, exchange, routing_key, **kwargs):
        """Publish message."""
        self._inplace_augment_message(message, exchange, routing_key)
        if exchange:
            return self.typeof(exchange).deliver(
                message, exchange, routing_key, **kwargs
            )
        # anon exchange: routing_key is the destination queue
        return self._put(routing_key, message, **kwargs)

    def _inplace_augment_message(self, message, exchange, routing_key):
        message['body'], body_encoding = self.encode_body(
            message['body'], self.body_encoding,
        )
        props = message['properties']
        props.update(
            body_encoding=body_encoding,
            delivery_tag=self._next_delivery_tag(),
        )
        props['delivery_info'].update(
            exchange=exchange,
            routing_key=routing_key,
        )

    def basic_consume(self, queue, no_ack, callback, consumer_tag, **kwargs):
        """Consume from `queue`."""
        self._tag_to_queue[consumer_tag] = queue
        self._active_queues.append(queue)

        def _callback(raw_message):
            message = self.Message(raw_message, channel=self)
            if not no_ack:
                self._delivery_queue(message, queue)
                self.qos.append(message, message.delivery_tag)
            return callback(message)

        self.connection._callbacks[queue] = _callback
        self._consumers.add(consumer_tag)

        self._reset_cycle()

    def basic_cancel(self, consumer_tag):
        """Cancel consumer by consumer tag."""
        if consumer_tag in self._consumers:
            self._consumers.remove(consumer_tag)
            queue = self._tag_to_queue.pop(consumer_tag, None)
            try:
                self._active_queues.remove(queue)
            except ValueError:
                pass
            self._reset_cycle()
            self.connection._callbacks.pop(queue, None)

    def basic_get(self, queue, no_ack=False, **kwargs):
        """Get message by direct access (synchronous)."""
        try:
            message = self.Message(self._get(queue), channel=self)
            if not no_ack:
                self._delivery_queue(message, queue)
                self.qos.append(message, message.delivery_tag)
            return message
        except Empty:
            pass

    def _delivery_queue(self, message, queue):
        """Record which queue actually delivered ``message``.

        The same exchange may route one copy to several queues, so the
        exchange/routing key alone cannot identify the queue that owns an
        unacknowledged delivery.  Recording the queue here lets requeue and
        close recovery return the copy to that queue even if the bindings
        change before the restore happens.
        """
        delivery_info = dict(message.delivery_info or {})
        delivery_info['queue'] = queue
        properties = dict(message.properties or {})
        properties['delivery_info'] = delivery_info

        tag = message.delivery_tag
        if tag is not None:
            delivered = getattr(self.qos, '_delivered', None)
            dirty = getattr(self.qos, '_dirty', ())
            # A payload fanned out to several queues may carry the same
            # published delivery tag in every copy (the in-memory and
            # filesystem stores do).  Two live deliveries on this channel
            # must not share a tag, or acking one would resolve to the
            # other.
            if (delivered is not None and tag in delivered and
                    tag not in dirty and delivered[tag] is not message):
                tag = self._next_delivery_tag()
                message.delivery_tag = tag
                properties['delivery_tag'] = tag

        # Replace (rather than mutate) the raw payload.  A direct
        # exchange may store the exact same payload object on several
        # queues, so writing the delivery queue into the stored object
        # would make the other copies report the wrong queue.
        raw = getattr(message, '_raw', None)
        if isinstance(raw, dict):
            raw = dict(raw)
            raw_properties = dict(raw.get('properties') or {})
            raw_properties['delivery_info'] = dict(delivery_info)
            if tag is not None:
                raw_properties['delivery_tag'] = tag
            raw['properties'] = raw_properties
            message._raw = raw

        message.delivery_info = delivery_info
        message.properties = properties

    def basic_ack(self, delivery_tag, multiple=False):
        """Acknowledge message."""
        self.qos.ack(delivery_tag)

    def basic_recover(self, requeue=False):
        """Recover unacked messages."""
        if requeue:
            return self.qos.restore_unacked()
        raise NotImplementedError('Does not support recover(requeue=False)')

    def basic_reject(self, delivery_tag, requeue=False):
        """Reject message."""
        self.qos.reject(delivery_tag, requeue=requeue)

    def basic_qos(self, prefetch_size=0, prefetch_count=0,
                  apply_global=False):
        """Change QoS settings for this channel.

        Note:
        ----
            Only `prefetch_count` is supported.
        """
        self.qos.prefetch_count = prefetch_count

    def get_exchanges(self):
        return list(self.state.exchanges)

    def get_table(self, exchange):
        """Get table of bindings for `exchange`."""
        return self.state.exchanges[exchange]['table']

    def typeof(self, exchange, default='direct'):
        """Get the exchange type instance for `exchange`."""
        try:
            type = self.state.exchanges[exchange]['type']
        except KeyError:
            type = default
        return self.exchange_types[type]

    def _lookup(self, exchange, routing_key, default=None):
        """Find all queues matching `routing_key` for the given `exchange`.

        Returns
        -------
            list[str]: queue names -- must return `[default]`
                if default is set and no queues matched.
        """
        if default is None:
            default = self.deadletter_queue
        if not exchange:  # anon exchange
            return [routing_key or default]

        try:
            R = self.typeof(exchange).lookup(
                self.get_table(exchange),
                exchange, routing_key, default,
            )
        except KeyError:
            R = []

        if not R and default is not None:
            warnings.warn(UndeliverableWarning(UNDELIVERABLE_FMT.format(
                exchange=exchange, routing_key=routing_key)),
            )
            self._new_queue(default)
            R = [default]
        return R

    def _restore(self, message):
        """Redeliver message to its original destination.

        Virtual transports that support restoring unacked messages return
        the copy to the queue that actually delivered it, so a copy that
        was delivered from queue A is never routed to a queue that was
        bound to the exchange after the delivery was made.  Transports
        that cannot identify the original queue, or that were configured
        with ``restore_to_original_queue=False``, keep routing the message
        through the exchange again.
        """
        payload = self._redelivery_payload(message)
        original_queue = message.delivery_info.get('queue')
        if original_queue is None or not self.restore_to_original_queue:
            for queue in self._lookup(
                message.delivery_info['exchange'],
                    message.delivery_info['routing_key']):
                self._put(queue, copy.deepcopy(payload))
            return

        if not self._has_queue(original_queue):
            raise ChannelError(
                RESTORE_MISSING_QUEUE_FMT.format(original_queue))
        self._put(original_queue, payload)

    def _restore_at_beginning(self, message):
        return self._restore(message)

    def _redelivery_payload(self, message):
        """Build the stored payload for a restored delivery.

        The payload is a deep copy, so the message object the application
        still holds is never modified.  The body, correlation id and other
        business properties are preserved, ``redelivered`` is set both on
        the payload and in ``delivery_info``, and the headers named in
        :attr:`first_delivery_headers` are dropped from this copy only.
        A :attr:`requeue_message_callback` may then replace the headers
        and/or properties of the redelivered copy.
        """
        payload = copy.deepcopy(message.serializable())
        payload['redelivered'] = True
        headers = payload.get('headers')
        if headers is not None:
            for name in self._first_delivery_header_names():
                headers.pop(name, None)
            headers['redelivered'] = True
        payload['properties']['delivery_info']['redelivered'] = True

        callback = self.requeue_message_callback
        if callback is not None:
            attrs = callback(message) or {}
            if 'headers' in attrs:
                payload['headers'] = copy.deepcopy(attrs['headers'])
            if 'properties' in attrs:
                properties = copy.deepcopy(attrs['properties'])
                properties.setdefault(
                    'delivery_info',
                    payload['properties']['delivery_info'],
                )
                properties.setdefault(
                    'delivery_tag',
                    payload['properties']['delivery_tag'],
                )
                properties.setdefault(
                    'body_encoding',
                    payload['properties'].get('body_encoding'),
                )
                payload['properties'] = properties
        return payload

    def _first_delivery_header_names(self):
        """Normalize :attr:`first_delivery_headers` to a tuple of names."""
        names = self.first_delivery_headers or ()
        if isinstance(names, str):
            names = (names,)
        return tuple(names)

    def set_first_delivery_headers(self, headers):
        """Declare the header names that only survive the first delivery.

        ``headers`` may be a single name or an iterable of names.  The
        limit applies to the redelivered copy produced by requeue and by
        close recovery; the message object held by the application is
        never modified.
        """
        if isinstance(headers, str):
            headers = (headers,)
        self.first_delivery_headers = tuple(headers or ())
        return self.first_delivery_headers

    def drain_events(self, timeout=None, callback=None):
        callback = callback or self.connection._deliver
        if self._consumers and self.qos.can_consume():
            if hasattr(self, '_get_many'):
                return self._get_many(self._active_queues, timeout=timeout)
            return self._poll(self.cycle, callback, timeout=timeout)
        raise Empty()

    def message_to_python(self, raw_message):
        """Convert raw message to :class:`Message` instance."""
        if not isinstance(raw_message, self.Message):
            return self.Message(payload=raw_message, channel=self)
        return raw_message

    def prepare_message(self, body, priority=None, content_type=None,
                        content_encoding=None, headers=None, properties=None):
        """Prepare message data."""
        properties = properties or {}
        properties.setdefault('delivery_info', {})
        properties.setdefault('priority', priority or self.default_priority)

        return {'body': body,
                'content-encoding': content_encoding,
                'content-type': content_type,
                'headers': headers or {},
                'properties': properties or {}}

    def flow(self, active=True):
        """Enable/disable message flow.

        Raises
        ------
            NotImplementedError: as flow
                is not implemented by the base virtual implementation.
        """
        raise NotImplementedError('virtual channels do not support flow.')

    def close(self):
        """Close channel.

        Cancel all consumers, and requeue unacked messages.

        Returns
        -------
            list: ``(exc, message)`` pairs for deliveries that could not
                be restored to their original queue, if any.
        """
        unrestored = []
        if not self.closed:
            self.closed = True
            for consumer in list(self._consumers):
                self.basic_cancel(consumer)
            if self._qos:
                unrestored = self._qos.restore_unacked_once()
            if self._cycle is not None:
                self._cycle.close()
                self._cycle = None
            if self.connection is not None:
                self.connection.close_channel(self)
        elif self._qos and (self._qos._restore_failed or
                            self._qos.restore_errors):
            # The caller fixed the cause of an earlier failed restore;
            # retry only the deliveries that were not restored yet.
            unrestored = self._qos.restore_unacked_once()
        self.exchange_types = None
        return unrestored

    def encode_body(self, body, encoding=None):
        if encoding and encoding.lower() != 'utf-8':
            return self.codecs.get(encoding).encode(body), encoding
        return body, encoding

    def decode_body(self, body, encoding=None):
        if encoding and encoding.lower() != 'utf-8':
            return self.codecs.get(encoding).decode(body)
        return body

    def _reset_cycle(self):
        self._cycle = FairCycle(
            self._get_and_deliver, self._active_queues, Empty)

    def __enter__(self):
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None
    ) -> None:
        self.close()

    @property
    def state(self):
        """Broker state containing exchanges and bindings."""
        return self.connection.state

    @property
    def qos(self):
        """:class:`QoS` manager for this channel."""
        if self._qos is None:
            self._qos = self.QoS(self)
        return self._qos

    @property
    def cycle(self):
        if self._cycle is None:
            self._reset_cycle()
        return self._cycle

    def _get_message_priority(self, message, reverse=False):
        """Get priority from message.

        The value is limited to within a boundary of 0 to 9.

        Note:
        ----
            Higher value has more priority.
        """
        try:
            priority = max(
                min(int(message['properties']['priority']),
                    self.max_priority),
                self.min_priority,
            )
        except (TypeError, ValueError, KeyError):
            priority = self.default_priority

        return (self.max_priority - priority) if reverse else priority

    def _get_free_channel_id(self):
        # Cast to a set for fast lookups, and keep stored as an array
        # for lower memory usage.
        used_channel_ids = set(self.connection._used_channel_ids)

        for channel_id in range(1, self.connection.channel_max + 1):
            if channel_id not in used_channel_ids:
                self.connection._used_channel_ids.append(channel_id)
                return channel_id

        raise ResourceError(
            'No free channel ids, current={}, channel_max={}'.format(
                len(self.connection.channels),
                self.connection.channel_max), (20, 10),
        )


class Management(base.Management):
    """Base class for the AMQP management API."""

    def __init__(self, transport):
        super().__init__(transport)
        self.channel = transport.client.channel()

    def get_bindings(self):
        return [{'destination': q, 'source': e, 'routing_key': r}
                for q, e, r in self.channel.list_bindings()]

    def close(self):
        self.channel.close()


class Transport(base.Transport):
    """Virtual transport.

    Arguments:
    ---------
        client (kombu.Connection): The client this is a transport for.
    """

    Channel = Channel
    Cycle = FairCycle
    Management = Management

    #: :class:`~kombu.utils.scheduling.FairCycle` instance
    #: used to fairly drain events from channels (set by constructor).
    cycle = None

    #: port number used when no port is specified.
    default_port = None

    #: active channels.
    channels = None

    #: queue/callback map.
    _callbacks = None

    #: Time to sleep between unsuccessful polls.
    polling_interval = 1.0

    #: Max number of channels
    channel_max = 65535

    implements = base.Transport.implements.extend(
        asynchronous=False,
        exchange_type=frozenset(['direct', 'topic']),
        heartbeats=False,
    )

    def __init__(self, client, **kwargs):
        self.client = client
        # :class:`BrokerState` containing declared exchanges and bindings.
        self.state = BrokerState()
        self.channels = []
        self._avail_channels = []
        self._callbacks = {}
        self.cycle = self.Cycle(self._drain_channel, self.channels, Empty)
        polling_interval = client.transport_options.get('polling_interval')
        if polling_interval is not None:
            self.polling_interval = polling_interval
        self._used_channel_ids = array(ARRAY_TYPE_H)

    def create_channel(self, connection):
        try:
            return self._avail_channels.pop()
        except IndexError:
            channel = self.Channel(connection)
            self.channels.append(channel)
            return channel

    def close_channel(self, channel):
        try:
            try:
                self._used_channel_ids.remove(channel.channel_id)
            except ValueError:
                # channel id already removed
                pass
            try:
                self.channels.remove(channel)
            except ValueError:
                pass
        finally:
            channel.connection = None

    def establish_connection(self):
        # creates channel to verify connection.
        # this channel is then used as the next requested channel.
        # (returned by ``create_channel``).
        self._avail_channels.append(self.create_channel(self))
        return self  # for drain events

    def close_connection(self, connection):
        self.cycle.close()
        for chan_list in self._avail_channels, self.channels:
            while chan_list:
                try:
                    channel = chan_list.pop()
                except LookupError:  # pragma: no cover
                    pass
                else:
                    channel.close()

    def drain_events(self, connection, timeout=None):
        time_start = monotonic()
        get = self.cycle.get
        polling_interval = self.polling_interval
        if timeout and polling_interval and polling_interval > timeout:
            polling_interval = timeout
        while 1:
            try:
                get(self._deliver, timeout=timeout)
            except Empty:
                if timeout is not None and monotonic() - time_start >= timeout:
                    raise socket.timeout()
                if polling_interval is not None:
                    sleep(polling_interval)
            else:
                break

    def _deliver(self, message, queue):
        if not queue:
            raise KeyError(
                'Received message without destination queue: {}'.format(
                    message))
        try:
            callback = self._callbacks[queue]
        except KeyError:
            logger.warning(W_NO_CONSUMERS, queue)
            self._reject_inbound_message(message)
        else:
            callback(message)

    def _reject_inbound_message(self, raw_message):
        for channel in self.channels:
            if channel:
                message = channel.Message(raw_message, channel=channel)
                channel.qos.append(message, message.delivery_tag)
                channel.basic_reject(message.delivery_tag, requeue=True)
                break

    def on_message_ready(self, channel, message, queue):
        if not queue or queue not in self._callbacks:
            raise KeyError(
                'Message for queue {!r} without consumers: {}'.format(
                    queue, message))
        self._callbacks[queue](message)

    def _drain_channel(self, channel, callback, timeout=None):
        return channel.drain_events(callback=callback, timeout=timeout)

    @property
    def default_connection_params(self):
        return {'port': self.default_port, 'hostname': 'localhost'}
