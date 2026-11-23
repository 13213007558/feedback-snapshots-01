from __future__ import annotations

import socket
from uuid import uuid4

import pytest

from kombu import Connection, Consumer, Exchange, Producer, Queue
from kombu.exceptions import ChannelError


class test_MemoryTransport:

    def setup_method(self):
        self.c = Connection(transport='memory')
        self.e = Exchange('test_transport_memory')
        self.q = Queue('test_transport_memory',
                       exchange=self.e,
                       routing_key='test_transport_memory')
        self.q2 = Queue('test_transport_memory2',
                        exchange=self.e,
                        routing_key='test_transport_memory2')
        self.fanout = Exchange('test_transport_memory_fanout', type='fanout')
        self.q3 = Queue('test_transport_memory_fanout1',
                        exchange=self.fanout)
        self.q4 = Queue('test_transport_memory_fanout2',
                        exchange=self.fanout)

    def test_driver_version(self):
        assert self.c.transport.driver_version()

    def test_produce_consume_noack(self):
        channel = self.c.channel()
        producer = Producer(channel, self.e)
        consumer = Consumer(channel, self.q, no_ack=True)

        for i in range(10):
            producer.publish({'foo': i}, routing_key='test_transport_memory')

        _received = []

        def callback(message_data, message):
            _received.append(message)

        consumer.register_callback(callback)
        consumer.consume()

        while 1:
            if len(_received) == 10:
                break
            self.c.drain_events()

        assert len(_received) == 10

    def test_produce_consume_fanout(self):
        producer = self.c.Producer()
        consumer = self.c.Consumer([self.q3, self.q4])

        producer.publish(
            {'hello': 'world'},
            declare=consumer.queues,
            exchange=self.fanout,
        )

        assert self.q3(self.c).get().payload == {'hello': 'world'}
        assert self.q4(self.c).get().payload == {'hello': 'world'}
        assert self.q3(self.c).get() is None
        assert self.q4(self.c).get() is None

    def test_produce_consume(self):
        channel = self.c.channel()
        producer = Producer(channel, self.e)
        consumer1 = Consumer(channel, self.q)
        consumer2 = Consumer(channel, self.q2)
        self.q2(channel).declare()

        for i in range(10):
            producer.publish({'foo': i}, routing_key='test_transport_memory')
        for i in range(10):
            producer.publish({'foo': i}, routing_key='test_transport_memory2')

        _received1 = []
        _received2 = []

        def callback1(message_data, message):
            _received1.append(message)
            message.ack()

        def callback2(message_data, message):
            _received2.append(message)
            message.ack()

        consumer1.register_callback(callback1)
        consumer2.register_callback(callback2)

        consumer1.consume()
        consumer2.consume()

        while 1:
            if len(_received1) + len(_received2) == 20:
                break
            self.c.drain_events()

        assert len(_received1) + len(_received2) == 20

        # compression
        producer.publish({'compressed': True},
                         routing_key='test_transport_memory',
                         compression='zlib')
        m = self.q(channel).get()
        assert m.payload == {'compressed': True}

        # queue.delete
        for i in range(10):
            producer.publish({'foo': i}, routing_key='test_transport_memory')
        assert self.q(channel).get()
        self.q(channel).delete()
        self.q(channel).declare()
        assert self.q(channel).get() is None

        # queue.purge
        for i in range(10):
            producer.publish({'foo': i}, routing_key='test_transport_memory2')
        assert self.q2(channel).get()
        self.q2(channel).purge()
        assert self.q2(channel).get() is None

    def test_drain_events(self):
        with pytest.raises(socket.timeout):
            self.c.drain_events(timeout=0.1)

        c1 = self.c.channel()
        c2 = self.c.channel()

        with pytest.raises(socket.timeout):
            self.c.drain_events(timeout=0.1)

        del c1  # so pyflakes doesn't complain.
        del c2

    def test_drain_events_unregistered_queue(self):
        c1 = self.c.channel()
        producer = self.c.Producer()
        consumer = self.c.Consumer([self.q2])

        producer.publish(
            {'hello': 'world'},
            declare=consumer.queues,
            routing_key=self.q2.routing_key,
            exchange=self.q2.exchange,
        )
        message = consumer.queues[0].get()._raw

        class Cycle:

            def get(self, callback, timeout=None):
                return (message, 'foo'), c1

        self.c.transport.cycle = Cycle()
        self.c.drain_events()

    def test_queue_for(self):
        chan = self.c.channel()
        chan.queues.clear()

        x = chan._queue_for('foo')
        assert x
        assert chan._queue_for('foo') is x

    # see the issue
    # https://github.com/celery/kombu/issues/1050
    def test_producer_on_return(self):
        def on_return(_exception, _exchange, _routing_key, _message):
            pass
        channel = self.c.channel()
        producer = Producer(channel, on_return=on_return)
        consumer = self.c.Consumer([self.q3])

        producer.publish(
            {'hello': 'on return'},
            declare=consumer.queues,
            exchange=self.fanout,
        )

        assert self.q3(self.c).get().payload == {'hello': 'on return'}
        assert self.q3(self.c).get() is None


TEMPORARY_HEADER = 'x-debug-trace'
BUSINESS_HEADER = 'x-request-id'


class test_OriginalQueueRestore:
    """Unacked deliveries return to the queue that actually delivered them."""

    def setup_method(self):
        self.connection = Connection(
            'memory://',
            transport_options={
                'do_restore': True,
                'first_delivery_headers': [TEMPORARY_HEADER],
            },
        )
        self.channel = self.connection.channel()
        self.exchange = Exchange(f'restore-{uuid4()}', type='direct')
        self.binding_key = f'restore-{uuid4()}'
        self.queue_a = Queue(f'a-{uuid4()}', self.exchange, self.binding_key)
        self.queue_b = Queue(f'b-{uuid4()}', self.exchange, self.binding_key)
        self.queue_a(self.channel).declare()
        self.queue_b(self.channel).declare()

    def teardown_method(self):
        for channel in list(self.connection.transport.channels):
            qos = getattr(channel, '_qos', None)
            if qos is not None:
                qos._on_collect.cancel()
                qos._delivered.clear()
                qos._restore_failed.clear()
                qos._dirty.clear()
                qos._delivered.restored = False
        self.connection.close()

    def _publish(self, correlation_id='corr-1', body=None):
        Producer(self.channel).publish(
            body if body is not None else {'task': 'work'},
            exchange=self.exchange,
            routing_key=self.binding_key,
            correlation_id=correlation_id,
            headers={TEMPORARY_HEADER: 'first-attempt-only',
                     BUSINESS_HEADER: 'request-1'},
        )

    def _bind_new_queue(self):
        queue_c = Queue(f'c-{uuid4()}', self.exchange, self.binding_key)
        queue_c(self.channel).declare()
        return queue_c

    def _assert_redelivery(self, message, queue, correlation_id='corr-1'):
        assert message is not None
        assert message.payload == {'task': 'work'}
        assert message.properties['correlation_id'] == correlation_id
        assert message.headers[BUSINESS_HEADER] == 'request-1'
        assert TEMPORARY_HEADER not in message.headers
        assert message.delivery_info['queue'] == queue.name
        assert message.delivery_info['redelivered'] is True
        assert message.headers['redelivered'] is True

    def test_explicit_requeue_from_basic_get_returns_only_to_a(self):
        self._publish()
        first = self.queue_a(self.channel).get(no_ack=False)
        other = self.queue_b(self.channel).get(no_ack=False)
        assert first.payload == other.payload
        assert first.delivery_tag != other.delivery_tag

        queue_c = self._bind_new_queue()
        first.requeue()

        redelivered = self.queue_a(self.channel).get(no_ack=False)
        self._assert_redelivery(redelivered, self.queue_a)
        assert self.queue_a(self.channel).get(no_ack=False) is None
        assert self.queue_b(self.channel).get(no_ack=False) is None
        assert queue_c(self.channel).get(no_ack=False) is None

        assert other.headers[TEMPORARY_HEADER] == 'first-attempt-only'
        assert TEMPORARY_HEADER in other.headers

    def test_explicit_requeue_from_callback_returns_only_to_a(self):
        received = []
        Consumer(
            self.channel, [self.queue_a],
            callbacks=[lambda body, message: received.append(message)],
        ).consume()
        self._publish()
        self.connection.drain_events(timeout=1)
        message, = received

        other = self.queue_b(self.channel).get(no_ack=False)
        self._bind_new_queue()
        message.requeue()

        redelivered = self.queue_a(self.channel).get(no_ack=False)
        self._assert_redelivery(redelivered, self.queue_a)
        assert self.queue_a(self.channel).get(no_ack=False) is None
        assert self.queue_b(self.channel).get(no_ack=False) is None
        assert other.headers[TEMPORARY_HEADER] == 'first-attempt-only'

    def test_close_recovery_from_basic_get_returns_only_to_a(self):
        self._publish()
        first = self.queue_a(self.channel).get(no_ack=False)
        other = self.queue_b(self.channel).get(no_ack=False)
        other.ack()
        queue_c = self._bind_new_queue()

        unrestored = self.channel.close()
        assert unrestored == []

        channel = self.connection.channel()
        redelivered = self.queue_a(channel).get(no_ack=False)
        self._assert_redelivery(redelivered, self.queue_a)
        assert self.queue_a(channel).get(no_ack=False) is None
        assert self.queue_b(channel).get(no_ack=False) is None
        assert queue_c(channel).get(no_ack=False) is None
        assert other.headers[TEMPORARY_HEADER] == 'first-attempt-only'

    def test_close_recovery_from_callback_returns_only_to_a(self):
        received = []
        Consumer(
            self.channel, [self.queue_a],
            callbacks=[lambda body, message: received.append(message)],
        ).consume()
        self._publish()
        self.connection.drain_events(timeout=1)
        message, = received

        other = self.queue_b(self.channel).get(no_ack=False)
        other.ack()
        queue_c = self._bind_new_queue()

        assert self.channel.close() == []

        channel = self.connection.channel()
        redelivered = self.queue_a(channel).get(no_ack=False)
        self._assert_redelivery(redelivered, self.queue_a)
        assert self.queue_a(channel).get(no_ack=False) is None
        assert self.queue_b(channel).get(no_ack=False) is None
        assert queue_c(channel).get(no_ack=False) is None
        assert other.headers[TEMPORARY_HEADER] == 'first-attempt-only'

    def test_recover_after_bindings_change_uses_delivery_queue(self):
        self._publish()
        first = self.queue_a(self.channel).get(no_ack=False)
        self.queue_b(self.channel).get(no_ack=False)

        # Unbind A and route the binding key to a new queue instead.
        self.queue_a(self.channel).queue_unbind()
        queue_c = self._bind_new_queue()
        bound = [queue for _, _, queue in self.channel.get_table(
            self.exchange.name)]
        assert self.queue_a.name not in bound
        assert queue_c.name in bound
        errors = self.channel.basic_recover(requeue=True)
        assert errors == []

        redelivered = self.queue_a(self.channel).get(no_ack=False)
        self._assert_redelivery(redelivered, self.queue_a)
        assert queue_c(self.channel).get(no_ack=False) is None

    def test_missing_queue_leaves_delivery_unrestored(self):
        self._publish()
        first = self.queue_a(self.channel).get(no_ack=False)
        self.queue_a(self.channel).delete()
        self._bind_new_queue()

        with pytest.raises(ChannelError, match='no longer exists'):
            first.requeue()

        # The delivery is still pending, so the caller can create the
        # queue again and retry the same message.
        assert len(self.channel.qos._delivered) == 1

        self.queue_a(self.channel).declare()
        first.requeue()
        redelivered = self.queue_a(self.channel).get(no_ack=False)
        self._assert_redelivery(redelivered, self.queue_a)

    def test_partial_restore_retries_only_the_failed_delivery(self):
        self._publish(correlation_id='first', body={'task': 'one'})
        self._publish(correlation_id='second', body={'task': 'two'})
        original_restore = self.channel._restore
        attempts = []

        def restore(message):
            attempts.append(message.properties['correlation_id'])
            if message.properties['correlation_id'] == 'first':
                raise ChannelError('write failed before enqueue')
            return original_restore(message)

        self.channel._restore = restore
        first = self.queue_a(self.channel).get(no_ack=False)
        second = self.queue_a(self.channel).get(no_ack=False)

        errors = self.channel.basic_recover(requeue=True)
        assert len(errors) == 1
        assert errors[0][1].properties['correlation_id'] == 'first'
        assert sorted(attempts) == ['first', 'second']

        # Only the failed delivery is retried; the one already restored is
        # not enqueued again.
        self.channel._restore = original_restore
        assert self.channel.basic_recover(requeue=True) == []

        restored = []
        while (message := self.queue_a(self.channel).get(
                no_ack=False)) is not None:
            restored.append(message.properties['correlation_id'])
        assert sorted(restored) == ['first', 'second']
        assert restored.count('first') == 1
        assert restored.count('second') == 1

    def test_first_delivery_headers_accept_an_alias(self):
        connection = Connection(
            'memory://',
            transport_options={
                'do_restore': True,
                'diagnostic_headers': ['x-debug-trace'],
            },
        )
        try:
            channel = connection.channel()
            self.queue_a(channel).declare()
            Producer(channel).publish(
                {'task': 'work'}, exchange=self.exchange,
                routing_key=self.binding_key, correlation_id='corr-1',
                headers={TEMPORARY_HEADER: 'first', 'x-keep': 'yes'},
            )
            first = self.queue_a(channel).get(no_ack=False)
            first.requeue()

            redelivered = self.queue_a(channel).get(no_ack=False)
            assert TEMPORARY_HEADER not in redelivered.headers
            assert redelivered.headers['x-keep'] == 'yes'
            assert redelivered.properties['correlation_id'] == 'corr-1'
        finally:
            connection.close()

    def test_set_first_delivery_headers_declares_policy(self):
        channel = self.channel
        assert channel.set_first_delivery_headers('x-one') == ('x-one',)
        assert channel.set_first_delivery_headers(['x-one', 'x-two']) == (
            'x-one', 'x-two')

        Producer(channel).publish(
            {'task': 'work'}, exchange=self.exchange,
            routing_key=self.binding_key, correlation_id='corr-1',
            headers={'x-one': '1', 'x-two': '2', 'x-keep': 'yes'},
        )
        first = self.queue_a(channel).get(no_ack=False)
        first.requeue()
        redelivered = self.queue_a(channel).get(no_ack=False)
        assert redelivered.headers == {'x-keep': 'yes', 'redelivered': True}
        assert redelivered.properties['correlation_id'] == 'corr-1'
        assert redelivered.payload == {'task': 'work'}

    def test_disabled_original_queue_option_keeps_exchange_routing(self):
        connection = Connection(
            'memory://',
            transport_options={
                'do_restore': True,
                'restore_to_original_queue': False,
            },
        )
        try:
            channel = connection.channel()
            self.queue_a(channel).declare()
            self.queue_b(channel).declare()
            Producer(channel).publish(
                {'task': 'work'}, exchange=self.exchange,
                routing_key=self.binding_key, correlation_id='corr-1',
            )
            first = self.queue_a(channel).get(no_ack=False)
            self.queue_b(channel).get(no_ack=False)
            queue_c = Queue(f'c-{uuid4()}', self.exchange, self.binding_key)
            queue_c(channel).declare()

            first.requeue()

            assert self.queue_a(channel).get(no_ack=False) is not None
            assert self.queue_b(channel).get(no_ack=False) is not None
            assert queue_c(channel).get(no_ack=False) is not None
        finally:
            connection.close()
