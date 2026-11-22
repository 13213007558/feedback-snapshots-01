from __future__ import annotations

import socket
from uuid import uuid4

import pytest

from kombu import Connection, Consumer, Exchange, Producer, Queue


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


TEMPORARY_DEBUG_HEADER = 'x-debug-temp'


def _drop_temporary_header(message):
    return {
        'headers': {
            key: value for key, value in message.headers.items()
            if key != TEMPORARY_DEBUG_HEADER
        },
    }


class test_RequeueMessageCallback:
    """Application defined requeue message properties."""

    def setup_method(self):
        self.connection = Connection(
            transport='memory',
            transport_options={
                'requeue_message_callback': _drop_temporary_header,
            },
        )
        self.channel = self.connection.channel()
        self.queue_name = f'test_requeue_properties_{uuid4()}'
        self.exchange = Exchange(self.queue_name)
        self.queue = Queue(
            self.queue_name,
            exchange=self.exchange,
            routing_key=self.queue_name,
        )
        self.queue(self.channel).declare()

    def teardown_method(self):
        self.connection.close()

    def _publish(self, channel=None, correlation_id='correlation-1'):
        Producer(channel or self.channel).publish(
            {'task': 'retry-me'},
            exchange=self.exchange,
            routing_key=self.queue_name,
            headers={
                TEMPORARY_DEBUG_HEADER: 'first-attempt-only',
                'x-trace': 'persisted',
            },
            correlation_id=correlation_id,
        )

    def test_first_delivery_keeps_temporary_header(self):
        self._publish()

        message = self.queue(self.channel).get()

        assert message.headers[TEMPORARY_DEBUG_HEADER] == 'first-attempt-only'
        assert message.headers['x-trace'] == 'persisted'
        assert message.properties['correlation_id'] == 'correlation-1'
        assert message.payload == {'task': 'retry-me'}

    def test_requeue_applies_callback_and_keeps_tracing(self):
        self._publish()

        first = self.queue(self.channel).get()
        assert TEMPORARY_DEBUG_HEADER in first.headers
        first.requeue()

        redelivered = self.queue(self.channel).get()
        assert TEMPORARY_DEBUG_HEADER not in redelivered.headers
        assert redelivered.headers == {'x-trace': 'persisted'}
        assert redelivered.properties['correlation_id'] == 'correlation-1'
        assert redelivered.payload == {'task': 'retry-me'}
        assert redelivered.delivery_info['routing_key'] == self.queue_name

    def test_requeue_does_not_mutate_the_original_message(self):
        self._publish()

        first = self.queue(self.channel).get()
        first.requeue()

        assert first.headers[TEMPORARY_DEBUG_HEADER] == 'first-attempt-only'

    def test_temporary_header_stays_gone_across_repeated_redeliveries(self):
        self._publish()

        message = self.queue(self.channel).get()
        for _ in range(3):
            message.requeue()
            message = self.queue(self.channel).get()
            assert TEMPORARY_DEBUG_HEADER not in message.headers
            assert message.headers == {'x-trace': 'persisted'}
            assert message.properties['correlation_id'] == 'correlation-1'
        message.ack()

    def test_recovery_redelivery_uses_requeue_properties(self):
        self._publish()

        first = self.queue(self.channel).get()
        assert TEMPORARY_DEBUG_HEADER in first.headers

        # A broker/connection recovery redelivers the unacked messages.
        errors = self.channel.basic_recover(requeue=True)
        assert errors == []

        redelivered = self.queue(self.channel).get()
        assert TEMPORARY_DEBUG_HEADER not in redelivered.headers
        assert redelivered.headers == {'x-trace': 'persisted'}
        assert redelivered.properties['correlation_id'] == 'correlation-1'
        assert redelivered.payload == {'task': 'retry-me'}

    def test_unacked_restore_uses_requeue_properties(self):
        self._publish()

        first = self.queue(self.channel).get()
        assert TEMPORARY_DEBUG_HEADER in first.headers

        # The QoS layer restores every unacked message, e.g. when the
        # connection is lost and the channel is torn down.
        errors = self.channel.qos.restore_unacked()
        assert errors == []

        redelivered = self.queue(self.channel).get()
        assert TEMPORARY_DEBUG_HEADER not in redelivered.headers
        assert redelivered.headers == {'x-trace': 'persisted'}
        assert redelivered.properties['correlation_id'] == 'correlation-1'
        assert redelivered.payload == {'task': 'retry-me'}

    def test_callback_can_redefine_properties(self):
        def redefine_properties(message):
            properties = dict(message.properties)
            properties['type'] = 'retried-task'
            return {'properties': properties}

        connection = Connection(
            transport='memory',
            transport_options={
                'requeue_message_callback': redefine_properties,
            },
        )
        channel = connection.channel()
        queue_name = f'test_requeue_properties_{uuid4()}'
        exchange = Exchange(queue_name)
        queue = Queue(queue_name, exchange=exchange, routing_key=queue_name)
        queue(channel).declare()
        Producer(channel).publish(
            {'task': 'retry-me'},
            exchange=exchange,
            routing_key=queue_name,
            correlation_id='correlation-2',
        )

        first = queue(channel).get()
        assert first.properties.get('type') is None
        first.requeue()

        redelivered = queue(channel).get()
        assert redelivered.properties['type'] == 'retried-task'
        assert redelivered.properties['correlation_id'] == 'correlation-2'
        assert redelivered.properties['delivery_info']['routing_key'] == \
            queue_name
        assert redelivered.payload == {'task': 'retry-me'}
        connection.close()

    def test_callback_returning_none_preserves_the_whole_message(self):
        connection = Connection(
            transport='memory',
            transport_options={'requeue_message_callback': lambda m: None},
        )
        channel = connection.channel()
        queue_name = f'test_requeue_properties_{uuid4()}'
        exchange = Exchange(queue_name)
        queue = Queue(queue_name, exchange=exchange, routing_key=queue_name)
        queue(channel).declare()
        Producer(channel).publish(
            {'task': 'retry-me'},
            exchange=exchange,
            routing_key=queue_name,
            headers={TEMPORARY_DEBUG_HEADER: 'first-attempt-only'},
            correlation_id='correlation-1',
        )

        first = queue(channel).get()
        first.requeue()

        redelivered = queue(channel).get()
        assert redelivered.headers[TEMPORARY_DEBUG_HEADER] == \
            'first-attempt-only'
        assert redelivered.properties['correlation_id'] == 'correlation-1'
        assert redelivered.payload == {'task': 'retry-me'}
        connection.close()

    def test_without_callback_requeue_preserves_the_whole_message(self):
        connection = Connection(transport='memory')
        channel = connection.channel()
        queue_name = f'test_requeue_properties_{uuid4()}'
        exchange = Exchange(queue_name)
        queue = Queue(queue_name, exchange=exchange, routing_key=queue_name)
        queue(channel).declare()
        Producer(channel).publish(
            {'task': 'retry-me'},
            exchange=exchange,
            routing_key=queue_name,
            headers={
                TEMPORARY_DEBUG_HEADER: 'first-attempt-only',
                'x-trace': 'persisted',
            },
            correlation_id='correlation-1',
        )

        first = queue(channel).get()
        first.requeue()

        redelivered = queue(channel).get()
        assert redelivered.headers[TEMPORARY_DEBUG_HEADER] == \
            'first-attempt-only'
        assert redelivered.headers['x-trace'] == 'persisted'
        assert redelivered.properties['correlation_id'] == 'correlation-1'
        assert redelivered.payload == {'task': 'retry-me'}
        connection.close()
