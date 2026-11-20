from __future__ import annotations

import socket

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


class test_MemoryQoSBudgets:
    """Repeatedly exhaust and release quotas on a small memory queue."""

    def setup_method(self):
        self.connection = Connection(transport='memory')
        self.queue = Queue(f'qos-budget-{id(self)}')
        self.channel = self.connection.channel()
        self.queue(self.channel).declare()
        self.producer = Producer(self.channel)
        self.received = []

    def teardown_method(self):
        for message in self.received:
            if not message.acknowledged:
                message.ack()

    def publish(self, payload, count=1):
        for i in range(count):
            self.producer.publish(
                {'n': i, 'payload': payload},
                routing_key=self.queue.name,
                serializer='json',
            )

    def drain(self, consumer):
        try:
            self.connection.drain_events(timeout=0.05)
        except socket.timeout:
            pass

    def test_count_budget_drains_and_is_released_by_ack(self):
        for _ in range(3):
            self.received.clear()
            self.publish('x', count=3)
            consumer = Consumer(
                self.channel, [self.queue], prefetch_count=1,
                callbacks=[
                    lambda body, message: self.received.append(message),
                ],
            )
            consumer.consume()
            try:
                self.drain(consumer)
                assert len(self.received) == 1
                assert not self.channel.qos.can_consume()
                self.drain(consumer)
                assert len(self.received) == 1

                self.received[0].ack()
                self.drain(consumer)
                assert len(self.received) == 2
            finally:
                consumer.cancel()
            for message in self.received:
                if not message.acknowledged:
                    message.ack()
            self.queue(self.channel).purge()

    def test_size_budget_drains_and_is_released_by_reject(self):
        for _ in range(2):
            message = self.channel.prepare_message(b'1234567890')
            self.channel.basic_publish(
                message, None, self.queue.name,
                content_type='application/octet-stream',
            )
        consumer = Consumer(
            self.channel, [self.queue], prefetch_size=10,
            callbacks=[lambda body, message: self.received.append(message)],
        )
        consumer.consume()
        try:
            self.drain(consumer)
            assert len(self.received) == 1
            assert not self.channel.qos.can_consume()
            self.drain(consumer)
            assert len(self.received) == 1

            self.received[0].reject(requeue=True)
            self.drain(consumer)
            assert len(self.received) == 2
        finally:
            consumer.cancel()

    def test_consumers_do_not_share_quota(self):
        # Two queues on one channel: each consumer gets its own budget.
        first = Queue(f'{self.queue.name}-a')
        second = Queue(f'{self.queue.name}-b')
        first(self.channel).declare()
        second(self.channel).declare()
        self.producer.publish(
            {'n': 0}, routing_key=first.name, serializer='json')
        self.producer.publish(
            {'n': 0}, routing_key=second.name, serializer='json')

        received_a, received_b = [], []
        consumer_a = Consumer(
            self.channel, [first], prefetch_count=1,
            callbacks=[lambda body, message: received_a.append(message)],
            tag_prefix='a-',
        )
        consumer_b = Consumer(
            self.channel, [second], prefetch_count=1,
            callbacks=[lambda body, message: received_b.append(message)],
            tag_prefix='b-',
        )
        consumer_a.consume()
        consumer_b.consume()
        try:
            deadline = 2.0
            while len(received_a) + len(received_b) < 2 and deadline > 0:
                self.drain(consumer_a)
                self.drain(consumer_b)
                deadline -= 0.05
            assert len(received_a) == len(received_b) == 1
        finally:
            consumer_a.cancel()
            consumer_b.cancel()
            for message in received_a + received_b:
                if not message.acknowledged:
                    message.ack()

    def test_cancelled_consumer_does_not_hold_quota_for_next(self):
        self.publish('held', count=1)
        self.publish('next', count=1)

        first = Consumer(
            self.channel, [self.queue], prefetch_count=1,
            callbacks=[lambda body, message: self.received.append(message)],
            tag_prefix='old-',
        )
        first.consume()
        self.drain(first)
        assert len(self.received) == 1
        held = self.received[0]
        assert not self.channel.qos.can_consume()
        first.cancel()

        second_batch = []
        second = Consumer(
            self.channel, [self.queue], prefetch_count=1,
            callbacks=[lambda body, message: second_batch.append(message)],
            tag_prefix='new-',
        )
        second.consume()
        try:
            self.drain(second)
            assert len(second_batch) == 1
            assert second_batch[0] is not held
            # The old delivery is still tracked and restorable.
            assert held.delivery_tag in self.channel.qos._delivered
        finally:
            second.cancel()
            if not second_batch[0].acknowledged:
                second_batch[0].ack()
            if not held.acknowledged:
                held.ack()
        self.received.clear()

    def test_consumer_prefetch_size_budget(self):
        for _ in range(2):
            message = self.channel.prepare_message(b'0123456789')
            self.channel.basic_publish(
                message, None, self.queue.name,
                content_type='application/octet-stream',
            )

        consumer = Consumer(
            self.channel, [self.queue], prefetch_size=10,
            callbacks=[lambda body, message: self.received.append(message)],
        )
        consumer.consume()
        try:
            self.drain(consumer)
            assert len(self.received) == 1
            assert not self.channel.qos.can_consume()
            assert self.channel.qos.can_consume_max_estimate() == 0
            self.drain(consumer)
            assert len(self.received) == 1
            self.received[0].ack()
            self.drain(consumer)
            assert len(self.received) == 2
        finally:
            consumer.cancel()
        self.queue(self.channel).purge()
