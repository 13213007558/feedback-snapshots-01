from __future__ import annotations

import pytest
from amqp import RecoverableConnectionError

from kombu import Connection, Exchange, Producer, Queue
from kombu.declarations import DeclarationPolicy, EXCHANGE_ENTITY
from kombu.exceptions import DeclarationNotAllowed
from kombu.transport import memory, virtual


def make_transport():
    """Return a memory transport with isolated broker state."""
    class IsolatedChannel(memory.Channel):
        # memory.Channel.queues is a class-level registry shared with every
        # subclass; give this transport its own registry to avoid leaking
        # queues between tests.
        queues = {}

    class IsolatedMemoryTransport(memory.Transport):
        Channel = IsolatedChannel
        global_state = virtual.BrokerState()

    return IsolatedMemoryTransport


def make_reconnecting_transport():
    """Memory transport whose first declaration call disconnects."""
    state = {'failures': 1, 'declarations': []}

    class ReconnectingChannel(memory.Channel):
        queues = {}

        def exchange_declare(self, *args, **kwargs):
            state['declarations'].append(
                ('exchange', kwargs.get('exchange')))
            if state['failures']:
                state['failures'] -= 1
                raise RecoverableConnectionError('connection lost')
            return super().exchange_declare(*args, **kwargs)

        def queue_declare(self, *args, **kwargs):
            state['declarations'].append(('queue', kwargs.get('queue')))
            if state['failures']:
                state['failures'] -= 1
                raise RecoverableConnectionError('connection lost')
            return super().queue_declare(*args, **kwargs)

    class ReconnectingTransport(memory.Transport):
        Channel = ReconnectingChannel
        global_state = virtual.BrokerState()

    return ReconnectingTransport, state


class test_DeclarationPolicyOnMemoryTransport:

    def test_insufficient_permissions_create_no_entities(self):
        transport = make_transport()
        with Connection(
            transport=transport,
            declaration_policy=DeclarationPolicy([]),
        ) as connection:
            broker_state = connection.transport.state
            producer = Producer(connection)
            queue = Queue(
                'finance.queue',
                exchange=Exchange('finance.events', type='topic'),
                routing_key='events.#',
            )

            with pytest.raises(DeclarationNotAllowed, match='queue'):
                producer.publish(
                    {'hello': 'world'},
                    routing_key='events.1',
                    declare=[queue],
                    retry=True,
                    retry_policy={'max_retries': 2},
                )

            # The policy must leave broker topology untouched, and retries
            # must not bypass it: the rejection is raised before any
            # declaration reaches the channel.
            assert broker_state.exchanges == {}
            assert broker_state.bindings == {}
            assert connection.default_channel.queues == {}

    def test_publish_only_policy_allows_exchange_and_publishing(self):
        transport = make_transport()
        with Connection(transport=transport) as init_connection:
            # The initialization service owns queues and bindings.
            prepared = Queue(
                'finance.queue',
                exchange=Exchange('finance.events', type='topic'),
                routing_key='events.#',
            )(init_connection.default_channel)
            prepared.declare()

        with Connection(
            transport=transport,
            declaration_policy=DeclarationPolicy([EXCHANGE_ENTITY]),
        ) as connection:
            broker_state = connection.transport.state
            producer = Producer(connection)
            exchange = Exchange('finance.events', type='topic')

            # Declaring a queue is outside the producer's permissions.
            with pytest.raises(DeclarationNotAllowed, match='queue'):
                producer.publish(
                    {'blocked': True},
                    exchange=exchange,
                    routing_key='events.1',
                    declare=[Queue(
                        'finance.unauthorized',
                        exchange=exchange,
                    )],
                )
            assert 'finance.unauthorized' not in \
                connection.default_channel.queues

            # Publishing to the prepared exchange is still possible; the
            # exchange itself may be (re)declared automatically.
            producer.publish(
                {'hello': 'world'},
                exchange=exchange,
                routing_key='events.1',
            )
            message = Queue('finance.queue')(
                connection.default_channel).get(no_ack=True)
            assert message.payload == {'hello': 'world'}

            # Only the entities created by the initialization service exist.
            assert set(connection.default_channel.queues) == \
                {'finance.queue'}
            assert 'finance.events' in broker_state.exchanges
            assert 'finance.unauthorized' not in \
                connection.default_channel.queues

    def test_allowed_declaration_is_retried_after_reconnect(self):
        transport, state = make_reconnecting_transport()
        with Connection(
            transport=transport,
            declaration_policy=DeclarationPolicy([EXCHANGE_ENTITY]),
        ) as connection:
            producer = Producer(
                connection,
                exchange=Exchange('recovered.exchange', type='topic'),
            )
            first_channel = producer.channel

            producer.publish(
                {'hello': 'world'},
                routing_key='events.1',
                retry=True,
                retry_policy={'max_retries': 1},
            )

            assert producer.channel is not first_channel
            exchange_attempts = [
                name for kind, name in state['declarations']
                if kind == 'exchange'
            ]
            assert exchange_attempts == [
                'recovered.exchange', 'recovered.exchange',
            ]
            assert 'recovered.exchange' in \
                connection.transport.state.exchanges

    def test_forbidden_declaration_is_not_retried_after_reconnect(self):
        transport, state = make_reconnecting_transport()
        with Connection(
            transport=transport,
            declaration_policy=DeclarationPolicy([EXCHANGE_ENTITY]),
        ) as connection:
            producer = Producer(connection)
            first_channel = producer.channel

            with pytest.raises(DeclarationNotAllowed, match='queue'):
                producer.publish(
                    {'hello': 'world'},
                    routing_key='events.1',
                    declare=[Queue('finance.queue')],
                    retry=True,
                    retry_policy={'max_retries': 3},
                )

            # Fail-closed: no channel replacement, no broker calls, no state.
            assert producer.channel is first_channel
            assert state['declarations'] == []
            assert connection.transport.state.exchanges == {}
            assert connection.default_channel.queues == {}

    def test_explicit_declare_is_not_governed_by_policy(self):
        transport = make_transport()
        with Connection(
            transport=transport,
            declaration_policy=DeclarationPolicy([]),
        ) as connection:
            # An explicit management action remains available; the policy
            # only constrains automatic declaration paths.
            exchange = Exchange(
                'managed.exchange', type='topic',
            )(connection.default_channel)
            exchange.declare()
            assert 'managed.exchange' in \
                connection.transport.state.exchanges

    def test_no_declare_entities_are_skipped_without_broker_calls(self):
        from kombu.common import maybe_declare

        transport = make_transport()
        with Connection(
            transport=transport,
            declaration_policy=DeclarationPolicy([]),
        ) as connection:
            queue = Queue('skipped.queue', no_declare=True)
            maybe_declare(queue, connection.default_channel)
            assert connection.default_channel.queues == {}
            assert connection.transport.state.exchanges == {}
