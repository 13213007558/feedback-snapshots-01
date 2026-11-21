from __future__ import annotations

import pickle
import socket
from copy import copy, deepcopy
from unittest.mock import Mock, patch

import pytest

from kombu import Connection, Consumer, Producer, parse_url
from kombu.connection import FailoverNode, Resource
from kombu.exceptions import (NodeNotApproved, NodeSecurityError,
                              OperationalError)
from kombu.utils.functional import lazy
from t.mocks import TimeoutingTransport, Transport


class test_connection_utils:

    def setup_method(self):
        self.url = 'amqp://user:pass@localhost:5672/my/vhost'
        self.nopass = 'amqp://user:**@localhost:5672/my/vhost'
        self.expected = {
            'transport': 'amqp',
            'userid': 'user',
            'password': 'pass',
            'hostname': 'localhost',
            'port': 5672,
            'virtual_host': 'my/vhost',
        }
        self.pg_url = 'sqla+postgresql://test:password@yms-pg/yms'
        self.pg_nopass = 'sqla+postgresql://test:**@yms-pg/yms'

    def test_parse_url(self):
        result = parse_url(self.url)
        assert result == self.expected

    def test_parse_generated_as_uri(self):
        conn = Connection(self.url)
        info = conn.info()
        for k, v in self.expected.items():
            assert info[k] == v
        # by default almost the same- no password
        assert conn.as_uri() == self.nopass
        assert conn.as_uri(include_password=True) == self.url

    def test_as_uri_when_prefix(self):
        pytest.importorskip('redis')
        conn = Connection('redis+socket:///var/spool/x/y/z/redis.sock')
        assert conn.as_uri() == 'redis+socket:///var/spool/x/y/z/redis.sock'

    def test_as_uri_when_mongodb(self):
        pytest.importorskip('pymongo')
        x = Connection('mongodb://localhost')
        assert x.as_uri()

    def test_bogus_scheme(self):
        with pytest.raises(KeyError):
            Connection('bogus://localhost:7421').transport

    def assert_info(self, conn, **fields):
        info = conn.info()
        for field, expected in fields.items():
            assert info[field] == expected

    @pytest.mark.parametrize('url,expected', [
        ('amqp://user:pass@host:10000/vhost',
         {'userid': 'user', 'password': 'pass', 'hostname': 'host',
          'port': 10000, 'virtual_host': 'vhost'}),
        ('amqp://user%61:%61pass@ho%61st:10000/v%2fhost',
         {'userid': 'usera', 'password': 'apass', 'hostname': 'hoast',
          'port': 10000, 'virtual_host': 'v/host'}),
        ('amqp://',
         {'userid': 'guest', 'password': 'guest', 'hostname': 'localhost',
          'port': 5672, 'virtual_host': '/'}),
        ('amqp://:@/',
         {'userid': 'guest', 'password': 'guest', 'hostname': 'localhost',
          'port': 5672, 'virtual_host': '/'}),
        ('amqp://user@/',
         {'userid': 'user', 'password': 'guest', 'hostname': 'localhost',
          'port': 5672, 'virtual_host': '/'}),
        ('amqp://user:pass@/',
         {'userid': 'user', 'password': 'pass', 'hostname': 'localhost',
          'port': 5672, 'virtual_host': '/'}),
        ('amqp://host',
         {'userid': 'guest', 'password': 'guest', 'hostname': 'host',
          'port': 5672, 'virtual_host': '/'}),
        ('amqp://:10000',
         {'userid': 'guest', 'password': 'guest', 'hostname': 'localhost',
          'port': 10000, 'virtual_host': '/'}),
        ('amqp:///vhost',
         {'userid': 'guest', 'password': 'guest', 'hostname': 'localhost',
          'port': 5672, 'virtual_host': 'vhost'}),
        ('amqp://host/',
         {'userid': 'guest', 'password': 'guest', 'hostname': 'host',
          'port': 5672, 'virtual_host': '/'}),
        ('amqp://host/%2f',
         {'userid': 'guest', 'password': 'guest', 'hostname': 'host',
          'port': 5672, 'virtual_host': '/'}),
    ])
    def test_rabbitmq_example_urls(self, url, expected):
        # see Appendix A of http://www.rabbitmq.com/uri-spec.html
        self.assert_info(Connection(url), **expected)

    @pytest.mark.parametrize('url,expected', [
        ('sqs://user:pass@',
         {'userid': None, 'password': None, 'hostname': None,
          'port': None, 'virtual_host': '/'}),
        ('sqs://',
         {'userid': None, 'password': None, 'hostname': None,
          'port': None, 'virtual_host': '/'}),
    ])
    def test_sqs_example_urls(self, url, expected, caplog):
        pytest.importorskip('boto3')
        self.assert_info(Connection('sqs://'), **expected)
        assert not caplog.records

    @pytest.mark.skip('TODO: urllib cannot parse ipv6 urls')
    def test_url_IPV6(self):
        self.assert_info(
            Connection('amqp://[::1]'),
            userid='guest', password='guest', hostname='[::1]',
            port=5672, virtual_host='/',
        )

    def test_connection_copy(self):
        conn = Connection(self.url, alternates=['amqp://host'])
        clone = deepcopy(conn)
        assert clone.alt == ['amqp://host']

    def test_parse_generated_as_uri_pg(self):
        pytest.importorskip('sqlalchemy')
        conn = Connection(self.pg_url)
        assert conn.as_uri() == self.pg_nopass
        assert conn.as_uri(include_password=True) == self.pg_url


class test_Connection_transport_scheme:
    """A transport name derived from a URL must not be an import path.

    resolve_transport() passes any name containing '.' or ':' straight to
    symbol_by_name(), which imports it from sys.path.  No transport alias
    contains either character, so both are rejected for URL-derived names.
    """

    def test_dotted_url_scheme_rejected(self):
        with pytest.raises(ValueError, match='Invalid transport scheme'):
            Connection('some.evil.module://localhost')

    def test_dotted_scheme_via_uri_prefix_rejected(self):
        with pytest.raises(ValueError, match='Invalid transport scheme'):
            Connection('some.evil.module+amqp://localhost')

    def test_colon_scheme_via_uri_prefix_rejected(self):
        # the `prefix+scheme://` split is raw text, not a scheme parse, so
        # a ':' survives it and symbol_by_name() would read it as
        # `module:attribute`.
        with pytest.raises(ValueError, match='Invalid transport scheme'):
            Connection('baitmod:x+amqp://localhost')

    def test_dotted_alternate_rejected_at_construction(self):
        # only alt[0] goes through the checks in __init__; the rest reach
        # transport_cls through switch() on the first failover.
        with pytest.raises(ValueError, match='Invalid transport scheme'):
            Connection('amqp://h1;a.b://h2')

    def test_dotted_alternate_in_list_rejected(self):
        with pytest.raises(ValueError, match='Invalid transport scheme'):
            Connection(['amqp://h1', 'a.b://h2'])

    def test_dotted_alternate_in_alternates_rejected(self):
        with pytest.raises(ValueError, match='Invalid transport scheme'):
            Connection('amqp://h1', alternates=['a.b://h2'])

    def test_dotted_scheme_via_switch_rejected(self):
        conn = Connection('amqp://h1')
        with pytest.raises(ValueError, match='Invalid transport scheme'):
            conn.switch('a.b://h2')

    def test_no_alias_is_rejected_by_the_check(self):
        # the check can only be this strict because no legitimate scheme
        # looks like an import path.
        from kombu.connection import _check_url_transport
        from kombu.transport import TRANSPORT_ALIASES
        for alias in TRANSPORT_ALIASES:
            assert _check_url_transport(alias) == alias

    def test_check_rejects_dot_and_colon(self):
        from kombu.connection import _check_url_transport
        for name in ('a.b', 'a:b', 'a.b:c'):
            with pytest.raises(ValueError, match='Invalid transport scheme'):
                _check_url_transport(name)

    def test_alias_scheme_not_rejected(self):
        assert Connection('memory://').transport_cls == 'memory'

    def test_uri_prefix_alias_not_rejected(self):
        # documented `prefix+scheme://` form with a non-dotted prefix
        assert Connection('sqla+mysql://localhost').uri_prefix == 'sqla'

    def test_alias_alternate_not_rejected(self):
        conn = Connection('memory://h1;memory://h2')
        assert conn.alt == ['memory://h1', 'memory://h2']

    def test_hostname_alternate_not_rejected(self):
        # an alternate without a scheme is a bare hostname, and dots in a
        # hostname are not a transport name.
        conn = Connection('amqp://h1;h2.example.com')
        assert conn.alt == ['amqp://h1', 'h2.example.com']

    def test_switch_to_alias_scheme_not_rejected(self):
        conn = Connection('memory://h1')
        conn.switch('redis://h2')
        assert conn.transport_cls == 'redis'
        assert conn.hostname == 'h2'

    def test_dotted_transport_keyword_not_rejected(self):
        # the documented way to use a custom transport class is the
        # `transport` keyword argument, which must keep working.
        from kombu.transport.memory import Transport as MemoryTransport
        conn = Connection(
            'memory://', transport='kombu.transport.memory:Transport')
        assert isinstance(conn.transport, MemoryTransport)


class test_Connection:

    def setup_method(self):
        self.conn = Connection(port=5672, transport=Transport)

    def test_establish_connection(self):
        conn = self.conn
        assert not conn.connected
        conn.connect()
        assert conn.connected
        assert conn.connection.connected
        assert conn.host == 'localhost:5672'
        channel = conn.channel()
        assert channel.open
        assert conn.drain_events() == 'event'
        _connection = conn.connection
        conn.close()
        assert not _connection.connected
        assert isinstance(conn.transport, Transport)

    def test_reuse_connection(self):
        conn = self.conn
        assert conn.connect() is conn.connection is conn.connect()

    def test_connect_no_transport_options(self):
        conn = self.conn
        conn._ensure_connection = Mock()

        conn.connect()
        # ensure_connection must be called to return immediately
        # and fail with transport exception
        conn._ensure_connection.assert_called_with(
            max_retries=1, reraise_as_library_errors=False
        )

    def test_connect_transport_options(self):
        conn = self.conn
        conn.transport_options = {
            'max_retries': 1,
            'interval_start': 2,
            'interval_step': 3,
            'interval_max': 4,
            'ignore_this': True
        }
        conn._ensure_connection = Mock()

        conn.connect()
        # connect() is ignoring transport options
        # ensure_connection must be called to return immediately
        # and fail with transport exception
        conn._ensure_connection.assert_called_with(
            max_retries=1, reraise_as_library_errors=False
        )

    def test_multiple_urls(self):
        conn1 = Connection('amqp://foo;amqp://bar')
        assert conn1.hostname == 'foo'
        assert conn1.alt == ['amqp://foo', 'amqp://bar']

        conn2 = Connection(['amqp://foo', 'amqp://bar'])
        assert conn2.hostname == 'foo'
        assert conn2.alt == ['amqp://foo', 'amqp://bar']

    def test_collect(self):
        connection = Connection('memory://')
        trans = connection._transport = Mock(name='transport')
        _collect = trans._collect = Mock(name='transport._collect')
        _close = connection._close = Mock(name='connection._close')
        connection.declared_entities = Mock(name='decl_entities')
        uconn = connection._connection = Mock(name='_connection')
        connection.collect()

        _close.assert_not_called()
        _collect.assert_called_with(uconn)
        connection.declared_entities.clear.assert_called_with()
        assert trans.client is None
        assert connection._transport is None
        assert connection._connection is None

    def test_prefer_librabbitmq_over_amqp_when_available(self):
        with patch('kombu.connection.supports_librabbitmq',
                   return_value=True):
            connection = Connection('amqp://')

        assert connection.transport_cls == 'librabbitmq'

    def test_select_amqp_when_librabbitmq_is_not_available(self):
        with patch('kombu.connection.supports_librabbitmq',
                   return_value=False):
            connection = Connection('amqp://')

        assert connection.transport_cls == 'amqp'

    def test_collect_no_transport(self):
        connection = Connection('memory://')
        connection._transport = None
        connection._do_close_self = Mock()
        connection._do_close_transport = Mock()
        connection.collect()
        connection._do_close_self.assert_called_with()
        connection._do_close_transport.assert_called_with()

        connection._do_close_self.side_effect = socket.timeout()
        connection.collect()

    def test_collect_transport_gone(self):
        connection = Connection('memory://')
        uconn = connection._connection = Mock(name='conn._conn')
        trans = connection._transport = Mock(name='transport')
        collect = trans._collect = Mock(name='transport._collect')

        def se(conn):
            connection._transport = None
        collect.side_effect = se

        connection.collect()
        collect.assert_called_with(uconn)
        assert connection._transport is None

    def test_uri_passthrough(self):
        transport = Mock(name='transport')
        with patch('kombu.connection.get_transport_cls') as gtc:
            gtc.return_value = transport
            transport.can_parse_url = True
            with patch('kombu.connection.parse_url') as parse_url:
                c = Connection('foo+mysql://some_host')
                assert c.transport_cls == 'foo'
                parse_url.assert_not_called()
                assert c.hostname == 'mysql://some_host'
                assert c.as_uri().startswith('foo+')
            with patch('kombu.connection.parse_url') as parse_url:
                c = Connection('mysql://some_host', transport='foo')
                assert c.transport_cls == 'foo'
                parse_url.assert_not_called()
                assert c.hostname == 'mysql://some_host'
        c = Connection('pyamqp+sqlite://some_host')
        assert c.as_uri().startswith('pyamqp+')

    def test_ensure_connection_on_error(self):
        c = Connection('amqp://A;amqp://B')
        with patch('kombu.connection.retry_over_time') as rot:
            c.ensure_connection()
            rot.assert_called()

            args = rot.call_args[0]
            cb = args[4]
            intervals = iter([1, 2, 3, 4, 5])
            assert cb(KeyError(), intervals, 0) == 0
            assert cb(KeyError(), intervals, 1) == 1
            assert cb(KeyError(), intervals, 2) == 0
            assert cb(KeyError(), intervals, 3) == 2
            assert cb(KeyError(), intervals, 4) == 0
            assert cb(KeyError(), intervals, 5) == 3
            assert cb(KeyError(), intervals, 6) == 0
            assert cb(KeyError(), intervals, 7) == 4

            errback = Mock()
            c.ensure_connection(errback=errback)
            args = rot.call_args[0]
            cb = args[4]
            assert cb(KeyError(), intervals, 0) == 0
            errback.assert_called()

    def test_ensure_connection_switches_host_even_if_errback_raises(self):
        """Verify host is switched even when errback raises an exception."""
        c = Connection('amqp://A;amqp://B')

        with patch('kombu.connection.retry_over_time') as rot:
            errback = Mock(side_effect=TimeoutError('stop'))
            c.ensure_connection(errback=errback)
            rot.assert_called()

            args = rot.call_args[0]
            cb = args[4]

            with patch.object(c, 'maybe_switch_next') as switch_mock:
                with pytest.raises(TimeoutError):
                    cb(KeyError(), iter([1, 2]), 0)
                switch_mock.assert_called_once()

    def test_supports_heartbeats(self):
        c = Connection(transport=Mock)
        c.transport.implements.heartbeats = False
        assert not c.supports_heartbeats

    def test_is_evented(self):
        c = Connection(transport=Mock)
        c.transport.implements.asynchronous = False
        assert not c.is_evented

    def test_register_with_event_loop(self):
        transport = Mock(name='transport')
        transport.connection_errors = []
        c = Connection(transport=transport)
        loop = Mock(name='loop')
        c.register_with_event_loop(loop)
        c.transport.register_with_event_loop.assert_called_with(
            c.connection, loop,
        )

    def test_manager(self):
        c = Connection(transport=Mock)
        assert c.manager is c.transport.manager

    def test_copy(self):
        c = Connection('amqp://example.com')
        assert copy(c).info() == c.info()

    def test_copy_multiples(self):
        c = Connection('amqp://A.example.com;amqp://B.example.com')
        assert c.alt
        d = copy(c)
        assert d.alt == c.alt

    def test_switch(self):
        c = Connection('amqp://foo')
        c._closed = True
        c.switch('redis://example.com//3')
        assert not c._closed
        assert c.hostname == 'example.com'
        assert c.transport_cls == 'redis'
        assert c.virtual_host == '/3'

    def test_maybe_switch_next(self):
        c = Connection('amqp://foo;redis://example.com//3')
        c.maybe_switch_next()
        assert not c._closed
        assert c.hostname == 'example.com'
        assert c.transport_cls == 'redis'
        assert c.virtual_host == '/3'

    def test_maybe_switch_next_no_cycle(self):
        c = Connection('amqp://foo')
        c.maybe_switch_next()
        assert not c._closed
        assert c.hostname == 'foo'
        assert c.transport_cls, ('librabbitmq', 'pyamqp' in 'amqp')

    def test_switch_without_uri_identifier(self):
        c = Connection('amqp://foo')
        assert c.hostname == 'foo'
        assert c.transport_cls, ('librabbitmq', 'pyamqp' in 'amqp')
        c._closed = True
        c.switch('example.com')
        assert not c._closed
        assert c.hostname == 'example.com'
        assert c.transport_cls, ('librabbitmq', 'pyamqp' in 'amqp')

    def test_heartbeat_check(self):
        c = Connection(transport=Transport)
        c.transport.heartbeat_check = Mock()
        c.heartbeat_check(3)
        c.transport.heartbeat_check.assert_called_with(c.connection, rate=3)

    def test_completes_cycle_no_cycle(self):
        c = Connection('amqp://')
        assert c.completes_cycle(0)
        assert c.completes_cycle(1)

    def test_completes_cycle(self):
        c = Connection('amqp://a;amqp://b;amqp://c')
        assert not c.completes_cycle(0)
        assert not c.completes_cycle(1)
        assert c.completes_cycle(2)

    def test_get_heartbeat_interval(self):
        self.conn.transport.get_heartbeat_interval = Mock(name='ghi')
        assert (self.conn.get_heartbeat_interval() is
                self.conn.transport.get_heartbeat_interval.return_value)
        self.conn.transport.get_heartbeat_interval.assert_called_with(
            self.conn.connection)

    def test_supports_exchange_type(self):
        self.conn.transport.implements.exchange_type = {'topic'}
        assert self.conn.supports_exchange_type('topic')
        assert not self.conn.supports_exchange_type('fanout')

    def test_qos_semantics_matches_spec(self):
        qsms = self.conn.transport.qos_semantics_matches_spec = Mock()
        assert self.conn.qos_semantics_matches_spec is qsms.return_value
        qsms.assert_called_with(self.conn.connection)

    def test__enter____exit__(self):
        with self.conn as context:
            assert context is self.conn
            self.conn.connect()
            assert self.conn.connection.connected
        assert self.conn.connection is None
        self.conn.close()    # again

    def test_close_survives_connerror(self):

        class _CustomError(Exception):
            pass

        class MyTransport(Transport):
            connection_errors = (_CustomError,)

            def close_connection(self, connection):
                raise _CustomError('foo')

        conn = Connection(transport=MyTransport)
        conn.connect()
        conn.close()
        assert conn._closed

    def test_close_when_default_channel(self):
        conn = self.conn
        conn._default_channel = Mock()
        conn._close()
        conn._default_channel.close.assert_called_with()

    def test_auto_reconnect_default_channel(self):
        # tests GH issue: #1208
        # Tests that default_channel automatically reconnects when connection
        # closed
        c = Connection('memory://')
        c._closed = True
        with patch.object(
            c, '_connection_factory', side_effect=c._connection_factory
        ) as cf_mock:
            c.default_channel
            cf_mock.assert_called_once_with()

    def test_close_when_default_channel_close_raises(self):

        class Conn(Connection):

            @property
            def connection_errors(self):
                return (KeyError,)

        conn = Conn('memory://')
        conn._default_channel = Mock()
        conn._default_channel.close.side_effect = KeyError()

        conn._close()
        conn._default_channel.close.assert_called_with()

    def test_revive_when_default_channel(self):
        conn = self.conn
        defchan = conn._default_channel = Mock()
        conn.revive(Mock())

        defchan.close.assert_called_with()
        assert conn._default_channel is None

    def test_ensure_connection(self):
        assert self.conn.ensure_connection()

    def test_ensure_success(self):
        def publish():
            return 'foobar'

        ensured = self.conn.ensure(None, publish)
        assert ensured() == 'foobar'

    def test_ensure_failure(self):
        class _CustomError(Exception):
            pass

        def publish():
            raise _CustomError('bar')

        ensured = self.conn.ensure(None, publish)
        with pytest.raises(_CustomError):
            ensured()

    def test_ensure_connection_failure(self):
        class _ConnectionError(Exception):
            pass

        def publish():
            raise _ConnectionError('failed connection')

        self.conn.get_transport_cls().connection_errors = (_ConnectionError,)
        ensured = self.conn.ensure(self.conn, publish)
        with pytest.raises(OperationalError):
            ensured()

    def test_ensure_switches_host_on_conn_error(self):
        """Verify ensure() calls maybe_switch_next on connection errors.

        When a connection error occurs (e.g. PRECONDITION_FAILED for a
        missing stream queue replica), ensure() should cycle to the next
        host before retrying.
        """
        class _ConnectionError(Exception):
            pass

        tries = 0

        def publish():
            nonlocal tries
            tries += 1
            if tries <= 1:
                raise _ConnectionError('PRECONDITION_FAILED')
            return 'ok'

        c = Connection('amqp://A;amqp://B', transport=Transport)
        c.get_transport_cls().connection_errors = (_ConnectionError,)
        c.get_transport_cls().channel_errors = ()

        with patch.object(c, 'maybe_switch_next') as switch_mock, \
                patch.object(c, '_ensure_connection'), \
                patch.object(c, 'collect'):
            c._default_channel = Mock()
            obj = Mock()
            ensured = c.ensure(obj, publish, max_retries=3)
            ensured()

            switch_mock.assert_called_once()

    def test_ensure_retry_errors_is_limited_by_max_retries(self):
        class _MessageNacked(Exception):
            pass

        tries = 0

        def publish():
            nonlocal tries
            tries += 1
            if tries <= 3:
                raise _MessageNacked('NACK')
            # On the 4th try, we let it pass
            return 'ACK'

        ensured = self.conn.ensure(
            self.conn,
            publish,
            max_retries=3,  # 3 retries + 1 initial try = 4 tries
            retry_errors=(_MessageNacked,)
        )

        assert ensured() == 'ACK'

    def test_ensure_channel_errors_stop_at_max_retries(self):
        class _ChannelError(Exception):
            pass

        class _Transport(Transport):
            recoverable_channel_errors = (_ChannelError,)
            recoverable_connection_errors = ()

        tries = 0

        def publish():
            nonlocal tries
            tries += 1
            raise _ChannelError('closed')

        conn = Connection(port=5672, transport=_Transport)
        ensured = conn.ensure(conn, publish, max_retries=3)
        with pytest.raises(OperationalError):
            ensured()
        # Same budget as connection errors: 1 try plus max_retries.
        assert tries == 4

    def test_autoretry(self):
        myfun = Mock()

        self.conn.get_transport_cls().connection_errors = (KeyError,)

        def on_call(*args, **kwargs):
            myfun.side_effect = None
            raise KeyError('foo')

        myfun.side_effect = on_call
        insured = self.conn.autoretry(myfun)
        insured()

        myfun.assert_called()

    def test_SimpleQueue(self):
        conn = self.conn
        q = conn.SimpleQueue('foo')
        assert q.channel is conn.default_channel
        chan = conn.channel()
        q2 = conn.SimpleQueue('foo', channel=chan)
        assert q2.channel is chan

    def test_SimpleBuffer(self):
        conn = self.conn
        q = conn.SimpleBuffer('foo')
        assert q.channel is conn.default_channel
        chan = conn.channel()
        q2 = conn.SimpleBuffer('foo', channel=chan)
        assert q2.channel is chan

    def test_SimpleQueue_with_parameters(self):
        conn = self.conn
        q = conn.SimpleQueue(
            'foo', True, {'durable': True}, {'x-queue-mode': 'lazy'},
            {'durable': True, 'type': 'fanout', 'delivery_mode': 'persistent'})

        assert q.queue.exchange.type == 'fanout'
        assert q.queue.exchange.durable
        assert not q.queue.exchange.auto_delete
        delivery_mode_code = q.queue.exchange.PERSISTENT_DELIVERY_MODE
        assert q.queue.exchange.delivery_mode == delivery_mode_code

        assert q.queue.queue_arguments['x-queue-mode'] == 'lazy'

        assert q.queue.durable
        assert not q.queue.auto_delete

    def test_SimpleBuffer_with_parameters(self):
        conn = self.conn
        q = conn.SimpleBuffer(
            'foo', True, {'durable': True}, {'x-queue-mode': 'lazy'},
            {'durable': True, 'type': 'fanout', 'delivery_mode': 'persistent'})
        assert q.queue.exchange.type == 'fanout'
        assert q.queue.exchange.durable
        assert q.queue.exchange.auto_delete
        delivery_mode_code = q.queue.exchange.PERSISTENT_DELIVERY_MODE
        assert q.queue.exchange.delivery_mode == delivery_mode_code
        assert q.queue.queue_arguments['x-queue-mode'] == 'lazy'
        assert q.queue.durable
        assert q.queue.auto_delete

    def test_Producer(self):
        conn = self.conn
        assert isinstance(conn.Producer(), Producer)
        assert isinstance(conn.Producer(conn.default_channel), Producer)

    def test_Consumer(self):
        conn = self.conn
        assert isinstance(conn.Consumer(queues=[]), Consumer)
        assert isinstance(
            conn.Consumer(queues=[], channel=conn.default_channel),
            Consumer)

    def test__repr__(self):
        assert repr(self.conn)

    def test__reduce__(self):
        x = pickle.loads(pickle.dumps(self.conn))
        assert x.info() == self.conn.info()

    def test_channel_errors(self):

        class MyTransport(Transport):
            channel_errors = (KeyError, ValueError)

        conn = Connection(transport=MyTransport)
        assert conn.channel_errors == (KeyError, ValueError)

    def test_channel_errors__exception_no_cache(self):
        """Ensure the channel_errors can be retrieved without an initialized
        transport.
        """

        class MyTransport(Transport):
            channel_errors = (KeyError,)

        conn = Connection(transport=MyTransport)
        MyTransport.__init__ = Mock(side_effect=Exception)
        assert conn.channel_errors == (KeyError,)

    def test_connection_errors(self):

        class MyTransport(Transport):
            connection_errors = (KeyError, ValueError)

        conn = Connection(transport=MyTransport)
        assert conn.connection_errors == (KeyError, ValueError)

    def test_connection_errors__exception_no_cache(self):
        """Ensure the connection_errors can be retrieved without an
        initialized transport.
        """

        class MyTransport(Transport):
            connection_errors = (KeyError,)

        conn = Connection(transport=MyTransport)
        MyTransport.__init__ = Mock(side_effect=Exception)
        assert conn.connection_errors == (KeyError,)

    def test_recoverable_connection_errors(self):

        class MyTransport(Transport):
            recoverable_connection_errors = (KeyError, ValueError)

        conn = Connection(transport=MyTransport)
        assert conn.recoverable_connection_errors == (KeyError, ValueError)

    def test_recoverable_connection_errors__fallback(self):
        """Ensure missing recoverable_connection_errors on the Transport does
        not cause a fatal error.
        """

        class MyTransport(Transport):
            connection_errors = (KeyError,)
            channel_errors = (ValueError,)

        conn = Connection(transport=MyTransport)
        assert conn.recoverable_connection_errors == (KeyError, ValueError)

    def test_recoverable_connection_errors__exception_no_cache(self):
        """Ensure the recoverable_connection_errors can be retrieved without
        an initialized transport.
        """

        class MyTransport(Transport):
            recoverable_connection_errors = (KeyError,)

        conn = Connection(transport=MyTransport)
        MyTransport.__init__ = Mock(side_effect=Exception)
        assert conn.recoverable_connection_errors == (KeyError,)

    def test_recoverable_channel_errors(self):

        class MyTransport(Transport):
            recoverable_channel_errors = (KeyError, ValueError)

        conn = Connection(transport=MyTransport)
        assert conn.recoverable_channel_errors == (KeyError, ValueError)

    def test_recoverable_channel_errors__fallback(self):
        """Ensure missing recoverable_channel_errors on the Transport does not
        cause a fatal error.
        """

        class MyTransport(Transport):
            pass

        conn = Connection(transport=MyTransport)
        assert conn.recoverable_channel_errors == ()

    def test_recoverable_channel_errors__exception_no_cache(self):
        """Ensure the recoverable_channel_errors can be retrieved without an
        initialized transport.
        """
        class MyTransport(Transport):
            recoverable_channel_errors = (KeyError,)

        conn = Connection(transport=MyTransport)
        MyTransport.__init__ = Mock(side_effect=Exception)
        assert conn.recoverable_channel_errors == (KeyError,)

    def test_multiple_urls_hostname(self):
        conn = Connection(['example.com;amqp://example.com'])
        assert conn.as_uri() == 'amqp://guest:**@example.com:5672//'
        conn = Connection(['example.com', 'amqp://example.com'])
        assert conn.as_uri() == 'amqp://guest:**@example.com:5672//'
        conn = Connection('example.com;example.com;')
        assert conn.as_uri() == 'amqp://guest:**@example.com:5672//'

    def test_connection_respect_its_timeout(self):
        invalid_port = 1222
        with Connection(
            f'amqp://guest:guest@localhost:{invalid_port}//',
            transport_options={'max_retries': 2},
            connect_timeout=1
        ) as conn:
            with pytest.raises(OperationalError):
                conn.default_channel

    def test_connection_failover_without_total_timeout(self):
        with Connection(
            ['server1', 'server2'],
            transport=TimeoutingTransport,
            connect_timeout=1,
            transport_options={'interval_start': 0, 'interval_step': 0},
        ) as conn:
            conn._establish_connection = Mock(
                side_effect=conn._establish_connection
            )
            with pytest.raises(OperationalError):
                conn.default_channel
            # Never retried, because `retry_over_time` `timeout` is equal
            # to `connect_timeout`
            conn._establish_connection.assert_called_once()

    def test_connection_failover_with_total_timeout(self):
        with Connection(
            ['server1', 'server2'],
            transport=TimeoutingTransport,
            connect_timeout=1,
            transport_options={'connect_retries_timeout': 2,
                               'interval_start': 0, 'interval_step': 0},
        ) as conn:
            conn._establish_connection = Mock(
                side_effect=conn._establish_connection
            )
            with pytest.raises(OperationalError):
                conn.default_channel
            assert conn._establish_connection.call_count == 2

    def test_connection_timeout_with_errback(self):
        errback = Mock()
        with Connection(
            ['server1', 'server2'],
            transport=TimeoutingTransport,
            connect_timeout=1,
            transport_options={
                'connect_retries_timeout': 2,
                'interval_start': 0,
                'interval_step': 0,
                'errback': errback
            },
        ) as conn:
            with pytest.raises(OperationalError):
                conn.default_channel

        errback.assert_called()

    def test_connection_timeout_with_callback(self):
        callback = Mock()
        with Connection(
            ['server1', 'server2'],
            transport=TimeoutingTransport,
            connect_timeout=1,
            transport_options={
                'connect_retries_timeout': 2,
                'interval_start': 0,
                'interval_step': 0,
                'callback': callback
            },
        ) as conn:
            with pytest.raises(OperationalError):
                conn.default_channel

        callback.assert_called()


class test_Connection_autoretry:

    @pytest.fixture
    def conn(self):
        with Connection('memory://', transport_options={
            'interval_start': 0, 'interval_step': 0, 'interval_max': 0,
        }) as conn:
            yield conn

    @pytest.fixture
    def fail_connections(self, conn, monkeypatch):
        def fail(count):
            attempts = []
            establish = conn._establish_connection
            error = conn.recoverable_connection_errors[0]('unavailable')

            def connect():
                attempts.append(None)
                if len(attempts) <= count:
                    raise error
                return establish()

            monkeypatch.setattr(conn, '_establish_connection', connect)
            return attempts, error
        return fail

    @pytest.mark.parametrize('max_retries', [0, 2])
    def test_initial_connection_retry_limit(self, conn, fail_connections,
                                            max_retries):
        attempts, error = fail_connections(3)
        calls = []

        def operation(channel):
            calls.append(channel)

        retry = conn.autoretry(operation, max_retries=max_retries)
        with pytest.raises(OperationalError) as exc_info:
            retry()
        assert exc_info.value.__cause__ is error
        assert len(attempts) == max_retries + 1
        assert calls == []

    def test_initial_connection_errback_intervals(self, conn, fail_connections,
                                                  monkeypatch):
        attempts, error = fail_connections(3)
        errors = []
        monkeypatch.setattr('kombu.utils.functional.sleep', lambda _: None)

        retry = conn.autoretry(
            lambda channel: 'done', max_retries=3,
            errback=lambda exc, interval: errors.append((exc, interval)),
            interval_start=1, interval_step=2, interval_max=4,
        )
        result, channel = retry()
        assert result == 'done'
        assert channel is conn.default_channel
        assert len(attempts) == 4
        assert errors == [(error, 1), (error, 3), (error, 4)]

    def test_initial_connection_inherits_transport_options(self, conn,
                                                           fail_connections):
        attempts, error = fail_connections(2)
        errors, callbacks = [], []
        conn.transport_options.update(
            max_retries=1,
            errback=lambda exc, interval: errors.append((exc, interval)),
            callback=lambda: callbacks.append('tick'),
        )
        original_options = conn.transport_options.copy()
        with pytest.raises(OperationalError):
            conn.autoretry(lambda channel: 'done')()
        assert len(attempts) == 2
        assert errors == [(error, 0)]
        assert callbacks == ['tick']
        assert conn.transport_options == original_options

    def test_initial_connection_overrides_transport_options(self, conn,
                                                            fail_connections):
        attempts, error = fail_connections(2)
        errors, transport_errors = [], []
        conn.transport_options.update(
            max_retries=0, interval_start=10, interval_step=10,
            interval_max=10,
            errback=lambda *args: transport_errors.append(args),
        )
        original_options = conn.transport_options.copy()
        result, channel = conn.autoretry(
            lambda channel: 'done', max_retries=None,
            interval_start=0, interval_step=0, interval_max=0,
            errback=lambda exc, interval: errors.append((exc, interval)),
        )()
        assert result == 'done'
        assert channel is conn.default_channel
        assert len(attempts) == 3
        assert errors == [(error, 0), (error, 0)]
        assert transport_errors == []
        assert conn.transport_options == original_options

    def test_initial_connection_explicit_no_errback(self, conn,
                                                    fail_connections):
        attempts, _ = fail_connections(1)
        errors = []
        conn.transport_options['errback'] = lambda *args: errors.append(args)
        result, _ = conn.autoretry(lambda channel: 'done', errback=None)()
        assert result == 'done'
        assert len(attempts) == 2
        assert errors == []

    @pytest.mark.parametrize('total_timeout, expected_attempts', [(None, 1), (5, 3)])
    def test_initial_connection_preserves_timeout(self, conn, fail_connections,
                                                  monkeypatch, total_timeout,
                                                  expected_attempts):
        clock = [0]
        conn.connect_timeout = 1
        if total_timeout is not None:
            conn.transport_options['connect_retries_timeout'] = total_timeout
        attempts, _ = fail_connections(4)
        establish = conn._establish_connection

        def connect():
            clock[0] += 2
            return establish()

        monkeypatch.setattr(conn, '_establish_connection', connect)
        monkeypatch.setattr('kombu.utils.functional.time', lambda: clock[0])
        with pytest.raises(OperationalError):
            conn.autoretry(lambda channel: 'done', max_retries=10)()
        assert len(attempts) == expected_attempts

    @pytest.mark.parametrize('existing_default', [False, True])
    def test_existing_channel(self, conn, fail_connections, existing_default):
        if existing_default:
            expected = conn.default_channel
            options = {}
        else:
            expected = object()
            options = {'channel': expected}
        attempts, _ = fail_connections(1)
        result, channel = conn.autoretry(
            lambda channel: channel, max_retries=0, **options,
        )()
        assert result is expected
        assert channel is expected
        assert attempts == []

    def test_operation_recovery(self, conn):
        channels, revived, errors = [], [], []
        error = conn.recoverable_connection_errors[0]('connection lost')

        def operation(channel):
            channels.append(channel)
            if len(channels) == 1:
                raise error
            return 'done'

        result, channel = conn.autoretry(
            operation, max_retries=1, on_revive=revived.append,
            errback=lambda exc, interval: errors.append((exc, interval)),
        )()
        assert result == 'done'
        assert len(channels) == 2
        assert channels[0] is not channels[1]
        assert channel is channels[1]
        assert revived == [channel]
        assert errors == [(error, 0)]


class test_Connection_callable_password:

    def test_connection_preserves_callable_password(self):
        """Callable password is stored without coercion."""
        password_func = Mock(return_value='secret')
        conn = Connection(port=5672, transport=Transport,
                          password=password_func)
        assert conn.password is password_func

    def test_clone_preserves_callable_password(self):
        """Cloned connection preserves callable password."""
        password_func = Mock(return_value='secret')
        conn = Connection(port=5672, transport=Transport,
                          password=password_func)
        cloned = conn.clone()
        assert cloned.password is password_func

    def test_as_uri_with_callable_password(self):
        """as_uri() resolves callable password without crashing."""
        password_func = Mock(return_value='secret_token')
        conn = Connection(
            'amqp://user@localhost:5672//',
            password=password_func,
            transport=Transport,
        )
        # Without include_password, password is masked and callable NOT invoked
        uri = conn.as_uri()
        assert '**' in uri
        password_func.assert_not_called()
        # With include_password, the resolved password appears
        uri_with_pass = conn.as_uri(include_password=True)
        assert 'secret_token' in uri_with_pass
        password_func.assert_called_once()


class test_Connection_with_transport_options:

    transport_options = {'pool_recycler': 3600, 'echo': True}

    def setup_method(self):
        self.conn = Connection(port=5672, transport=Transport,
                               transport_options=self.transport_options)

    def test_establish_connection(self):
        conn = self.conn
        assert conn.transport_options == self.transport_options


class FakeNodeTransport(Transport):
    """Transport whose connection attempts are scripted per node.

    ``fail_hosts`` lists the hosts whose first attempt raises; every
    later attempt on that host succeeds.  ``attempts`` records the host
    of every connection attempt in order, and ``verified`` records the
    hosts whose connections passed ``verify_connection``.

    The transport instance is recreated when the connection switches
    nodes, so the record is kept on the class.
    """

    recoverable_connection_errors = (TimeoutError,)

    attempts = []
    verified = []
    fail_hosts = []

    def establish_connection(self):
        host = self.client.hostname
        self.attempts.append(host)
        if host in self.fail_hosts:
            self.fail_hosts.remove(host)
            raise TimeoutError(f'{host} is temporarily down')
        return super().establish_connection()

    def verify_connection(self, connection):
        if connection is not None and connection.connected:
            host = self.client.hostname
            # ``connected`` polls verification, so record transitions
            # between verified hosts rather than every poll.
            if not self.verified or self.verified[-1] != host:
                self.verified.append(host)
            return True
        return False


def make_fake_connection(urls, alternate_settings=None, **kwargs):
    # A failover URL selects its transport from its scheme, so the fake
    # transport is named per node as well as for the primary node.
    FakeNodeTransport.attempts = []
    FakeNodeTransport.verified = []
    FakeNodeTransport.fail_hosts = []
    settings = {
        str(url): dict(alternate_settings.get(str(url), {})
                       if alternate_settings else {},
                       transport=FakeNodeTransport)
        for url in urls
    }
    return Connection(
        urls,
        transport=FakeNodeTransport,
        alternate_settings=settings,
        transport_options={'interval_start': 0, 'interval_step': 0},
        **kwargs
    )


class test_Connection_failover_trust:
    """Each failover node authenticates with its own settings.

    The nodes are fake connections: the transport records which host was
    attempted, which connection verified, and the credentials and trust
    settings in force for that host.
    """

    def test_alternate_uses_own_credentials(self):
        conn = make_fake_connection(
            ['amqp://u1:p1@first', 'amqp://u2:p2@backup'],
            approved_alternates=['amqp://u2:p2@backup'],
        )
        conn.maybe_switch_next()
        assert conn.hostname == 'backup'
        assert (conn.userid, conn.password) == ('u2', 'p2')

    def test_alternate_settings_restore_authentication(self):
        conn = make_fake_connection(
            ['amqp://u1:p1@first', 'amqp://backup'],
            approved_alternates=['amqp://backup'],
            alternate_settings={
                'amqp://backup': {'userid': 'svc', 'password': 'token'},
            },
        )
        conn.maybe_switch_next()
        assert conn.hostname == 'backup'
        assert (conn.userid, conn.password) == ('svc', 'token')

    def test_primary_trust_does_not_leak_to_alternate(self):
        conn = Connection(
            'amqps://u1:p1@first?ssl_cert_reqs=required&ssl_ca_certs=/ca1;'
            'amqp://backup',
            transport=FakeNodeTransport,
        )
        assert conn.ssl['ssl_ca_certs'] == '/ca1'
        conn.maybe_switch_next()
        assert conn.hostname == 'backup'
        assert not conn.ssl
        # ...and the primary keeps its own trust policy when we return.
        conn.switch(conn.alt[0])
        assert conn.ssl['ssl_ca_certs'] == '/ca1'

    def test_alternate_uses_own_transport_trust(self):
        conn = Connection(
            'amqp://first;amqps://backup?ssl_cert_reqs=required'
            '&ssl_ca_certs=/ca2',
            approved_alternates=[
                'amqps://backup?ssl_cert_reqs=required&ssl_ca_certs=/ca2',
            ],
            transport=FakeNodeTransport,
        )
        conn.maybe_switch_next()
        assert conn.hostname == 'backup'
        assert conn.ssl['ssl_ca_certs'] == '/ca2'

    def test_unapproved_alternate_is_never_attempted(self):
        conn = make_fake_connection(
            ['amqp://first', 'amqp://backup'],
            approved_alternates=['amqp://first'],
        )
        conn.maybe_switch_next()
        assert conn.hostname == 'first'
        # nothing was attempted, and the connection did not move
        assert conn._active_node is None
        assert FakeNodeTransport.attempts == []

    def test_primary_is_always_usable_without_approval(self):
        # The list vets failover destinations; the configured node is
        # where the connection already is.
        conn = make_fake_connection(
            ['amqp://first', 'amqp://backup'],
            approved_alternates=['amqp://backup'],
        )
        assert conn.connect()
        assert conn.hostname == 'first'
        assert FakeNodeTransport.attempts == ['first']

    def test_no_approved_alternate_keeps_current_node(self):
        conn = make_fake_connection(
            ['amqp://first', 'amqp://backup', 'amqp://other'],
            approved_alternates=['amqp://first'],
        )
        conn.maybe_switch_next()
        assert conn.hostname == 'first'

    def test_explicit_switch_to_unapproved_node_is_refused(self):
        conn = make_fake_connection(
            ['amqp://first', 'amqp://backup'],
            approved_alternates=['amqp://first'],
        )
        with pytest.raises(NodeNotApproved):
            conn.switch('amqp://backup')
        assert conn.hostname == 'first'

    @pytest.mark.parametrize('alternate', [
        'amqps://backup',
        'amqps://backup?ssl_check_hostname=false',
        'amqps://backup?ssl_cert_reqs=none',
    ])
    def test_secure_alternate_without_trust_info_is_refused(self, alternate):
        conn = make_fake_connection(
            ['amqp://first', alternate], approved_alternates=[alternate],
            connect_timeout=1,
        )
        with pytest.raises(NodeSecurityError):
            conn.maybe_switch_next()
        # nothing was switched to, and no connection attempt was made
        assert conn.hostname == 'first'
        assert FakeNodeTransport.attempts == []

    def test_plain_alternate_does_not_need_ssl_policy(self):
        conn = make_fake_connection(
            ['amqp://first', 'amqp://backup'],
            approved_alternates=['amqp://backup'],
        )
        conn.maybe_switch_next()
        assert conn.hostname == 'backup'

    def test_node_settings_survive_copy_and_pickle(self):
        settings = {'amqp://backup': {'userid': 'svc', 'password': 'token'}}
        conn = make_fake_connection(
            ['amqp://first', 'amqp://backup'],
            approved_alternates=['amqp://backup'],
            alternate_settings=settings,
        )
        for clone in (copy(conn), deepcopy(conn),
                      pickle.loads(pickle.dumps(conn))):
            assert clone.info() == conn.info()
            assert clone.alt[1].approved
            clone.maybe_switch_next()
            assert (clone.userid, clone.password) == ('svc', 'token')

    def test_failover_node_is_still_a_url_string(self):
        conn = make_fake_connection(
            ['amqp://first', 'amqp://backup'],
            approved_alternates=['amqp://backup'],
        )
        assert conn.alt[1] == 'amqp://backup'
        assert isinstance(conn.alt[1], str)
        assert isinstance(conn.alt[1], FailoverNode)

    def test_primary_url_credentials_do_not_fill_in_for_alternate(self):
        # The primary URL's credentials are the primary node's, not a
        # fallback for a node that declares its own.
        conn = make_fake_connection(
            ['amqp://u1:p1@first', 'amqp://backup'],
            approved_alternates=['amqp://backup'],
        )
        conn.maybe_switch_next()
        assert conn.hostname == 'backup'
        assert conn.userid is None
        assert conn.password is None

    def test_verified_connection_is_not_replaced_by_failover(self):
        conn = make_fake_connection(
            ['amqp://first', 'amqp://backup'],
            approved_alternates=['amqp://first', 'amqp://backup'],
        )
        conn.connect()
        assert conn.connected
        assert FakeNodeTransport.verified == ['first']

        # The transport re-raises a recoverable error for an operation
        # that already succeeded on the open, authenticated connection.
        conn.maybe_switch_next()

        assert conn.hostname == 'first'
        assert conn.connected
        assert not conn._switching_allowed

    def test_lost_connection_still_fails_over(self):
        conn = make_fake_connection(
            ['amqp://first', 'amqp://backup'],
            approved_alternates=['amqp://first', 'amqp://backup'],
        )
        conn.connect()
        conn._connection = None
        conn.maybe_switch_next()
        assert conn.hostname == 'backup'
        assert conn.connect()
        assert FakeNodeTransport.verified == ['first', 'backup']


class test_Connection_failover_sequence:
    """Observe the order of connection attempts and verified connections.

    The fake transport scripts three nodes: the first temporarily fails,
    the backup proves its identity, and a second backup is missing the
    security information its URL scheme requires.
    """

    def test_first_fails_backup_verifies(self):
        conn = make_fake_connection(
            ['amqp://u1:p1@first', 'amqp://u2:p2@backup'],
            approved_alternates=['amqp://u2:p2@backup'],
            connect_timeout=1,
        )
        conn.transport.fail_hosts.append('first')

        assert conn.connect()
        assert conn.connected

        assert FakeNodeTransport.attempts == ['first', 'backup']
        assert FakeNodeTransport.verified == ['backup']
        assert conn.hostname == 'backup'
        assert (conn.userid, conn.password) == ('u2', 'p2')

    def test_backup_missing_security_info_stops_before_attempt(self):
        conn = make_fake_connection(
            ['amqp://first', 'amqps://backup'],
            approved_alternates=['amqps://backup'],
            connect_timeout=1,
        )
        conn.transport.fail_hosts.append('first')

        with pytest.raises(NodeSecurityError):
            conn.connect()

        # The first node was attempted and failed; the backup was refused
        # before the switch, so it was never attempted and the connection
        # did not move onto a node whose trust rules are unmet.
        assert FakeNodeTransport.attempts == ['first']
        assert FakeNodeTransport.verified == []
        assert conn.hostname == 'first'
        assert conn._active_node is None
        assert not conn.connected

    def test_verified_backup_is_kept_even_if_primary_returns(self):
        conn = make_fake_connection(
            ['amqp://first', 'amqp://u2:p2@backup'],
            approved_alternates=['amqp://u2:p2@backup'],
            connect_timeout=1,
        )
        conn.transport.fail_hosts.append('first')
        conn.connect()
        assert conn.hostname == 'backup'

        # A recoverable error arrives while the verified backup session
        # is still open: the result must not be replaced by the primary.
        conn.maybe_switch_next()
        assert conn.hostname == 'backup'
        assert conn.connected
        assert FakeNodeTransport.attempts == ['first', 'backup']


class xResource(Resource):

    def setup(self):
        pass


class ResourceCase:

    def create_resource(self, limit):
        raise NotImplementedError('subclass responsibility')

    def assert_state(self, P, avail, dirty):
        assert P._resource.qsize() == avail
        assert len(P._dirty) == dirty

    def test_setup(self):
        with pytest.raises(NotImplementedError):
            Resource()

    def test_acquire__release(self):
        P = self.create_resource(10)
        self.assert_state(P, 10, 0)
        chans = [P.acquire() for _ in range(10)]
        self.assert_state(P, 0, 10)
        with pytest.raises(P.LimitExceeded):
            P.acquire()
        chans.pop().release()
        self.assert_state(P, 1, 9)
        [chan.release() for chan in chans]
        self.assert_state(P, 10, 0)

    def test_acquire_prepare_raises(self):
        P = self.create_resource(10)

        assert len(P._resource.queue) == 10
        P.prepare = Mock()
        P.prepare.side_effect = IOError()
        with pytest.raises(IOError):
            P.acquire(block=True)
        assert len(P._resource.queue) == 10

    def test_acquire_no_limit(self):
        P = self.create_resource(None)
        P.acquire().release()

    def test_acquire_resize_in_use(self):
        P = self.create_resource(5)
        self.assert_state(P, 5, 0)
        chans = [P.acquire() for _ in range(5)]
        self.assert_state(P, 0, 5)
        with pytest.raises(RuntimeError):
            P.resize(4)
        [chan.release() for chan in chans]
        self.assert_state(P, 5, 0)

    def test_acquire_resize_ignore_err_no_shrink(self):
        P = self.create_resource(5)
        self.assert_state(P, 5, 0)
        chans = [P.acquire() for _ in range(5)]
        self.assert_state(P, 0, 5)
        P.resize(4, ignore_errors=True)
        self.assert_state(P, 0, 5)
        [chan.release() for chan in chans]
        self.assert_state(P, 5, 0)

    def test_acquire_resize_ignore_err_shrink(self):
        P = self.create_resource(5)
        self.assert_state(P, 5, 0)
        chans = [P.acquire() for _ in range(4)]
        self.assert_state(P, 1, 4)
        P.resize(4, ignore_errors=True)
        self.assert_state(P, 0, 4)
        [chan.release() for chan in chans]
        self.assert_state(P, 4, 0)

    def test_acquire_resize_larger(self):
        P = self.create_resource(1)
        self.assert_state(P, 1, 0)
        c1 = P.acquire()
        self.assert_state(P, 0, 1)
        with pytest.raises(P.LimitExceeded):
            P.acquire()
        P.resize(2)
        self.assert_state(P, 1, 1)
        c2 = P.acquire()
        self.assert_state(P, 0, 2)
        c1.release()
        c2.release()
        self.assert_state(P, 2, 0)

    def test_acquire_resize_force_smaller(self):
        P = self.create_resource(2)
        self.assert_state(P, 2, 0)
        c1 = P.acquire()
        c2 = P.acquire()
        self.assert_state(P, 0, 2)
        with pytest.raises(P.LimitExceeded):
            P.acquire()
        P.resize(1, force=True)     # acts like reset
        del c1
        del c2
        self.assert_state(P, 1, 0)
        c1 = P.acquire()
        self.assert_state(P, 0, 1)
        with pytest.raises(P.LimitExceeded):
            P.acquire()
        c1.release()
        self.assert_state(P, 1, 0)

    def test_acquire_resize_reset(self):
        P = self.create_resource(2)
        self.assert_state(P, 2, 0)
        c1 = P.acquire()
        c2 = P.acquire()
        self.assert_state(P, 0, 2)
        with pytest.raises(P.LimitExceeded):
            P.acquire()
        P.resize(3, reset=True)
        del c1
        del c2
        self.assert_state(P, 3, 0)
        c1 = P.acquire()
        c2 = P.acquire()
        c3 = P.acquire()
        self.assert_state(P, 0, 3)
        with pytest.raises(P.LimitExceeded):
            P.acquire()
        c1.release()
        c2.release()
        c3.release()
        self.assert_state(P, 3, 0)

    def test_replace_when_limit(self):
        P = self.create_resource(10)
        r = P.acquire()
        P._dirty = Mock()
        P.close_resource = Mock()

        P.replace(r)
        P._dirty.discard.assert_called_with(r)
        P.close_resource.assert_called_with(r)

    def test_replace_no_limit(self):
        P = self.create_resource(None)
        r = P.acquire()
        P._dirty = Mock()
        P.close_resource = Mock()

        P.replace(r)
        P._dirty.discard.assert_not_called()
        P.close_resource.assert_called_with(r)

    def test_interface_prepare(self):
        x = xResource()
        assert x.prepare(10) == 10

    def test_force_close_all_handles_AttributeError(self):
        P = self.create_resource(10)
        cr = P.collect_resource = Mock()
        cr.side_effect = AttributeError('x')

        P.acquire()
        assert P._dirty

        P.force_close_all()

    def test_force_close_all_no_mutex(self):
        P = self.create_resource(10)
        P.close_resource = Mock()

        m = P._resource = Mock()
        m.mutex = None
        m.queue.pop.side_effect = IndexError

        P.force_close_all()

    def test_add_when_empty(self):
        P = self.create_resource(None)
        P._resource.queue.clear()
        assert not P._resource.queue
        P._add_when_empty()
        assert P._resource.queue


class test_ConnectionPool(ResourceCase):

    def create_resource(self, limit):
        return Connection(port=5672, transport=Transport).Pool(limit)

    def test_collect_resource__does_not_collect_lazy_resource(self):
        P = self.create_resource(10)
        res = lazy(object())
        res.collect = Mock(name='collect')
        P.collect_resource(res)
        res.collect.assert_not_called()

    def test_collect_resource(self):
        res = Mock(name='res')
        P = self.create_resource(10)
        P.collect_resource(res, socket_timeout=10.3)
        res.collect.assert_called_with(10.3)

    def test_setup(self):
        P = self.create_resource(10)
        q = P._resource.queue
        assert q[0]()._connection is None
        assert q[1]()._connection is None
        assert q[2]()._connection is None

    def test_acquire_raises_evaluated(self):
        P = self.create_resource(1)
        # evaluate the connection first
        r = P.acquire()
        r.release()
        P.prepare = Mock()
        P.prepare.side_effect = MemoryError()
        P.release = Mock()
        with pytest.raises(MemoryError):
            with P.acquire():
                assert False
        P.release.assert_called_with(r)

    def test_release_no__debug(self):
        P = self.create_resource(10)
        R = Mock()
        R._debug.side_effect = AttributeError()
        P.release_resource(R)

    def test_setup_no_limit(self):
        P = self.create_resource(None)
        assert not P._resource.queue
        assert P.limit is None

    def test_prepare_not_callable(self):
        P = self.create_resource(None)
        conn = Connection('memory://')
        assert P.prepare(conn) is conn

    def test_acquire_channel(self):
        P = self.create_resource(10)
        with P.acquire_channel() as (conn, channel):
            assert channel is conn.default_channel

    def test_exception_during_connection_use(self):
        """Tests that connections retrieved from a pool are replaced.

        In case of an exception during usage of an exception, it is required that the
        connection is 'replaced' (effectively closing the connection) before releasing
        it back into the pool. This ensures that reconnecting to the broker is required
        before the next usage.
        """
        P = self.create_resource(1)

        # Raising an exception during a network call should cause the cause the
        # connection to be replaced.
        with pytest.raises(IOError):
            with P.acquire() as connection:
                connection.connect()
                connection.heartbeat_check = Mock()
                connection.heartbeat_check.side_effect = IOError()
                _ = connection.heartbeat_check()

        # Acquiring the same connection from the pool yields a disconnected Connection
        # object.
        with P.acquire() as connection:
            assert not connection.connected

        # acquire_channel automatically reconnects
        with pytest.raises(IOError):
            with P.acquire_channel() as (connection, _):
                # The Connection object should still be connected
                assert connection.connected
                connection.heartbeat_check = Mock()
                connection.heartbeat_check.side_effect = IOError()
                _ = connection.heartbeat_check()

        with P.acquire() as connection:
            # The connection should be closed
            assert not connection.connected


class test_ChannelPool(ResourceCase):

    def create_resource(self, limit):
        return Connection(port=5672, transport=Transport).ChannelPool(limit)

    def test_setup(self):
        P = self.create_resource(10)
        q = P._resource.queue
        with pytest.raises(AttributeError):
            q[0].basic_consume

    def test_setup_no_limit(self):
        P = self.create_resource(None)
        assert not P._resource.queue
        assert P.limit is None

    def test_prepare_not_callable(self):
        P = self.create_resource(10)
        conn = Connection('memory://')
        chan = conn.default_channel
        assert P.prepare(chan) is chan
