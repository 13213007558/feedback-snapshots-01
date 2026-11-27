import json

import pytest

import falcon
from falcon import testing
from falcon.asgi import App


def test_at_least_one_event_method_required():
    class Foo:
        pass

    app = App()

    with pytest.raises(TypeError):
        app.add_middleware(Foo())


def test_startup_only():
    class Foo:
        async def process_startup(self, scope, event):
            self._called = True

    foo = Foo()

    app = App()
    app.add_middleware(foo)
    client = testing.TestClient(app)

    client.simulate_get()

    assert foo._called


def test_startup_raises():
    class Foo:
        def __init__(self):
            self._shutdown_called = False

        async def process_startup(self, scope, event):
            raise Exception('testing 123')

        async def process_shutdown(self, scope, event):
            self._shutdown_called = True

    class Bar:
        def __init__(self):
            self._startup_called = False
            self._shutdown_called = False

        async def process_startup(self, scope, event):
            self._startup_called = True

        async def process_shutdown(self, scope, event):
            self._shutdown_called = True

    foo = Foo()
    bar = Bar()

    app = App()
    app.add_middleware([foo, bar])
    client = testing.TestClient(app)

    with pytest.raises(RuntimeError) as excinfo:
        client.simulate_get()

    message = str(excinfo.value)

    assert message.startswith('ASGI app returned lifespan.startup.failed.')
    assert 'testing 123' in message

    assert not foo._shutdown_called
    assert not bar._startup_called
    assert not bar._shutdown_called


def test_startup_failure_rolls_back_already_prepared_handlers():
    # NOTE: Two authorization plugins are prepared during ASGI startup. The
    #   first one acquires a resource (e.g. opens a connection); the second
    #   one's approval condition is not met and its startup raises. The
    #   framework must unwind the already-prepared part of the chain instead
    #   of leaving a half-initialized authorization chain behind.
    class FirstAuthPlugin:
        def __init__(self, events):
            self._events = events

        async def process_startup(self, scope, event):
            self._events.append('first:acquire')

        async def process_shutdown(self, scope, event):
            self._events.append('first:release')

        async def process_request(self, req, resp):
            self._events.append('first:authorize')

    class SecondAuthPlugin:
        def __init__(self, events, fail_startup):
            self._events = events
            self._fail_startup = fail_startup

        async def process_startup(self, scope, event):
            if self._fail_startup:
                self._events.append('second:startup-failed')
                raise RuntimeError('approval condition not met')
            self._events.append('second:acquire')

        async def process_shutdown(self, scope, event):
            self._events.append('second:release')

        async def process_request(self, req, resp):
            self._events.append('second:authorize')

    events: list[str] = []
    fail_startup = True
    app = App()
    app.add_middleware(
        [FirstAuthPlugin(events), SecondAuthPlugin(events, fail_startup)]
    )
    client = testing.TestClient(app)

    with pytest.raises(RuntimeError) as excinfo:
        client.simulate_get()

    message = str(excinfo.value)
    assert message.startswith('ASGI app returned lifespan.startup.failed.')
    assert 'approval condition not met' in message

    # NOTE: The first plugin's resource was prepared, then deterministically
    #   released during rollback; the second plugin never finished starting and
    #   therefore has no resource to release.
    assert events == [
        'first:acquire',
        'second:startup-failed',
        'first:release',
    ]


def test_startup_failure_recovery_then_request_flows_through_chain():
    # NOTE: End-to-end local use case: a failed startup attempt must clean up
    #   every prepared resource, after which recovering the approval condition
    #   allows the app to start again and serve a request through the complete
    #   authorization chain.
    class FirstAuthPlugin:
        def __init__(self, events):
            self._events = events
            self.active = False

        async def process_startup(self, scope, event):
            self.active = True
            self._events.append('first:acquire')

        async def process_shutdown(self, scope, event):
            self.active = False
            self._events.append('first:release')

        async def process_request(self, req, resp):
            assert self.active
            self._events.append('first:authorize')

    class SecondAuthPlugin:
        def __init__(self, events, fail_startup):
            self._events = events
            self._fail_startup = fail_startup
            self.active = False

        async def process_startup(self, scope, event):
            if self._fail_startup[0]:
                self._events.append('second:startup-failed')
                raise RuntimeError('approval condition not met')
            self.active = True
            self._events.append('second:acquire')

        async def process_shutdown(self, scope, event):
            self.active = False
            self._events.append('second:release')

        async def process_request(self, req, resp):
            assert self.active
            self._events.append('second:authorize')

    class ProtectedResource:
        async def on_get(self, req, resp):
            resp.media = {'status': 'authorized'}

    events: list[str] = []
    fail_startup = [True]
    first = FirstAuthPlugin(events)
    second = SecondAuthPlugin(events, fail_startup)

    app = App()
    app.add_middleware([first, second])
    app.add_route('/protected', ProtectedResource())

    # First startup attempt: the second plugin fails its approval condition.
    with pytest.raises(RuntimeError) as excinfo:
        testing.TestClient(app).simulate_get('/protected')

    assert 'approval condition not met' in str(excinfo.value)

    # NOTE: No half-initialized chain survives the failure: the prepared
    #   resource of the first plugin was released, and neither plugin is active.
    assert events == [
        'first:acquire',
        'second:startup-failed',
        'first:release',
    ]
    assert not first.active
    assert not second.active

    # Recover the approval condition and start the app again. A new lifespan
    # run (a fresh TestClient) models the server process restarting.
    fail_startup[0] = False
    response = testing.TestClient(app).simulate_get('/protected')

    assert response.status == falcon.HTTP_200
    assert json.loads(response.text) == {'status': 'authorized'}

    # NOTE: On the successful run both resources are prepared, the request is
    #   authorized by every plugin in order, and TestClient shutdown releases
    #   both resources in reverse order.
    assert events == [
        'first:acquire',
        'second:startup-failed',
        'first:release',
        'first:acquire',
        'second:acquire',
        'first:authorize',
        'second:authorize',
        'second:release',
        'first:release',
    ]
    assert not first.active
    assert not second.active


def test_startup_rollback_error_is_reported_alongside_startup_error():
    class FailingRollback:
        async def process_startup(self, scope, event):
            pass

        async def process_shutdown(self, scope, event):
            raise RuntimeError('rollback boom')

    class FailingStartup:
        async def process_startup(self, scope, event):
            raise RuntimeError('startup boom')

    app = App()
    app.add_middleware([FailingRollback(), FailingStartup()])
    client = testing.TestClient(app)

    with pytest.raises(RuntimeError) as excinfo:
        client.simulate_get()

    message = str(excinfo.value)
    assert message.startswith('ASGI app returned lifespan.startup.failed.')
    assert 'startup boom' in message
    assert 'rollback boom' in message


def test_startup_rollback_skips_handlers_without_shutdown():
    # NOTE: A handler that only implements process_startup has no resource to
    #   release; rollback must skip it cleanly rather than assume every
    #   started handler defines process_shutdown.
    class StartupOnly:
        def __init__(self, events):
            self._events = events

        async def process_startup(self, scope, event):
            self._events.append('startup-only:acquire')

    class FailingAuthPlugin:
        def __init__(self, events):
            self._events = events

        async def process_startup(self, scope, event):
            self._events.append('failing:startup-failed')
            raise RuntimeError('approval condition not met')

    events: list[str] = []
    app = App()
    app.add_middleware([StartupOnly(events), FailingAuthPlugin(events)])

    with pytest.raises(RuntimeError) as excinfo:
        testing.TestClient(app).simulate_get()

    assert 'approval condition not met' in str(excinfo.value)
    assert events == ['startup-only:acquire', 'failing:startup-failed']


def test_failed_startup_never_enters_request_serving_context():
    # NOTE: When an authorization plugin fails startup, the ASGI conductor
    #   must raise before handing control to the request path, so that no
    #   half-initialized authorization chain can ever serve a request.
    class FirstAuthPlugin:
        def __init__(self, events):
            self._events = events

        async def process_startup(self, scope, event):
            self._events.append('first:acquire')

        async def process_shutdown(self, scope, event):
            self._events.append('first:release')

        async def process_request(self, req, resp):
            self._events.append('first:authorize')

    class FailingAuthPlugin:
        def __init__(self, events):
            self._events = events

        async def process_startup(self, scope, event):
            self._events.append('second:startup-failed')
            raise RuntimeError('approval condition not met')

        async def process_shutdown(self, scope, event):
            self._events.append('second:release')

        async def process_request(self, req, resp):
            self._events.append('second:authorize')

    class ProtectedResource:
        async def on_get(self, req, resp):
            resp.media = {'status': 'authorized'}

    events: list[str] = []
    app = App()
    app.add_middleware([FirstAuthPlugin(events), FailingAuthPlugin(events)])
    app.add_route('/protected', ProtectedResource())

    async def scenario():
        with pytest.raises(RuntimeError) as excinfo:
            async with testing.ASGIConductor(app) as conductor:
                await conductor.simulate_get('/protected')

        assert 'approval condition not met' in str(excinfo.value)

    falcon.async_to_sync(scenario)

    # NOTE: The prepared resource was rolled back and no request was ever
    #   authorized while the chain was in a half-initialized state.
    assert events == [
        'first:acquire',
        'second:startup-failed',
        'first:release',
    ]


def test_shutdown_raises():
    class HandlerA:
        def __init__(self):
            self._startup_called = False

        async def process_startup(self, scope, event):
            self._startup_called = True

        async def process_shutdown(self, scope, event):
            raise Exception('testing 321')

    class HandlerB:
        def __init__(self):
            self._startup_called = False
            self._shutdown_called = False

        async def process_startup(self, scope, event):
            self._startup_called = True

        async def process_shutdown(self, scope, event):
            self._shutdown_called = True

    a = HandlerA()
    b1 = HandlerB()
    b2 = HandlerB()

    app = App()
    app.add_middleware(b1)
    app.add_middleware([a, b2])
    client = testing.TestClient(app)

    with pytest.raises(RuntimeError) as excinfo:
        client.simulate_get()

    message = str(excinfo.value)

    assert message.startswith('ASGI app returned lifespan.shutdown.failed.')
    assert 'testing 321' in message

    assert a._startup_called
    assert b1._startup_called
    assert not b1._shutdown_called
    assert b2._startup_called
    assert b2._shutdown_called


def test_shutdown_only():
    class Foo:
        async def process_shutdown(self, scope, event):
            self._called = True

    foo = Foo()

    app = App()
    app.add_middleware(foo)
    client = testing.TestClient(app)

    client.simulate_get()

    assert foo._called


def test_multiple_handlers():
    counter = 0

    class HandlerA:
        async def process_startup(self, scope, event):
            nonlocal counter
            self._called_startup = counter
            counter += 1

    class HandlerB:
        async def process_startup(self, scope, event):
            nonlocal counter
            self._called_startup = counter
            counter += 1

        async def process_shutdown(self, scope, event):
            nonlocal counter
            self._called_shutdown = counter
            counter += 1

    class HandlerC:
        async def process_shutdown(self, scope, event):
            nonlocal counter
            self._called_shutdown = counter
            counter += 1

    class HandlerD:
        async def process_startup(self, scope, event):
            nonlocal counter
            self._called_startup = counter
            counter += 1

    class HandlerE:
        async def process_startup(self, scope, event):
            nonlocal counter
            self._called_startup = counter
            counter += 1

        async def process_shutdown(self, scope, event):
            nonlocal counter
            self._called_shutdown = counter
            counter += 1

        async def process_request(self, req, resp):
            self._called_request = True

    app = App()

    a = HandlerA()
    b = HandlerB()
    c = HandlerC()
    d = HandlerD()
    e = HandlerE()

    app.add_middleware([a, b, c, d, e])

    client = testing.TestClient(app)
    client.simulate_get()

    assert a._called_startup == 0
    assert b._called_startup == 1
    assert d._called_startup == 2
    assert e._called_startup == 3

    assert e._called_shutdown == 4
    assert c._called_shutdown == 5
    assert b._called_shutdown == 6

    assert e._called_request


def test_asgi_conductor_raised_error_skips_shutdown():
    class SomeException(Exception):
        pass

    class Foo:
        def __init__(self):
            self.called_startup = False
            self.called_shutdown = False

        async def process_startup(self, scope, event):
            self.called_startup = True

        async def process_shutdown(self, scope, event):
            self.called_shutdown = True

    foo = Foo()

    app = App()
    app.add_middleware(foo)

    async def t():
        with pytest.raises(SomeException):
            async with testing.ASGIConductor(app):
                raise SomeException()

    falcon.async_to_sync(t)
    assert foo.called_startup
    assert not foo.called_shutdown


def test_asgi_conductor_raised_error_cancels_lifespan_task():
    class SomeException(Exception):
        pass

    conductor = testing.ASGIConductor(App())

    async def t():
        with pytest.raises(SomeException):
            async with conductor:
                raise SomeException()

    falcon.async_to_sync(t)

    # NOTE(vytas): Private attr; the cancellation is not observable otherwise.
    assert conductor._lifespan_task.cancelled()
