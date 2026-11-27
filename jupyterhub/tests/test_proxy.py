"""Test a proxy being started before the Hub"""

import asyncio
import json
import os
import socket
from contextlib import contextmanager
from subprocess import Popen
from types import SimpleNamespace
from urllib.parse import quote, urlparse

import pytest
from traitlets import TraitError
from traitlets.config import Config

from .. import orm
from ..proxy import ConfigurableHTTPProxy, Proxy
from ..utils import random_port, wait_for_http_server
from ..utils import url_path_join as ujoin
from .mocking import MockHub
from .test_api import add_user, api_request


@pytest.fixture
def disable_check_routes(app):
    # disable periodic check_routes while we are testing
    app._periodic_callbacks["last_activity"].stop()
    try:
        yield
    finally:
        app._periodic_callbacks["last_activity"].start()


async def test_external_proxy(request):
    auth_token = 'secret!'
    proxy_ip = '127.0.0.1'
    proxy_port = random_port()
    cfg = Config()
    cfg.ConfigurableHTTPProxy.auth_token = auth_token
    cfg.ConfigurableHTTPProxy.api_url = f'http://{proxy_ip}:{proxy_port}'
    cfg.ConfigurableHTTPProxy.should_start = False

    app = MockHub.instance(config=cfg)
    # disable last_activity polling to avoid check_routes being called during the test,
    # which races with some of our test conditions
    app.last_activity_interval = 0

    def fin():
        MockHub.clear_instance()
        app.http_server.stop()

    request.addfinalizer(fin)

    # configures and starts proxy process
    env = os.environ.copy()
    env['CONFIGPROXY_AUTH_TOKEN'] = auth_token
    cmd = [
        'configurable-http-proxy',
        '--ip',
        app.ip,
        '--port',
        str(app.port),
        '--api-ip',
        proxy_ip,
        '--api-port',
        str(proxy_port),
        '--log-level=debug',
    ]
    if app.subdomain_host:
        cmd.append('--host-routing')
    proxy = Popen(cmd, env=env)

    def _cleanup_proxy():
        if proxy.poll() is None:
            proxy.terminate()
            proxy.wait(timeout=10)

    request.addfinalizer(_cleanup_proxy)

    def wait_for_proxy():
        return wait_for_http_server(f'http://{proxy_ip}:{proxy_port}')

    await wait_for_proxy()

    await app.initialize([])
    await app.start()
    assert app.proxy.proxy_process is None

    # test if api service has a root route '/'
    routes = await app.proxy.get_all_routes()
    assert list(routes.keys()) == [app.hub.routespec]

    # add user to the db and start a single user server
    name = 'river'
    add_user(app.db, app, name=name)
    r = await api_request(
        app, 'users', name, 'server', method='post', bypass_proxy=True
    )
    r.raise_for_status()

    routes = await app.proxy.get_all_routes()
    # sets the desired path result
    user_path = ujoin(app.base_url, 'user/river') + '/'
    print(app.base_url, user_path)
    host = ''
    if app.subdomain_host:
        host = f'{name}.{urlparse(app.subdomain_host).hostname}'
    user_spec = host + user_path
    assert sorted(routes.keys()) == [app.hub.routespec, user_spec]

    # teardown the proxy and start a new one in the same place
    proxy.terminate()
    proxy.wait(timeout=10)
    proxy = Popen(cmd, env=env)
    await wait_for_proxy()

    routes = await app.proxy.get_all_routes()

    assert list(routes.keys()) == []

    # poke the server to update the proxy
    r = await api_request(app, 'proxy', method='post', bypass_proxy=True)
    r.raise_for_status()

    # check that the routes are correct
    routes = await app.proxy.get_all_routes()
    assert sorted(routes.keys()) == [app.hub.routespec, user_spec]

    # teardown the proxy, and start a new one with different auth and port
    proxy.terminate()
    proxy.wait(timeout=10)
    new_auth_token = 'different!'
    env['CONFIGPROXY_AUTH_TOKEN'] = new_auth_token
    proxy_port = random_port()
    cmd = [
        'configurable-http-proxy',
        '--ip',
        app.ip,
        '--port',
        str(app.port),
        '--api-ip',
        proxy_ip,
        '--api-port',
        str(proxy_port),
        '--default-target',
        f'http://{app.hub_ip}:{app.hub_port}',
    ]
    if app.subdomain_host:
        cmd.append('--host-routing')
    proxy = Popen(cmd, env=env)
    await wait_for_proxy()

    # tell the hub where the new proxy is
    new_api_url = f'http://{proxy_ip}:{proxy_port}'
    r = await api_request(
        app,
        'proxy',
        method='patch',
        data=json.dumps({'api_url': new_api_url, 'auth_token': new_auth_token}),
        bypass_proxy=True,
    )
    r.raise_for_status()
    assert app.proxy.api_url == new_api_url

    assert app.proxy.auth_token == new_auth_token

    # check that the routes are correct
    routes = await app.proxy.get_all_routes()
    assert sorted(routes.keys()) == [app.hub.routespec, user_spec]


@pytest.mark.parametrize("username", ['zoe', '50fia', '秀樹', '~TestJH', 'has@'])
async def test_check_routes(app, username, disable_check_routes):
    proxy = app.proxy
    test_user = add_user(app.db, app, name=username)
    r = await api_request(app, f'users/{username}/server', method='post')
    r.raise_for_status()

    # check a valid route exists for user
    routes = await app.proxy.get_all_routes()
    before = sorted(routes)
    assert test_user.proxy_spec in before

    # check if a route is removed when user deleted
    await app.proxy.check_routes(app.users, app._service_map)
    await proxy.delete_user(test_user)
    routes = await app.proxy.get_all_routes()
    during = sorted(routes)
    assert test_user.proxy_spec not in during

    # check if a route exists for user
    await app.proxy.check_routes(app.users, app._service_map)
    routes = await app.proxy.get_all_routes()
    after = sorted(routes)
    assert test_user.proxy_spec in after

    # check that before and after state are the same
    assert before == after


@pytest.mark.parametrize(
    "routespec",
    [
        '/has%20space/foo/',
        '/missing-trailing/slash',
        '/has/@/',
        '/has/' + quote('üñîçø∂é'),
        'host.name/path/',
        'other.host/path/no/slash',
    ],
)
async def test_extra_routes(app, routespec):
    proxy = app.proxy
    # When using host_routing, it's up to the admin to
    # provide routespecs that have a domain in them.
    # We don't explicitly validate that here.
    if app.subdomain_host and routespec.startswith("/"):
        routespec = 'example.com/' + routespec
    elif not app.subdomain_host and not routespec.startswith("/"):
        pytest.skip("requires subdomains")
    validated_routespec = routespec
    if not routespec.endswith("/"):
        validated_routespec = routespec + "/"
    target = 'http://localhost:9999/test'
    proxy.extra_routes = {routespec: target}

    await proxy.check_routes(app.users, app._service_map)

    routes = await app.proxy.get_all_routes()
    print(routes)
    assert validated_routespec in routes
    assert routes[validated_routespec]['target'] == target
    assert routes[validated_routespec]['data']['extra']


@pytest.mark.parametrize(
    "needs_subdomain, routespec, expected",
    [
        (False, "/prefix/", "/prefix/"),
        (False, "/prefix", "/prefix/"),
        (False, "prefix/", ValueError),
        (True, "/prefix/", ValueError),
        (True, "example.com/prefix/", "example.com/prefix/"),
        (True, "example.com/prefix", "example.com/prefix/"),
        (False, 100, TraitError),
    ],
)
def test_extra_routes_validate_routespec(
    request, app, needs_subdomain, routespec, expected
):
    save_host = app.subdomain_host
    request.addfinalizer(lambda: setattr(app, "subdomain_host", save_host))
    if needs_subdomain:
        app.subdomain_host = "localhost.jovyan.org"
    else:
        app.subdomain_host = ""

    proxy = app.proxy

    extra_routes = {routespec: "https://127.0.0.1"}
    if isinstance(expected, type) and issubclass(expected, BaseException):
        with pytest.raises(expected):
            proxy.extra_routes = extra_routes
        return
    proxy.extra_routes = extra_routes
    assert list(proxy.extra_routes) == [expected]


@pytest.mark.parametrize(
    "target, expected",
    [
        ("http://host", "http://host"),
        ("https://host", "https://host"),
        ("/missing-host", ValueError),
        ("://missing-scheme", ValueError),
        (100, TraitError),
    ],
)
def test_extra_routes_validate_target(app, target, expected):
    proxy = app.proxy
    routespec = "/prefix/"
    if app.subdomain_host:
        routespec = f"host.tld{routespec}"
    extra_routes = {routespec: target}
    if isinstance(expected, type) and issubclass(expected, BaseException):
        with pytest.raises(expected):
            proxy.extra_routes = extra_routes
        return
    proxy.extra_routes = extra_routes
    assert list(proxy.extra_routes.values()) == [expected]


@pytest.mark.parametrize(
    "routespec",
    [
        '/has%20space/foo/',
        '/missing-trailing/slash',
        '/has/@/',
        '/has/' + quote('üñîçø∂é'),
        'host.name/path/',
        'other.host/path/no/slash',
    ],
)
async def test_add_get_delete(app, routespec, disable_check_routes):
    arg = routespec
    if not routespec.endswith('/'):
        routespec = routespec + '/'

    # host-routes when not host-routing raises an error
    # and vice versa
    expect_value_error = bool(app.subdomain_host) ^ (not routespec.startswith('/'))

    @contextmanager
    def context():
        if expect_value_error:
            with pytest.raises(ValueError):
                yield
        else:
            yield

    proxy = app.proxy
    target = 'https://localhost:1234'
    with context():
        await proxy.add_route(arg, target, {})
    routes = await proxy.get_all_routes()
    if not expect_value_error:
        assert routespec in routes.keys()
    with context():
        route = await proxy.get_route(arg)
        assert route == {
            'target': target,
            'routespec': routespec,
            'data': route.get('data'),
        }
    with context():
        await proxy.delete_route(arg)
    with context():
        route = await proxy.get_route(arg)
        assert route is None


@pytest.mark.parametrize("test_data", [None, 'notjson', json.dumps([])])
async def test_proxy_patch_bad_request_data(app, test_data):
    r = await api_request(app, 'proxy', method='patch', data=test_data)
    assert r.status_code == 400


async def test_proxy_bind_ip(request, app, tmp_path):
    public_port = random_port()
    api_port = random_port()
    public_url = f"http://0.0.0.0:{public_port}"
    api_url = f"http://0.0.0.0:{api_port}"
    proxy = ConfigurableHTTPProxy(
        public_url=public_url,
        api_url=api_url,
        app=app,
        hub=app.hub,
        pid_file=str(tmp_path / "proxy.pid"),
    )
    await proxy.start()
    request.addfinalizer(proxy.stop)
    cmdline = " ".join(proxy.proxy_process.args)
    assert '--ip 0.0.0.0' in cmdline
    assert '--api-ip 0.0.0.0' in cmdline
    public_ip = socket.gethostbyname(socket.gethostname())
    # make sure it is connectable on both local and public ips
    await wait_for_http_server(public_url.replace("0.0.0.0", "127.0.0.1"))
    await wait_for_http_server(public_url.replace("0.0.0.0", public_ip))
    await wait_for_http_server(api_url.replace("0.0.0.0", "127.0.0.1"))
    await wait_for_http_server(api_url.replace("0.0.0.0", public_ip))


class RecordingProxy(Proxy):
    """In-memory proxy stand-in for testing route add/delete behavior.

    - records every add/delete in `calls`
    - can be told to fail the next add_route attempts
    - can block a failing add_route so tests can inspect
      the state while a route commit is in flight
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.routes = {}
        self.calls = []
        self.fail_next_adds = 0
        self.add_route_blocker = None
        self.first_add_attempt = asyncio.Event()

    async def get_all_routes(self):
        return {
            routespec: dict(route, routespec=routespec)
            for routespec, route in self.routes.items()
        }

    async def add_route(self, routespec, target, data):
        self.first_add_attempt.set()
        self.calls.append(('add', routespec, target))
        if self.fail_next_adds:
            self.fail_next_adds -= 1
            if self.add_route_blocker is not None:
                # wait for the test to inspect the in-flight state
                await self.add_route_blocker.wait()
            raise RuntimeError("add_route failed, as requested by the test")
        self.routes[routespec] = {'target': target, 'data': data}

    async def delete_route(self, routespec):
        self.calls.append(('delete', routespec))
        self.routes.pop(routespec, None)


async def test_late_stop_report_from_replaced_server(app, disable_check_routes):
    """A late stop report must not take down the replacement server

    Timeline:
    1. the old server runs, the route points at it
    2. the old server stops, but its stop report (poll callback)
       has not been delivered yet
    3. a new server with the same name starts; the first proxy write
       fails and is retried; the healthy new server is not serviceable
       until its route is actually committed
    4. the old server's delayed stop report arrives:
       it may only clean up its own record, the new route must survive
    """
    proxy = RecordingProxy(app=app, hub=app.hub, log=app.log)
    real_proxy = app.proxy
    app.proxy = proxy
    app.tornado_settings['proxy'] = proxy
    try:
        name = 'latestop'
        user = add_user(app.db, app, name=name)
        routespec = user.proxy_spec

        # 1. start the old server
        r = await api_request(
            app, 'users', name, 'server', method='post', bypass_proxy=True
        )
        assert r.code == 201
        old_spawner = user.spawners['']
        old_target = old_spawner.server.host
        old_token = old_spawner.api_token
        assert proxy.routes[routespec]['target'] == old_target
        # the spawn authorized an API token for the old server
        assert orm.APIToken.find(app.db, old_token) is not None

        # 2. stop the old server; its stop report is still in flight
        r = await api_request(
            app, 'users', name, 'server', method='delete', bypass_proxy=True
        )
        assert r.code == 204
        assert routespec not in proxy.routes
        # the old server's authorization was revoked
        assert orm.APIToken.find(app.db, old_token) is None
        assert '' not in user.spawners

        # 3. start the replacement server; the first proxy write fails
        proxy.first_add_attempt.clear()
        proxy.fail_next_adds = 1
        proxy.add_route_blocker = asyncio.Event()
        spawn = asyncio.ensure_future(
            api_request(app, 'users', name, 'server', method='post', bypass_proxy=True)
        )
        # wait until the first (doomed) write is in flight
        await asyncio.wait_for(proxy.first_add_attempt.wait(), 10)

        # the new server is up and healthy, but not serviceable yet:
        # its route has not been committed to the proxy
        new_spawner = user.spawners['']
        assert new_spawner is not old_spawner
        assert new_spawner.server is not None
        assert await new_spawner.poll() is None
        assert new_spawner._proxy_pending
        assert not new_spawner.ready
        assert routespec not in proxy.routes

        # let the first write fail; the retried write commits the route
        proxy.add_route_blocker.set()
        r = await spawn
        assert r.code == 201
        new_target = new_spawner.server.host
        assert new_target != old_target
        assert proxy.routes[routespec]['target'] == new_target
        assert new_spawner.ready
        # the new spawn authorized a new API token
        new_token = new_spawner.api_token
        assert new_token != old_token
        assert orm.APIToken.find(app.db, new_token) is not None

        # the route was committed exactly once, after one failed attempt
        assert proxy.calls == [
            ('add', routespec, old_target),
            ('delete', routespec),
            ('add', routespec, new_target),
            ('add', routespec, new_target),
        ]

        # 4. the old server's delayed stop report arrives
        await old_spawner.poll_and_notify()
        # make sure the report was actually delivered, not still pending
        assert not old_spawner._callbacks

        # it only cleaned up after itself: nothing else was deleted,
        # and the new route, server, and authorization all survive
        assert proxy.calls.count(('delete', routespec)) == 1
        assert proxy.routes[routespec]['target'] == new_target
        assert user.spawners[''] is new_spawner
        assert new_spawner.ready
        assert await new_spawner.poll() is None
        assert orm.APIToken.find(app.db, new_token) is not None
    finally:
        app.proxy = real_proxy
        app.tornado_settings['proxy'] = real_proxy


async def test_delete_user_only_removes_own_route(app):
    """Proxy.delete_user only removes a route owned by the stopping server"""
    proxy = RecordingProxy(app=app, hub=app.hub, log=app.log)
    user = add_user(app.db, app, name='routecheck')
    routespec = user.proxy_spec
    target = 'http://127.0.0.1:12345'
    route = {'target': target, 'data': {'user': user.name, 'server_name': ''}}
    proxy.routes[routespec] = route

    # a stop report for a previous incarnation whose server doesn't match
    # the current route target must not remove the route
    stale = SimpleNamespace(
        server=SimpleNamespace(host='http://127.0.0.1:11111'),
        _log_name=f'{user.name} (previous)',
    )
    await proxy.delete_user(user, '', spawner=stale)
    assert proxy.routes[routespec] == route
    assert proxy.calls == []

    # a stop report for a server that is already gone cleans up nothing
    gone = SimpleNamespace(server=None, _log_name=f'{user.name} (gone)')
    await proxy.delete_user(user, '', spawner=gone)
    assert proxy.routes[routespec] == route
    assert proxy.calls == []

    # a stop report whose server matches the route removes its own record
    own = SimpleNamespace(
        server=SimpleNamespace(host=target), _log_name=f'{user.name} (own)'
    )
    await proxy.delete_user(user, '', spawner=own)
    assert routespec not in proxy.routes
    assert proxy.calls == [('delete', routespec)]

    # without any spawner information, the route is removed (legacy cleanup)
    proxy.routes[routespec] = route
    proxy.calls.clear()
    await proxy.delete_user(user, '')
    assert routespec not in proxy.routes
    assert proxy.calls == [('delete', routespec)]
