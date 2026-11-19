import pytest
from django.core.exceptions import ImproperlyConfigured
from django.urls import path, re_path

from channels.generic.websocket import AsyncWebsocketConsumer
from channels.routing import URLRouter
from channels.security.websocket import (
    OriginRule,
    OriginValidator,
    OriginValidatorRouter,
)
from channels.testing import WebsocketCommunicator


class TrackingConsumer(AsyncWebsocketConsumer):
    """
    Records whether the ASGI application (and therefore the consumer) was
    actually entered for a connection.
    """

    initialized = 0
    connected = 0

    async def __call__(self, scope, receive, send):
        type(self).initialized += 1
        await super().__call__(scope, receive, send)

    async def connect(self):
        type(self).connected += 1
        await self.accept()


def build_application():
    TrackingConsumer.initialized = 0
    TrackingConsumer.connected = 0
    return OriginValidatorRouter(
        TrackingConsumer(),
        routes=[
            # Browser-facing mount point: only registered sites may connect.
            path(
                "browser/",
                OriginRule(
                    ["https://app.example.com", "https://.example.com:443"]
                ),
            ),
            # Collector mount point: independent policy, no Origin header is OK.
            path(
                "collector/",
                OriginRule(
                    ["https://collector.example.com"], allow_no_origin=True
                ),
            ),
        ],
        # Default rule covers every path without an explicit route.
        default_rule=OriginRule(["https://default.example.com"]),
    )


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_browser_route_accepts_registered_origin():
    application = build_application()
    communicator = WebsocketCommunicator(
        application,
        "/browser/ws/",
        headers=[(b"origin", b"https://app.example.com")],
    )
    connected, _ = await communicator.connect()
    assert connected
    assert TrackingConsumer.connected == 1
    await communicator.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_browser_route_rejects_unregistered_origin():
    application = build_application()
    communicator = WebsocketCommunicator(
        application,
        "/browser/ws/",
        headers=[(b"origin", b"https://evil.example.org")],
    )
    connected, _ = await communicator.connect()
    assert not connected
    await communicator.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_browser_route_rejects_missing_origin():
    application = build_application()
    communicator = WebsocketCommunicator(application, "/browser/ws/", headers=[])
    connected, _ = await communicator.connect()
    assert not connected
    await communicator.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_collector_route_accepts_missing_origin():
    application = build_application()
    communicator = WebsocketCommunicator(
        application, "/collector/agent/42/", headers=[]
    )
    connected, _ = await communicator.connect()
    assert connected
    assert TrackingConsumer.connected == 1
    await communicator.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_collector_route_still_validates_present_origin():
    application = build_application()
    communicator = WebsocketCommunicator(
        application,
        "/collector/agent/42/",
        headers=[(b"origin", b"https://evil.example.org")],
    )
    connected, _ = await communicator.connect()
    assert not connected
    await communicator.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_collector_route_accepts_configured_origin():
    application = build_application()
    communicator = WebsocketCommunicator(
        application,
        "/collector/agent/42/",
        headers=[(b"origin", b"https://collector.example.com")],
    )
    connected, _ = await communicator.connect()
    assert connected
    await communicator.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_default_rule_covers_unconfigured_path():
    application = build_application()

    allowed = WebsocketCommunicator(
        application,
        "/somewhere/else/",
        headers=[(b"origin", b"https://default.example.com")],
    )
    connected, _ = await allowed.connect()
    assert connected
    await allowed.disconnect()

    denied = WebsocketCommunicator(
        application,
        "/somewhere/else/",
        headers=[(b"origin", b"https://app.example.com")],
    )
    connected, _ = await denied.connect()
    assert not connected
    await denied.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_rejected_connection_never_initializes_consumer():
    application = build_application()
    communicator = WebsocketCommunicator(
        application,
        "/browser/ws/",
        headers=[(b"origin", b"https://evil.example.org")],
    )
    connected, _ = await communicator.connect()
    assert not connected
    assert TrackingConsumer.initialized == 0
    assert TrackingConsumer.connected == 0
    await communicator.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_mount_points_use_independent_rules_from_handshake():
    """
    The same origin header must be decided differently depending on the mount
    point, proving each route runs its own validator from the handshake.
    """
    application = build_application()
    shared_origin = [(b"origin", b"https://app.example.com")]

    browser = WebsocketCommunicator(application, "/browser/", headers=shared_origin)
    connected, _ = await browser.connect()
    assert connected
    await browser.disconnect()

    # That origin is not registered for the collector route.
    collector = WebsocketCommunicator(
        application, "/collector/", headers=shared_origin
    )
    connected, _ = await collector.connect()
    assert not connected
    await collector.disconnect()

    # No origin works for the collector but not for the browser route.
    headless_collector = WebsocketCommunicator(
        application, "/collector/", headers=[]
    )
    connected, _ = await headless_collector.connect()
    assert connected
    await headless_collector.disconnect()

    headless_browser = WebsocketCommunicator(
        application, "/browser/", headers=[]
    )
    connected, _ = await headless_browser.connect()
    assert not connected
    await headless_browser.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_router_works_nested_inside_url_router():
    inner = OriginValidatorRouter(
        TrackingConsumer(),
        routes=[
            path("browser/", OriginRule(["https://app.example.com"])),
        ],
        default_rule=OriginRule(["*"]),
    )
    application = URLRouter([path("ws/", inner)])

    communicator = WebsocketCommunicator(
        application,
        "/ws/browser/room/",
        headers=[(b"origin", b"https://app.example.com")],
    )
    connected, _ = await communicator.connect()
    assert connected
    await communicator.disconnect()

    communicator = WebsocketCommunicator(
        application,
        "/ws/browser/room/",
        headers=[(b"origin", b"https://evil.example.org")],
    )
    connected, _ = await communicator.connect()
    assert not connected
    await communicator.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_re_path_route_matches_path_prefix():
    application = OriginValidatorRouter(
        TrackingConsumer(),
        routes=[
            re_path(
                r"^collector/v\d+/",
                OriginRule(["*"], allow_no_origin=True),
            ),
        ],
        default_rule=OriginRule(["https://default.example.com"]),
    )

    matched = WebsocketCommunicator(
        application, "/collector/v2/agent/42/", headers=[]
    )
    connected, _ = await matched.connect()
    assert connected
    await matched.disconnect()

    # An unrelated path falls through to the default rule, which needs an
    # Origin header and does not allow a missing one.
    fallthrough = WebsocketCommunicator(application, "/other/", headers=[])
    connected, _ = await fallthrough.connect()
    assert not connected
    await fallthrough.disconnect()


@pytest.mark.asyncio
async def test_router_rejects_non_websocket_scope():
    application = OriginValidatorRouter(
        TrackingConsumer(),
        routes=[path("browser/", OriginRule(["*"]))],
        default_rule=OriginRule(["*"]),
    )
    with pytest.raises(ValueError):
        await application({"type": "http", "path": "/browser/"}, None, None)


def test_route_callback_must_be_origin_rule():
    with pytest.raises(ImproperlyConfigured):
        OriginValidatorRouter(
            TrackingConsumer(),
            routes=[path("browser/", TrackingConsumer())],
            default_rule=OriginRule(["*"]),
        )


def test_default_rule_must_be_origin_rule():
    with pytest.raises(ImproperlyConfigured):
        OriginValidatorRouter(
            TrackingConsumer(),
            routes=[],
            default_rule=["https://app.example.com"],
        )


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_origin_validator_allow_no_origin_flag():
    # allow_no_origin=True admits a connection without an Origin header...
    application = OriginValidator(
        AsyncWebsocketConsumer(), ["https://app.example.com"], allow_no_origin=True
    )
    communicator = WebsocketCommunicator(application, "/", headers=[])
    connected, _ = await communicator.connect()
    assert connected
    await communicator.disconnect()

    # ...while still rejecting origins that are not allowed.
    communicator = WebsocketCommunicator(
        application, "/", headers=[(b"origin", b"https://evil.example.org")]
    )
    connected, _ = await communicator.connect()
    assert not connected
    await communicator.disconnect()

    # Default behaviour (flag omitted) keeps rejecting missing origins.
    application = OriginValidator(
        AsyncWebsocketConsumer(), ["https://app.example.com"]
    )
    communicator = WebsocketCommunicator(application, "/", headers=[])
    connected, _ = await communicator.connect()
    assert not connected
    await communicator.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_origin_rule_allowed_hosts_default(settings):
    settings.DEBUG = False
    settings.ALLOWED_HOSTS = ["app.example.com"]
    rule = OriginRule.allowed_hosts(allow_no_origin=True)
    application = OriginValidatorRouter(
        TrackingConsumer(),
        routes=[path("browser/", rule)],
        default_rule=OriginRule([]),
    )

    communicator = WebsocketCommunicator(
        application,
        "/browser/",
        headers=[(b"origin", b"http://app.example.com")],
    )
    connected, _ = await communicator.connect()
    assert connected
    await communicator.disconnect()

    communicator = WebsocketCommunicator(application, "/browser/", headers=[])
    connected, _ = await communicator.connect()
    assert connected
    await communicator.disconnect()
