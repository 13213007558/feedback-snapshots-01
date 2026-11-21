import socket
from http.client import HTTPSConnection

import pytest

import sentry_sdk
from sentry_sdk.integrations.asgi import SentryAsgiMiddleware
from sentry_sdk.integrations.stdlib import StdlibIntegration
from sentry_sdk.tracing_utils import (
    DEFAULT_BAGGAGE_CATEGORIES,
    MINIMAL_BAGGAGE_CATEGORIES,
    Baggage,
    get_baggage_categories,
)


def _parse_baggage(header: str) -> dict:
    items = {}
    for item in header.split(","):
        key, _, value = item.partition("=")
        if key.startswith("sentry-"):
            items[key[len("sentry-") :]] = value
    return items


def test_third_party_baggage():
    header = "other-vendor-value-1=foo;bar;baz, other-vendor-value-2=foo;bar;"
    baggage = Baggage.from_incoming_header(header)

    assert baggage.mutable
    assert baggage.sentry_items == {}
    assert (
        baggage.third_party_items
        == "other-vendor-value-1=foo;bar;baz,other-vendor-value-2=foo;bar;"
    )

    assert baggage.dynamic_sampling_context() == {}
    assert baggage.serialize() == ""
    assert (
        baggage.serialize(include_third_party=True)
        == "other-vendor-value-1=foo;bar;baz,other-vendor-value-2=foo;bar;"
    )


def test_mixed_baggage():
    header = (
        "other-vendor-value-1=foo;bar;baz, sentry-trace_id=771a43a4192642f0b136d5159a501700, "
        "sentry-public_key=49d0f7386ad645858ae85020e393bef3, sentry-sample_rate=0.01337, "
        "sentry-user_id=Am%C3%A9lie, sentry-foo=bar, other-vendor-value-2=foo;bar;"
    )

    baggage = Baggage.from_incoming_header(header)

    assert not baggage.mutable

    assert baggage.sentry_items == {
        "public_key": "49d0f7386ad645858ae85020e393bef3",
        "trace_id": "771a43a4192642f0b136d5159a501700",
        "user_id": "Amélie",
        "sample_rate": "0.01337",
        "foo": "bar",
    }

    assert (
        baggage.third_party_items
        == "other-vendor-value-1=foo;bar;baz,other-vendor-value-2=foo;bar;"
    )

    assert baggage.dynamic_sampling_context() == {
        "public_key": "49d0f7386ad645858ae85020e393bef3",
        "trace_id": "771a43a4192642f0b136d5159a501700",
        "user_id": "Amélie",
        "sample_rate": "0.01337",
        "foo": "bar",
    }

    assert baggage.serialize() == (
        "sentry-trace_id=771a43a4192642f0b136d5159a501700,"
        "sentry-public_key=49d0f7386ad645858ae85020e393bef3,"
        "sentry-sample_rate=0.01337,sentry-user_id=Am%C3%A9lie,"
        "sentry-foo=bar"
    )

    assert baggage.serialize(include_third_party=True) == (
        "sentry-trace_id=771a43a4192642f0b136d5159a501700,"
        "sentry-public_key=49d0f7386ad645858ae85020e393bef3,"
        "sentry-sample_rate=0.01337,sentry-user_id=Am%C3%A9lie,sentry-foo=bar,"
        "other-vendor-value-1=foo;bar;baz,other-vendor-value-2=foo;bar;"
    )


def test_sentry_only_baggage():
    header = (
        "sentry-trace_id=771a43a4192642f0b136d5159a501700,"
        "sentry-public_key=49d0f7386ad645858ae85020e393bef3,"
        "sentry-sample_rate=0.01337"
    )
    baggage = Baggage.from_incoming_header(header)

    assert baggage.third_party_items == ""

    serialized = baggage.serialize(include_third_party=True)

    # with no third-party items, include_third_party should change nothing
    assert serialized == baggage.serialize()
    assert serialized == (
        "sentry-trace_id=771a43a4192642f0b136d5159a501700,"
        "sentry-public_key=49d0f7386ad645858ae85020e393bef3,"
        "sentry-sample_rate=0.01337"
    )


def test_malformed_baggage():
    header = ","

    baggage = Baggage.from_incoming_header(header)

    assert baggage.sentry_items == {}
    assert baggage.third_party_items == ""
    assert baggage.mutable


def test_baggage_with_optional_whitespace_around_equals():
    # W3C baggage allows optional whitespace around "=" in list members
    header = (
        "sentry-trace_id = 771a43a4192642f0b136d5159a501700, "
        "sentry-sample_rand= 0.5, other-vendor = foo"
    )

    baggage = Baggage.from_incoming_header(header)

    assert baggage.sentry_items == {
        "trace_id": "771a43a4192642f0b136d5159a501700",
        "sample_rand": "0.5",
    }
    assert baggage._sample_rand() == 0.5
    assert baggage.serialize() == (
        "sentry-trace_id=771a43a4192642f0b136d5159a501700,sentry-sample_rand=0.5"
    )


def test_incoming_and_caller_items_are_distinguished():
    header = (
        "sentry-trace_id=771a43a4192642f0b136d5159a501700,"
        "sentry-sample_rate=0.5,"
        "sentry-upstream_reference=secret,"
        "other-vendor=value"
    )
    baggage = Baggage.from_incoming_header(header)
    baggage.set_caller_item("tenant", "acme")

    assert baggage.item_categories() == {
        "trace_id": "dsc",
        "sample_rate": "dsc",
        "upstream_reference": "incoming",
        "tenant": "caller",
    }

    # The default serialization keeps all Sentry items.
    assert baggage.serialize() == (
        "sentry-trace_id=771a43a4192642f0b136d5159a501700,"
        "sentry-sample_rate=0.5,"
        "sentry-upstream_reference=secret,"
        "sentry-tenant=acme"
    )


def test_serialize_for_categories():
    header = (
        "sentry-trace_id=771a43a4192642f0b136d5159a501700,"
        "sentry-sample_rate=0.5,"
        "sentry-upstream_reference=secret,"
        "other-vendor=value"
    )
    baggage = Baggage.from_incoming_header(header)
    baggage.set_caller_item("tenant", "acme")

    assert baggage.serialize_for_categories({"dsc"}) == (
        "sentry-trace_id=771a43a4192642f0b136d5159a501700,sentry-sample_rate=0.5"
    )
    assert baggage.serialize_for_categories({"dsc", "caller"}) == (
        "sentry-trace_id=771a43a4192642f0b136d5159a501700,"
        "sentry-sample_rate=0.5,"
        "sentry-tenant=acme"
    )
    assert baggage.serialize_for_categories({"dsc", "incoming"}) == (
        "sentry-trace_id=771a43a4192642f0b136d5159a501700,"
        "sentry-sample_rate=0.5,"
        "sentry-upstream_reference=secret"
    )
    assert baggage.serialize_for_categories(
        {"dsc", "caller", "incoming", "third_party"}
    ) == (
        "sentry-trace_id=771a43a4192642f0b136d5159a501700,"
        "sentry-sample_rate=0.5,"
        "sentry-upstream_reference=secret,"
        "sentry-tenant=acme,"
        "other-vendor=value"
    )


def test_caller_item_cannot_override_dsc():
    baggage = Baggage.from_incoming_header(
        "sentry-trace_id=771a43a4192642f0b136d5159a501700"
    )
    baggage.set_caller_item("trace_id", "spoofed")

    assert baggage.sentry_items["trace_id"] == "771a43a4192642f0b136d5159a501700"
    assert baggage.item_categories()["trace_id"] == "dsc"


@pytest.mark.asyncio
@pytest.mark.parametrize("span_streaming", [True, False])
async def test_baggage_propagation_targets_per_downstream(sentry_init, span_streaming):
    """Business baggage only goes to registered targets; others get the DSC.

    An ASGI request carries an incoming trace with a Sentry baggage item that
    was inherited from upstream. The handler sets a caller-owned item and then
    calls an internal and a public downstream. The internal service receives
    both business items, the public one only the dynamic sampling context, and
    both calls keep the same allowed trace id.
    """
    sentry_init(
        traces_sample_rate=1.0,
        trace_lifecycle="stream" if span_streaming else "static",
        integrations=[StdlibIntegration()],
        baggage_propagation_targets=[
            {"url": "internal.example.com", "propagate": ["caller", "incoming"]},
            {"url": "public.example.com", "propagate": ["dsc"]},
        ],
    )

    trace_id = "771a43a4192642f0b136d5159a501700"
    parent_span_id = "1234567890abcdef"
    delivered = {}

    class RecordingConnection(HTTPSConnection):
        def send(self, *args, **kwargs):
            lines = args[0].decode("utf-8").split("\r\n")[1:]
            headers = {}
            for line in lines:
                if line and ": " in line:
                    key, value = line.split(": ", 1)
                    headers[key.lower()] = value

            delivered[self.host] = headers

            server_sock, client_sock = socket.socketpair()
            server_sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            server_sock.close()
            self.sock = client_sock

        def getresponse(self, *args, **kwargs):
            return real_getresponse(self, *args, **kwargs)

    real_getresponse = HTTPSConnection.getresponse

    async def app(scope, receive, send):
        sentry_sdk.set_baggage("tenant", "acme")

        for host in ("internal.example.com", "public.example.com"):
            connection = RecordingConnection(host)
            connection.request("GET", "/status")
            connection.getresponse()

        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"text/plain"]],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = SentryAsgiMiddleware(app)

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(message):
        pass

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/catalog",
        "scheme": "http",
        "server": ("gateway.example.org", 80),
        "headers": [
            (
                b"sentry-trace",
                f"{trace_id}-{parent_span_id}-1".encode(),
            ),
            (
                b"baggage",
                (
                    f"sentry-trace_id={trace_id},"
                    "sentry-sample_rate=0.5,"
                    "sentry-sample_rand=0.100000,"
                    "sentry-upstream_reference=secret"
                ).encode(),
            ),
        ],
    }

    await middleware(scope, receive, send)

    internal = _parse_baggage(delivered["internal.example.com"]["baggage"])
    public = _parse_baggage(delivered["public.example.com"]["baggage"])

    # The internal downstream was registered for both business categories.
    assert internal["tenant"] == "acme"
    assert internal["upstream_reference"] == "secret"

    # The public downstream only gets the dynamic sampling context.
    assert "tenant" not in public
    assert "upstream_reference" not in public
    assert public["trace_id"] == trace_id

    # Both calls continue the same allowed trace.
    for host in ("internal.example.com", "public.example.com"):
        assert delivered[host]["sentry-trace"].startswith(f"{trace_id}-")
        assert _parse_baggage(delivered[host]["baggage"])["trace_id"] == trace_id


@pytest.mark.parametrize("span_streaming", [True, False])
def test_no_policy_keeps_all_sentry_items(sentry_init, span_streaming):
    """Without the option, existing serialization behavior is unchanged."""
    sentry_init(
        traces_sample_rate=1.0,
        trace_lifecycle="stream" if span_streaming else "static",
    )

    trace_id = "771a43a4192642f0b136d5159a501700"
    headers = {
        "sentry-trace": f"{trace_id}-1234567890abcdef-1",
        "baggage": (
            f"sentry-trace_id={trace_id},"
            "sentry-sample_rate=0.5,"
            "sentry-upstream_reference=secret"
        ),
    }

    if span_streaming:
        sentry_sdk.traces.continue_trace(headers)
        with sentry_sdk.traces.start_span(name="segment"):
            propagation_headers = dict(
                sentry_sdk.get_current_scope().iter_trace_propagation_headers()
            )
    else:
        transaction = sentry_sdk.continue_trace(headers)
        with sentry_sdk.start_transaction(transaction, name="transaction"):
            propagation_headers = dict(
                sentry_sdk.get_current_scope().iter_trace_propagation_headers()
            )

    assert _parse_baggage(propagation_headers["baggage"])["upstream_reference"] == (
        "secret"
    )


@pytest.mark.parametrize(
    "categories,expected",
    [
        ([], {"trace_id", "sample_rate", "sample_rand"}),
        (["dsc"], {"trace_id", "sample_rate", "sample_rand"}),
        (["caller"], {"trace_id", "sample_rate", "sample_rand", "tenant"}),
        (
            ["incoming"],
            {"trace_id", "sample_rate", "sample_rand", "upstream_reference"},
        ),
        (
            ["caller", "incoming"],
            {
                "trace_id",
                "sample_rate",
                "sample_rand",
                "tenant",
                "upstream_reference",
            },
        ),
    ],
)
def test_iter_trace_propagation_headers_with_categories(
    sentry_init, categories, expected
):
    sentry_init(
        traces_sample_rate=1.0,
    )

    trace_id = "771a43a4192642f0b136d5159a501700"
    transaction = sentry_sdk.continue_trace(
        {
            "sentry-trace": f"{trace_id}-1234567890abcdef-1",
            "baggage": (
                f"sentry-trace_id={trace_id},"
                "sentry-sample_rate=0.5,"
                "sentry-upstream_reference=secret"
            ),
        },
        name="transaction",
    )
    sentry_sdk.set_baggage("tenant", "acme")

    with sentry_sdk.start_transaction(transaction):
        propagation_headers = dict(
            sentry_sdk.get_current_scope().iter_trace_propagation_headers(
                categories=categories
            )
        )

    assert set(_parse_baggage(propagation_headers["baggage"])) == expected
    assert propagation_headers["sentry-trace"].startswith(f"{trace_id}-")


@pytest.mark.parametrize("span_streaming", [True, False])
def test_caller_baggage_survives_head_baggage_creation(sentry_init, span_streaming):
    """Caller items set before the transaction are not lost as the head SDK."""
    sentry_init(
        traces_sample_rate=1.0,
        trace_lifecycle="stream" if span_streaming else "static",
    )

    sentry_sdk.set_baggage("tenant", "acme")

    if span_streaming:
        with sentry_sdk.traces.start_span(
            name="segment", attributes={"sentry.op": "http.server"}
        ):
            propagation_headers = dict(
                sentry_sdk.get_current_scope().iter_trace_propagation_headers(
                    categories=["caller"]
                )
            )
    else:
        with sentry_sdk.start_transaction(name="transaction"):
            propagation_headers = dict(
                sentry_sdk.get_current_scope().iter_trace_propagation_headers(
                    categories=["caller"]
                )
            )

    assert _parse_baggage(propagation_headers["baggage"])["tenant"] == "acme"


def test_remove_baggage(sentry_init):
    sentry_init(traces_sample_rate=1.0)

    sentry_sdk.set_baggage("tenant", "acme")
    assert _parse_baggage(sentry_sdk.get_baggage())["tenant"] == "acme"

    sentry_sdk.remove_baggage("tenant")
    assert "tenant" not in _parse_baggage(sentry_sdk.get_baggage())


def test_baggage_propagation_targets_resolution(sentry_init):
    sentry_init(
        traces_sample_rate=1.0,
        baggage_propagation_targets=[
            {"url": "internal.example.com", "propagate": ["caller", "incoming"]},
            {"url": "dsc-only.example.com"},
        ],
    )
    client = sentry_sdk.get_client()

    assert get_baggage_categories(client, "https://internal.example.com/a") == (
        DEFAULT_BAGGAGE_CATEGORIES
    )
    assert get_baggage_categories(client, "https://dsc-only.example.com/a") == (
        MINIMAL_BAGGAGE_CATEGORIES
    )
    # Unlisted targets fall back to the dynamic sampling context only.
    assert get_baggage_categories(client, "https://public.example.org/a") == (
        MINIMAL_BAGGAGE_CATEGORIES
    )
