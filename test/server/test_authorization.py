"""Test TLS client authorization (access adapter).

The service path is driven with transport doubles that carry either a
verified or an unverified TLS identity. No real device or external
certificate service is involved; the peer certificate is an in-memory object
exposed by the fake SSL object.
"""

import hashlib
from unittest import mock

import pytest

from pymodbus.constants import ExcCodes
from pymodbus.framer import FramerType
from pymodbus.pdu import (
    ExceptionResponse,
    ReadCoilsRequest,
    ReadHoldingRegistersRequest,
)
from pymodbus.server import (
    AuthorizationException,
    ModbusBaseServer,
    TlsAccessPolicy,
    TlsAccessRule,
    TlsIdentity,
    identity_from_transport,
)
from pymodbus.simulator import DataType, SimData, SimDevice
from pymodbus.transport import CommParams, CommType


# --------------------------------------------------------------------------- #
# Transport doubles
# --------------------------------------------------------------------------- #
class FakeSslObject:  # pylint: disable=too-few-public-methods
    """Mimic the relevant parts of an asyncio SSL object."""

    def __init__(self, der_cert, parsed_cert):
        """Initialize with the certificate the TLS layer verified."""
        self._der = der_cert
        self._parsed = parsed_cert

    def getpeercert(self, binary_form=False):
        """Return the peer certificate like ssl.SSLObject."""
        if binary_form:
            return self._der
        return self._parsed


class FakeTransport:
    """Transport double exposing an optional SSL object."""

    def __init__(self, ssl_object=None):
        """Initialize with an optional TLS SSL object."""
        self._ssl_object = ssl_object

    def get_extra_info(self, name):
        """Return the SSL object for the 'ssl_object' extra info key."""
        if name == "ssl_object":
            return self._ssl_object
        return None

    def close(self):
        """Close the connection (no-op double)."""
        self._ssl_object = None


def make_ssl_object(common_name=None, alt_names=None, der_marker=b"client-a"):
    """Build a fake verified SSL object and its expected identity pieces."""
    parsed = {}
    subject = []
    if common_name is not None:
        subject = [(("commonName", common_name),)]
    if subject:
        parsed["subject"] = subject
    if alt_names:
        parsed["subjectAltName"] = [("DNS", name) for name in alt_names]
    ssl_object = FakeSslObject(der_marker, parsed)
    fingerprint = hashlib.sha256(der_marker).hexdigest()
    return ssl_object, fingerprint


class RecordingContext:
    """Record every device/function call the datastore receives."""

    def __init__(self, device_ids):
        """Initialize with the served device ids."""
        self._device_ids = list(device_ids)
        self.calls = []

    def device_ids(self):
        """Return served device ids."""
        return list(self._device_ids)

    async def async_getValues(self, device_id, func_code, address, count=1):
        """Record a read and return placeholder values."""
        self.calls.append((device_id, func_code, "get", address, count))
        return [0] * count

    async def async_setValues(self, device_id, func_code, address, values):
        """Record a write."""
        self.calls.append((device_id, func_code, "set", address, list(values)))
        return None


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
def build_server(access_policy=None, device_ids=(1, 2)):
    """Create a base server with a recording context and optional policy."""
    sim_devices = [
        SimDevice(dev_id, SimData(0, datatype=DataType.REGISTERS, values=[1] * 10))
        for dev_id in device_ids
    ]
    server = ModbusBaseServer(
        CommParams(
            comm_type=CommType.TLS,
            comm_name="server_listener",
            reconnect_delay=0.0,
            reconnect_delay_max=0.0,
            timeout_connect=0.0,
            source_address=("0", 0),
        ),
        sim_devices,
        False,
        False,
        None,
        FramerType.TLS,
        None,
        None,
        None,
        [],
    )
    server.context = RecordingContext(device_ids)
    server.access_policy = access_policy
    return server


def connect_handler(server, ssl_object=None):
    """Create a handler and run the connection-made identity resolution."""
    handler = server.callback_new_connection()
    handler.pdu_send = mock.Mock(return_value=True)
    handler.connection_made(FakeTransport(ssl_object))
    return handler


class TestIdentityExtraction:
    """Identity must come from the TLS context, never from PDU fields."""

    def test_no_transport_is_unverified(self):
        """A missing transport yields an unverified identity."""
        identity = identity_from_transport(None)
        assert identity.verified is False
        assert not identity.principals

    def test_non_tls_transport_is_unverified(self):
        """A plain transport without an SSL object is unverified."""
        identity = identity_from_transport(FakeTransport(None))
        assert identity.verified is False

    def test_tls_without_certificate_is_unverified(self):
        """An SSL object exposing no peer certificate is unverified."""
        ssl_object = FakeSslObject(None, {})
        identity = identity_from_transport(FakeTransport(ssl_object))
        assert identity.verified is False
        assert identity.common_name is None

    def test_verified_certificate_identity(self):
        """A verified certificate exposes CN, SAN and fingerprint."""
        ssl_object, fingerprint = make_ssl_object(
            common_name="scada-client", alt_names=["scada.example"], der_marker=b"x"
        )
        identity = identity_from_transport(FakeTransport(ssl_object))
        assert identity.verified is True
        assert identity.common_name == "scada-client"
        assert identity.subject_alt == ("scada.example",)
        assert identity.fingerprint == fingerprint
        assert "scada-client" in identity.principals
        assert "scada.example" in identity.principals
        assert fingerprint in identity.principals

    def test_certificate_without_subject_fields(self):
        """A DER-only certificate still yields a fingerprint principal."""
        ssl_object, fingerprint = make_ssl_object(
            common_name=None, alt_names=None, der_marker=b"y"
        )
        identity = identity_from_transport(FakeTransport(ssl_object))
        assert identity.verified is True
        assert identity.common_name is None
        assert not identity.subject_alt
        assert identity.principals == (fingerprint,)

    def test_subject_without_common_name_is_none(self):
        """A subject lacking a CN entry falls back to None, not an error."""
        parsed = {"subject": [[("organizationName", "acme")]]}
        ssl_object = FakeSslObject(b"z", parsed)
        identity = identity_from_transport(FakeTransport(ssl_object))
        assert identity.verified is True
        assert identity.common_name is None
        assert identity.fingerprint == hashlib.sha256(b"z").hexdigest()

    def test_empty_subject_alt_values_are_skipped(self):
        """Falsy subjectAltName values are not exposed as principals."""
        parsed = {"subjectAltName": [("DNS", ""), ("DNS", "real.example")]}
        ssl_object = FakeSslObject(b"w", parsed)
        identity = identity_from_transport(FakeTransport(ssl_object))
        assert identity.subject_alt == ("real.example",)


class TestAccessPolicyUnit:
    """Direct checks of the policy mapping and default-deny behaviour."""

    def test_rule_permissions(self):
        """Rules report device and function membership."""
        rule = TlsAccessRule("cn", device_ids=[1, 2], function_codes=[1, 3])
        assert rule.permits_device(1)
        assert not rule.permits_device(9)
        assert rule.permits_function(3)
        assert not rule.permits_function(6)

    def test_unverified_identity_denied(self):
        """An unverified connection never resolves to a rule."""
        policy = TlsAccessPolicy(
            [TlsAccessRule("cn", device_ids=[1], function_codes=[1])]
        )
        assert policy.resolve(TlsIdentity.unverified()) is None

    def test_unknown_certificate_has_no_mapping(self):
        """A verified certificate without a rule resolves to None."""
        policy = TlsAccessPolicy([TlsAccessRule("known", [1], [1])])
        identity = TlsIdentity(common_name="stranger", verified=True)
        assert policy.resolve(identity) is None

    def test_known_certificate_resolves_by_common_name(self):
        """A CN principal maps to its rule."""
        rule = TlsAccessRule("known", [1], [1])
        policy = TlsAccessPolicy([rule])
        identity = TlsIdentity(common_name="known", verified=True)
        assert policy.resolve(identity) is rule

    def test_resolve_matches_fingerprint_principal(self):
        """Rules may key on the certificate fingerprint."""
        rule = TlsAccessRule("fp-123", [2], [3])
        policy = TlsAccessPolicy([rule])
        identity = TlsIdentity(fingerprint="fp-123", verified=True)
        assert policy.resolve(identity) is rule

    def test_add_rule_replaces_existing(self):
        """Adding a rule for the same principal replaces the old one."""
        policy = TlsAccessPolicy([TlsAccessRule("cn", [1], [1])])
        replacement = TlsAccessRule("cn", [7], [6])
        policy.add_rule(replacement)
        assert (
            policy.resolve(TlsIdentity(common_name="cn", verified=True)) is replacement
        )

    def test_authorize_unknown_identity_raises(self):
        """Unknown mapping raises a gateway-path exception before access."""
        policy = TlsAccessPolicy([TlsAccessRule("known", [1], [1])])
        request = ReadCoilsRequest(dev_id=1, address=0, count=1)
        with pytest.raises(AuthorizationException) as exc:
            policy.authorize(TlsIdentity(common_name="x", verified=True), request)
        assert exc.value.exception_code == ExcCodes.GATEWAY_PATH_UNAVIABLE

    def test_authorize_denies_unverified(self):
        """Even with a matching CN, an unverified identity is denied."""
        policy = TlsAccessPolicy([TlsAccessRule("cn", [1], [1])])
        request = ReadCoilsRequest(dev_id=1, address=0, count=1)
        with pytest.raises(AuthorizationException):
            policy.authorize(TlsIdentity(common_name="cn", verified=False), request)

    def test_authorize_denies_device(self):
        """A mapped client is restricted to its device set."""
        policy = TlsAccessPolicy([TlsAccessRule("cn", [1], [1])])
        identity = TlsIdentity(common_name="cn", verified=True)
        request = ReadCoilsRequest(dev_id=2, address=0, count=1)
        with pytest.raises(AuthorizationException) as exc:
            policy.authorize(identity, request)
        assert exc.value.exception_code == ExcCodes.GATEWAY_PATH_UNAVIABLE

    def test_authorize_denies_function(self):
        """A mapped client is restricted to its function range."""
        policy = TlsAccessPolicy([TlsAccessRule("cn", [1], [1])])
        identity = TlsIdentity(common_name="cn", verified=True)
        request = ReadHoldingRegistersRequest(dev_id=1, address=0, count=1)
        with pytest.raises(AuthorizationException) as exc:
            policy.authorize(identity, request)
        assert exc.value.exception_code == ExcCodes.ILLEGAL_FUNCTION

    def test_authorize_allows_permitted_request(self):
        """A fully permitted request returns the matched rule."""
        rule = TlsAccessRule("cn", [1], [1])
        policy = TlsAccessPolicy([rule])
        identity = TlsIdentity(common_name="cn", verified=True)
        request = ReadCoilsRequest(dev_id=1, address=0, count=1)
        assert policy.authorize(identity, request) is rule


class TestServicePath:
    """Drive the request handler with verified/unverified transports."""

    async def _response_for(self, handler, request):
        """Run one request and return the response handed to the transport."""
        await handler.handle_request(request)
        assert handler.pdu_send.called
        return handler.pdu_send.call_args.args[0]

    async def test_verified_permitted_request_reaches_device(self):
        """An allowed request is executed on the addressed device."""
        ssl_object, _ = make_ssl_object(common_name="client-a")
        policy = TlsAccessPolicy(
            [TlsAccessRule("client-a", device_ids=[1, 2], function_codes=[1, 3])]
        )
        server = build_server(policy)
        handler = connect_handler(server, ssl_object)

        response = await self._response_for(
            handler, ReadCoilsRequest(dev_id=1, address=0, count=2)
        )
        assert not isinstance(response, ExceptionResponse)
        assert server.context.calls == [(1, 1, "get", 0, 2)]

    async def test_verified_client_restricted_to_its_device_set(self):
        """A second device is denied and never receives the call."""
        ssl_object, _ = make_ssl_object(common_name="client-a")
        policy = TlsAccessPolicy(
            [TlsAccessRule("client-a", device_ids=[1], function_codes=[1, 3])]
        )
        server = build_server(policy)
        handler = connect_handler(server, ssl_object)

        response = await self._response_for(
            handler, ReadCoilsRequest(dev_id=2, address=0, count=1)
        )
        assert isinstance(response, ExceptionResponse)
        assert response.exception_code == ExcCodes.GATEWAY_PATH_UNAVIABLE
        assert server.context.calls == []

    async def test_verified_client_restricted_to_its_functions(self):
        """A disallowed function is denied before device access."""
        ssl_object, _ = make_ssl_object(common_name="client-a")
        policy = TlsAccessPolicy(
            [TlsAccessRule("client-a", device_ids=[1], function_codes=[1])]
        )
        server = build_server(policy)
        handler = connect_handler(server, ssl_object)

        response = await self._response_for(
            handler, ReadHoldingRegistersRequest(dev_id=1, address=0, count=1)
        )
        assert isinstance(response, ExceptionResponse)
        assert response.exception_code == ExcCodes.ILLEGAL_FUNCTION
        assert server.context.calls == []

    async def test_unverified_connection_denied(self):
        """A transport without a verified certificate cannot reach devices."""
        policy = TlsAccessPolicy(
            [TlsAccessRule("client-a", device_ids=[1], function_codes=[1])]
        )
        server = build_server(policy)
        handler = connect_handler(server, ssl_object=None)
        assert handler.identity.verified is False

        response = await self._response_for(
            handler, ReadCoilsRequest(dev_id=1, address=0, count=1)
        )
        assert isinstance(response, ExceptionResponse)
        assert response.exception_code == ExcCodes.GATEWAY_PATH_UNAVIABLE
        assert server.context.calls == []

    async def test_unknown_certificate_mapping_denied(self):
        """A verified certificate without a rule is rejected pre-access."""
        ssl_object, _ = make_ssl_object(common_name="unmapped")
        policy = TlsAccessPolicy(
            [TlsAccessRule("client-a", device_ids=[1], function_codes=[1])]
        )
        server = build_server(policy)
        handler = connect_handler(server, ssl_object)
        assert handler.identity.verified is True

        response = await self._response_for(
            handler, ReadCoilsRequest(dev_id=1, address=0, count=1)
        )
        assert isinstance(response, ExceptionResponse)
        assert response.exception_code == ExcCodes.GATEWAY_PATH_UNAVIABLE
        assert server.context.calls == []

    async def test_reconnect_re_evaluates_identity(self):
        """Each new connection derives the identity from its own TLS context."""
        policy = TlsAccessPolicy(
            [TlsAccessRule("client-a", device_ids=[1], function_codes=[1])]
        )
        server = build_server(policy)

        allowed_ssl, _ = make_ssl_object(common_name="client-a", der_marker=b"a")
        first = connect_handler(server, allowed_ssl)
        first.connection_lost(None)
        assert first.running is False

        # A reconnect presenting an unmapped certificate is a fresh identity.
        stranger_ssl, _ = make_ssl_object(common_name="stranger", der_marker=b"b")
        second = connect_handler(server, stranger_ssl)
        response = await self._response_for(
            second, ReadCoilsRequest(dev_id=1, address=0, count=1)
        )
        assert isinstance(response, ExceptionResponse)
        assert response.exception_code == ExcCodes.GATEWAY_PATH_UNAVIABLE
        assert server.context.calls == []

    async def test_multi_device_policy_isolates_clients(self):
        """Two mapped clients each only reach their own device and functions."""
        ssl_a, _ = make_ssl_object(common_name="client-a", der_marker=b"a")
        ssl_b, _ = make_ssl_object(common_name="client-b", der_marker=b"b")
        policy = TlsAccessPolicy(
            [
                TlsAccessRule("client-a", device_ids=[1], function_codes=[1]),
                TlsAccessRule("client-b", device_ids=[2], function_codes=[3]),
            ]
        )
        server = build_server(policy, device_ids=(1, 2))

        handler_a = connect_handler(server, ssl_a)
        await self._response_for(
            handler_a, ReadCoilsRequest(dev_id=1, address=0, count=1)
        )
        denied = await self._response_for(
            handler_a, ReadHoldingRegistersRequest(dev_id=2, address=0, count=1)
        )
        assert isinstance(denied, ExceptionResponse)

        handler_b = connect_handler(server, ssl_b)
        await self._response_for(
            handler_b, ReadHoldingRegistersRequest(dev_id=2, address=0, count=1)
        )

        assert server.context.calls == [
            (1, 1, "get", 0, 1),
            (2, 3, "get", 0, 1),
        ]

    async def test_server_without_policy_keeps_open_access(self):
        """Without a policy the handler behaves as a plain TLS server."""
        server = build_server(access_policy=None)
        handler = connect_handler(server, ssl_object=None)
        response = await self._response_for(
            handler, ReadCoilsRequest(dev_id=2, address=0, count=1)
        )
        assert not isinstance(response, ExceptionResponse)
        assert server.context.calls == [(2, 1, "get", 0, 1)]

    async def test_pdu_device_id_is_not_used_as_credential(self):
        """Spoofing the PDU dev_id cannot bypass the certificate mapping."""
        # Certificate identifies client-a, which is only mapped to device 1.
        ssl_object, _ = make_ssl_object(common_name="client-a")
        policy = TlsAccessPolicy(
            [TlsAccessRule("client-a", device_ids=[1], function_codes=[1])]
        )
        server = build_server(policy)
        handler = connect_handler(server, ssl_object)

        spoofed = ReadCoilsRequest(dev_id=1, address=0, count=1)
        # The request still identifies as device 1 inside the PDU; claiming
        # another identity is impossible because the PDU has no identity field.
        response = await self._response_for(handler, spoofed)
        assert not isinstance(response, ExceptionResponse)

        # Reusing the same connection but addressing a forbidden device fails.
        forbidden = ReadCoilsRequest(dev_id=2, address=0, count=1)
        denied = await self._response_for(handler, forbidden)
        assert isinstance(denied, ExceptionResponse)
        assert server.context.calls == [(1, 1, "get", 0, 1)]
