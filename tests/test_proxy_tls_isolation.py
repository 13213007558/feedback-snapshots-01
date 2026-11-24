"""Proxy vs endpoint TLS material isolation for the aiohttp backend.

Two object stores are reached through one TLS enterprise proxy. The proxy's
trust root and the stores' trust roots are approved by different teams, and
some stores present client certificates, so configuration, connection and
reconnection must never mix the two purposes up:

* connection reuse is keyed by the trust material actually in effect — two
  approved configurations may share the proxy yet must not share connections;
* a TLS failure is attributed to the leg that failed — the proxy hop or the
  tunnelled endpoint — while direct connections keep their original errors.

These tests use a recording connector double and never touch the network.
The approved material paths are fake on purpose: what matters is which SSL
context — the proxy hop's or the endpoint's — each load lands on.
"""

from __future__ import annotations

import collections
import ssl
from types import SimpleNamespace

import aiohttp
import pytest
from aiohttp import (
    ClientConnectorCertificateError,
    ClientProxyConnectionError,
)
from aiohttp.client_reqrep import ConnectionKey
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ProxyConnectionError, SSLError
from botocore.httpsession import ProxyConfiguration
from yarl import URL

import aiobotocore.httpsession
from aiobotocore.httpsession import AIOHTTPSession, _ProxySSLTCPConnector

PROXY_URL = 'https://proxy.corp.example:8443'
PROXY_BUNDLE = '/approved/proxy/root-ca.pem'
PROXY_CERT = ('/approved/proxy/client.pem', '/approved/proxy/client.key')
STORE_A_BUNDLE = '/approved/store-a/root-ca.pem'
STORE_A_CERT = ('/approved/store-a/client.pem', '/approved/store-a/client.key')
STORE_B_BUNDLE = '/approved/store-b/root-ca.pem'
STORE_B_CERT = ('/approved/store-b/client.pem', '/approved/store-b/client.key')


def _unscripted_attempt(req):
    raise RuntimeError('connector double used without a scripted failure')


class _RecordingConnector(_ProxySSLTCPConnector):
    """Connector double recording the TLS material it was pooled with.

    Never connects: attempts fail with the scripted error, raised from the
    same method aiohttp would surface it from — ``_create_direct_connection``
    for the proxy hop (or a direct connection), ``_create_connection`` for
    the tunnelled endpoint.
    """

    instances = []
    fail_at = 'connection'
    failure = _unscripted_attempt

    def __init__(self, *args, **kwargs):
        # AIOHTTPSession._create_connector passes both contexts as keywords.
        self.endpoint_ssl_context = kwargs['ssl']
        self.proxy_ssl_context = kwargs['proxy_ssl_context']
        type(self).instances.append(self)
        super().__init__(*args, **kwargs)

    async def _create_connection(self, req, traces, timeout):
        if type(self).fail_at == 'connection':
            raise type(self).failure(req)
        return await super()._create_connection(req, traces, timeout)

    async def _create_direct_connection(self, req, traces, timeout, **kwargs):
        if type(self).fail_at == 'direct':
            raise type(self).failure(req)
        return await super()._create_direct_connection(
            req, traces, timeout, **kwargs
        )


@pytest.fixture
def recording_connector(monkeypatch):
    """Swap in the recording double, with fresh class state per test."""

    class RecordingConnector(_RecordingConnector):
        instances = []
        fail_at = 'connection'
        failure = _unscripted_attempt

    monkeypatch.setattr(
        aiobotocore.httpsession, '_ProxySSLTCPConnector', RecordingConnector
    )
    return RecordingConnector


@pytest.fixture
def tls_loads(monkeypatch):
    """Record SSLContext file loads without touching the filesystem."""

    loads = collections.defaultdict(list)

    def load_verify_locations(self, *args, **kwargs):
        loads[self].append(('verify_locations', args, kwargs))

    def load_cert_chain(self, *args, **kwargs):
        loads[self].append(('cert_chain', args, kwargs))

    monkeypatch.setattr(
        ssl.SSLContext, 'load_verify_locations', load_verify_locations
    )
    monkeypatch.setattr(ssl.SSLContext, 'load_cert_chain', load_cert_chain)
    return loads


def _cafiles(loads, context):
    return {
        args[0] if args else kwargs.get('cafile')
        for method, args, kwargs in loads[context]
        if method == 'verify_locations'
    }


def _cert_chains(loads, context):
    return {
        (args[0], args[1] if len(args) > 1 else kwargs.get('keyfile'))
        for method, args, kwargs in loads[context]
        if method == 'cert_chain'
    }


def _https_request(host='store-a.example', port=443):
    request = AWSRequest(
        method='GET',
        url=f'https://{host}:{port}/foo?id=1',
        headers={'Accept': 'application/json'},
    ).prepare()
    request.stream_output = False
    return request


def _certificate_error(req, message):
    return ClientConnectorCertificateError(
        req.connection_key, ssl.SSLCertVerificationError(message)
    )


async def test_connection_reuse_is_keyed_by_the_approved_trust_material(
    recording_connector, tls_loads
):
    async with AIOHTTPSession(
        verify=STORE_A_BUNDLE,
        client_cert=STORE_A_CERT,
        proxies={'https': PROXY_URL},
        proxies_config={
            'proxy_ca_bundle': PROXY_BUNDLE,
            'proxy_client_cert': PROXY_CERT,
        },
    ) as session:
        # 预热第一套: warming up store A pools a connector whose two hops
        # each got their own approved material.
        warmed = await session._get_session(PROXY_URL)
        (connector_a,) = recording_connector.instances
        endpoint_ctx = connector_a.endpoint_ssl_context
        proxy_ctx = connector_a.proxy_ssl_context
        assert endpoint_ctx is not proxy_ctx
        assert endpoint_ctx.check_hostname is True
        assert proxy_ctx.check_hostname is True
        assert _cafiles(tls_loads, endpoint_ctx) == {STORE_A_BUNDLE}
        assert _cert_chains(tls_loads, endpoint_ctx) == {STORE_A_CERT}
        # The proxy hop inherits the endpoint's verify settings (botocore
        # semantics) and adds the proxy team's root on top; the proxy root
        # never leaks into the endpoint context.
        assert _cafiles(tls_loads, proxy_ctx) == {
            STORE_A_BUNDLE,
            PROXY_BUNDLE,
        }
        # Client certificates never cross hops: the proxy offers only the
        # proxy client certificate, never the store's.
        assert _cert_chains(tls_loads, proxy_ctx) == {PROXY_CERT}

        # Same material reuses the warmed pool entry.
        assert await session._get_session(PROXY_URL) is warmed
        assert len(recording_connector.instances) == 1

        # 再连另一套: store B is approved for the same proxy but brings its
        # own root and client certificate — it must not get store A's
        # connections.
        session._verify = STORE_B_BUNDLE
        session._cert_file, session._key_file = STORE_B_CERT
        await session._get_session(PROXY_URL)
        assert len(recording_connector.instances) == 2
        connector_b = recording_connector.instances[1]
        assert connector_b is not connector_a
        assert _cafiles(tls_loads, connector_b.endpoint_ssl_context) == {
            STORE_B_BUNDLE
        }
        assert _cert_chains(tls_loads, connector_b.endpoint_ssl_context) == {
            STORE_B_CERT
        }
        # The shared proxy hop still gets the proxy team's material.
        assert _cafiles(tls_loads, connector_b.proxy_ssl_context) == {
            STORE_B_BUNDLE,
            PROXY_BUNDLE,
        }
        assert _cert_chains(tls_loads, connector_b.proxy_ssl_context) == {
            PROXY_CERT
        }

        # Store A's pool entry is still keyed by its own material.
        session._verify = STORE_A_BUNDLE
        session._cert_file, session._key_file = STORE_A_CERT
        assert await session._get_session(PROXY_URL) is warmed
        assert len(recording_connector.instances) == 2

        # 改走直连: no proxy hop, so no proxy material at all.
        session._proxy_config = ProxyConfiguration()
        session._verify = STORE_B_BUNDLE
        session._cert_file, session._key_file = STORE_B_CERT
        await session._get_session(None)
        assert len(recording_connector.instances) == 3
        connector_c = recording_connector.instances[2]
        assert connector_c.proxy_ssl_context is None
        assert _cafiles(tls_loads, connector_c.endpoint_ssl_context) == {
            STORE_B_BUNDLE
        }
        assert _cert_chains(tls_loads, connector_c.endpoint_ssl_context) == {
            STORE_B_CERT
        }


async def test_tls_failure_names_the_failing_leg(
    recording_connector, tls_loads
):
    async with AIOHTTPSession(
        verify=STORE_A_BUNDLE,
        proxies={'https': PROXY_URL},
        proxies_config={'proxy_ca_bundle': PROXY_BUNDLE},
    ) as session:
        # 代理段不符合: the proxy's certificate doesn't chain to the
        # approved proxy root — reported as a proxy failure.
        recording_connector.fail_at = 'direct'
        recording_connector.failure = lambda req: _certificate_error(
            req, 'proxy root not trusted'
        )
        with pytest.raises(ProxyConnectionError):
            await session.send(_https_request())

        # 目标不匹配: the tunnelled endpoint's certificate doesn't match
        # its approved root — reported as the endpoint's SSLError.
        recording_connector.fail_at = 'connection'
        recording_connector.failure = lambda req: _certificate_error(
            req, 'hostname mismatch'
        )
        with pytest.raises(SSLError):
            await session.send(_https_request())

    # 直连: unchanged — an endpoint TLS failure is an SSLError.
    recording_connector.fail_at = 'direct'
    async with AIOHTTPSession(verify=STORE_A_BUNDLE) as session:
        with pytest.raises(SSLError):
            await session.send(_https_request())


async def test_proxy_connector_attributes_proxy_hop_tls_failures(monkeypatch):
    # _create_proxy_connection re-attributes only the proxy hop's TLS
    # errors; the tunnelled endpoint's pass through untouched.
    proxy = URL(PROXY_URL)
    proxy_key = ConnectionKey(
        'proxy.corp.example', 8443, True, None, None, None, None
    )
    target_key = ConnectionKey(
        'store-a.example', 443, True, None, proxy, None, None
    )

    connector = _ProxySSLTCPConnector(
        ssl=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    )
    try:
        req = SimpleNamespace(proxy=proxy)

        async def fail_proxy_hop(self, req, traces, timeout):
            raise ClientConnectorCertificateError(
                proxy_key,
                ssl.SSLCertVerificationError('proxy root not trusted'),
            )

        monkeypatch.setattr(
            aiohttp.TCPConnector, '_create_proxy_connection', fail_proxy_hop
        )
        with pytest.raises(ClientProxyConnectionError):
            await connector._create_proxy_connection(req, [], None)

        async def fail_target_hop(self, req, traces, timeout):
            raise ClientConnectorCertificateError(
                target_key,
                ssl.SSLCertVerificationError('hostname mismatch'),
            )

        monkeypatch.setattr(
            aiohttp.TCPConnector, '_create_proxy_connection', fail_target_hop
        )
        with pytest.raises(ClientConnectorCertificateError):
            await connector._create_proxy_connection(req, [], None)
    finally:
        await connector.close()
