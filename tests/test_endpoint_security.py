"""Controlled endpoint-selection and credential-release tests.

These tests use locally generated certificates and synthetic EndpointDescription
objects, so they do not need a listening socket.  Live accept/reject runs
against a real server are covered by `examples/client-auto-endpoint-security.py`.
"""

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from asyncua import Client, ua
from asyncua.client import endpoint_security as es
from asyncua.crypto import security_policies
from asyncua.crypto.cert_gen import generate_private_key, generate_self_signed_app_certificate

POLICY = security_policies.SecurityPolicyBasic256Sha256.URI
PORT = 4840
URL = f"opc.tcp://127.0.0.1:{PORT}/srv"
APP_URI = "urn:test:server"


def make_key_and_cert(uri=APP_URI, dns="127.0.0.1"):
    key = generate_private_key()
    cert = generate_self_signed_app_certificate(
        key, uri, {}, [x509.UniformResourceIdentifier(uri), x509.DNSName(dns)], [ExtendedKeyUsageOID.SERVER_AUTH]
    )
    return key, cert


def make_cert(uri=APP_URI, dns="127.0.0.1"):
    return make_key_and_cert(uri, dns)[1]


def endpoint(
    url=URL, uri=APP_URI, cert=None, mode=ua.MessageSecurityMode.SignAndEncrypt, level=70, token_policy=POLICY
):
    ep = ua.EndpointDescription()
    ep.EndpointUrl = url
    ep.Server = ua.ApplicationDescription(ApplicationUri=uri)
    ep.ServerCertificate = es.uacrypto.der_from_x509(cert) if cert is not None else None
    ep.SecurityMode = mode
    ep.SecurityPolicyUri = POLICY
    ep.SecurityLevel = level
    ep.UserIdentityTokens = [
        ua.UserTokenPolicy(PolicyId="u", TokenType=ua.UserTokenType.UserName, SecurityPolicyUri=token_policy)
    ]
    return ep


@pytest.fixture(scope="module")
def certs():
    return {"server": make_cert(), "other": make_cert("urn:test:other")}


@pytest.fixture
def origin():
    return es.EndpointOrigin.parse(URL)


def policy_for(cert, origins=frozenset()):
    return es.EndpointSecurityPolicy(identity=es.ServerIdentity(APP_URI, certificate=cert, allowed_origins=origins))


def test_accepts_strongest_allowed(certs, origin):
    weaker = endpoint(mode=ua.MessageSecurityMode.Sign, level=50, cert=certs["server"])
    stronger = endpoint(level=70, cert=certs["server"])
    selection = es.select_endpoint([weaker, stronger], policy_for(certs["server"]), origin)
    assert selection.security_mode is ua.MessageSecurityMode.SignAndEncrypt
    assert selection.origin == origin
    assert selection.application_uri == APP_URI


def test_declared_level_is_not_trust(certs, origin):
    lying = endpoint(level=255, cert=certs["server"])
    selection = es.select_endpoint([lying], policy_for(certs["server"]), origin)
    assert selection.declared_security_level == 255
    assert selection.effective_security_level == 70
    assert not selection.declared_security_level_matches_policy


def test_rejects_other_address_same_cert(certs, origin):
    with pytest.raises(es.EndpointSelectionError):
        es.select_endpoint(
            [endpoint(url=f"opc.tcp://127.0.0.1:{PORT + 1}/srv", cert=certs["server"])],
            policy_for(certs["server"]),
            origin,
        )


def test_rejects_same_address_other_cert(certs, origin):
    with pytest.raises(es.EndpointSelectionError):
        es.select_endpoint([endpoint(cert=certs["other"])], policy_for(certs["server"]), origin)


def test_rejects_other_application_uri(certs, origin):
    with pytest.raises(es.EndpointSelectionError):
        es.select_endpoint([endpoint(uri="urn:evil", cert=certs["server"])], policy_for(certs["server"]), origin)


def test_rejects_unsigned(certs, origin):
    with pytest.raises(es.EndpointSelectionError):
        es.select_endpoint(
            [endpoint(mode=ua.MessageSecurityMode.Sign, cert=certs["server"])], policy_for(certs["server"]), origin
        )


def test_missing_trust_anchor():
    with pytest.raises(es.MissingServerTrustError):
        es.ServerIdentity(APP_URI)


def test_create_session_endpoint_change(certs, origin):
    selected = es.select_endpoint([endpoint(cert=certs["server"])], policy_for(certs["server"]), origin)
    with pytest.raises(es.ServerEndpointChanged):
        es.validate_session_endpoint(
            selected,
            policy_for(certs["server"]),
            [endpoint(url=f"opc.tcp://127.0.0.1:{PORT + 1}/srv", cert=certs["server"])],
            origin,
            es.uacrypto.der_from_x509(certs["server"]),
        )
    with pytest.raises(es.ServerEndpointChanged):
        es.validate_session_endpoint(
            selected,
            policy_for(certs["server"]),
            [endpoint(cert=certs["other"])],
            origin,
            es.uacrypto.der_from_x509(certs["other"]),
        )


def test_credential_gate(certs, origin):
    selected = es.select_endpoint([endpoint(cert=certs["server"])], policy_for(certs["server"]), origin)
    with pytest.raises(es.CredentialReleaseDenied):
        es.require_credentials_allowed(selected, policy_for(certs["server"]), POLICY, ua.MessageSecurityMode.Sign)
    es.require_credentials_allowed(selected, policy_for(certs["server"]), POLICY, ua.MessageSecurityMode.SignAndEncrypt)


async def test_client_blocks_credentials_without_pinned_identity(monkeypatch):
    client = Client(URL)
    client.set_user("alice")
    client.set_password("secret")
    called = []

    async def fake_endpoints():
        called.append(True)
        return [endpoint(cert=make_cert())]

    monkeypatch.setattr(client, "connect_and_get_server_endpoints", fake_endpoints)
    with pytest.raises(es.MissingServerTrustError):
        await client.set_security(security_policies.SecurityPolicyBasic256Sha256, b"client-cert", b"client-key")
    assert called == []


async def test_client_strict_accepts_and_records(monkeypatch, certs):
    client = Client(URL)
    client.set_user("alice")
    client.set_password("secret")
    cert = certs["server"]

    async def fake_endpoints():
        return [endpoint(cert=cert)]

    monkeypatch.setattr(client, "connect_and_get_server_endpoints", fake_endpoints)

    async def fake_load_certificate(path_or_content, extension=None):
        return cert

    server_key = generate_private_key()

    async def fake_load_key(path_or_content, password=None, extension=None):
        return server_key

    monkeypatch.setattr(es.uacrypto, "load_certificate", fake_load_certificate)
    monkeypatch.setattr(es.uacrypto, "load_private_key", fake_load_key)
    monkeypatch.setattr("asyncua.client.client.uacrypto.check_certificate", lambda *a, **k: True)
    await client.set_security(
        security_policies.SecurityPolicyBasic256Sha256,
        b"client-cert",
        b"client-key",
        endpoint_security_policy=policy_for(cert),
    )
    assert client.selected_endpoint is not None
    assert client.selected_endpoint.origin == es.EndpointOrigin.parse(URL)
    assert client.security_policy.peer_certificate == es.uacrypto.der_from_x509(cert)


def make_client_with_selection(monkeypatch, certs):
    client = Client(URL)
    client.set_user("alice")
    client.set_password("secret")
    cert = certs["server"]
    server_key = generate_private_key()

    async def fake_endpoints():
        return [endpoint(cert=cert)]

    async def fake_load_certificate(path_or_content, extension=None):
        return cert

    async def fake_load_key(path_or_content, password=None, extension=None):
        return server_key

    monkeypatch.setattr(client, "connect_and_get_server_endpoints", fake_endpoints)
    monkeypatch.setattr(es.uacrypto, "load_certificate", fake_load_certificate)
    monkeypatch.setattr(es.uacrypto, "load_private_key", fake_load_key)
    monkeypatch.setattr("asyncua.client.client.uacrypto.check_certificate", lambda *a, **k: True)
    client.last_connection_target = es.EndpointOrigin.parse(URL)
    return client


async def test_create_session_accepts_and_releases(monkeypatch, certs):
    client = make_client_with_selection(monkeypatch, certs)
    selection = await client.set_security(
        security_policies.SecurityPolicyBasic256Sha256,
        b"client-cert",
        b"client-key",
        endpoint_security_policy=policy_for(certs["server"]),
    )
    assert selection is not None
    calls = []
    client.credential_release_callback = calls.append
    with pytest.raises(es.CredentialReleaseDenied):
        client._authorize_credential_release("alice", "secret")
    assert calls == []

    cert = certs["server"]

    class Verify:
        def verify(self, data, sig):
            return None

    client.security_policy.asymmetric_cryptography = Verify()  # type: ignore[attr-defined]
    response = ua.CreateSessionResult()
    response.ServerNonce = b"n" * 32
    response.ServerCertificate = es.uacrypto.der_from_x509(cert)
    response.ServerEndpoints = [endpoint(cert=cert)]
    response.RevisedSessionTimeout = 1000

    async def fake_create_session(params):
        return response

    monkeypatch.setattr(client.uaclient, "create_session", fake_create_session)
    await client.create_session()
    client._authorize_credential_release("alice", "secret")
    assert calls == [client.session_endpoint]


class _ServerSignatureVerifier:
    def verify(self, data, sig):
        return None


async def prepare_create_session(monkeypatch, certs, server_endpoints, server_certificate):
    client = make_client_with_selection(monkeypatch, certs)
    await client.set_security(
        security_policies.SecurityPolicyBasic256Sha256,
        b"client-cert",
        b"client-key",
        endpoint_security_policy=policy_for(certs["server"]),
    )
    client.security_policy.asymmetric_cryptography = _ServerSignatureVerifier()  # type: ignore[attr-defined]
    response = ua.CreateSessionResult()
    response.ServerNonce = b"n" * 32
    response.ServerCertificate = server_certificate
    response.ServerEndpoints = server_endpoints
    response.RevisedSessionTimeout = 1000

    async def fake_create_session(params):
        return response

    monkeypatch.setattr(client.uaclient, "create_session", fake_create_session)
    released = []
    client.credential_release_callback = released.append
    client.last_connection_target = es.EndpointOrigin.parse(URL)
    return client, released


@pytest.mark.parametrize(
    ("case", "response_endpoints", "response_certificate"),
    [
        ("different_address", [endpoint(url=f"opc.tcp://127.0.0.1:{PORT + 1}/srv")], "selected"),
        ("different_certificate", [endpoint()], "other"),
        ("different_mode", [endpoint(mode=ua.MessageSecurityMode.Sign)], "selected"),
        ("different_policy", [endpoint()], "selected"),
        ("empty_endpoints", [], "selected"),
        ("no_certificate", [endpoint()], None),
    ],
)
async def test_create_session_change_rejected(monkeypatch, certs, case, response_endpoints, response_certificate):
    if case == "different_policy":
        for ep in response_endpoints:
            ep.SecurityPolicyUri = security_policies.SecurityPolicyAes256Sha256RsaPss.URI
    for ep in response_endpoints:
        ep.ServerCertificate = es.uacrypto.der_from_x509(certs["server"])
        ep.Server.ApplicationUri = APP_URI
    if response_certificate == "selected":
        response_certificate = es.uacrypto.der_from_x509(certs["server"])
    elif response_certificate == "other":
        response_certificate = es.uacrypto.der_from_x509(certs["other"])
    client, released = await prepare_create_session(monkeypatch, certs, response_endpoints, response_certificate)
    with pytest.raises(es.ServerEndpointChanged):
        await client.create_session()
    assert released == []


async def test_create_session_success_records_session_endpoint(monkeypatch, certs):
    client, released = await prepare_create_session(
        monkeypatch, certs, [endpoint(cert=certs["server"])], es.uacrypto.der_from_x509(certs["server"])
    )
    await client.create_session()
    assert client.session_endpoint is not None
    assert client.session_endpoint.origin == es.EndpointOrigin.parse(URL)
    client._authorize_credential_release("alice", "secret")
    assert released == [client.session_endpoint]


async def test_legacy_credentials_without_cert_blocked(monkeypatch):
    client = Client(URL)
    client.set_user("alice")
    client.set_password("secret")
    called = []

    async def fake_endpoints():
        called.append(True)
        return []

    monkeypatch.setattr(client, "connect_and_get_server_endpoints", fake_endpoints)
    with pytest.raises(es.MissingServerTrustError):
        await client.set_security(security_policies.SecurityPolicyBasic256Sha256, b"c", b"k")
    assert called == []


async def test_trust_store_accepts_and_rejects(certs, origin, tmp_path):
    from asyncua.crypto.truststore import TrustStore

    trusted_dir = tmp_path / "trusted"
    trusted_dir.mkdir()
    (trusted_dir / "server.der").write_bytes(es.uacrypto.der_from_x509(certs["server"]))
    store = TrustStore([trusted_dir], [])
    await store.load()
    policy = es.EndpointSecurityPolicy(identity=es.ServerIdentity(APP_URI, trust_store=store))
    selection = es.select_endpoint([endpoint(cert=certs["server"])], policy, origin)
    assert selection.application_uri == APP_URI
    with pytest.raises(es.EndpointSelectionError):
        es.select_endpoint([endpoint(cert=certs["other"])], policy, origin)


def test_same_address_other_policy(certs, origin):
    same_mode_other_policy = endpoint(cert=certs["server"])
    same_mode_other_policy.SecurityPolicyUri = security_policies.SecurityPolicyAes256Sha256RsaPss.URI
    with pytest.raises(es.EndpointSelectionError):
        es.select_endpoint(
            [same_mode_other_policy],
            policy_for(certs["server"]),
            origin,
            required_policy_uri=POLICY,
        )


def test_multiple_origins_allowlisted(certs):
    secondary = f"opc.tcp://127.0.0.1:{PORT + 2}/srv"
    policy = policy_for(certs["server"], frozenset({es.EndpointOrigin.parse(URL), es.EndpointOrigin.parse(secondary)}))
    selection = es.select_endpoint(
        [endpoint(url=secondary, cert=certs["server"])], policy, es.EndpointOrigin.parse(secondary)
    )
    assert selection.origin == es.EndpointOrigin.parse(secondary)
    with pytest.raises(es.EndpointSelectionError):
        es.select_endpoint([endpoint(cert=certs["server"])], policy, es.EndpointOrigin.parse(secondary))


async def test_username_token_is_encrypted_and_released_once(monkeypatch, certs):
    client, released = await prepare_create_session(
        monkeypatch, certs, [endpoint(cert=certs["server"])], es.uacrypto.der_from_x509(certs["server"])
    )
    await client.create_session()
    params = ua.ActivateSessionParameters()
    client._add_user_auth(params, "alice", "secret")
    token = params.UserIdentityToken
    assert token.PolicyId == "u"
    assert token.EncryptionAlgorithm == security_policies.SecurityPolicyBasic256Sha256.AsymmetricEncryptionURI
    assert b"secret" not in token.Password
    assert released == [client.session_endpoint]


def test_rejects_unencrypted_user_token_policy(certs, origin):
    plain = endpoint(cert=certs["server"], token_policy=security_policies.SecurityPolicyNone.URI)
    with pytest.raises(es.EndpointSelectionError):
        es.select_endpoint([plain], policy_for(certs["server"]), origin)


def test_requires_username_token_when_credentials_configured(certs, origin):
    no_user_token = endpoint(cert=certs["server"])
    no_user_token.UserIdentityTokens = []
    policy = es.EndpointSecurityPolicy(
        identity=es.ServerIdentity(APP_URI, certificate=certs["server"]),
        require_username_token=True,
    )
    with pytest.raises(es.EndpointSelectionError):
        es.select_endpoint([no_user_token], policy, origin)


async def test_credential_gate_requires_create_session_evidence(monkeypatch, certs):
    client = make_client_with_selection(monkeypatch, certs)
    await client.set_security(
        security_policies.SecurityPolicyBasic256Sha256,
        b"client-cert",
        b"client-key",
        endpoint_security_policy=policy_for(certs["server"]),
    )
    released = []
    client.credential_release_callback = released.append
    with pytest.raises(es.CredentialReleaseDenied):
        client._authorize_credential_release("alice", "secret")
    assert released == []


async def test_legacy_credentials_require_create_session(monkeypatch, certs):
    client = Client(URL)
    client.set_user("alice")
    client.set_password("secret")
    server_key = generate_private_key()

    async def fake_load_certificate(path_or_content, extension=None):
        return certs["server"]

    async def fake_load_key(path_or_content, password=None, extension=None):
        return server_key

    monkeypatch.setattr(es.uacrypto, "load_certificate", fake_load_certificate)
    monkeypatch.setattr(es.uacrypto, "load_private_key", fake_load_key)
    monkeypatch.setattr("asyncua.client.client.uacrypto.check_certificate", lambda *a, **k: True)
    await client.set_security(
        security_policies.SecurityPolicyBasic256Sha256,
        b"client-cert",
        b"client-key",
        server_certificate=es.uacrypto.der_from_x509(certs["server"]),
    )
    released = []
    client.credential_release_callback = released.append
    with pytest.raises(es.CredentialReleaseDenied):
        client._authorize_credential_release("alice", "secret")
    assert released == []
