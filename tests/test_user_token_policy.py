from pathlib import Path
from types import SimpleNamespace

import pytest

from asyncua import Client, Server, ua
from asyncua.common.utils import ServiceError
from asyncua.crypto import security_policies, uacrypto
from asyncua.crypto.permission_rules import User, UserRole

BASE_DIR = Path(__file__).parent.parent
EXAMPLE_PATH = BASE_DIR / "examples"
PASSWORD = "fixed-fake-pa$$wörd-123"
SERVER_CREDENTIALS = [
    (EXAMPLE_PATH / "certificate-example.der", EXAMPLE_PATH / "private-key-example.pem"),
    (EXAMPLE_PATH / "certificate-3072-example.der", EXAMPLE_PATH / "private-key-3072-example.pem"),
]
USER_CERT = EXAMPLE_PATH / "certificates" / "peer-certificate-example-1.der"
USER_KEY = EXAMPLE_PATH / "certificates" / "peer-private-key-example-1.pem"

pytestmark = pytest.mark.asyncio


class RecordingUserManager:
    def __init__(self) -> None:
        self.calls: list[tuple[str | None, str | None]] = []

    def get_user(
        self,
        iserver: object,
        username: str | None = None,
        password: str | None = None,
        certificate: object | None = None,
    ) -> User:
        self.calls.append((username, password))
        if username == "alice" and password == PASSWORD:
            return User(role=UserRole.User)
        return User(role=UserRole.Anonymous)


def _channel_stub(server: Server, mode: ua.MessageSecurityMode, uri: str) -> SimpleNamespace:
    return SimpleNamespace(
        URI=uri,
        Mode=mode,
        peer_certificate=uacrypto.der_from_x509(server.iserver.certificate),
    )


async def _make_server(
    cert: Path,
    key: Path,
    policy_types: list[ua.SecurityPolicyType],
    tokens: list[type],
) -> Server:
    server = Server(user_manager=RecordingUserManager())
    await server.init()
    server.set_endpoint("opc.tcp://127.0.0.1:1/token-policy")
    server.set_security_policy(policy_types)
    await server.load_certificate(cert)
    await server.load_private_key(key)
    server.set_identity_tokens(tokens)
    await server._setup_server_nodes()
    return server


def _encrypted_token(
    server: Server,
    client: Client,
    policy_uri: str,
    nonce: bytes,
    password: str = PASSWORD,
) -> ua.UserNameIdentityToken:
    params = ua.ActivateSessionParameters()
    client._server_nonce = nonce
    client._policy_ids = [
        ua.UserTokenPolicy(PolicyId="username", TokenType=ua.UserTokenType.UserName, SecurityPolicyUri=policy_uri)
    ]
    client._add_user_auth(params, "alice", password)
    return params.UserIdentityToken


def _activate(
    server: Server,
    token: ua.UserIdentityToken,
    endpoint: ua.EndpointDescription,
    nonce: bytes,
) -> None:
    session = server.iserver.create_session("token-policy-session")
    session.nonce = nonce
    session.activate_session(
        ua.ActivateSessionParameters(UserIdentityToken=token),
        None,
        endpoint.SecurityPolicyUri,
        endpoint.SecurityMode,
    )


def _expect_reject(
    server: Server,
    token: ua.UserIdentityToken,
    endpoint: ua.EndpointDescription,
    nonce: bytes,
    code: int,
) -> None:
    manager = server.iserver.user_manager
    assert isinstance(manager, RecordingUserManager)
    before = len(manager.calls)
    with pytest.raises(ServiceError) as exc_info:
        _activate(server, token, endpoint, nonce)
    assert exc_info.value.code == code
    assert len(manager.calls) == before


@pytest.mark.parametrize("cert,key", SERVER_CREDENTIALS)
async def test_encrypted_username_token_roundtrip(cert: Path, key: Path) -> None:
    server = await _make_server(
        cert, key, [ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt], [ua.UserNameIdentityToken]
    )
    endpoint = server.iserver.endpoints[0]
    client = Client("opc.tcp://127.0.0.1:1/token-policy")
    client.security_policy = _channel_stub(server, endpoint.SecurityMode, endpoint.SecurityPolicyUri)
    nonce = b"0" * 32

    token = _encrypted_token(server, client, endpoint.UserIdentityTokens[0].SecurityPolicyUri, nonce)
    assert token.PolicyId == "username"
    assert token.EncryptionAlgorithm == security_policies.SecurityPolicyBasic256Sha256.AsymmetricEncryptionURI
    assert isinstance(token.Password, bytes) and len(token.Password) > 0
    assert PASSWORD.encode("utf-8") not in token.Password

    _activate(server, token, endpoint, nonce)
    manager = server.iserver.user_manager
    assert isinstance(manager, RecordingUserManager)
    assert manager.calls == [("alice", PASSWORD)]


@pytest.mark.parametrize("cert,key", SERVER_CREDENTIALS)
async def test_unknown_policy_id_is_rejected_without_callback(cert: Path, key: Path) -> None:
    server = await _make_server(
        cert, key, [ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt], [ua.UserNameIdentityToken]
    )
    endpoint = server.iserver.endpoints[0]
    token = ua.UserNameIdentityToken(
        PolicyId="not-advertised", UserName="alice", Password=b"whatever", EncryptionAlgorithm=None
    )
    _expect_reject(server, token, endpoint, b"1" * 32, ua.StatusCodes.BadIdentityTokenRejected)


@pytest.mark.parametrize("cert,key", SERVER_CREDENTIALS)
async def test_unknown_encryption_algorithm_is_rejected(cert: Path, key: Path) -> None:
    server = await _make_server(
        cert, key, [ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt], [ua.UserNameIdentityToken]
    )
    endpoint = server.iserver.endpoints[0]
    token = ua.UserNameIdentityToken(
        PolicyId="username",
        UserName="alice",
        Password=b"0" * 256,
        EncryptionAlgorithm="http://invalid.example/unknown-algorithm",
    )
    _expect_reject(server, token, endpoint, b"2" * 32, ua.StatusCodes.BadSecurityPolicyRejected)


@pytest.mark.parametrize("cert,key", SERVER_CREDENTIALS)
async def test_plaintext_token_rejected_on_encrypted_endpoint(cert: Path, key: Path) -> None:
    server = await _make_server(
        cert, key, [ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt], [ua.UserNameIdentityToken]
    )
    endpoint = server.iserver.endpoints[0]
    token = ua.UserNameIdentityToken(
        PolicyId="username", UserName="alice", Password=PASSWORD.encode("utf-8"), EncryptionAlgorithm=None
    )
    _expect_reject(server, token, endpoint, b"3" * 32, ua.StatusCodes.BadSecurityPolicyRejected)


@pytest.mark.parametrize("cert,key", SERVER_CREDENTIALS)
async def test_encrypted_token_rejected_on_none_channel(cert: Path, key: Path) -> None:
    server = await _make_server(
        cert,
        key,
        [ua.SecurityPolicyType.NoSecurity, ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt],
        [ua.UserNameIdentityToken],
    )
    none_endpoint = next(
        endpoint for endpoint in server.iserver.endpoints if endpoint.SecurityMode == ua.MessageSecurityMode.None_
    )
    none_endpoint.UserIdentityTokens[0].SecurityPolicyUri = security_policies.SecurityPolicyBasic256Sha256.URI
    client = Client("opc.tcp://127.0.0.1:1/token-policy")
    client.security_policy = _channel_stub(
        server, ua.MessageSecurityMode.None_, security_policies.SecurityPolicyNone.URI
    )
    token = _encrypted_token(server, client, security_policies.SecurityPolicyBasic256Sha256.URI, b"4" * 32)
    _expect_reject(server, token, none_endpoint, b"4" * 32, ua.StatusCodes.BadSecurityPolicyRejected)


@pytest.mark.parametrize("cert,key", SERVER_CREDENTIALS)
async def test_wrong_server_nonce_is_rejected(cert: Path, key: Path) -> None:
    server = await _make_server(
        cert, key, [ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt], [ua.UserNameIdentityToken]
    )
    endpoint = server.iserver.endpoints[0]
    client = Client("opc.tcp://127.0.0.1:1/token-policy")
    client.security_policy = _channel_stub(server, endpoint.SecurityMode, endpoint.SecurityPolicyUri)
    token = _encrypted_token(server, client, endpoint.UserIdentityTokens[0].SecurityPolicyUri, b"client" + b"5" * 26)
    _expect_reject(server, token, endpoint, b"server" + b"6" * 26, ua.StatusCodes.BadIdentityTokenInvalid)


@pytest.mark.parametrize("cert,key", SERVER_CREDENTIALS)
async def test_declared_length_outside_blob_is_rejected(cert: Path, key: Path) -> None:
    server = await _make_server(
        cert, key, [ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt], [ua.UserNameIdentityToken]
    )
    endpoint = server.iserver.endpoints[0]
    nonce = b"7" * 32
    public_key = server.iserver.certificate.public_key()
    inner = ua.ua_binary.Primitives.Bytes.pack((10_000_000).to_bytes(4, "little") + b"short")
    data, algorithm = security_policies.encrypt_asymmetric(
        public_key, inner, security_policies.SecurityPolicyBasic256Sha256.URI
    )
    token = ua.UserNameIdentityToken(
        PolicyId="username", UserName="alice", Password=data, EncryptionAlgorithm=algorithm
    )
    _expect_reject(server, token, endpoint, nonce, ua.StatusCodes.BadIdentityTokenInvalid)


async def test_plaintext_none_policy_accepted_on_none_channel() -> None:
    server = Server(user_manager=RecordingUserManager())
    await server.init()
    server.set_endpoint("opc.tcp://127.0.0.1:1/token-policy")
    server.set_identity_tokens([ua.UserNameIdentityToken])
    await server._setup_server_nodes()
    endpoint = server.iserver.endpoints[0]
    assert endpoint.UserIdentityTokens[0].SecurityPolicyUri == security_policies.SecurityPolicyNone.URI

    client = Client("opc.tcp://127.0.0.1:1/token-policy")
    client.security_policy = _channel_stub(
        server, ua.MessageSecurityMode.None_, security_policies.SecurityPolicyNone.URI
    )
    params = ua.ActivateSessionParameters()
    client._policy_ids = endpoint.UserIdentityTokens
    client._add_user_auth(params, "alice", PASSWORD)
    token = params.UserIdentityToken
    assert token.EncryptionAlgorithm is None
    assert token.Password == PASSWORD.encode("utf-8")

    _activate(server, token, endpoint, b"8" * 32)
    manager = server.iserver.user_manager
    assert isinstance(manager, RecordingUserManager)
    assert manager.calls == [("alice", PASSWORD)]


async def test_independent_token_policy_interoperates() -> None:
    cert, key = SERVER_CREDENTIALS[0]
    server = await _make_server(
        cert,
        key,
        [
            ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt,
            ua.SecurityPolicyType.Aes256Sha256RsaPss_SignAndEncrypt,
        ],
        [ua.UserNameIdentityToken],
    )
    endpoint = next(
        ep
        for ep in server.iserver.endpoints
        if ep.SecurityPolicyUri == security_policies.SecurityPolicyBasic256Sha256.URI
    )
    endpoint.UserIdentityTokens[0].SecurityPolicyUri = security_policies.SecurityPolicyAes256Sha256RsaPss.URI
    client = Client("opc.tcp://127.0.0.1:1/token-policy")
    client.security_policy = _channel_stub(server, endpoint.SecurityMode, endpoint.SecurityPolicyUri)
    nonce = b"9" * 32
    token = _encrypted_token(server, client, security_policies.SecurityPolicyAes256Sha256RsaPss.URI, nonce)
    assert token.EncryptionAlgorithm == security_policies.SecurityPolicyAes256Sha256RsaPss.AsymmetricEncryptionURI
    _activate(server, token, endpoint, nonce)
    manager = server.iserver.user_manager
    assert isinstance(manager, RecordingUserManager)
    assert manager.calls == [("alice", PASSWORD)]


async def test_empty_security_policy_uri_inherits_channel_policy() -> None:
    cert, key = SERVER_CREDENTIALS[0]
    server = await _make_server(
        cert, key, [ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt], [ua.UserNameIdentityToken]
    )
    endpoint = server.iserver.endpoints[0]
    endpoint.UserIdentityTokens[0].SecurityPolicyUri = None
    policy = server.iserver.resolve_user_token_policy(
        ua.UserNameIdentityToken(PolicyId="username"), endpoint.SecurityPolicyUri
    )
    assert policy.SecurityPolicyUri == endpoint.SecurityPolicyUri

    client = Client("opc.tcp://127.0.0.1:1/token-policy")
    client.security_policy = _channel_stub(server, endpoint.SecurityMode, endpoint.SecurityPolicyUri)
    nonce = b"a" * 32
    token = _encrypted_token(server, client, endpoint.SecurityPolicyUri, nonce)
    _activate(server, token, endpoint, nonce)


async def test_duplicate_policy_id_with_conflicting_uri_is_rejected() -> None:
    cert, key = SERVER_CREDENTIALS[0]
    server = await _make_server(
        cert, key, [ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt], [ua.UserNameIdentityToken]
    )
    endpoint = server.iserver.endpoints[0]
    endpoint.UserIdentityTokens.append(
        ua.UserTokenPolicy(
            PolicyId="username",
            TokenType=ua.UserTokenType.UserName,
            SecurityPolicyUri=security_policies.SecurityPolicyAes256Sha256RsaPss.URI,
        )
    )
    token = ua.UserNameIdentityToken(PolicyId="username", UserName="alice")
    _expect_reject(server, token, endpoint, b"b" * 32, ua.StatusCodes.BadSecurityPolicyRejected)


async def test_duplicate_policy_id_with_same_uri_is_accepted() -> None:
    cert, key = SERVER_CREDENTIALS[0]
    server = await _make_server(
        cert, key, [ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt], [ua.UserNameIdentityToken]
    )
    endpoint = server.iserver.endpoints[0]
    endpoint.UserIdentityTokens.append(
        ua.UserTokenPolicy(
            PolicyId="username",
            TokenType=ua.UserTokenType.UserName,
            SecurityPolicyUri=security_policies.SecurityPolicyBasic256Sha256.URI,
        )
    )
    client = Client("opc.tcp://127.0.0.1:1/token-policy")
    client.security_policy = _channel_stub(server, endpoint.SecurityMode, endpoint.SecurityPolicyUri)
    nonce = b"c" * 32
    token = _encrypted_token(server, client, endpoint.SecurityPolicyUri, nonce)
    _activate(server, token, endpoint, nonce)


async def test_client_without_advertised_policy_refuses_to_send() -> None:
    client = Client("opc.tcp://127.0.0.1:1/token-policy")
    client.security_policy = SimpleNamespace(
        URI=security_policies.SecurityPolicyBasic256Sha256.URI,
        Mode=ua.MessageSecurityMode.SignAndEncrypt,
        peer_certificate=b"",
    )
    client._policy_ids = []
    with pytest.raises(ua.UaError):
        client._add_user_auth(ua.ActivateSessionParameters(), "alice", PASSWORD)


async def test_x509_token_must_match_advertised_signature_algorithm() -> None:
    cert, key = SERVER_CREDENTIALS[0]
    server = await _make_server(
        cert, key, [ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt], [ua.X509IdentityToken]
    )
    endpoint = server.iserver.endpoints[0]
    policy = server.iserver.resolve_user_token_policy(
        ua.X509IdentityToken(PolicyId="certificate"), endpoint.SecurityPolicyUri
    )
    user_cert = await uacrypto.load_certificate(USER_CERT)
    user_key = await uacrypto.load_private_key(USER_KEY)
    session = server.iserver.create_session("x509-session")
    session.nonce = b"d" * 32
    challenge = uacrypto.der_from_x509(server.iserver.certificate) + session.nonce
    signature, algorithm = security_policies.sign_asymmetric(
        user_key, challenge, security_policies.SecurityPolicyBasic256Sha256.URI
    )
    token = ua.X509IdentityToken(PolicyId="certificate", CertificateData=uacrypto.der_from_x509(user_cert))
    verified = server.iserver.verify_x509_token(
        session, token, ua.SignatureData(Algorithm=algorithm, Signature=signature), policy
    )
    assert verified == token.CertificateData

    with pytest.raises(ServiceError) as exc_info:
        server.iserver.verify_x509_token(
            session,
            token,
            ua.SignatureData(Algorithm="http://invalid.example/signature", Signature=signature),
            policy,
        )
    assert exc_info.value.code == ua.StatusCodes.BadSecurityPolicyRejected


async def test_anonymous_token_rejected_against_username_policy() -> None:
    cert, key = SERVER_CREDENTIALS[0]
    server = await _make_server(
        cert, key, [ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt], [ua.UserNameIdentityToken]
    )
    endpoint = server.iserver.endpoints[0]
    token = ua.AnonymousIdentityToken(PolicyId="username")
    _expect_reject(server, token, endpoint, b"f" * 32, ua.StatusCodes.BadIdentityTokenRejected)


async def test_user_name_token_rejected_against_wrong_token_type_policy() -> None:
    cert, key = SERVER_CREDENTIALS[0]
    server = await _make_server(
        cert,
        key,
        [ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt],
        [ua.UserNameIdentityToken, ua.X509IdentityToken],
    )
    endpoint = server.iserver.endpoints[0]
    token = ua.UserNameIdentityToken(PolicyId="certificate", UserName="alice", Password=b"x")
    _expect_reject(server, token, endpoint, b"10" * 16, ua.StatusCodes.BadIdentityTokenRejected)


async def test_rejections_never_log_password(caplog: pytest.LogCaptureFixture) -> None:
    cert, key = SERVER_CREDENTIALS[0]
    server = await _make_server(
        cert, key, [ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt], [ua.UserNameIdentityToken]
    )
    endpoint = server.iserver.endpoints[0]
    with caplog.at_level("DEBUG"):
        for token in (
            ua.UserNameIdentityToken(PolicyId="missing", UserName="alice", Password=PASSWORD.encode("utf-8")),
            ua.UserNameIdentityToken(
                PolicyId="username",
                UserName="alice",
                Password=PASSWORD.encode("utf-8"),
                EncryptionAlgorithm="http://invalid.example/algorithm",
            ),
            ua.UserNameIdentityToken(
                PolicyId="username", UserName="alice", Password=PASSWORD.encode("utf-8"), EncryptionAlgorithm=None
            ),
        ):
            with pytest.raises(ServiceError):
                _activate(server, token, endpoint, b"e" * 32)
    assert PASSWORD not in caplog.text
