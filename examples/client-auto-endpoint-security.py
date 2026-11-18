"""Select a discovered endpoint under a deployment-owned server identity.

Run against a server you control.  The script generates local test
certificates and demonstrates three outcomes:

* accept: discovery offers a SignAndEncrypt endpoint whose application URI,
  certificate and address match the configured identity;
* reject: discovery offers the same certificate at another address, another
  certificate at the same address, or another application URI, all refused
  before any user token is built;
* missing trust configuration: no trust anchor is configured, so credential
  setup fails instead of silently trusting the discovery response.

The client records every real socket target in
``client.last_connection_target`` and every credential release in
``client.credential_release_callback``.  ``SecurityLevel`` is printed only as a
diagnostic; selection uses the local policy/mode classification.
"""

import asyncio
import logging
import socket
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from asyncua import Client, Server, ua
from asyncua.client.endpoint_security import (
    EndpointOrigin,
    EndpointSecurityError,
    EndpointSecurityPolicy,
    MissingServerTrustError,
    ServerIdentity,
    select_endpoint,
)
from asyncua.crypto import uacrypto
from asyncua.crypto.cert_gen import generate_private_key, generate_self_signed_app_certificate
from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256

logging.basicConfig(level=logging.WARNING)

SERVER_URI = "urn:example:auto-endpoint-security:server"
CLIENT_URI = "urn:example:auto-endpoint-security:client"
CERT_DIR = Path(__file__).parent / "certificates" / "auto-endpoint-security"


def ensure_certificate(name: str, uri: str, usage: list[x509.ObjectIdentifier]) -> tuple[Path, Path]:
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    key_file = CERT_DIR / f"{name}.key.pem"
    cert_file = CERT_DIR / f"{name}.der"
    if key_file.exists() and cert_file.exists():
        return cert_file, key_file
    key = generate_private_key()
    cert = generate_self_signed_app_certificate(
        key,
        uri,
        {},
        [x509.UniformResourceIdentifier(uri), x509.DNSName("127.0.0.1")],
        usage,
    )
    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_file.write_bytes(key_bytes)
    cert_file.write_bytes(uacrypto.der_from_x509(cert))
    return cert_file, key_file


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def start_server(port: int, cert: Path, key: Path) -> Server:
    server = Server()
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port}/secure")
    server.set_security_policy([ua.SecurityPolicyType.NoSecurity, ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
    server.set_identity_tokens([ua.UserNameIdentityToken])
    await server.load_certificate(cert)
    await server.load_private_key(key)
    await server.start()
    return server


def prove_rejected(endpoints, policy: EndpointSecurityPolicy, url: str) -> None:
    try:
        select_endpoint(endpoints, policy, EndpointOrigin.parse(url))
    except EndpointSecurityError as exc:
        print(f"[rejected] {type(exc).__name__}: {exc}")


def make_policy(server_cert: Path, url: str) -> EndpointSecurityPolicy:
    identity = ServerIdentity(
        SERVER_URI,
        certificate=x509.load_der_x509_certificate(server_cert.read_bytes()),
        allowed_origins=frozenset({EndpointOrigin.parse(url)}),
    )
    return EndpointSecurityPolicy(
        identity=identity,
        allowed_security_policy_uris=frozenset({SecurityPolicyBasic256Sha256.URI}),
    )


async def run() -> None:
    server_cert, server_key = ensure_certificate("server", SERVER_URI, [ExtendedKeyUsageOID.SERVER_AUTH])
    client_cert, client_key = ensure_certificate(
        "client", CLIENT_URI, [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
    )
    port = free_port()
    url = f"opc.tcp://127.0.0.1:{port}/secure"
    server = await start_server(port, server_cert, server_key)
    try:
        policy = make_policy(server_cert, url)

        print("== discovery only: no session and no credential callback ==")
        probe = Client(url)
        selection = await probe.select_endpoint_from_discovery(policy)
        print(f"[accepted] {selection.describe()}")
        print(
            f"[security level] declared={selection.declared_security_level} "
            f"local={selection.effective_security_level} "
            f"match={selection.declared_security_level_matches_policy}"
        )

        print("== accept: configured identity plus pinned certificate ==")
        client = Client(url)
        client.set_user("operator")
        client.set_password("not-a-real-secret")
        client.credential_release_callback = lambda released: print(f"[credential callback] {released.describe()}")
        await client.set_security(
            SecurityPolicyBasic256Sha256,
            certificate=client_cert,
            private_key=client_key,
            endpoint_security_policy=policy,
        )
        await client.connect()
        print(f"[connect target] {client.last_connection_target}")
        print(f"[session endpoint] {client.session_endpoint.describe() if client.session_endpoint else None}")
        await client.disconnect()

        print("== reject: same certificate, different endpoint address ==")
        endpoints = await probe.connect_and_get_server_endpoints()
        endpoints[0].EndpointUrl = f"opc.tcp://127.0.0.1:{port + 1}/secure"
        prove_rejected(endpoints, policy, url)

        print("== reject: same address, different certificate ==")
        other_cert, _ = ensure_certificate(
            "other", "urn:example:auto-endpoint-security:other", [ExtendedKeyUsageOID.SERVER_AUTH]
        )
        endpoints = await probe.connect_and_get_server_endpoints()
        endpoints[0].ServerCertificate = other_cert.read_bytes()
        prove_rejected(endpoints, policy, url)

        print("== reject: same address and certificate, different application URI ==")
        endpoints = await probe.connect_and_get_server_endpoints()
        endpoints[0].Server.ApplicationUri = "urn:example:auto-endpoint-security:impostor"
        prove_rejected(endpoints, policy, url)

        print("== reject: trusted address taken over by another certificate ==")
        await server.stop()
        impostor_cert, impostor_key = ensure_certificate("impostor", SERVER_URI, [ExtendedKeyUsageOID.SERVER_AUTH])
        impostor = await start_server(port, impostor_cert, impostor_key)
        try:
            impostor_client = Client(url)
            impostor_client.set_user("operator")
            impostor_client.set_password("not-a-real-secret")
            seen = []
            impostor_client.credential_release_callback = seen.append
            try:
                await impostor_client.set_security(
                    SecurityPolicyBasic256Sha256,
                    certificate=client_cert,
                    private_key=client_key,
                    endpoint_security_policy=policy,
                )
            except EndpointSecurityError as exc:
                print(f"[rejected] {type(exc).__name__}: {exc}")
            print(f"[credential callback] {len(seen)} call(s)")
            print(f"[last dialed target] {impostor_client.last_connection_target}")
            await impostor_client.disconnect()
        finally:
            await impostor.stop()

        print("== missing trust configuration ==")
        try:
            ServerIdentity(SERVER_URI)
        except MissingServerTrustError as exc:
            print(f"[missing trust] {type(exc).__name__}: {exc}")
    finally:
        if server.bserver is not None:
            await server.stop()


if __name__ == "__main__":
    asyncio.run(run())
