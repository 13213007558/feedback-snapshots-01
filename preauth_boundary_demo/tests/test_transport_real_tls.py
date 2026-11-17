"""Real crypto check, no network and no listening port.

TLS is established over an in-memory socketpair using asyncio's ``start_tls``
so both ends handshake concurrently on one event loop (a synchronous,
same-thread two-sided handshake on a socket pair would deadlock). This proves
the transport classifier distinguishes an encrypted-but-unverified socket
from a peer whose certificate chain and hostname actually verify.
"""

import asyncio
import datetime
import os
import socket
import ssl
import tempfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from preauth_boundary_demo.transport import (
    TransportKind,
    classify_ssl_object,
    local_trusted_evidence,
)


def _make_cert(cn: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _write_temp(pem: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".pem")
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
    return path


async def _tls_pair(cn: str, verify_peer: bool):
    key, cert = _make_cert(cn)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    cert_path = _write_temp(cert_pem)
    key_path = _write_temp(key_pem)

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert_path, key_path)

    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if verify_peer:
        client_ctx.load_verify_locations(cadata=cert_pem.decode())
        client_ctx.check_hostname = True
        client_ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE

    loop = asyncio.get_running_loop()
    client_sock, server_sock = socket.socketpair()

    server_coro = loop.connect_accepted_socket(
        asyncio.Protocol, server_sock, ssl=server_ctx
    )
    client_coro = loop.create_connection(
        asyncio.Protocol, sock=client_sock, ssl=client_ctx, server_hostname=cn
    )
    (client_transport, _), (server_transport, _) = await asyncio.gather(
        client_coro, server_coro
    )

    for path in (cert_path, key_path):
        os.unlink(path)
    return client_transport, server_transport


@pytest.mark.asyncio
async def test_verified_hostname_produces_tls_verified():
    client_transport, server_transport = await _tls_pair(
        "mail.example.com", verify_peer=True
    )
    ssl_object = client_transport.get_extra_info("ssl_object")
    evidence = classify_ssl_object(ssl_object, "mail.example.com")
    assert evidence.kind is TransportKind.TLS_VERIFIED
    assert evidence.peer_identity == "mail.example.com"
    assert evidence.proves_peer_identity is True
    assert evidence.is_encrypted is True
    client_transport.close()
    server_transport.close()


@pytest.mark.asyncio
async def test_unverified_handshake_is_tls_unverified_not_verified():
    client_transport, server_transport = await _tls_pair(
        "mail.example.com", verify_peer=False
    )
    ssl_object = client_transport.get_extra_info("ssl_object")
    evidence = classify_ssl_object(ssl_object, "mail.example.com")
    assert evidence.kind is TransportKind.TLS_UNVERIFIED
    assert evidence.peer_identity is None
    assert evidence.is_encrypted is True
    assert evidence.proves_peer_identity is False
    client_transport.close()
    server_transport.close()


@pytest.mark.asyncio
async def test_valid_chain_wrong_hostname_is_unverified():
    client_transport, server_transport = await _tls_pair(
        "mail.example.com", verify_peer=True
    )
    ssl_object = client_transport.get_extra_info("ssl_object")
    evidence = classify_ssl_object(ssl_object, "other.example.net")
    assert evidence.kind is TransportKind.TLS_UNVERIFIED
    assert evidence.peer_identity is None
    client_transport.close()
    server_transport.close()


def test_local_trust_requires_explicit_channel_id():
    evidence = local_trusted_evidence("imap-sidecar", peer_addr="127.0.0.1")
    assert evidence.kind is TransportKind.LOCAL_TRUSTED
    assert evidence.peer_identity == "imap-sidecar"
    assert evidence.proves_peer_identity is True
