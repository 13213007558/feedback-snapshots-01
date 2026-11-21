"""Local PKI stand-in for the corporate-CA acceptance suite.

Generates, entirely offline:

* a corporate root CA (the trust anchor the platform rolls out);
* server certificates for the authenticated index host and the approved
  artifact host, signed by the corporate CA;
* a server certificate for an *unapproved* host, signed by a separate CA,
  standing in for any redirect/CDN destination not covered by the rollout;
* an mTLS client certificate signed by the corporate CA.

No network sockets are used; callers load the PEM files into real TLS
contexts (see tls_peer.py).
"""

from __future__ import annotations

import dataclasses
import datetime
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_HOUR = datetime.timedelta(hours=1)


@dataclasses.dataclass(frozen=True)
class Material:
    root_dir: Path
    corp_ca_cert: Path
    other_ca_cert: Path
    index_server_pem: Path
    artifact_server_pem: Path
    unapproved_server_pem: Path
    client_pem: Path
    index_host: str
    artifact_host: str
    unapproved_host: str


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _write(path: Path, payload: bytes) -> Path:
    path.write_bytes(payload)
    os.chmod(path, 0o600)
    return path


def _ca(common_name: str) -> tuple[x509.Certificate, rsa.RSAPrivateKey, x509.Name]:
    key = _key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - _HOUR)
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=False, content_commitment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key, subject


def _server_cert(
    hostname: str,
    issuer_cert: x509.Certificate,
    issuer_key: rsa.RSAPrivateKey,
    issuer_name: x509.Name,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = _key()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - _HOUR)
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )
    return cert, key


def _client_cert(
    common_name: str,
    issuer_cert: x509.Certificate,
    issuer_key: rsa.RSAPrivateKey,
    issuer_name: x509.Name,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = _key()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - _HOUR)
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )
    return cert, key


def _pem(cert: x509.Certificate, key: rsa.RSAPrivateKey) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM) + key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def generate(root_dir: str | os.PathLike[str]) -> Material:
    root = Path(root_dir)
    root.mkdir(parents=True, exist_ok=True)

    corp_cert, corp_key, corp_name = _ca("Corp Build Platform Root CA")
    other_cert, other_key, other_name = _ca("Unapproved External CA")

    _write(root / "corp-ca.pem", corp_cert.public_bytes(serialization.Encoding.PEM))
    _write(root / "unapproved-ca.pem", other_cert.public_bytes(serialization.Encoding.PEM))

    index_host = "index.corp.example"
    artifact_host = "files.corp.example"
    unapproved_host = "cdn.unapproved.example"

    index_cert, index_key = _server_cert(index_host, corp_cert, corp_key, corp_name)
    artifact_cert, artifact_key = _server_cert(artifact_host, corp_cert, corp_key, corp_name)
    unapproved_cert, unapproved_key = _server_cert(
        unapproved_host, other_cert, other_key, other_name
    )
    client_cert, client_key = _client_cert("build-worker-0001", corp_cert, corp_key, corp_name)

    return Material(
        root_dir=root,
        corp_ca_cert=_write(root / "corp-ca.pem", corp_cert.public_bytes(serialization.Encoding.PEM)),
        other_ca_cert=_write(root / "unapproved-ca.pem", other_cert.public_bytes(serialization.Encoding.PEM)),
        index_server_pem=_write(root / "index-server.pem", _pem(index_cert, index_key)),
        artifact_server_pem=_write(root / "artifact-server.pem", _pem(artifact_cert, artifact_key)),
        unapproved_server_pem=_write(root / "unapproved-server.pem", _pem(unapproved_cert, unapproved_key)),
        client_pem=_write(root / "client-mtls.pem", _pem(client_cert, client_key)),
        index_host=index_host,
        artifact_host=artifact_host,
        unapproved_host=unapproved_host,
    )
