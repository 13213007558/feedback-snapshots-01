"""Socket-pair TLS peer used for repeatable, bind-free acceptance checks.

Real TCP port binding is unavailable in some locked-down CI sandboxes. Every
handshake here runs over an AF_UNIX socketpair, while still exercising the
full TLS stack (handshake, chain verification, hostname check, optional
mTLS). Two client backends are provided:

* ``pip_truststore`` mirrors ``PipSession`` on pip >= 24.2: a truststore
  SSLContext seeded with certifi, with the corporate PEM added through
  ``load_verify_locations`` exactly the way urllib3 applies ``ca_certs``.
* ``openssl`` is the deterministic reference backend (plain stdlib
  SSLContext with ``cafile``), used to distinguish a genuine trust failure
  from an environment where the OS trust API itself is blocked.
"""

from __future__ import annotations

import dataclasses
import socket
import ssl
import threading
from pathlib import Path
from typing import Any


@dataclasses.dataclass
class HandshakeResult:
    ok: bool
    error_type: str | None
    error_message: str
    peer_cert_cn: str | None
    authorization_header: str | None


def _cert_common_name(cert: dict[str, Any] | None) -> str | None:
    if not cert:
        return None
    subject = cert.get("subject")
    if not subject:
        return None
    for rdn in subject:
        for attr in rdn:
            if attr[0] == "commonName":
                return attr[1]
    return None


def make_server_context(server_pem: Path, *, require_client_ca: Path | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(server_pem))
    if require_client_ca is not None:
        ctx.load_verify_locations(str(require_client_ca))
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def make_pip_truststore_context(ca_pem: Path | None) -> ssl.SSLContext:
    from pip._vendor import certifi
    from pip._vendor import truststore

    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(certifi.where())
    if ca_pem is not None:
        # Same call urllib3 performs when requests passes verify=<pem path>.
        ctx.load_verify_locations(str(ca_pem))
    return ctx


def make_openssl_context(ca_pem: Path | None) -> ssl.SSLContext:
    return ssl.create_default_context(
        cafile=str(ca_pem) if ca_pem is not None else None
    )


def handshake(
    *,
    server_pem: Path,
    hostname: str,
    ca_pem: Path | None,
    backend: str = "openssl",
    client_cert_pem: Path | None = None,
    require_client_ca: Path | None = None,
    authorization: str | None = None,
) -> HandshakeResult:
    """Run one TLS + HTTP/1.1 round-trip over a socketpair."""
    server_ctx = make_server_context(server_pem, require_client_ca=require_client_ca)
    try:
        client_ctx = (
            make_pip_truststore_context(ca_pem)
            if backend == "pip_truststore"
            else make_openssl_context(ca_pem)
        )
        if client_cert_pem is not None:
            client_ctx.load_cert_chain(str(client_cert_pem))
    except Exception as exc:
        return HandshakeResult(
            ok=False,
            error_type=type(exc).__name__,
            error_message=str(exc),
            peer_cert_cn=None,
            authorization_header=None,
        )

    left, right = socket.socketpair()
    observed: dict[str, Any] = {}

    def serve() -> None:
        try:
            with server_ctx.wrap_socket(right, server_side=True) as tls:
                observed["peer_cert"] = tls.getpeercert()
                data = tls.recv(65536)
                observed["authorization"] = next(
                    (
                        line.split(":", 1)[1].strip()
                        for line in data.decode("utf-8", "replace").split("\r\n")
                        if line.lower().startswith("authorization:")
                    ),
                    None,
                )
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        except Exception as exc:  # recorded for the report
            observed["server_error"] = f"{type(exc).__name__}: {exc}"

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        with client_ctx.wrap_socket(left, server_hostname=hostname) as tls:
            request = f"GET /simple/demo/ HTTP/1.1\r\nHost: {hostname}\r\n"
            if authorization:
                request += f"Authorization: {authorization}\r\n"
            request += "\r\n"
            tls.sendall(request.encode())
            tls.recv(64)
        thread.join(timeout=5)
        return HandshakeResult(
            ok=True,
            error_type=None,
            error_message="",
            peer_cert_cn=_cert_common_name(observed.get("peer_cert")),
            authorization_header=observed.get("authorization"),
        )
    except Exception as exc:
        thread.join(timeout=5)
        return HandshakeResult(
            ok=False,
            error_type=type(exc).__name__,
            error_message=str(exc),
            peer_cert_cn=_cert_common_name(observed.get("peer_cert")),
            authorization_header=observed.get("authorization"),
        )


def truststore_usable(*, anchor_pem: Path, server_pem: Path, hostname: str) -> bool:
    """Return True when the OS-backed truststore can validate an explicitly
    anchored chain. A False result means the OS trust API is unavailable in
    this environment (e.g. macOS sandbox OSStatus -26276), not that the
    certificate is wrong."""
    result = handshake(
        server_pem=server_pem,
        hostname=hostname,
        ca_pem=anchor_pem,
        backend="pip_truststore",
    )
    return result.ok
