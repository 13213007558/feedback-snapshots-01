"""Transport evidence: what the *channel* can independently prove.

This module only describes properties of the transport. It never looks at the
IMAP greeting text and never decides who the mail user is. Keeping transport
evidence separate from the server's self-reported status (see ``greeting.py``)
is the whole point of the boundary this demo draws:

* a TLS socket being open proves nothing by itself -- the certificate chain
  and the hostname must verify;
* a loopback address is not automatically trusted -- a local channel is only
  trustworthy when the deployment explicitly says so;
* the word ``PREAUTH`` in a greeting is a server assertion, not transport
  evidence.
"""

from __future__ import annotations

import ipaddress
import ssl
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier


_SUBJECT_ALT_NAME_OID = ObjectIdentifier("2.5.29.17")


def _cert_dns_names(ssl_object: ssl.SSLObject) -> List[str]:
    """Extract the DNS names from a peer certificate's Subject Alternative Name.

    Uses the already-validated DER cert from the handshake rather than the
    removed-in-3.12 ``ssl.match_hostname`` helper.
    """

    der_cert = ssl_object.getpeercert(binary_form=True)
    if not der_cert:
        return []
    certificate = x509.load_der_x509_certificate(der_cert)
    try:
        extension = certificate.extensions.get_extension_for_oid(_SUBJECT_ALT_NAME_OID)
    except x509.ExtensionNotFound:
        common_name = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return [common_name[0].value] if common_name else []
    return extension.value.get_values_for_type(x509.DNSName)


def _hostname_matches(hostname: str, dns_names: List[str]) -> bool:
    lowered = hostname.lower().rstrip(".")
    for name in dns_names:
        pattern = name.lower().rstrip(".")
        if pattern.startswith("*."):
            # Single-label wildcard per RFC 6125: *.example.com matches
            # mail.example.com but not a.b.example.com.
            suffix = pattern[1:]  # ".example.com"
            if lowered.endswith(suffix) and "." not in lowered[: -len(suffix)]:
                return True
        elif pattern == lowered:
            return True
    return False


class TransportKind(str, Enum):
    """How the peer's identity was established, strongest guarantee first."""

    PLAINTEXT = "plaintext"
    TLS_UNVERIFIED = "tls-unverified"
    TLS_VERIFIED = "tls-verified"
    LOCAL_TRUSTED = "local-trusted"


@dataclass(frozen=True)
class TransportEvidence:
    """Facts about the channel that the policy layer can rely on.

    ``peer_identity`` is the identity *proved by the channel itself*:
    a verified hostname for TLS, or an explicit local channel id for an
    explicitly trusted local path. It is ``None`` when the channel cannot
    prove a peer identity. ``None`` here is deliberate -- a greeting string
    must never be copied into this field.
    """

    kind: TransportKind
    peer_identity: Optional[str] = None
    cipher: Optional[str] = None
    peer_addr: Optional[str] = None
    detail: str = ""

    @property
    def proves_peer_identity(self) -> bool:
        return self.peer_identity is not None

    @property
    def is_encrypted(self) -> bool:
        return self.kind in (TransportKind.TLS_UNVERIFIED, TransportKind.TLS_VERIFIED)

    def describe(self) -> str:
        identity = self.peer_identity if self.peer_identity is not None else "no channel-proven identity"
        return f"{self.kind.value} ({identity})"


def is_loopback_address(host: Optional[str]) -> bool:
    if not host:
        return False
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def classify_ssl_object(
    ssl_object: ssl.SSLObject,
    expected_hostname: Optional[str],
    peer_addr: Optional[str] = None,
) -> TransportEvidence:
    """Classify an :class:`ssl.SSLObject` after the handshake.

    The decisive check is :meth:`SSLObject.getpeercert`, which returns an
    empty dict for an unverified handshake. An open, encrypted socket with no
    validated chain is therefore reported as ``TLS_UNVERIFIED`` -- it is
    *not* treated as a confirmed peer identity.
    """

    cipher = ssl_object.cipher()
    cipher_name = cipher[0] if cipher else None
    verified_chain = bool(ssl_object.getpeercert())

    if verified_chain and expected_hostname is not None:
        dns_names = _cert_dns_names(ssl_object)
        if not _hostname_matches(expected_hostname, dns_names):
            return TransportEvidence(
                kind=TransportKind.TLS_UNVERIFIED,
                cipher=cipher_name,
                peer_addr=peer_addr,
                detail=(
                    f"certificate chain valid but hostname {expected_hostname!r} "
                    f"is not in SAN {dns_names}"
                ),
            )
        return TransportEvidence(
            kind=TransportKind.TLS_VERIFIED,
            peer_identity=expected_hostname,
            cipher=cipher_name,
            peer_addr=peer_addr,
            detail="certificate chain verified and hostname matched",
        )

    reason = "no certificate chain was validated" if not verified_chain else "no expected hostname supplied"
    return TransportEvidence(
        kind=TransportKind.TLS_UNVERIFIED,
        cipher=cipher_name,
        peer_addr=peer_addr,
        detail=reason,
    )


def classify_asyncio_transport(
    transport,
    expected_hostname: Optional[str],
) -> TransportEvidence:
    """Classify a real asyncio transport (plain or TLS)."""

    sock = transport.get_extra_info("socket")
    peer_addr = transport.get_extra_info("peername")
    peer_host = peer_addr[0] if isinstance(peer_addr, (tuple, list)) and peer_addr else None
    ssl_object = transport.get_extra_info("ssl_object")

    if ssl_object is not None:
        return classify_ssl_object(ssl_object, expected_hostname, peer_host)

    return TransportEvidence(
        kind=TransportKind.PLAINTEXT,
        peer_addr=peer_host,
        detail="cleartext %s transport" % type(sock).__name__ if sock is not None else "cleartext transport",
    )


def local_trusted_evidence(channel_id: str, peer_addr: Optional[str] = None) -> TransportEvidence:
    """Build evidence for an *explicitly configured* trusted local channel.

    The trust comes from the operator's configuration (``channel_id``), not
    from the fact that the address happens to be loopback.
    """

    return TransportEvidence(
        kind=TransportKind.LOCAL_TRUSTED,
        peer_identity=channel_id,
        peer_addr=peer_addr,
        detail=f"local channel {channel_id!r} is explicitly trusted by configuration",
    )


# --- Test/demo only -------------------------------------------------------
# The helpers below label scripted, in-memory transports used by the demo and
# its tests. They must never be wired to a production connection: there is no
# real socket and therefore no real channel guarantee behind them.


def fake_evidence(
    kind: TransportKind,
    *,
    peer_identity: Optional[str] = None,
    peer_addr: Optional[str] = "203.0.113.10",
    detail: str = "scripted in-memory transport (no real network)",
) -> TransportEvidence:
    """Create explicit transport evidence for a fake (in-memory) transport."""

    if kind == TransportKind.LOCAL_TRUSTED and not peer_identity:
        raise ValueError("a fake local-trusted channel requires an explicit channel id")
    if kind == TransportKind.TLS_VERIFIED and not peer_identity:
        raise ValueError("a fake verified-TLS channel requires the verified hostname")
    return TransportEvidence(
        kind=kind,
        peer_identity=peer_identity,
        peer_addr=peer_addr,
        detail=detail,
    )
