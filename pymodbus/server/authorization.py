"""TLS client authorization for the modbus server.

After the TLS layer has authenticated a client certificate, the server still
has to decide which devices and which modbus function codes that particular
client is allowed to use. This module is the access adapter bridging the two:

- :class:`TlsIdentity` is the *verified* identity taken from the TLS
  connection. It is never derived from a PDU field or a value the client gets
  to choose inside the request.
- :class:`TlsAccessRule` binds a certificate principal to the set of device
  ids and function codes it may use.
- :class:`TlsAccessPolicy` maps a verified :class:`TlsIdentity` to a rule and
  enforces the decision, defaulting to deny.

The identity is resolved once per connection from the TLS verification
context, so a reconnecting client is re-evaluated on every new connection and
a certificate without a mapping is rejected before any device is touched.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence

from ..constants import ExcCodes
from ..exceptions import ModbusException
from ..logging import Log
from ..pdu import ModbusPDU


class AuthorizationException(ModbusException):
    """A request was rejected by the TLS access policy."""

    def __init__(self, string: str, exception_code: ExcCodes) -> None:
        """Initialize the exception.

        :param string: Human readable reason for the rejection.
        :param exception_code: Modbus exception code returned to the client.
        """
        self.exception_code = exception_code
        ModbusException.__init__(self, f"[Authorization] {string}")


class TlsIdentity:
    """Verified identity of a TLS connection.

    The attributes are extracted from the peer certificate as presented by the
    TLS verification context. They describe the certificate, they are not
    values taken from a modbus PDU.

    :param common_name: Subject common name (CN), or ``None`` when absent.
    :param subject_alt: DNS/URI/other names from the subjectAltName extension.
    :param fingerprint: SHA-256 fingerprint (hex) of the DER certificate.
    :param verified: ``True`` when the certificate was verified by TLS. An
        unverified connection carries an empty identity and is always denied.
    """

    def __init__(
        self,
        common_name: str | None = None,
        subject_alt: Sequence[str] | None = None,
        fingerprint: str | None = None,
        verified: bool = False,
    ) -> None:
        """Initialize the verified identity."""
        self.common_name = common_name
        self.subject_alt: tuple[str, ...] = tuple(subject_alt or ())
        self.fingerprint = fingerprint
        self.verified = verified

    @property
    def principals(self) -> tuple[str, ...]:
        """Return every principal that can be matched against a rule."""
        names: list[str] = []
        if self.common_name:
            names.append(self.common_name)
        names.extend(self.subject_alt)
        if self.fingerprint:
            names.append(self.fingerprint)
        return tuple(names)

    @staticmethod
    def unverified() -> TlsIdentity:
        """Return the empty identity used for an unverified connection."""
        return TlsIdentity(verified=False)


class TlsAccessRule:
    """Permissions granted to one certificate principal.

    :param principal: CN, subjectAltName entry or certificate fingerprint that
        identifies the client certificate.
    :param device_ids: Device ids the principal may address.
    :param function_codes: Modbus function codes the principal may invoke.
    """

    def __init__(
        self,
        principal: str,
        device_ids: Iterable[int],
        function_codes: Iterable[int],
    ) -> None:
        """Initialize an access rule."""
        self.principal = principal
        self.device_ids = frozenset(device_ids)
        self.function_codes = frozenset(function_codes)

    def permits_device(self, device_id: int) -> bool:
        """Return true when the rule allows access to ``device_id``."""
        return device_id in self.device_ids

    def permits_function(self, function_code: int) -> bool:
        """Return true when the rule allows ``function_code``."""
        return function_code in self.function_codes


class TlsAccessPolicy:
    """Map verified TLS identities to device/function permissions.

    Lookup is purely based on the verified certificate principals. A PDU
    device id or any other self-reported field is never used as a credential;
    the device id is only checked *after* the certificate has been matched to
    a rule.

    :param rules: Access rules keyed by certificate principal.
    """

    def __init__(self, rules: Iterable[TlsAccessRule] | None = None) -> None:
        """Initialize the policy with an optional set of rules."""
        self.rules: dict[str, TlsAccessRule] = {}
        for rule in rules or ():
            self.add_rule(rule)

    def add_rule(self, rule: TlsAccessRule) -> None:
        """Add or replace the rule for its principal."""
        self.rules[rule.principal] = rule

    def resolve(self, identity: TlsIdentity) -> TlsAccessRule | None:
        """Return the rule matching a verified identity, or ``None``.

        Unverified identities and verified certificates without a configured
        mapping both resolve to ``None`` and are therefore denied.
        """
        if not identity.verified:
            return None
        for principal in identity.principals:
            if rule := self.rules.get(principal):
                return rule
        return None

    def authorize(self, identity: TlsIdentity, pdu: ModbusPDU) -> TlsAccessRule:
        """Authorize a request using its connection identity.

        The check happens before any datastore/device access.

        :param identity: Verified identity of the TLS connection.
        :param pdu: Decoded request; only device id and function code are read.
        :returns: The matching rule on success.
        :raises AuthorizationException: When the request must be denied.
        """
        if (rule := self.resolve(identity)) is None:
            Log.warning(
                "TLS authorization denied: no mapping for verified identity {}",
                identity.principals,
            )
            raise AuthorizationException(
                "client identity has no access rule",
                ExcCodes.GATEWAY_PATH_UNAVIABLE,
            )
        if not rule.permits_device(pdu.dev_id):
            Log.warning(
                "TLS authorization denied: {} may not access device {}",
                rule.principal,
                pdu.dev_id,
            )
            raise AuthorizationException(
                f"device {pdu.dev_id} not permitted",
                ExcCodes.GATEWAY_PATH_UNAVIABLE,
            )
        if not rule.permits_function(pdu.function_code):
            Log.warning(
                "TLS authorization denied: {} may not use function {}",
                rule.principal,
                pdu.function_code,
            )
            raise AuthorizationException(
                f"function {pdu.function_code} not permitted",
                ExcCodes.ILLEGAL_FUNCTION,
            )
        return rule


def identity_from_transport(transport) -> TlsIdentity:
    """Build a :class:`TlsIdentity` from a TLS transport.

    The identity is taken exclusively from the TLS verification context (the
    peer certificate exposed by the SSL object). When the transport is not a
    TLS transport or the peer did not present a usable certificate an
    unverified identity is returned, which the policy denies.

    :param transport: asyncio transport (or a test double) for the connection.
    :type transport: asyncio.BaseTransport or object with get_extra_info
    """
    if transport is None:
        return TlsIdentity.unverified()
    if (ssl_object := transport.get_extra_info("ssl_object")) is None:
        return TlsIdentity.unverified()

    if not (der_cert := ssl_object.getpeercert(binary_form=True)):
        return TlsIdentity.unverified()

    cert = ssl_object.getpeercert()
    common_name = _extract_common_name(cert)
    subject_alt = _extract_subject_alt(cert)
    fingerprint = hashlib.sha256(der_cert).hexdigest()
    return TlsIdentity(
        common_name=common_name,
        subject_alt=subject_alt,
        fingerprint=fingerprint,
        verified=True,
    )


def _extract_common_name(cert) -> str | None:
    """Read the subject common name from a parsed peer certificate."""
    if not cert:
        return None
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName" and value:
                return value
    return None


def _extract_subject_alt(cert) -> tuple[str, ...]:
    """Read all subjectAltName values from a parsed peer certificate."""
    if not cert:
        return ()
    names: list[str] = []
    for key, value in cert.get("subjectAltName", ()):
        _ = key
        if value:
            names.append(value)
    return tuple(names)
