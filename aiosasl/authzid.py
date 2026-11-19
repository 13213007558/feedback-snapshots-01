########################################################################
# File name: authzid.py
# This file is part of: aiosasl
#
# LICENSE
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/>.
#
########################################################################
"""
Support for explicit authorization identities (``authzid``).

The authentication identity (``authcid``) proves possession of a
credential.  The authorization identity (``authzid``) is a *request* to
act as another identity after authentication.  This module only encodes
that request and offers a small, source-bound resolver for the identity
which is used by the application afterwards.

The resolver never treats the request as granted.  The effective
identity must either be reported by a trusted server or be granted by an
explicit mapping supplied by the application.
"""

import base64
import collections
import typing

from . import common, stringprep


__all__ = [
    "AuthorizationFailure",
    "AuthorizationResult",
    "GS2Header",
    "PlainClientResponse",
    "SCRAMClientFirst",
    "SCRAMClientFinal",
    "build_gs2_header",
    "encode_plain_payload",
    "encode_scram_authcid",
    "encode_scram_authzid",
    "parse_gs2_header",
    "parse_plain_client_response",
    "parse_scram_client_final",
    "parse_scram_client_first",
    "resolve_authorization",
]

#: The identity source used when the server did not request a different
#: identity and the client is acting as itself.
SOURCE_IMPLICIT = "implicit"

#: The identity was reported by the trusted server.
SOURCE_SERVER = "server"

#: The identity was granted by an explicit client-side mapping.
SOURCE_MAPPING = "mapping"


class AuthorizationFailure(common.SASLError):
    """
    Raised when an authorization identity request is not granted.

    This is deliberately not an :class:`~.AuthenticationFailure`: the
    authentication identity may have proven its credentials successfully,
    while the delegation request has still been refused.  It is a
    :class:`~.SASLError` so that callers which already handle SASL errors
    see it, but its ``kind`` is ``"authorization failed"``.

    .. attribute:: authcid

       The authentication identity which made the request.

    .. attribute:: authzid

       The requested authorization identity.
    """

    def __init__(
            self,
            authcid: str,
            authzid: str,
            text: typing.Optional[str] = None):
        if text is None:
            text = (
                "authorization identity {!r} was not granted to "
                "{!r}".format(authzid, authcid)
            )
        super().__init__(None, "authorization failed", text=text)
        self.authcid = authcid
        self.authzid = authzid


#: The result of :func:`resolve_authorization`.
#:
#: ``authcid`` is the proven identity, ``requested_authzid`` is the
#: requested identity (or :data:`None`), ``effective_identity`` is the
#: identity the application must use, ``delegated`` indicates whether
#: that identity differs from ``authcid``, and ``source`` is one of
#: :data:`SOURCE_IMPLICIT`, :data:`SOURCE_SERVER` or
#: :data:`SOURCE_MAPPING`.
AuthorizationResult = collections.namedtuple(
    "AuthorizationResult",
    [
        "authcid",
        "requested_authzid",
        "effective_identity",
        "delegated",
        "source",
    ]
)


#: A parsed GS2 header.
#:
#: ``flag`` is the raw GS2 channel binding flag, ``authzid`` is the
#: decoded authorization identity as :class:`bytes` (or :data:`None`),
#: and ``raw`` is the exact header including the final comma.
GS2Header = collections.namedtuple(
    "GS2Header",
    [
        "flag",
        "authzid",
        "raw",
    ]
)


#: A parsed PLAIN client response.
#:
#: ``authzid`` is :data:`None` when the response used the legacy
#: ``NUL authcid NUL password`` form.
PlainClientResponse = collections.namedtuple(
    "PlainClientResponse",
    [
        "authzid",
        "authcid",
        "password",
    ]
)


#: A parsed SCRAM client-first message.
#:
#: ``gs2`` is a :class:`GS2Header`, ``authcid`` is the decoded SASL
#: username (as :class:`bytes`), ``nonce`` is the raw nonce, and ``bare``
#: is the exact client-first-message-bare.
SCRAMClientFirst = collections.namedtuple(
    "SCRAMClientFirst",
    [
        "gs2",
        "authcid",
        "nonce",
        "bare",
    ]
)


#: A parsed SCRAM client-final message.
#:
#: ``gs2`` is a :class:`GS2Header`, ``channel_binding_data`` is the raw
#: channel binding data following the header, and ``nonce`` and ``proof``
#: are the raw field values.
SCRAMClientFinal = collections.namedtuple(
    "SCRAMClientFinal",
    [
        "gs2",
        "channel_binding_data",
        "nonce",
        "proof",
    ]
)


def _require_identity(
        value: typing.Any,
        name: str,
        *,
        allow_empty: bool = False,
        ) -> str:
    if not isinstance(value, str):
        raise TypeError("{} must be a str".format(name))
    if not value and not allow_empty:
        raise ValueError("{} must not be empty".format(name))
    return value


def _normalize_authzid(
        authzid: typing.Optional[str],
        ) -> typing.Optional[str]:
    # An empty authzid is the wire-equivalent of "no request" for PLAIN
    # and cannot be represented in the GS2 grammar.  Treat it as absent
    # so that callers can pass through optional configuration values
    # without special-casing.
    if authzid is None or authzid == "":
        return None
    return _require_identity(authzid, "authzid")


def _escape_saslname(value: bytes) -> bytes:
    # `,` and `=` are the only escape triggers.  A literal sequence like
    # ``=2C`` in the source must not be double-escaped, so the scan is
    # explicit rather than two sequential replacements.
    out = bytearray()
    for char in value:
        if char == ord(","):
            out.extend(b"=2C")
        elif char == ord("="):
            out.extend(b"=3D")
        else:
            out.append(char)
    return bytes(out)


def _unescape_saslname(value: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(value):
        char = value[i:i + 1]
        if char != b"=":
            if char == b"\0":
                raise ValueError("NUL byte in SASL name")
            out.extend(char)
            i += 1
            continue

        escape = value[i:i + 3]
        if escape == b"=2C":
            out.append(0x2c)
        elif escape == b"=3D":
            out.append(0x3d)
        else:
            raise ValueError("invalid `=` escape in SASL name")
        i += 3

    return bytes(out)


def encode_scram_authcid(authcid: str) -> bytes:
    """
    Prepare and encode an authentication identity for SCRAM.

    The authentication identity is treated as a query string, as
    mandated by :rfc:`5802#section-5.1`: unassigned code points are
    allowed.  The resulting SASL name is escaped for use in a GS2
    message (``,`` and ``=``).
    """

    prepared = stringprep.saslprep(
        _require_identity(authcid, "authcid", allow_empty=True),
        allow_unassigned=True,
    )
    encoded = prepared.encode("utf-8")
    if b"\0" in encoded:
        raise ValueError("NUL byte in authcid is disallowed")
    return _escape_saslname(encoded)


def encode_scram_authzid(authzid: str) -> bytes:
    """
    Prepare and encode an authorization identity for SCRAM.

    Unlike the authentication identity, the authorization identity is
    prepared as a stored string: unassigned code points are rejected,
    because the identity is expected to name an existing account.  The
    resulting SASL name is escaped for use in a GS2 message.
    """

    prepared = stringprep.saslprep(
        _require_identity(authzid, "authzid"),
    )
    encoded = prepared.encode("utf-8")
    if b"\0" in encoded:
        raise ValueError("NUL byte in authzid is disallowed")
    return _escape_saslname(encoded)


def build_gs2_header(
        flag: bytes,
        authzid: typing.Optional[str] = None,
        ) -> bytes:
    """
    Build a GS2 header with an optional authorization identity.

    `flag` is the raw GS2 channel binding flag (``n``, ``y`` or
    ``p=<name>``).  When `authzid` is :data:`None`, the legacy header
    ``<flag>,,`` is returned unchanged.  Otherwise the header contains
    ``a=<escaped-authzid>`` between the two commas.
    """

    authzid = _normalize_authzid(authzid)
    if authzid is None:
        return flag + b",,"
    return flag + b",a=" + encode_scram_authzid(authzid) + b","


def encode_plain_payload(
        authcid: str,
        password: str,
        authzid: typing.Optional[str] = None,
        ) -> bytes:
    """
    Encode a PLAIN client response (see :rfc:`4616`).

    PLAIN uses NUL as field separator.  If `authzid` is :data:`None`,
    the legacy ``NUL authcid NUL password`` payload is produced.  If it
    is provided, the payload is ``authzid NUL authcid NUL password``.

    PLAIN clients do not apply SASLprep here; :rfc:`4616` makes the
    server responsible for preparation.  What is enforced locally is
    that neither identity (and not the password) contains a NUL byte,
    because that would silently change field boundaries.
    """

    encoded_authcid = _require_identity(
        authcid,
        "authcid",
        allow_empty=True,
    ).encode("utf-8")
    encoded_password = password.encode("utf-8")

    if b"\0" in encoded_authcid or b"\0" in encoded_password:
        raise ValueError("NUL byte in authcid or password is disallowed")

    authzid = _normalize_authzid(authzid)
    if authzid is None:
        return b"\0" + encoded_authcid + b"\0" + encoded_password

    encoded_authzid = authzid.encode("utf-8")
    if b"\0" in encoded_authzid:
        raise ValueError("NUL byte in authzid is disallowed")

    return encoded_authzid + b"\0" + encoded_authcid + b"\0" + encoded_password


def _split_gs2_header(
        msg: bytes,
        ) -> typing.Tuple[bytes, bytes, bytes]:
    first_comma = msg.find(b",")
    if first_comma < 0:
        raise ValueError("malformed GS2 header: missing first comma")
    second_comma = msg.find(b",", first_comma + 1)
    if second_comma < 0:
        raise ValueError("malformed GS2 header: missing second comma")
    authzid_field = msg[first_comma + 1:second_comma]
    return msg[:second_comma + 1], msg[:first_comma], authzid_field


def parse_gs2_header(msg: bytes) -> GS2Header:
    """
    Parse the GS2 header at the start of `msg`.

    Return a :class:`GS2Header`.  The remainder of `msg` is ignored.
    Invalid separators or invalid ``=`` escapes raise :class:`ValueError`.
    """

    raw, flag, authzid_field = _split_gs2_header(msg)

    if flag not in (b"n", b"y") and (
            not flag.startswith(b"p=") or flag == b"p="):
        raise ValueError("invalid GS2 channel binding flag")

    if not authzid_field:
        authzid = None
    else:
        if not authzid_field.startswith(b"a="):
            raise ValueError("invalid GS2 authorization identity field")
        authzid = _unescape_saslname(authzid_field[2:])
        if not authzid:
            raise ValueError("empty GS2 authorization identity")

    return GS2Header(flag, authzid, raw)


def parse_plain_client_response(payload: bytes) -> PlainClientResponse:
    """
    Parse a PLAIN client response with an independent field splitter.

    The response must contain exactly two NUL separators.  This catches
    both swapped/missing fields and injected separators.  An empty first
    field is reported as ``authzid=None``.
    """

    fields = payload.split(b"\0")
    if len(fields) != 3:
        raise ValueError(
            "PLAIN response must contain exactly two NUL separators"
        )

    authzid, authcid, password = fields
    if authzid == b"":
        parsed_authzid = None
    else:
        parsed_authzid = authzid

    return PlainClientResponse(parsed_authzid, authcid, password)


def parse_scram_client_first(payload: bytes) -> SCRAMClientFirst:
    """
    Parse a SCRAM client-first message with independent field readers.

    The GS2 header is split at its first two commas.  The client-first
    message bare is split at its first two unescaped commas.  The
    authentication identity and the authorization identity are decoded
    separately, so a value in one position can never be mistaken for the
    other.
    """

    gs2 = parse_gs2_header(payload)
    bare = payload[len(gs2.raw):]
    fields = bare.split(b",")

    if len(fields) < 2:
        raise ValueError("malformed SCRAM client-first message")

    name_key, separator, encoded_authcid = fields[0].partition(b"=")
    if separator != b"=" or name_key != b"n":
        raise ValueError("missing SCRAM authentication identity")

    nonce_key, separator, nonce = fields[1].partition(b"=")
    if separator != b"=" or nonce_key != b"r":
        raise ValueError("missing SCRAM nonce")

    authcid = _unescape_saslname(encoded_authcid)
    if not authcid:
        raise ValueError("empty SCRAM authentication identity")

    return SCRAMClientFirst(gs2, authcid, nonce, bare)


def parse_scram_client_final(payload: bytes) -> SCRAMClientFinal:
    """
    Parse a SCRAM client-final message.

    The ``c`` field contains base64 of the GS2 header followed by the
    channel binding data.  The header (and its authorization identity,
    if any) is decoded separately from the nonce and proof.
    """

    values = {}
    for field in payload.split(b","):
        key, separator, value = field.partition(b"=")
        if separator != b"=" or len(key) != 1:
            raise ValueError("malformed SCRAM client-final message")
        if key in values:
            raise ValueError("duplicate SCRAM client-final field")
        values[key] = value

    try:
        channel_binding = values[b"c"]
        nonce = values[b"r"]
        proof = values[b"p"]
    except KeyError:
        raise ValueError("malformed SCRAM client-final message") from None

    try:
        decoded_channel_binding = base64.b64decode(
            channel_binding,
            validate=True,
        )
    except Exception:
        raise ValueError("invalid SCRAM channel binding field") from None

    gs2 = parse_gs2_header(decoded_channel_binding)
    channel_binding_data = decoded_channel_binding[len(gs2.raw):]

    return SCRAMClientFinal(gs2, channel_binding_data, nonce, proof)


def resolve_authorization(
        authcid: str,
        requested_authzid: typing.Optional[str],
        *,
        server_identity: typing.Optional[str] = None,
        mapping: typing.Optional[
            typing.Mapping[str, typing.Iterable[str]]
        ] = None,
        ) -> AuthorizationResult:
    """
    Resolve the identity the application is allowed to use.

    `authcid` is the identity which proved the credential.
    `requested_authzid` is the value sent on the wire, or :data:`None`.

    The effective identity is only derived from one of two trusted
    sources:

    * `server_identity`, the identity reported by the trusted server.
    * `mapping`, an explicit ``{authcid: {authzid, ...}}`` grant table
      controlled by the application, or a callable
      ``mapping(authcid, authzid) -> bool``.

    A requested authzid which is not covered by either source raises
    :class:`AuthorizationFailure`.  In particular, a caller cannot make
    the requested value effective merely by passing it in.

    If `server_identity` is present, it wins over `mapping`: a trusted
    server result is authoritative even when it maps the request onto a
    different identity (for example a role).  A server which reports the
    authentication identity has declined the delegation; the result then
    has ``delegated == False`` and the authentication identity as the
    effective identity.
    """

    _require_identity(authcid, "authcid", allow_empty=True)
    requested_authzid = _normalize_authzid(requested_authzid)

    if server_identity is not None:
        _require_identity(server_identity, "server_identity")

        return AuthorizationResult(
            authcid,
            requested_authzid,
            server_identity,
            server_identity != authcid,
            SOURCE_SERVER,
        )

    if requested_authzid is None or requested_authzid == authcid:
        return AuthorizationResult(
            authcid,
            requested_authzid,
            authcid,
            False,
            SOURCE_IMPLICIT,
        )

    if mapping is not None:
        if callable(mapping):
            allowed = mapping(authcid, requested_authzid)
        else:
            try:
                allowed = requested_authzid in mapping.get(authcid, ())
            except AttributeError:
                raise TypeError(
                    "mapping must be a mapping or a callable"
                ) from None
        if allowed:
            return AuthorizationResult(
                authcid,
                requested_authzid,
                requested_authzid,
                True,
                SOURCE_MAPPING,
            )

    raise AuthorizationFailure(authcid, requested_authzid)
