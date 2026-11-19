from __future__ import annotations

import enum
from typing import NamedTuple, Tuple

from .types import Header


__all__ = [
    "AssociatedDataError",
    "DecodedAssociatedData",
    "Direction",
    "SessionContext",
    "build_associated_data",
    "decode_associated_data",
    "encode_associated_data",
    "encode_session_context"
]


class AssociatedDataError(ValueError):
    """
    Raised when a session context or associated data encoding is malformed, non-canonical, or out of range.
    """


@enum.unique
class Direction(enum.IntEnum):
    """
    The logical direction of a message. The value describes the direction, not whether this party is sending
    or receiving, so both parties derive the same byte sequence for the same message.
    """

    INITIATOR_TO_RESPONDER = 0
    RESPONDER_TO_INITIATOR = 1


class SessionContext(NamedTuple):
    """
    The identity of a Double Ratchet session, excluding the per-message direction and application data.

    The initiator and responder are stable identifiers, not local role names. For example, ``b"alice"`` and
    ``b"bob"`` are suitable, while ``b"me"`` and ``b"peer"`` are not: both parties would encode different
    bytes for the same message.
    """

    session_id: bytes
    initiator: bytes
    responder: bytes


class DecodedAssociatedData(NamedTuple):
    """
    The fields authenticated by a canonical associated data byte sequence.
    """

    context: SessionContext
    direction: Direction
    application_data: bytes
    header: Header
    suite: int


_MAGIC_CONTEXT = b"DR-CTX"
_MAGIC_APPLICATION_DATA = b"DR-ADB"
_MAGIC_ASSOCIATED_DATA = b"DR-AAD"
_VERSION = 1
_MAX_U16 = (1 << 16) - 1
_MAX_U32 = (1 << 32) - 1
_MAX_U64 = (1 << 64) - 1


def _check_bytes(value: object, name: str, *, allow_empty: bool) -> bytes:
    if not isinstance(value, bytes):
        raise AssociatedDataError(f"{name} must be bytes, not {type(value).__name__}.")
    if not allow_empty and not value:
        raise AssociatedDataError(f"{name} must not be empty.")
    if len(value) > _MAX_U32:
        raise AssociatedDataError(f"{name} is too long to encode.")
    return value


def _check_int(value: object, name: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AssociatedDataError(f"{name} must be an integer, not {type(value).__name__}.")
    if not 0 <= value <= maximum:
        raise AssociatedDataError(f"{name} must be in the range 0 to {maximum}.")
    return value


def _encode_u8(value: int) -> bytes:
    return value.to_bytes(1, "big")


def _encode_u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _encode_u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def _encode_u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _encode_length_prefixed(value: bytes) -> bytes:
    return _encode_u32(len(value)) + value


def _read_exact(data: bytes, offset: int, length: int, what: str) -> Tuple[bytes, int]:
    end = offset + length
    if end > len(data):
        raise AssociatedDataError(f"Truncated associated data: expected {what}.")
    return data[offset:end], end


def _read_u8(data: bytes, offset: int, what: str) -> Tuple[int, int]:
    raw, offset = _read_exact(data, offset, 1, what)
    return raw[0], offset


def _read_u16(data: bytes, offset: int, what: str) -> Tuple[int, int]:
    raw, offset = _read_exact(data, offset, 2, what)
    return int.from_bytes(raw, "big"), offset


def _read_u32(data: bytes, offset: int, what: str) -> Tuple[int, int]:
    raw, offset = _read_exact(data, offset, 4, what)
    return int.from_bytes(raw, "big"), offset


def _read_u64(data: bytes, offset: int, what: str) -> Tuple[int, int]:
    raw, offset = _read_exact(data, offset, 8, what)
    return int.from_bytes(raw, "big"), offset


def _read_length_prefixed(data: bytes, offset: int, what: str) -> Tuple[bytes, int]:
    length, offset = _read_u32(data, offset, f"{what} length")
    return _read_exact(data, offset, length, what)


def _read_magic(data: bytes, offset: int, magic: bytes) -> int:
    value, offset = _read_exact(data, offset, len(magic), "magic")
    if value != magic:
        raise AssociatedDataError("Invalid associated data magic.")
    return offset


def _read_version(data: bytes, offset: int) -> int:
    version, offset = _read_u8(data, offset, "version")
    if version != _VERSION:
        raise AssociatedDataError(f"Unsupported associated data version {version}.")
    return offset


def encode_session_context(context: SessionContext) -> bytes:
    """
    Encode the stable identity of a session into a canonical, self-delimiting byte sequence.

    The encoding is injective over all sessions: a session ID, initiator, or responder that is a prefix,
    suffix, or concatenation of another field cannot produce the same bytes as a different session.

    Args:
        context: The session identity to encode.

    Returns:
        The canonical byte sequence describing the session.

    Raises:
        AssociatedDataError: if an identifier is empty, not bytes, or too long to encode.
    """

    if not isinstance(context, SessionContext):
        raise AssociatedDataError(f"context must be a SessionContext, not {type(context).__name__}.")

    session_id = _check_bytes(context.session_id, "session_id", allow_empty=False)
    initiator = _check_bytes(context.initiator, "initiator", allow_empty=False)
    responder = _check_bytes(context.responder, "responder", allow_empty=False)

    return (
        _MAGIC_CONTEXT
        + _encode_u8(_VERSION)
        + _encode_length_prefixed(session_id)
        + _encode_length_prefixed(initiator)
        + _encode_length_prefixed(responder)
    )


def encode_associated_data(
    context: SessionContext,
    direction: Direction,
    application_data: bytes
) -> bytes:
    """
    Encode the session identity, message direction, and application data into the canonical value that is
    passed to :meth:`DoubleRatchet.encrypt_message` and :meth:`DoubleRatchet.decrypt_message`.

    The result is not yet the AEAD associated data. A subclass of :class:`DoubleRatchet` must return
    :func:`build_associated_data` from ``_build_associated_data`` to frame this value together with the
    message header.

    Args:
        context: The stable identity of the session.
        direction: The logical direction of this message.
        application_data: Application-defined bytes to authenticate. May be empty.

    Returns:
        The canonical byte sequence containing the session context, direction, and application data.

    Raises:
        AssociatedDataError: if any field is malformed.
    """

    if not isinstance(direction, Direction):
        raise AssociatedDataError(f"direction must be a Direction, not {type(direction).__name__}.")
    application_data = _check_bytes(application_data, "application_data", allow_empty=True)

    return (
        _MAGIC_APPLICATION_DATA
        + _encode_u8(_VERSION)
        + _encode_length_prefixed(encode_session_context(context))
        + _encode_u8(int(direction))
        + _encode_length_prefixed(application_data)
    )


def build_associated_data(associated_data: bytes, header: Header, *, suite: int = 1) -> bytes:
    """
    Build the byte sequence passed to the AEAD, authenticating the canonical session context, direction,
    application data, and every field of the message header.

    This function is intended to be returned from ``DoubleRatchet._build_associated_data``. It validates
    ``associated_data`` first, so a caller cannot accidentally pass an arbitrary, non-canonical byte string
    as the session/application binding.

    The outer length prefix makes the set of associated data values prefix-free. That matters because some
    AEAD implementations (including :class:`doubleratchet.recommended.aead_aes_hmac.AEAD`) authenticate
    ``associated_data + ciphertext`` without a length between the two. A prefix-free associated data value
    prevents an attacker from moving ciphertext bytes into the associated data while preserving the tag.

    Args:
        associated_data: The canonical value returned by :func:`encode_associated_data`.
        header: The message header. All three fields are authenticated.
        suite: An application-assigned identifier for the complete crypto and encoding profile. Both parties
            must use the same value, and the value must be part of the session's negotiated state.

    Returns:
        The canonical AEAD associated data.

    Raises:
        AssociatedDataError: if the associated data, header, or suite is malformed.
    """

    _decode_application_data(associated_data)
    _check_int(suite, "suite", _MAX_U16)

    if not isinstance(header, Header):
        raise AssociatedDataError(f"header must be a Header, not {type(header).__name__}.")
    ratchet_pub = _check_bytes(header.ratchet_pub, "header.ratchet_pub", allow_empty=False)
    previous_sending_chain_length = _check_int(
        header.previous_sending_chain_length,
        "header.previous_sending_chain_length",
        _MAX_U64
    )
    sending_chain_length = _check_int(
        header.sending_chain_length,
        "header.sending_chain_length",
        _MAX_U64
    )

    body = (
        _MAGIC_ASSOCIATED_DATA
        + _encode_u8(_VERSION)
        + _encode_u16(suite)
        + _encode_length_prefixed(associated_data)
        + _encode_length_prefixed(ratchet_pub)
        + _encode_u64(previous_sending_chain_length)
        + _encode_u64(sending_chain_length)
    )

    return _encode_u32(len(body)) + body


def _decode_session_context(data: bytes, offset: int) -> Tuple[SessionContext, int]:
    offset = _read_magic(data, offset, _MAGIC_CONTEXT)
    offset = _read_version(data, offset)
    session_id, offset = _read_length_prefixed(data, offset, "session_id")
    initiator, offset = _read_length_prefixed(data, offset, "initiator")
    responder, offset = _read_length_prefixed(data, offset, "responder")

    return SessionContext(
        session_id=_check_bytes(session_id, "session_id", allow_empty=False),
        initiator=_check_bytes(initiator, "initiator", allow_empty=False),
        responder=_check_bytes(responder, "responder", allow_empty=False)
    ), offset


def _decode_application_data(data: bytes) -> Tuple[SessionContext, Direction, bytes]:
    offset = _read_magic(data, 0, _MAGIC_APPLICATION_DATA)
    offset = _read_version(data, offset)

    encoded_context, offset = _read_length_prefixed(data, offset, "session context")
    context, context_offset = _decode_session_context(encoded_context, 0)
    if context_offset != len(encoded_context):
        raise AssociatedDataError("Trailing bytes in the session context.")

    direction_value, offset = _read_u8(data, offset, "direction")
    try:
        direction = Direction(direction_value)
    except ValueError as error:
        raise AssociatedDataError(f"Invalid direction {direction_value}.") from error

    application_data, offset = _read_length_prefixed(data, offset, "application_data")
    if offset != len(data):
        raise AssociatedDataError("Trailing bytes in the associated data.")

    return context, direction, application_data


def decode_associated_data(associated_data: bytes) -> DecodedAssociatedData:
    """
    Parse and validate a canonical AEAD associated data value. This is primarily useful for diagnostics,
    interoperability tests, and audit tooling.

    Args:
        associated_data: The value returned by :func:`build_associated_data`.

    Returns:
        The authenticated fields.

    Raises:
        AssociatedDataError: if the value is malformed, non-canonical, or truncated.
    """

    if not isinstance(associated_data, bytes):
        raise AssociatedDataError(
            f"associated_data must be bytes, not {type(associated_data).__name__}."
        )
    if len(associated_data) < 4:
        raise AssociatedDataError("Truncated associated data.")

    body_length = int.from_bytes(associated_data[:4], "big")
    body = associated_data[4:]
    if body_length != len(body):
        raise AssociatedDataError("Associated data length does not match its content.")

    offset = _read_magic(body, 0, _MAGIC_ASSOCIATED_DATA)
    offset = _read_version(body, offset)
    suite, offset = _read_u16(body, offset, "suite")
    encoded_application_data, offset = _read_length_prefixed(body, offset, "application data")
    ratchet_pub, offset = _read_length_prefixed(body, offset, "ratchet_pub")
    previous_sending_chain_length, offset = _read_u64(body, offset, "previous_sending_chain_length")
    sending_chain_length, offset = _read_u64(body, offset, "sending_chain_length")
    if offset != len(body):
        raise AssociatedDataError("Trailing bytes in the associated data.")

    context, direction, application_data = _decode_application_data(encoded_application_data)

    return DecodedAssociatedData(
        context=context,
        direction=direction,
        application_data=application_data,
        header=Header(
            ratchet_pub=_check_bytes(ratchet_pub, "header.ratchet_pub", allow_empty=False),
            previous_sending_chain_length=previous_sending_chain_length,
            sending_chain_length=sending_chain_length
        ),
        suite=suite
    )
