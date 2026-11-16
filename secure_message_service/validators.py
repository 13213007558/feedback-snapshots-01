"""Explicit application validators for statements asn1tools cannot guarantee.

Each function maps 1:1 to a ``path`` in constraint_inventory.json. They are
hand-written policy checks, not generic evaluations of ASN.1 constraint
expressions: the inventory tells the gateway which paths need them, and the
functions here encode the actual service policy.
"""

from asn1tools.errors import ConstraintsError

MSG_ID_ROOT_MIN, MSG_ID_ROOT_MAX = 1, 10


def validate_msg_id(value):
    """MsgId is INTEGER (1..10, ...): the extension marker makes the range
    unenforceable in asn1tools. The service policy rejects extension values
    outright, so re-implement the root range explicitly."""
    if not isinstance(value, int) or not MSG_ID_ROOT_MIN <= value <= MSG_ID_ROOT_MAX:
        raise ConstraintsError(
            f"MsgId extension value {value!r} rejected by application policy "
            f"(root range {MSG_ID_ROOT_MIN}..{MSG_ID_ROOT_MAX} is mandatory).")


def _ber_content_end(wire):
    """Return the offset just past the BER TLV at offset 0 (outer SEQUENCE)."""
    offset = 1  # skip outer tag
    first = wire[offset]
    offset += 1
    if first < 0x80:
        length = first
    else:
        num_bytes = first & 0x7F
        length = int.from_bytes(wire[offset:offset + num_bytes], "big")
        offset += num_bytes
    return offset + length


def _count_top_level_elements(wire):
    """Count TLV elements inside the outer BER SEQUENCE, including any
    unknown extension additions that the decoder silently skips."""
    offset = 1
    first = wire[offset]
    offset += 1
    if first < 0x80:
        length = first
    else:
        num_bytes = first & 0x7F
        length = int.from_bytes(wire[offset:offset + num_bytes], "big")
        offset += num_bytes
    content_end = offset + length
    count = 0
    while offset < content_end:
        offset += 1  # tag
        len_octet = wire[offset]
        offset += 1
        if len_octet < 0x80:
            inner_len = len_octet
        else:
            n = len_octet & 0x7F
            inner_len = int.from_bytes(wire[offset:offset + n], "big")
            offset += n
        offset += inner_len
        count += 1
    return count


# Number of root members declared in SecureMessage (before the "...").
EXPECTED_ROOT_MEMBER_COUNT = 5


def make_extension_addition_validator(codec):
    """Build a validator that rejects any extension addition on the wire.

    For BER/DER the outer SEQUENCE TLV is walked: more than the five root
    elements means a peer sent an unknown extension the decoder would hide.
    For PER/OER unknown additions raise a structural decode error already,
    so the check is a defensive no-op returning the decoded data unchanged.
    """
    def reject_unknown_extension_additions(decoded):
        if codec not in ("ber", "der"):
            return
        wire = reject_unknown_extension_additions.wire
        if _ber_content_end(wire) != len(wire):
            raise ConstraintsError("Trailing bytes after outer SEQUENCE TLV.")
        element_count = _count_top_level_elements(wire)
        if element_count > EXPECTED_ROOT_MEMBER_COUNT:
            raise ConstraintsError(
                f"Wire carries {element_count} outer elements but the root schema "
                f"defines only {EXPECTED_ROOT_MEMBER_COUNT}: unknown extension addition "
                "forbidden by admission policy.")

    reject_unknown_extension_additions.wire = b""
    return reject_unknown_extension_additions


# Registry keys must match inventory paths. The gateway binds the current
# wire to the extension validator before each receive().
BER_VALIDATORS = {
    "SecureMessage.msgId": validate_msg_id,
}

PER_VALIDATORS = {
    "SecureMessage.msgId": validate_msg_id,
}
