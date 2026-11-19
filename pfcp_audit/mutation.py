"""Byte-level mutators for the F-TEID evidence checks.

The mutators deliberately work on the *captured wire bytes*, never on the
parsed structure, so the tests prove the audit cannot be fooled by a single
flipped flag bit into treating the following field as an address.
"""

from __future__ import annotations

from typing import Tuple

from .evidence import IEPath
from .fteid import MASK_CH, MASK_CHID, MASK_V4, MASK_V6

# F-TEID value starts after the IE Type/Len[/EID] header; the first value byte
# carries the spare/CHID/CH/V6/V4 flags.
FLAG_MASKS = {
    'CHID': MASK_CHID,
    'CH': MASK_CH,
    'V6': MASK_V6,
    'V4': MASK_V4,
}


def fteid_value_offset(path: IEPath, has_eid: bool = False) -> int:
    """Absolute offset of the F-TEID value (flags) byte in the message."""
    return path.byte_offset + (6 if has_eid else 4)


def flip_flag(
    message: bytes,
    path: IEPath,
    flag: str,
    has_eid: bool = False,
) -> Tuple[bytes, int]:
    """Return a mutated message with one F-TEID flags bit toggled.

    Returns the new bytes and the offset that was changed, leaving every other
    byte untouched.
    """
    if flag not in FLAG_MASKS:
        raise ValueError('unknown F-TEID flag %r' % flag)
    offset = fteid_value_offset(path, has_eid)
    buf = bytearray(message)
    buf[offset] ^= FLAG_MASKS[flag]
    return bytes(buf), offset


def clear_flag(
    message: bytes,
    path: IEPath,
    flag: str,
    has_eid: bool = False,
) -> Tuple[bytes, int]:
    """Return a mutated message with one F-TEID flags bit forced to zero."""
    if flag not in FLAG_MASKS:
        raise ValueError('unknown F-TEID flag %r' % flag)
    offset = fteid_value_offset(path, has_eid)
    buf = bytearray(message)
    buf[offset] &= ~FLAG_MASKS[flag]
    return bytes(buf), offset


def set_flag(
    message: bytes,
    path: IEPath,
    flag: str,
    has_eid: bool = False,
) -> Tuple[bytes, int]:
    """Return a mutated message with one F-TEID flags bit forced to one."""
    if flag not in FLAG_MASKS:
        raise ValueError('unknown F-TEID flag %r' % flag)
    offset = fteid_value_offset(path, has_eid)
    buf = bytearray(message)
    buf[offset] |= FLAG_MASKS[flag]
    return bytes(buf), offset


def truncate_fteid_value(
    message: bytes,
    path: IEPath,
    drop: int = 1,
    has_eid: bool = False,
) -> bytes:
    """Drop the last `drop` byte(s) of one F-TEID IE, header included.

    The surrounding message is kept intact so the auditor must detect the
    truncation from the IE length / value layout rather than crash.
    """
    start = path.byte_offset
    end = start + path.byte_length
    if drop >= path.byte_length:
        raise ValueError('cannot drop the whole F-TEID IE')
    return bytes(message[:end - drop]) + bytes(message[end:])
