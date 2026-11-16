"""Python implementation of ASCII85/ASCIIHex decoder (Adobe version)."""

import re
from base64 import a85decode
from binascii import unhexlify
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pdfminer.decodebudget import DecodeBudget

start_re = re.compile(rb"^\s*<?\s*~\s*")
end_re = re.compile(rb"\s*~\s*>?\s*$")


def _a85decode_bounded(
    data: bytes,
    budget: "DecodeBudget",
    layer: str,
) -> bytes:
    """Streaming ASCII85 decoder that charges each produced group.

    Unlike :func:`base64.a85decode`, output is appended one encoded group
    at a time and the budget is consulted before the group's bytes are
    retained, so an oversized stream never materializes in memory.
    """
    group: list[int] = []
    out = bytearray()
    for char in data:
        if char in b" \t\n\r\f\v":
            continue
        if char == ord("z"):
            # 'z' marks a group boundary: it emits four zero bytes and
            # discards any digits accumulated since the last boundary,
            # matching the lenient behavior of base64.a85decode.
            group = []
            budget.charge(layer, 4)
            out.extend(b"\x00\x00\x00\x00")
            continue
        if not ord("!") <= char <= ord("u"):
            raise ValueError(f"Invalid ASCII85 character: {char!r}")
        group.append(char - ord("!"))
        if len(group) == 5:
            value = 0
            for digit in group:
                value = value * 85 + digit
            group = []
            budget.charge(layer, 4)
            out.extend(value.to_bytes(4, "big"))
    if group:
        # A partial final group of n (2..4) characters encodes n-1
        # bytes. Pad with the maximum digit 'u' (84) to a full group
        # and keep the leading bytes, matching base64.a85decode.
        n = len(group)
        padded = group + [84] * (5 - n)
        value = 0
        for digit in padded:
            value = value * 85 + digit
        decoded = value.to_bytes(4, "big")[: n - 1]
        budget.charge(layer, len(decoded))
        out.extend(decoded)
    return bytes(out)


def ascii85decode(
    data: bytes,
    budget: "DecodeBudget | None" = None,
    layer: str = "ASCII85Decode",
) -> bytes:
    """In ASCII85 encoding, every four bytes are encoded with five ASCII
    letters, using 85 different types of characters (as 256**4 < 85**5).
    When the length of the original bytes is not a multiple of 4, a special
    rule is used for round up.

    Adobe's ASCII85 implementation expects the input to be terminated
    by `b"~>"`, and (though this is absent from the PDF spec) it can
    also begin with `b"<~"`.  We can't reliably expect this to be the
    case, and there can be off-by-one errors in stream lengths which
    mean that we only see `~` at the end.  Worse, `<` and `>` are in
    ASCII85 digits, so we can't strip them.  We settle on a compromise
    where we strip leading `<~` or `~` and trailing `~` or `~>`.
    """
    data = start_re.sub(b"", data)
    data = end_re.sub(b"", data)
    if budget is not None:
        return _a85decode_bounded(data, budget, layer)
    return a85decode(data)


bws_re = re.compile(rb"\s")


def asciihexdecode(
    data: bytes,
    budget: "DecodeBudget | None" = None,
    layer: str = "ASCIIHexDecode",
) -> bytes:
    """ASCIIHexDecode filter: PDFReference v1.4 section 3.3.1
    For each pair of ASCII hexadecimal digits (0-9 and A-F or a-f), the
    ASCIIHexDecode filter produces one byte of binary data. All white-space
    characters are ignored. A right angle bracket character (>) indicates
    EOD. Any other characters will cause an error. If the filter encounters
    the EOD marker after reading an odd number of hexadecimal digits, it
    will behave as if a 0 followed the last digit.
    """
    data = bws_re.sub(b"", data)
    idx = data.find(b">")
    if idx != -1:
        data = data[:idx]
        if idx % 2 == 1:
            data += b"0"
    if budget is not None:
        # Two hexadecimal digits produce exactly one output byte, so
        # the exact output size is known before any allocation.
        budget.charge(layer, len(data) // 2)
    return unhexlify(data)
