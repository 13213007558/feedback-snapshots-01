from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

# Characters that must be escaped when they appear in an RDN value.
# Reference: RFC 4514 section 3, plus NUL which cannot appear in a valid DN string.
_RDN_SPECIAL = frozenset(',+"\\<>;=\x00')


def escape_rdn_value(value: str) -> str:
    """Escape an RDN value for inclusion in a distinguished name (RFC 4514).

    Unlike a naive comma-only replacement, this escapes every reserved character, a literal
    NUL byte (rendered as ``\\00``), and leading/trailing spaces and number signs.

    Args:
        value: The raw, unescaped RDN value as stored in the database.

    Returns:
        The escaped RDN value safe to place after an ``=`` in a DN string.
    """
    if value == "":
        return ""

    chars: list[str] = []
    last_index = len(value) - 1
    for index, char in enumerate(value):
        if char in _RDN_SPECIAL:
            if char == "\x00":
                chars.append("\\00")
            else:
                chars.extend(("\\", char))
        elif ord(char) < 0x20 or ord(char) == 0x7F:
            # RFC 4514: control characters are escaped as a backslash and two hex digits.
            chars.append(f"\\{ord(char):02X}")
        elif char in (" ", "#") and index in (0, last_index):
            chars.extend(("\\", char))
        else:
            chars.append(char)
    return "".join(chars)


def render_rdn(rdn_type: str, values: Sequence[str]) -> str:
    """Render a (possibly multi-valued) relative distinguished name.

    A single-valued RDN renders as ``TYPE=value``. A multi-valued RDN joins its attribute
    value assertions with ``+`` per RFC 4514 instead of silently dropping all but the first
    value.

    Args:
        rdn_type: The RDN attribute type (for example ``cn`` or ``dc``).
        values: One or more raw RDN values for this object.

    Returns:
        The rendered RDN without a parent suffix.
    """
    escaped_type = escape_rdn_value(rdn_type)
    return "+".join(f"{escaped_type}={escape_rdn_value(value)}" for value in values)
