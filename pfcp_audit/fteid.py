"""Strict F-TEID (TS 29.244 section 8.2.3) layout inspection.

pycrate's :class:`FTEID` transparently drops fields according to the flags and
silently keeps leftover bytes in an ``ext`` buffer.  An audit backend needs the
opposite: every presence bit must be checked against the actual byte length, and
a missing address under the CH (CP function shall assign) flag must stay
*missing* instead of being read as a zero address or as the following IE.

The parser below walks the raw F-TEID value bytes itself, records every layout
problem as a :class:`LayoutAnomaly`, and only then cross-checks the result with
pycrate's structured decoder.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional

import pycrate_mobile.TS29244_PFCP as pfcp


class FTEIDKind(str, Enum):
    """Endpoint semantics carried by an F-TEID IE."""

    SPECIFIED = 'specified'
    ALLOCATION_REQUEST = 'allocation_request'
    UNKNOWN = 'unknown'


class LayoutAnomaly(str, Enum):
    """Layout problems that prevent treating the IE as a usable endpoint."""

    EMPTY = 'empty_fteid'
    TRUNCATED = 'truncated_fteid'
    TRAILING_BYTES = 'trailing_bytes'
    CHID_WITHOUT_CH = 'chid_without_ch'
    ADDR_FLAG_WITH_CH = 'address_flag_set_under_ch'
    NO_ADDRESS_FLAG = 'no_address_flag'
    ZERO_IPV4 = 'zero_ipv4_address'
    ZERO_IPV6 = 'zero_ipv6_address'
    STRUCTURED_DECODE_FAILED = 'pycrate_structured_decode_failed'


# flag byte masks, MSB first: spare(4) | CHID | CH | V6 | V4
MASK_CHID = 0x08
MASK_CH = 0x04
MASK_V6 = 0x02
MASK_V4 = 0x01


class FTEIDLayout:
    """Evidence extracted from one F-TEID value, without any session inference."""

    def __init__(
        self,
        raw: bytes,
        chid: bool = False,
        ch: bool = False,
        v6: bool = False,
        v4: bool = False,
        teid: Optional[int] = None,
        ipv4: Optional[bytes] = None,
        ipv6: Optional[bytes] = None,
        choose_id: Optional[int] = None,
        expected_len: Optional[int] = None,
        kind: FTEIDKind = FTEIDKind.UNKNOWN,
        anomalies: Optional[List[LayoutAnomaly]] = None,
        pycrate_consistent: bool = False,
    ) -> None:
        self.raw = bytes(raw)
        self.flags = {'CHID': chid, 'CH': ch, 'V6': v6, 'V4': v4}
        self.teid = teid
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.choose_id = choose_id
        self.expected_len = expected_len
        self.actual_len = len(raw)
        self.kind = kind
        self.anomalies: List[LayoutAnomaly] = list(anomalies or [])
        self.pycrate_consistent = pycrate_consistent

    @property
    def valid(self) -> bool:
        """True only when the layout alone is internally consistent."""
        return not self.anomalies

    def addresses(self) -> List[bytes]:
        """Addresses actually present on the wire (never synthesized zeros)."""
        return [a for a in (self.ipv4, self.ipv6) if a is not None]

    def __repr__(self) -> str:
        return (
            'FTEIDLayout(kind={0}, flags={1}, teid={2}, choose_id={3}, '
            'anomalies={4})'.format(
                self.kind.value, self.flags, self.teid, self.choose_id,
                [a.value for a in self.anomalies],
            )
        )


def _pycrate_crosscheck(raw: bytes, layout: FTEIDLayout) -> bool:
    """Decode with pycrate and compare the fields pycrate exposes.

    Returns True when pycrate produces a structured F-TEID matching the manual
    walk.  A fallback to the raw ``Buf`` representation (or any exception) is
    recorded as evidence instead of being hidden.
    """
    try:
        decoded = pfcp.FTEID()
        decoded.from_bytes(raw)
    except Exception:
        layout.anomalies.append(LayoutAnomaly.STRUCTURED_DECODE_FAILED)
        return False
    # pycrate parks unknown trailing bytes in its ext buffer instead of
    # rejecting them; the audit keeps that as an explicit mismatch.
    if bytes(decoded['ext'].get_val() or b''):
        return False
    if decoded['CH'].get_val() != int(layout.flags['CH']):
        return False
    if decoded['CHID'].get_val() != int(layout.flags['CHID']):
        return False
    if decoded['V4'].get_val() != int(layout.flags['V4']):
        return False
    if decoded['V6'].get_val() != int(layout.flags['V6']):
        return False
    if layout.teid is not None and decoded['TEID'].get_val() != layout.teid:
        return False
    if layout.choose_id is not None and decoded['CHOOSE_ID'].get_val() != layout.choose_id:
        return False
    if layout.ipv4 is not None and decoded['IPv4Addr'].get_val() != layout.ipv4:
        return False
    if layout.ipv6 is not None and decoded['IPv6Addr'].get_val() != layout.ipv6:
        return False
    return True


def inspect_fteid(raw: bytes) -> FTEIDLayout:
    """Parse one F-TEID value buffer and keep every layout defect as evidence."""
    data = bytes(raw or b'')
    layout = FTEIDLayout(data)

    if not data:
        layout.anomalies.append(LayoutAnomaly.EMPTY)
        layout.pycrate_consistent = _pycrate_crosscheck(data, layout)
        return layout

    flags = data[0]
    chid = bool(flags & MASK_CHID)
    ch = bool(flags & MASK_CH)
    v6 = bool(flags & MASK_V6)
    v4 = bool(flags & MASK_V4)
    layout.flags = {'CHID': chid, 'CH': ch, 'V6': v6, 'V4': v4}

    # TS 29.244 section 8.2.3 field order:
    #   flags | [TEID] | [IPv4] | [IPv6] | [CHOOSE_ID]
    # CH removes TEID and both addresses; CHID always adds the CHOOSE_ID.
    expected_len = 1
    if not ch:
        expected_len += 4  # TEID
        expected_len += 4 if v4 else 0
        expected_len += 16 if v6 else 0
    if chid:
        expected_len += 1  # CHOOSE_ID
    layout.expected_len = expected_len

    if len(data) < expected_len:
        layout.anomalies.append(LayoutAnomaly.TRUNCATED)
    elif len(data) > expected_len:
        layout.anomalies.append(LayoutAnomaly.TRAILING_BYTES)

    cursor = 1
    if not ch and len(data) >= expected_len:
        layout.kind = FTEIDKind.SPECIFIED
        layout.teid = int.from_bytes(data[1:5], 'big')
        cursor = 5
        if v4:
            layout.ipv4 = data[cursor:cursor + 4]
            if layout.ipv4 == b'\x00\x00\x00\x00':
                layout.anomalies.append(LayoutAnomaly.ZERO_IPV4)
            cursor += 4
        if v6:
            layout.ipv6 = data[cursor:cursor + 16]
            if layout.ipv6 == b'\x00' * 16:
                layout.anomalies.append(LayoutAnomaly.ZERO_IPV6)
        if not v4 and not v6:
            # No address presence bit: nothing to read, nothing to invent.
            layout.anomalies.append(LayoutAnomaly.NO_ADDRESS_FLAG)
    elif ch:
        # With CH set the UPF selects TEID and address, so TEID and both
        # address fields are absent even if a presence bit is mistakenly set.
        layout.kind = FTEIDKind.ALLOCATION_REQUEST
        if v4 or v6:
            layout.anomalies.append(LayoutAnomaly.ADDR_FLAG_WITH_CH)
    else:
        layout.kind = FTEIDKind.UNKNOWN

    if chid and len(data) >= expected_len:
        # CHOOSE_ID is the final byte whenever CHID is set, on both sides.
        layout.choose_id = data[expected_len - 1]

    if layout.kind == FTEIDKind.SPECIFIED and layout.anomalies:
        layout.kind = FTEIDKind.UNKNOWN
    layout.pycrate_consistent = _pycrate_crosscheck(data, layout)
    return layout
