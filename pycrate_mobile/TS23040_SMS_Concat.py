# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.8
# *
# * Copyright 2026. pycrate contributors.
# *
# * This library is free software; you can redistribute it and/or
# * modify it under the terms of the GNU Lesser General Public
# * License as published by the Free Software Foundation; either
# * version 2.1 of the License, or (at your option) any later version.
# *
# * This library is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# * Lesser General Public License for more details.
# *
# * You should have received a copy of the GNU Lesser General Public
# * License along with this library; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# * MA 02110-1301  USA
# *
# *--------------------------------------------------------
# * File Name : pycrate_mobile/TS23040_SMS_Concat.py
# * Created : 2026-11-19
# *--------------------------------------------------------
#*/

"""
Read-only reassembly of concatenated short messages from SMS TP-DUs.

The concatenation reference (TP-UDH IE 0x00 or 0x08) is only an 8 or 16 bit
value chosen by the sender.  It is not a globally unique message identifier:
different senders, directions, DCS values, application ports or reference
widths may legitimately use the same value at the same time.

This module therefore never groups segments on the reference alone.  A group
identity contains:

  * the direction (MO / MT),
  * the originator and destination addresses carried by the TP-DU (or supplied
    by the caller when the TP-DU does not carry that side),
  * the complete TP-DCS octet,
  * the application port pair and its width, when present,
  * the concatenation reference and its width (8 or 16 bits).

Every accepted segment keeps its original TP-DU bytes and its decoded body.
A group is only reported as complete when all sequence numbers are present,
the total segment count is unambiguous and every duplicated sequence number
carries the same content.  Conflicting duplicate segments are never resolved
by taking the last one received: all variants are retained and the group is
reported as a conflict for the caller to judge.

The assembly is read-only with respect to the evidence: input bytes, decoded
body bytes and per-segment values are retained exactly.  Nothing in this
module rewrites a TP-DU or chooses between conflicting segment contents.
"""

from binascii import unhexlify
from collections import namedtuple
from dataclasses import dataclass, field
from typing import Optional, Tuple, Any

from pycrate_core.charpy import Charpy

from .TS23038 import DCS_7B, DCS_UCS
from .TS23040_SMS import SMS_DELIVER, SMS_SUBMIT, SMS_TP


__all__ = [
    'ConcatKey',
    'ConcatSegment',
    'ConcatMessage',
    'RejectedTPDU',
    'SMSConcatAssembler',
    'SMSConcatReassembler',
    'SMSConcatMessage',
    'SMSConcatSegment',
    'assemble_concat_sms',
    'reassemble_concat_sms',
    'reassemble_sms',
    'STATE_COMPLETE',
    'STATE_INCOMPLETE',
    'STATE_CONFLICT',
    'ISSUE_DUPLICATE_IDENTICAL',
    'ISSUE_DUPLICATE_CONFLICT',
    'ISSUE_TOTAL_CONFLICT',
    'ISSUE_MISSING_SEGMENTS',
    'ISSUE_BODY_UNDECODABLE',
    'ISSUE_REDUNDANT_CONCAT_IE',
    'ISSUE_REDUNDANT_PORT_IE',
    'ISSUE_PID_CONFLICT',
    'REFERENCE_8BIT',
    'REFERENCE_16BIT',
]


#------------------------------------------------------------------------------#
# Public state and issue names
#------------------------------------------------------------------------------#

STATE_COMPLETE   = 'complete'
STATE_INCOMPLETE = 'incomplete'
STATE_CONFLICT   = 'conflict'

ISSUE_DUPLICATE_IDENTICAL = 'duplicate_identical'
ISSUE_DUPLICATE_CONFLICT  = 'duplicate_conflict'
ISSUE_TOTAL_CONFLICT      = 'total_conflict'
ISSUE_MISSING_SEGMENTS    = 'missing_segments'
ISSUE_BODY_UNDECODABLE    = 'body_undecodable'
ISSUE_REDUNDANT_CONCAT_IE = 'redundant_concat_ie'
ISSUE_REDUNDANT_PORT_IE   = 'redundant_port_ie'
ISSUE_PID_CONFLICT        = 'pid_conflict'

REFERENCE_8BIT  = 8
REFERENCE_16BIT = 16

# Concatenation IE types from TS 23.040, section 9.2.3.24
_CONCAT_IE_TYPES = {0x00: REFERENCE_8BIT, 0x08: REFERENCE_16BIT}
_PORT_IE_TYPES   = {0x04: 8, 0x05: 16}


#------------------------------------------------------------------------------#
# Group identity
#------------------------------------------------------------------------------#

ConcatKey = namedtuple('ConcatKey', (
    'direction',       # 'MO' or 'MT'
    'originator',      # canonical identity of the sender, or None
    'destination',     # canonical identity of the receiver, or None
    'dcs',             # full TP-DCS octet
    'port_bits',       # 8, 16 or None
    'dest_port',       # destination application port, or None
    'origin_port',     # originating application port, or None
    'reference_bits',  # 8 or 16
    'reference',       # concatenation reference number
    ))


#------------------------------------------------------------------------------#
# Helpers
#------------------------------------------------------------------------------#

def _coerce_tpdu(tpdu):
    """Return an immutable copy of a TP-DU.

    Accepts bytes-like objects, hexadecimal strings and pycrate SMS_TP
    instances.  A pycrate instance is serialized once; its original bytes are
    not available from the object, so callers handling evidence should pass
    the bytes that were captured on the wire.
    """
    if isinstance(tpdu, SMS_TP):
        tpdu = tpdu.to_bytes()
    elif isinstance(tpdu, str):
        tpdu = unhexlify(''.join(tpdu.split()).replace(':', ''))
    if isinstance(tpdu, (bytearray, memoryview)):
        tpdu = bytes(tpdu)
    if not isinstance(tpdu, bytes):
        raise TypeError('TP-DU must be bytes-like, a hex string or SMS_TP, got %r'
                        % type(tpdu).__name__)
    if not tpdu:
        raise ValueError('empty TP-DU')
    return tpdu


def _normalize_direction(direction):
    if direction is None:
        return None
    d = str(direction).strip().upper()
    if d in ('MT', 'DL', 'DOWNLINK', 'NETWORK_TO_MS', 'NETWORK->MS', 'N->MS'):
        return 'MT'
    if d in ('MO', 'UL', 'UPLINK', 'MS_TO_NETWORK', 'MS->NETWORK', 'MS->N'):
        return 'MO'
    raise ValueError('invalid SMS direction: %r' % direction)


def _address_display(address):
    try:
        num = address['Num'].decode()
    except Exception:
        num = None
    return num


def _address_identity(address):
    """Canonical identity from TON, NPI and the decoded number.

    Length nibbles, extension bits and the BCD filler nibble are not part of
    the identity: the same subscriber may be encoded with different padding.
    """
    try:
        ton = int(address['Type']())
        npi = int(address['NumberingPlan']())
        number = address['Num'].decode()
        return 'addr:%d:%d:%s' % (ton, npi, number)
    except Exception:
        return 'raw:' + repr(address)


def _context_value(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    text = str(value).strip()
    return text or None


def _context_identity(value):
    value = _context_value(value)
    if value is None:
        return None
    if isinstance(value, bytes):
        return 'ctx:' + value.hex()
    return 'ctx:' + value.upper()


def _context_display(value):
    value = _context_value(value)
    if value is None:
        return None
    if isinstance(value, bytes):
        try:
            return value.decode()
        except Exception:
            return value.hex()
    return value


def _content_key(segment):
    """Semantic content used to decide whether two segments are duplicates.

    Timestamps, message references and other transport metadata are not
    content.  The PID is included because it changes the interpretation of
    the body.  GSM 7 bit text is preferred over its packed bytes so that
    different padding bits around the same text do not create a false
    conflict.  UCS2 and 8 bit data are compared as bytes, because a UCS2
    character (or surrogate pair) may legitimately span two segments.
    """
    if segment.charset == DCS_7B and isinstance(segment.text, str):
        body = ('text', segment.text)
    else:
        body = ('bytes', segment.body_bytes)
    return (segment.pid, body)


class _Reject(Exception):
    def __init__(self, reason, detail=None):
        Exception.__init__(self, reason)
        self.reason = reason
        self.detail = detail


#------------------------------------------------------------------------------#
# Segment
#------------------------------------------------------------------------------#

@dataclass(frozen=True)
class ConcatSegment:
    """One accepted TP-DU, retained as evidence.

    `raw_tpdu` is the exact input.  `body_bytes` is the TP-UD payload without
    the UDH.  `text` is the pycrate-decoded body (str for GSM 7 bit and UCS2,
    bytes for 8 bit data).
    """

    raw_tpdu: bytes
    direction: str
    originator: Optional[str]
    destination: Optional[str]
    dcs: int
    charset: int
    pid: int
    scts: Optional[bytes]
    concat_ref: int
    concat_total: int
    concat_seq: int
    reference_bits: int
    ports: Optional[Tuple[Optional[int], Optional[int]]]
    port_bits: Optional[int]
    body_bytes: bytes
    text: Any
    udh_bytes: bytes
    received_index: int
    key: ConcatKey = field(repr=False, compare=False)
    tpdu: Any = field(repr=False, compare=False, default=None)
    issues: Tuple[str, ...] = ()

    @property
    def reference_form(self):
        return '8-bit' if self.reference_bits == REFERENCE_8BIT else '16-bit'

    @property
    def raw_tpdu_hex(self):
        return self.raw_tpdu.hex()

    @property
    def body_hex(self):
        return self.body_bytes.hex()

    def _text_for_dict(self):
        if isinstance(self.text, bytes):
            return {'hex': self.text.hex()}
        return self.text

    def as_dict(self):
        return {
            'raw_tpdu': self.raw_tpdu_hex,
            'direction': self.direction,
            'originator': self.originator,
            'destination': self.destination,
            'dcs': self.dcs,
            'charset': self.charset,
            'pid': self.pid,
            'scts': None if self.scts is None else self.scts.hex(),
            'reference': self.concat_ref,
            'reference_bits': self.reference_bits,
            'reference_form': self.reference_form,
            'total': self.concat_total,
            'sequence': self.concat_seq,
            'ports': list(self.ports) if self.ports is not None else None,
            'port_bits': self.port_bits,
            'body': self.body_hex,
            'text': self._text_for_dict(),
            'udh': self.udh_bytes.hex(),
            'received_index': self.received_index,
            'issues': list(self.issues),
        }


#------------------------------------------------------------------------------#
# Rejected input
#------------------------------------------------------------------------------#

@dataclass(frozen=True)
class RejectedTPDU:
    """A TP-DU that could not become part of a concatenation group."""

    raw_tpdu: bytes
    direction: Optional[str]
    reason: str
    detail: Optional[str] = None

    @property
    def raw_tpdu_hex(self):
        return self.raw_tpdu.hex()

    def _text_for_dict(self):
        if isinstance(self.text, bytes):
            return {'hex': self.text.hex()}
        return self.text

    def as_dict(self):
        return {
            'raw_tpdu': self.raw_tpdu_hex,
            'direction': self.direction,
            'reason': self.reason,
            'detail': self.detail,
        }


#------------------------------------------------------------------------------#
# TP-DU parsing
#------------------------------------------------------------------------------#

def _parse_tpdu(raw, direction, origin=None, destination=None, received_index=0):
    """Parse a TP-DU into a ConcatSegment.

    Raises `_Reject` when the TP-DU is malformed, is not concatenated, or
    cannot be assigned to an unambiguous group.
    """
    if not raw:
        raise _Reject('empty_tpdu')

    mti = raw[0] & 0x03
    try:
        direction = _normalize_direction(direction)
    except ValueError as err:
        raise _Reject('invalid_direction', str(err))

    if direction is None:
        # The MTI distinguishes SMS-DELIVER from SMS-SUBMIT in the common
        # case.  Status reports and reports carry no concatenated user data.
        if mti == 0:
            direction = 'MT'
        elif mti == 1:
            direction = 'MO'
        else:
            raise _Reject('unsupported_mti',
                          'cannot infer direction for MTI %d' % mti)

    if direction == 'MT':
        if mti != 0:
            raise _Reject('direction_mismatch',
                          'MT direction with TP-MTI %d' % mti)
        tpdu = SMS_DELIVER()
    else:
        if mti != 1:
            raise _Reject('direction_mismatch',
                          'MO direction with TP-MTI %d' % mti)
        tpdu = SMS_SUBMIT()

    try:
        char = Charpy(raw)
        tpdu.from_bytes(char)
        leftover = char.len_bit()
    except Exception as err:
        raise _Reject('parse_error', '%s: %s' % (type(err).__name__, err))
    if leftover < 0:
        raise _Reject('truncated_tpdu', '%d bits missing' % -leftover)
    if leftover != 0:
        raise _Reject('trailing_bytes', '%d bits left after TP-DU' % leftover)

    try:
        udhi = int(tpdu['TP_UDHI']())
        ud = tpdu['TP_UD']
        udh = ud['UDH']
    except Exception as err:
        raise _Reject('missing_fields', '%s: %s' % (type(err).__name__, err))
    if not udhi or udh.get_trans():
        raise _Reject('not_concatenated', 'TP-UDHI is not set')
    try:
        if int(udh['UDHL']()) == 0:
            raise _Reject('not_concatenated', 'empty UDH')
    except _Reject:
        raise
    except Exception as err:
        raise _Reject('malformed_udh', '%s: %s' % (type(err).__name__, err))

    concats, ports = [], []
    segment_issues = []
    try:
        udh_ies = list(udh['UDH'])
    except Exception as err:
        raise _Reject('malformed_udh', '%s: %s' % (type(err).__name__, err))

    for ie in udh_ies:
        try:
            typ = int(ie['T']())
            length = int(ie['L']())
        except Exception as err:
            raise _Reject('malformed_udh_ie', '%s: %s' % (type(err).__name__, err))
        if typ in _CONCAT_IE_TYPES:
            expected_len = 3 if typ == 0x00 else 4
            if length != expected_len:
                raise _Reject('malformed_concat_ie',
                              'IE 0x%02x has length %d, expected %d'
                              % (typ, length, expected_len))
            try:
                value = ie['V']
                concats.append((typ,
                                int(value['MsgRef']()),
                                int(value['MsgParts']()),
                                int(value['MsgNum']())))
            except Exception as err:
                raise _Reject('malformed_concat_ie',
                              '%s: %s' % (type(err).__name__, err))
        elif typ in _PORT_IE_TYPES:
            expected_len = 2 if typ == 0x04 else 4
            if length != expected_len:
                raise _Reject('malformed_port_ie',
                              'IE 0x%02x has length %d, expected %d'
                              % (typ, length, expected_len))
            try:
                value = ie['V']
                ports.append((typ, int(value['Dest']()), int(value['Origin']())))
            except Exception as err:
                raise _Reject('malformed_port_ie',
                              '%s: %s' % (type(err).__name__, err))

    if not concats:
        raise _Reject('no_concat_ie', 'UDH carries no concatenation IE')
    if len(concats) > 1:
        first = concats[0]
        if any(c != first for c in concats[1:]):
            raise _Reject('conflicting_concat_ie',
                          'several different concatenation IEs in one UDH')
        segment_issues.append(ISSUE_REDUNDANT_CONCAT_IE)
    typ, ref, total, seq = concats[0]
    reference_bits = _CONCAT_IE_TYPES[typ]
    if total == 0 or seq == 0 or seq > total:
        raise _Reject('invalid_concat_values',
                      'reference %d, total %d, sequence %d'
                      % (ref, total, seq))

    port_bits = dest_port = origin_port = None
    if ports:
        first = ports[0]
        if any(p != first for p in ports[1:]):
            raise _Reject('conflicting_port_ie',
                          'several different application port IEs in one UDH')
        if len(ports) > 1:
            segment_issues.append(ISSUE_REDUNDANT_PORT_IE)
        port_bits = _PORT_IE_TYPES[first[0]]
        dest_port, origin_port = first[1], first[2]
        # The port IE width is part of the group identity; a 16 bit port with
        # the same numeric value as an 8 bit port is a different application.
        if port_bits not in (8, 16):
            raise _Reject('malformed_port_ie', 'unsupported port width')
        if port_bits == 8:
            if not (0 <= dest_port <= 0xFF and 0 <= origin_port <= 0xFF):
                raise _Reject('malformed_port_ie', '8 bit port value overflow')
        else:
            if not (0 <= dest_port <= 0xFFFF and 0 <= origin_port <= 0xFFFF):
                raise _Reject('malformed_port_ie', '16 bit port value overflow')

    try:
        dcs = int.from_bytes(tpdu['TP_DCS'].to_bytes(), 'big')
    except Exception:
        dcs = int(tpdu['TP_DCS'].get_val() or 0) & 0xFF
    try:
        pid = int.from_bytes(tpdu['TP_PID'].to_bytes(), 'big') & 0xFF
    except Exception:
        pid = 0
    charset = ud.get_dcs()

    # Retain the exact SCTS bytes, when the TP-DU carries one.
    scts = None
    if direction == 'MT':
        try:
            scts = bytes(tpdu['TP_SCTS'].to_bytes())
        except Exception:
            scts = None

    try:
        udh_bytes = bytes(udh.to_bytes())
    except Exception:
        udh_bytes = b''
    try:
        body_bytes = bytes(ud['UD'].get_val() or b'')
    except Exception:
        body_bytes = b''
    try:
        text = ud['UD'].decode()
    except Exception:
        # UCS2 characters may legitimately span two segments; the complete
        # message body is decoded at assembly time.  A failing GSM 7 bit
        # segment is a real decoding problem and is reported as such.
        text = None
        if charset == DCS_7B:
            segment_issues.append(ISSUE_BODY_UNDECODABLE)

    # Addresses: the TP-DU owns one side, the caller may supply the other
    # (for an SMS-SUBMIT, the submitting subscriber is not in the TP-DU).
    parsed_origin = parsed_destination = None
    origin_display = destination_display = None
    if direction == 'MT':
        try:
            parsed_origin = _address_identity(tpdu['TP_OA'])
            origin_display = _address_display(tpdu['TP_OA'])
        except Exception:
            pass
    else:
        try:
            parsed_destination = _address_identity(tpdu['TP_DA'])
            destination_display = _address_display(tpdu['TP_DA'])
        except Exception:
            pass

    origin_identity = parsed_origin or _context_identity(origin)
    if parsed_origin is None:
        origin_display = _context_display(origin)
        if direction == 'MO' and origin_identity is None:
            # An SMS-SUBMIT carries only the destination address.  Without a
            # caller-supplied origin, two subscribers sharing a reference,
            # destination, DCS and ports would collapse into one group.  Do
            # not guess: reject the segment and preserve it in `rejected`.
            raise _Reject('origin_required',
                          'SMS-SUBMIT has no originator; supply origin')
    destination_identity = parsed_destination or _context_identity(destination)
    if parsed_destination is None:
        destination_display = _context_display(destination)

    key = ConcatKey(direction, origin_identity, destination_identity, dcs,
                    port_bits, dest_port, origin_port, reference_bits, ref)

    return ConcatSegment(
        raw_tpdu=raw,
        direction=direction,
        originator=origin_display,
        destination=destination_display,
        dcs=dcs,
        charset=charset,
        pid=pid,
        scts=scts,
        concat_ref=ref,
        concat_total=total,
        concat_seq=seq,
        reference_bits=reference_bits,
        ports=(dest_port, origin_port) if ports else None,
        port_bits=port_bits,
        body_bytes=body_bytes,
        text=text,
        udh_bytes=udh_bytes,
        received_index=received_index,
        key=key,
        tpdu=tpdu,
        issues=tuple(segment_issues),
        )


#------------------------------------------------------------------------------#
# Assembled message
#------------------------------------------------------------------------------#

class ConcatMessage:
    """A read-only view over all segments sharing one group identity.

    The view is computed from the segments every time it is accessed, so it
    always reflects the current evidence.  It never selects one of several
    conflicting duplicate segments.
    """

    def __init__(self, key, segments):
        self._key = key
        self._segments = tuple(segments)

    # identity -------------------------------------------------------------
    @property
    def key(self):
        return self._key

    @property
    def direction(self):
        return self._key.direction

    @property
    def originator(self):
        for segment in self._segments:
            if segment.originator is not None:
                return segment.originator
        return None

    @property
    def destination(self):
        for segment in self._segments:
            if segment.destination is not None:
                return segment.destination
        return None

    @property
    def dcs(self):
        return self._key.dcs

    @property
    def charset(self):
        return self._segments[0].charset if self._segments else None

    @property
    def reference(self):
        return self._key.reference

    @property
    def concat_ref(self):
        return self._key.reference

    @property
    def reference_bits(self):
        return self._key.reference_bits

    @property
    def reference_form(self):
        return '8-bit' if self._key.reference_bits == REFERENCE_8BIT else '16-bit'

    @property
    def port_bits(self):
        return self._key.port_bits

    @property
    def ports(self):
        if self._key.port_bits is None:
            return None
        return (self._key.dest_port, self._key.origin_port)

    # evidence -------------------------------------------------------------
    @property
    def segments(self):
        """All accepted segments in arrival order, including duplicates."""
        return self._segments

    @property
    def raw_tpdus(self):
        return tuple(segment.raw_tpdu for segment in self._segments)

    @property
    def segments_by_seq(self):
        by_seq = {}
        for segment in self._segments:
            by_seq.setdefault(segment.concat_seq, []).append(segment)
        return {seq: tuple(items) for seq, items in by_seq.items()}

    def for_seq(self, seq):
        """All variants received for sequence number `seq`."""
        return self.segments_by_seq.get(seq, ())

    def segment(self, seq):
        """The single segment for `seq`, or None if absent or conflicting."""
        variants = self.for_seq(seq)
        if len(variants) == 1:
            return variants[0]
        if variants and len({_content_key(v) for v in variants}) == 1:
            return variants[0]
        return None

    @property
    def ordered_segments(self):
        """One representative per sequence, ordered by sequence number."""
        return tuple(self.segments_by_seq[seq][0]
                     for seq in sorted(self.segments_by_seq))

    # completeness ---------------------------------------------------------
    @property
    def totals(self):
        return tuple(sorted({segment.concat_total for segment in self._segments}))

    @property
    def total(self):
        totals = self.totals
        return totals[0] if len(totals) == 1 else None

    @property
    def conflicting_totals(self):
        totals = self.totals
        return totals if len(totals) > 1 else ()

    @property
    def duplicates(self):
        """Sequence numbers received more than once, with all variants."""
        return {seq: variants
                for seq, variants in self.segments_by_seq.items()
                if len(variants) > 1}

    @property
    def duplicate_conflicts(self):
        """Sequence numbers whose duplicate variants disagree on content."""
        return {seq: variants for seq, variants in self.duplicates.items()
                if len({_content_key(v) for v in variants}) > 1}

    @property
    def missing_by_total(self):
        by_seq = self.segments_by_seq
        return {total: tuple(seq for seq in range(1, total + 1)
                             if seq not in by_seq)
                for total in self.totals}

    @property
    def missing(self):
        """Missing sequence numbers, or None when the total is ambiguous."""
        if len(self.totals) != 1:
            return None
        return self.missing_by_total[self.totals[0]]

    @property
    def issues(self):
        issues = []
        for segment in self._segments:
            for issue in segment.issues:
                if issue not in issues:
                    issues.append(issue)
        if self.duplicate_conflicts:
            issues.append(ISSUE_DUPLICATE_CONFLICT)
        elif self.duplicates:
            issues.append(ISSUE_DUPLICATE_IDENTICAL)
        if self.conflicting_totals:
            issues.append(ISSUE_TOTAL_CONFLICT)
        if self.missing:
            issues.append(ISSUE_MISSING_SEGMENTS)
        if len({segment.pid for segment in self._segments}) > 1:
            issues.append(ISSUE_PID_CONFLICT)
        if any(segment.text is None and segment.charset == DCS_7B
               for segment in self._segments):
            if ISSUE_BODY_UNDECODABLE not in issues:
                issues.append(ISSUE_BODY_UNDECODABLE)
        return tuple(issues)

    @property
    def state(self):
        if (self.conflicting_totals or self.duplicate_conflicts
                or ISSUE_PID_CONFLICT in self.issues):
            return STATE_CONFLICT
        if self.missing:
            return STATE_INCOMPLETE
        if ISSUE_BODY_UNDECODABLE in self.issues:
            return STATE_INCOMPLETE
        return STATE_COMPLETE

    @property
    def complete(self):
        return self.state == STATE_COMPLETE

    @property
    def is_complete(self):
        return self.complete

    @property
    def incomplete(self):
        return not self.complete

    # body -----------------------------------------------------------------
    def _ordered_unique_segments(self):
        if self.total is None:
            return None
        return tuple(self.segment(seq) for seq in range(1, self.total + 1))

    @property
    def text(self):
        """Complete message text, or None if the message is not complete.

        Returning None for incomplete or conflicting groups is deliberate:
        a partial concatenation must not be mistaken for a complete SMS.
        """
        if not self.complete:
            return None
        segments = self._ordered_unique_segments()
        if segments is None or any(segment is None for segment in segments):
            return None
        try:
            if self.charset == DCS_7B:
                return ''.join(segment.text for segment in segments)
            if self.charset == DCS_UCS:
                return b''.join(segment.body_bytes
                                for segment in segments).decode('utf-16-be')
            # 8 bit data is binary; callers should use body_bytes.
            return None
        except Exception:
            return None

    @property
    def body_bytes(self):
        """Complete body bytes for UCS2 / 8 bit messages, None otherwise.

        GSM 7 bit bodies are packed per segment and are exposed as text;
        concatenating their packed bytes would be incorrect.
        """
        if not self.complete or self.charset == DCS_7B:
            return None
        segments = self._ordered_unique_segments()
        if segments is None or any(segment is None for segment in segments):
            return None
        return b''.join(segment.body_bytes for segment in segments)

    @property
    def partial_text(self):
        """Contiguous prefix of unambiguous text, for inspection only.

        Stops at the first missing or conflicting sequence number.  This is
        never evidence and is never used to build a complete message.
        """
        parts = []
        for seq in range(1, (self.total or 0) + 1):
            variants = self.for_seq(seq)
            if not variants or len({_content_key(v) for v in variants}) != 1:
                break
            text = variants[0].text
            if not isinstance(text, str):
                break
            parts.append(text)
        return ''.join(parts)

    # serialization --------------------------------------------------------
    def as_dict(self):
        return {
            'state': self.state,
            'complete': self.complete,
            'direction': self.direction,
            'originator': self.originator,
            'destination': self.destination,
            'dcs': self.dcs,
            'charset': self.charset,
            'reference': self.reference,
            'reference_bits': self.reference_bits,
            'reference_form': self.reference_form,
            'port_bits': self.port_bits,
            'ports': list(self.ports) if self.ports is not None else None,
            'totals': list(self.totals),
            'total': self.total,
            'conflicting_totals': list(self.conflicting_totals),
            'missing': None if self.missing is None else list(self.missing),
            'missing_by_total': {str(k): list(v)
                                 for k, v in self.missing_by_total.items()},
            'duplicates': {str(seq): [s.as_dict() for s in variants]
                           for seq, variants in self.duplicates.items()},
            'duplicate_conflicts': {str(seq): [s.as_dict() for s in variants]
                                    for seq, variants in self.duplicate_conflicts.items()},
            'issues': list(self.issues),
            'text': self.text,
            'body': None if self.body_bytes is None else self.body_bytes.hex(),
            'segments': [segment.as_dict() for segment in self._segments],
        }

    def __repr__(self):
        return '<ConcatMessage %s ref=%s/%s seqs=%s state=%s>' % (
            self.direction, self.reference, self.reference_form,
            ','.join(str(s.concat_seq) for s in self._segments), self.state)


# Convenience aliases, in line with the rest of pycrate's naming.
SMSConcatMessage = ConcatMessage
SMSConcatSegment = ConcatSegment


#------------------------------------------------------------------------------#
# Assembler
#------------------------------------------------------------------------------#

class SMSConcatAssembler:
    """Collect SMS TP-DUs and expose read-only concatenation groups.

    The assembler only accepts TP-DUs.  It does not mutate them, does not use
    the concatenation reference as a global key, and never resolves a
    conflicting group by arrival order.
    """

    def __init__(self):
        self._groups = {}
        self._rejected = []
        self._count = 0

    # ingestion ------------------------------------------------------------
    def add_tpdu(self, tpdu, direction=None, origin=None, destination=None):
        """Add one TP-DU.

        Args:
            tpdu: bytes, hex string or pycrate SMS_TP instance.  For evidence,
                always pass the exact bytes captured from the interface.
            direction: 'MO'/'MT' (also accepts UL/DL); if omitted it is
                inferred from TP-MTI (0 = MT SMS-DELIVER, 1 = MO SMS-SUBMIT).
            origin: caller-supplied sender identity.  Used only when the
                TP-DU does not carry an originator (MO SMS-SUBMIT), so that
                two subscribers using the same reference are not merged.
            destination: caller-supplied receiver identity, used only when the
                TP-DU does not carry a destination (MT SMS-DELIVER).

        Returns:
            ConcatSegment on success, None if the TP-DU was rejected.  The
            rejected input and reason remain available in `rejected`.
        """
        try:
            raw = _coerce_tpdu(tpdu)
        except Exception as err:
            raw = b''
            detail = '%s: %s' % (type(err).__name__, err)
            self._rejected.append(RejectedTPDU(raw, _safe_direction(direction),
                                               'invalid_input', detail))
            return None
        index = self._count
        self._count += 1
        try:
            segment = _parse_tpdu(raw, direction, origin, destination, index)
        except _Reject as err:
            self._rejected.append(RejectedTPDU(raw, _safe_direction(direction),
                                               err.reason, err.detail))
            return None
        group = self._groups.get(segment.key)
        if group is None:
            self._groups[segment.key] = [index, [segment]]
        else:
            group[1].append(segment)
        return segment

    # aliases
    add = add_tpdu
    feed = add_tpdu

    # results --------------------------------------------------------------
    @property
    def messages(self):
        """All concatenation groups, in order of first arrival."""
        return tuple(
            ConcatMessage(key, tuple(self._groups[key][1]))
            for key in sorted(self._groups, key=lambda k: self._groups[k][0]))

    @property
    def groups(self):
        """Mapping of group key to ConcatMessage, in first-arrival order."""
        return {key: ConcatMessage(key, tuple(self._groups[key][1]))
                for key in sorted(self._groups, key=lambda k: self._groups[k][0])}

    @property
    def rejected(self):
        return tuple(self._rejected)

    @property
    def segments(self):
        """All accepted segments, in arrival order, across every group."""
        return tuple(segment
                     for key in sorted(self._groups, key=lambda k: self._groups[k][0])
                     for segment in self._groups[key][1])

    def as_dict(self):
        return {
            'messages': [message.as_dict() for message in self.messages],
            'rejected': [item.as_dict() for item in self._rejected],
        }

    def messages_for_reference(self, reference, reference_bits=None,
                               direction=None):
        """All groups using `reference`, discriminated by the rest of the key."""
        result = []
        for key, group in self._groups.items():
            if key.reference != reference:
                continue
            if reference_bits is not None and key.reference_bits != reference_bits:
                continue
            if direction is not None and key.direction != _normalize_direction(direction):
                continue
            result.append(ConcatMessage(key, tuple(group[1])))
        result.sort(key=lambda message: message.segments[0].received_index)
        return tuple(result)

    def __iter__(self):
        return iter(self.messages)

    def __len__(self):
        return len(self._groups)

    def __getitem__(self, key):
        if key not in self._groups:
            raise KeyError(key)
        return ConcatMessage(key, tuple(self._groups[key][1]))

    def __repr__(self):
        return '<SMSConcatAssembler groups=%d rejected=%d>' % (
            len(self._groups), len(self._rejected))


SMSConcatReassembler = SMSConcatAssembler


def _safe_direction(direction):
    try:
        return _normalize_direction(direction)
    except Exception:
        return None


#------------------------------------------------------------------------------#
# Functional helpers
#------------------------------------------------------------------------------#

def _iter_inputs(items):
    for item in items:
        if isinstance(item, dict):
            yield (item.get('tpdu', item.get('raw_tpdu')),
                   item.get('direction'),
                   item.get('origin'),
                   item.get('destination'))
        elif isinstance(item, (tuple, list)) and len(item) in (2, 4):
            if len(item) == 2:
                yield item[0], item[1], None, None
            else:
                yield item[0], item[1], item[2], item[3]
        else:
            yield item, None, None, None


def assemble_concat_sms(tpdus, direction=None):
    """Add several TP-DUs and return the assembler.

    Each item may be a bytes-like TP-DU, an SMS_TP instance, a tuple
    `(tpdu, direction)` / `(tpdu, direction, origin, destination)`, or a dict
    with keys `tpdu` (or `raw_tpdu`), `direction`, `origin`, `destination`.
    """
    assembler = SMSConcatAssembler()
    for item, item_direction, origin, destination in _iter_inputs(tpdus):
        assembler.add_tpdu(item,
                           direction=item_direction if item_direction is not None else direction,
                           origin=origin, destination=destination)
    return assembler


def reassemble_concat_sms(tpdus, direction=None):
    """Return the tuple of concatenation groups, preserving evidence.

    Use `assemble_concat_sms` when the rejected TP-DUs are also needed.
    """
    return assemble_concat_sms(tpdus, direction).messages


reassemble_sms = reassemble_concat_sms
