# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Description : Diameter AVP comprehension review layer
# *
# * This module adds a semantic comprehension check on top of the structural
# * decoding provided by pycrate_diameter.Diameter.  Structural decoding only
# * proves that AVP length fields allow the message to be walked; it does not
# * prove that the reviewing node actually understands every AVP.
# *
# * Per RFC 6733 section 4.1.1 / 6.2:
# *   - an unknown AVP with the M-bit clear is an optional AVP and may be
# *     ignored (the message is only partially understood),
# *   - an unknown AVP with the M-bit set exceeds the receiver's capabilities
# *     and mandates rejection with Result-Code 5010
# *     (DIAMETER_AVP_UNSUPPORTED),
# *   - an AVP identity is the (Vendor-ID, AVP Code) pair: a base-protocol
# *     code (V=0) never grants understanding of a vendor-specific AVP (V=1)
# *     that reuses the same numeric code.
# *
# * The review is fully offline: it never opens a socket and never talks to an
# * AAA server.  All original message bytes are retained unchanged in the
# * review result.
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
# * You should have received a copy of the GNU Lesser General Public License
# * along with this library; if not, write to the Free Software Foundation, Inc.,
# * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
# *--------------------------------------------------------
# * File Name : pycrate_diameter/DiameterReview.py
# *--------------------------------------------------------
#*/

__all__ = [
    'VENDOR_IETF',
    'VENDOR_3GPP',
    'Disposition',
    'Verdict',
    'StructuralError',
    'AVPIdentity',
    'AVPCapability',
    'AVPObservation',
    'ReviewResult',
    'CapRegistry',
    'default_registry',
    'review_message',
    'build_avp',
    'build_message',
    ]

from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional

from pycrate_core.utils import PycrateErr
from pycrate_diameter.Diameter import DiameterGeneric


#------------------------------------------------------------------------------#
# constants
#------------------------------------------------------------------------------#

#: vendor id 0 means the V-bit is clear and the AVP is defined in the base
#: protocol (RFC 6733 and companion IETF RFCs)
VENDOR_IETF = 0

#: 3GPP vendor id, as registered in IANA "SMI Network Management Private
#: Enterprise Codes" and used by TS 29.230
VENDOR_3GPP = 10415

#: Diameter header size, per RFC 6733 section 3
DIAMETER_HDR_LEN = 20

#: minimal AVP header size (8 without Vendor-ID, 12 with), per RFC 6733 4.1
AVP_HDR_LEN = 8
AVP_HDR_LEN_V = 12


class Disposition:
    """What the reviewing node is able to do with a given AVP instance."""

    #: AVP identity is present in the local capability registry
    KNOWN = 'known'

    #: unknown AVP, M-bit clear: RFC 6733 4.1.1 allows it to be ignored
    UNKNOWN_OPTIONAL = 'unknown-optional-ignored'

    #: unknown AVP, M-bit set: the node lacks a required capability and the
    #: message must be rejected (Result-Code 5010)
    UNKNOWN_MANDATORY = 'unknown-mandatory-reject'


class Verdict:
    """Message-level comprehension verdict."""

    #: every AVP at every nesting level is recognized
    FULLY_UNDERSTOOD = 'fully-understood'

    #: structural parsing is fine, but at least one unknown optional AVP had
    #: to be ignored; skipping a length field is not equivalent to
    #: understanding the authentication content
    PARTIALLY_UNDERSTOOD = 'partially-understood'

    #: at least one unknown mandatory AVP is present, or the message is
    #: structurally malformed
    NOT_UNDERSTOOD = 'not-understood'


class StructuralError:
    """Machine-readable structural error codes."""

    TRUNCATED_MESSAGE = 'truncated-message'
    BAD_VERSION = 'bad-diameter-version'
    BAD_MESSAGE_LENGTH = 'bad-message-length'
    TRUNCATED_AVP_HEADER = 'truncated-avp-header'
    BAD_AVP_LENGTH = 'bad-avp-length'
    TRUNCATED_AVP_DATA = 'truncated-avp-data'
    TRUNCATED_AVP_PADDING = 'truncated-avp-padding'
    NON_ZERO_PADDING = 'non-zero-avp-padding'
    MALFORMED_GROUPED = 'malformed-grouped-avp'
    PYCRATE_DECODE_ERROR = 'pycrate-decode-error'


#------------------------------------------------------------------------------#
# capability registry: an AVP identity is (Vendor-ID, AVP Code)
#------------------------------------------------------------------------------#

@dataclass(frozen=True)
class AVPIdentity:
    """Diameter AVP identity.

    The Vendor-ID is part of the identity.  Code 264 with vendor 0 is the
    base-protocol Origin-Realm AVP, while code 264 with vendor 10415 would be
    a different, vendor-specific AVP; the two must never be conflated.
    """

    code: int
    vendor_id: int = VENDOR_IETF

    def __str__(self):
        if self.vendor_id == VENDOR_IETF:
            return 'AVP(code=%d, vendor=IETF(0))' % (self.code, )
        return 'AVP(code=%d, vendor=%d)' % (self.code, self.vendor_id)


@dataclass(frozen=True)
class AVPCapability:
    """A capability the reviewing node actually implements."""

    identity: AVPIdentity
    name: str
    grouped: bool = False


class CapRegistry:
    """Capability table keyed by the full AVP identity.

    A base-protocol entry never matches a V=1 AVP that happens to share the
    same numeric code, because the lookup tuple includes the Vendor-ID.
    """

    def __init__(self):
        self._caps: Dict[Tuple[int, int], AVPCapability] = {}

    def register(self, code, vendor_id=VENDOR_IETF, name=None, grouped=False):
        identity = AVPIdentity(code, vendor_id)
        if name is None:
            name = str(identity)
        self._caps[(vendor_id, code)] = AVPCapability(identity, name, grouped)
        return self

    def register_capability(self, capability: AVPCapability):
        self._caps[(capability.identity.vendor_id,
                    capability.identity.code)] = capability
        return self

    def get(self, identity: AVPIdentity) -> Optional[AVPCapability]:
        return self._caps.get((identity.vendor_id, identity.code))

    def is_known(self, identity: AVPIdentity) -> bool:
        return (identity.vendor_id, identity.code) in self._caps

    def is_grouped(self, identity: AVPIdentity) -> bool:
        cap = self.get(identity)
        return cap is not None and cap.grouped

    def names(self) -> List[str]:
        return sorted(cap.name for cap in self._caps.values())

    def __len__(self):
        return len(self._caps)


def default_registry() -> CapRegistry:
    """Build the default capability registry from the pycrate dictionaries.

    Only AVPs whose data format pycrate knows how to decode are advertised as
    understood.  Grouped AVPs are flagged so the reviewer recurses into them.
    The IETF table is keyed under vendor 0; the 3GPP table under vendor 10415,
    so same-numbered codes from different vendors never collide.
    """

    registry = CapRegistry()
    # IETF / base protocol AVPs (RFC 6733 and companions), V-bit clear
    from pycrate_diameter.DiameterIETF import FMT_LUT_IETF, Grouped as IETFGrouped
    from pycrate_diameter.iana_diameter_dicts import AVPCodes_dict
    for code, fmt in FMT_LUT_IETF.items():
        registry.register(
            code,
            VENDOR_IETF,
            AVPCodes_dict.get(code, 'IETF-AVP-%d' % code),
            grouped=(fmt is IETFGrouped),
            )
    # 3GPP vendor-specific AVPs (TS 29.230), V-bit set, vendor 10415
    try:
        from pycrate_diameter.Diameter3GPP import (
            TGPPAVPInfos_dict, Grouped as TGPPGrouped)
    except ImportError:
        TGPPAVPInfos_dict = {}
        TGPPGrouped = None
    for code, info in TGPPAVPInfos_dict.items():
        name, fmt = info
        registry.register(
            code,
            VENDOR_3GPP,
            name,
            grouped=(TGPPGrouped is not None and fmt is TGPPGrouped),
            )
    return registry


#------------------------------------------------------------------------------#
# review observations
#------------------------------------------------------------------------------#

@dataclass
class AVPObservation:
    """One AVP instance as seen on the wire, with its comprehension status."""

    identity: AVPIdentity
    name: Optional[str]
    # header flags, retained exactly as received (RFC 6733 section 4.1)
    flag_v: int
    flag_m: int
    flag_p: int
    # wire geometry (all lengths in bytes)
    offset: int
    declared_length: int          # value of the AVP Length field
    header_length: int           # 8 or 12 depending on the V-bit
    data_length: int
    padding_length: int
    wire_length: int             # declared length rounded up to 32 bits
    # nesting: rendered path and 0-based occurrence among same-identity siblings
    path: List[str]
    occurrence: int
    same_identity_count: int
    disposition: str
    reason: str
    # original bytes, retained verbatim
    raw: bytes
    data: bytes
    # recursive content for known grouped AVPs
    nested: List['AVPObservation'] = field(default_factory=list)

    @property
    def path_str(self):
        return ' / '.join(self.path)

    def is_unknown(self):
        return self.disposition in (
            Disposition.UNKNOWN_OPTIONAL, Disposition.UNKNOWN_MANDATORY)


@dataclass
class ReviewResult:
    """Full offline review output; the original bytes are kept untouched."""

    verdict: str
    original: bytes
    header: Dict[str, int]
    pycrate_structural_decode: str
    observations: List[AVPObservation]
    structural_errors: List[Dict[str, str]]
    duplicates: List[Dict[str, object]]
    unknown_optional: List[AVPObservation]
    unknown_mandatory: List[AVPObservation]
    body_consumed: bool

    def flat_observations(self) -> List[AVPObservation]:
        out = []

        def _walk(obs_list):
            for obs in obs_list:
                out.append(obs)
                _walk(obs.nested)

        _walk(self.observations)
        return out

    def summary(self) -> str:
        lines = []
        lines.append('verdict: %s' % self.verdict)
        lines.append('pycrate structural decode: %s'
                     % self.pycrate_structural_decode)
        lines.append('message length: %d bytes, body fully consumed: %s'
                     % (len(self.original), self.body_consumed))
        if self.structural_errors:
            lines.append('structural errors:')
            for err in self.structural_errors:
                lines.append('  - [%s] %s @ %s'
                             % (err['code'], err['detail'], err['path']))
        lines.append('AVP observations (in nesting order):')
        for obs in self.flat_observations():
            lines.append('  - %s | M=%d V=%d P=%d | pad=%d | %s | %s'
                         % (obs.path_str, obs.flag_m, obs.flag_v, obs.flag_p,
                            obs.padding_length, obs.disposition, obs.reason))
        if self.duplicates:
            lines.append('duplicate identities:')
            for dup in self.duplicates:
                lines.append('  - %s x%d under %s'
                             % (dup['identity'], dup['count'], dup['path']))
        return '\n'.join(lines)


#------------------------------------------------------------------------------#
# wire parsing helpers
#------------------------------------------------------------------------------#

def _u24(buf, off):
    return (buf[off] << 16) | (buf[off + 1] << 8) | buf[off + 2]


def _u32(buf, off):
    return ((buf[off] << 24) | (buf[off + 1] << 16) |
            (buf[off + 2] << 8) | buf[off + 3])


def _segment_label(identity: AVPIdentity, occurrence: int) -> str:
    return '%s#%d' % (identity, occurrence)


def _parse_one(buf: bytes, offset: int, path: List[str]
               ) -> Tuple[AVPObservation, int, List[Dict[str, str]]]:
    """Parse one AVP (header + data + padding) from `buf` at `offset`.

    Returns the observation, the offset just after the padding, and any
    non-fatal structural warnings.  Fatal structural problems raise
    :class:`ReviewError`.
    """

    warnings: List[Dict[str, str]] = []
    if len(buf) - offset < AVP_HDR_LEN:
        raise ReviewError(
            StructuralError.TRUNCATED_AVP_HEADER,
            'only %d bytes left, need at least 8 for an AVP header'
            % (len(buf) - offset, ),
            path, offset)
    code = _u32(buf, offset)
    flags = buf[offset + 4]
    declared = _u24(buf, offset + 5)
    flag_v = (flags >> 7) & 1
    flag_m = (flags >> 6) & 1
    flag_p = (flags >> 5) & 1
    header_len = AVP_HDR_LEN_V if flag_v else AVP_HDR_LEN
    if declared < header_len:
        raise ReviewError(
            StructuralError.BAD_AVP_LENGTH,
            'AVP Length %d is smaller than the %d-byte header'
            % (declared, header_len),
            path, offset)
    if offset + declared > len(buf):
        raise ReviewError(
            StructuralError.TRUNCATED_AVP_DATA,
            'AVP Length %d at offset %d overruns the %d-byte buffer'
            % (declared, offset, len(buf)),
            path, offset)
    if flag_v:
        vendor_id = _u32(buf, offset + 8)
    else:
        vendor_id = VENDOR_IETF
    data = buf[offset + header_len: offset + declared]
    wire_len = (declared + 3) & ~3
    if offset + wire_len > len(buf):
        raise ReviewError(
            StructuralError.TRUNCATED_AVP_PADDING,
            'padded AVP span %d at offset %d overruns the %d-byte buffer'
            % (wire_len, offset, len(buf)),
            path, offset)
    padding_len = wire_len - declared
    if padding_len and buf[offset + declared: offset + wire_len] != \
            b'\x00' * padding_len:
        warnings.append({
            'path': ' / '.join(path),
            'code': StructuralError.NON_ZERO_PADDING,
            'detail': '%s uses %d non-zero padding byte(s)'
                      % (AVPIdentity(code, vendor_id), padding_len),
            })
    raw = buf[offset: offset + wire_len]
    obs = AVPObservation(
        identity=AVPIdentity(code, vendor_id),
        name=None,
        flag_v=flag_v,
        flag_m=flag_m,
        flag_p=flag_p,
        offset=offset,
        declared_length=declared,
        header_length=header_len,
        data_length=len(data),
        padding_length=padding_len,
        wire_length=wire_len,
        path=list(path),
        occurrence=0,
        same_identity_count=1,
        disposition=Disposition.KNOWN,
        reason='',
        raw=raw,
        data=data,
        )
    return obs, offset + wire_len, warnings


class ReviewError(PycrateErr):
    """Fatal structural problem encountered while walking an AVP buffer."""

    def __init__(self, code, detail, path, offset):
        super(ReviewError, self).__init__(
            '%s: %s (offset %d, path %s)'
            % (code, detail, offset, ' / '.join(path) or '<message>'))
        self.code = code
        self.detail = detail
        self.path = list(path)
        self.offset = offset


def _disposition_reason(obs: AVPObservation, cap: Optional[AVPCapability]
                        ) -> Tuple[str, str]:
    if cap is not None:
        kind = 'grouped AVP' if cap.grouped else 'AVP'
        return (Disposition.KNOWN,
                '%s "%s" is implemented in the local capability registry'
                % (kind, cap.name))
    if obs.flag_m:
        return (Disposition.UNKNOWN_MANDATORY,
                'no capability for %s and M-bit is set: RFC 6733 6.2 '
                'requires rejection with Result-Code 5010 '
                '(DIAMETER_AVP_UNSUPPORTED)' % obs.identity)
    return (Disposition.UNKNOWN_OPTIONAL,
            'no capability for %s and M-bit is clear: RFC 6733 4.1.1 '
            'allows the AVP to be ignored, but its content is not '
            'understood' % obs.identity)


def _walk_level(buf: bytes, registry: CapRegistry,
                parent_path: List[str], depth_offset: int,
                deep_scan: bool
                ) -> Tuple[List[AVPObservation], List[Dict[str, str]],
                           List[Dict[str, object]],
                           List[AVPObservation], List[AVPObservation]]:
    observations: List[AVPObservation] = []
    errors: List[Dict[str, str]] = []
    unknown_optional: List[AVPObservation] = []
    unknown_mandatory: List[AVPObservation] = []
    seen: Dict[Tuple[int, int], List[AVPObservation]] = {}
    offset = 0
    while offset < len(buf):
        path = parent_path + ['<offset %d>' % (depth_offset + offset, )]
        try:
            obs, next_offset, warnings = _parse_one(buf, offset, path)
        except ReviewError as exc:
            errors.append({
                'path': ' / '.join(exc.path) or '<message>',
                'code': exc.code,
                'detail': exc.detail,
                })
            if parent_path:
                # inside a grouped AVP: let the parent label the failure
                raise
            # top level: keep everything parsed before the failure and stop
            break
        errors.extend(warnings)
        cap = registry.get(obs.identity)
        obs.name = cap.name if cap is not None else None
        obs.disposition, obs.reason = _disposition_reason(obs, cap)
        # replace the offset-only segment with a stable, human-readable label
        occurrence = len(seen.setdefault(
            (obs.identity.vendor_id, obs.identity.code), []))
        obs.occurrence = occurrence
        obs.path = parent_path + [
            _segment_label(obs.identity, occurrence)]
        seen[(obs.identity.vendor_id, obs.identity.code)].append(obs)
        if obs.disposition == Disposition.UNKNOWN_OPTIONAL:
            unknown_optional.append(obs)
        elif obs.disposition == Disposition.UNKNOWN_MANDATORY:
            unknown_mandatory.append(obs)
        # recurse only into grouped AVPs we actually understand; an unknown
        # grouped AVP is opaque and is treated per its M-bit
        stop = False
        if cap is not None and cap.grouped:
            try:
                nested, nerr, _ndup, nopt, nman = _walk_level(
                    obs.data, registry, obs.path,
                    depth_offset + obs.header_length, deep_scan)
            except ReviewError as exc:
                errors.append({
                    'path': ' / '.join(exc.path),
                    'code': StructuralError.MALFORMED_GROUPED,
                    'detail': exc.detail,
                    })
                # the grouped content cannot be walked further; everything
                # parsed before the failure is still retained on `obs`
                stop = True
            else:
                obs.nested = nested
                errors.extend(nerr)
                unknown_optional.extend(nopt)
                unknown_mandatory.extend(nman)
        elif cap is None and deep_scan:
            # optional diagnostic only: attempt a structural walk without
            # granting any comprehension credit
            try:
                nested, nerr, _ndup, nopt, nman = _walk_level(
                    obs.data, registry, obs.path + ['<deep-scan>'],
                    depth_offset + obs.header_length, False)
                obs.nested = nested
                errors.extend(nerr)
                unknown_optional.extend(nopt)
                unknown_mandatory.extend(nman)
            except ReviewError:
                obs.nested = []
        observations.append(obs)
        offset = next_offset
        if stop:
            break
    duplicates: List[Dict[str, object]] = []
    for (vendor_id, code), siblings in seen.items():
        if len(siblings) > 1:
            for sibling in siblings:
                sibling.same_identity_count = len(siblings)
            duplicates.append({
                'identity': str(AVPIdentity(code, vendor_id)),
                'count': len(siblings),
                'path': ' / '.join(parent_path) or '<message>',
                })
    return (observations, errors, duplicates,
            unknown_optional, unknown_mandatory)


#------------------------------------------------------------------------------#
# message-level review
#------------------------------------------------------------------------------#

def _parse_header(msg: bytes) -> Dict[str, int]:
    if len(msg) < DIAMETER_HDR_LEN:
        raise ReviewError(
            StructuralError.TRUNCATED_MESSAGE,
            'only %d bytes, need a 20-byte Diameter header' % len(msg),
            [], 0)
    version = msg[0]
    if version != 1:
        raise ReviewError(
            StructuralError.BAD_VERSION,
            'Diameter Version field is %d, expected 1' % version, [], 0)
    length = _u24(msg, 1)
    if length < DIAMETER_HDR_LEN or length > len(msg):
        raise ReviewError(
            StructuralError.BAD_MESSAGE_LENGTH,
            'message Length field is %d, buffer holds %d bytes'
            % (length, len(msg)), [], 1)
    # flags live in the last byte of the 32-bit Version/Length word
    flags = msg[4]
    return {
        'version': version,
        'length': length,
        'R': (flags >> 7) & 1,
        'P': (flags >> 6) & 1,
        'E': (flags >> 5) & 1,
        'T': (flags >> 4) & 1,
        'cmd': _u24(msg, 5) & 0x00FFFFFF,
        'app_id': _u32(msg, 8),
        'hop_by_hop': _u32(msg, 12),
        'end_to_end': _u32(msg, 16),
        }


def review_message(msg: bytes, registry: Optional[CapRegistry] = None,
                   deep_scan: bool = False) -> ReviewResult:
    """Review a raw Diameter message offline and report comprehension.

    The message bytes are never modified and never sent anywhere.  pycrate
    first performs the structural decode; the capability registry then decides
    which AVPs the reviewing node actually understands, recursively inside
    grouped AVPs.
    """

    if registry is None:
        registry = default_registry()
    original = bytes(msg)
    structural_errors: List[Dict[str, str]] = []
    try:
        header = _parse_header(original)
    except ReviewError as exc:
        return ReviewResult(
            Verdict.NOT_UNDERSTOOD, original, {},
            'not attempted', [],
            [{'path': ' / '.join(exc.path) or '<message>',
              'code': exc.code, 'detail': exc.detail}],
            [], [], [], False)
    body = original[DIAMETER_HDR_LEN: header['length']]
    # layer 1: pycrate structural decoding.  This only proves that length
    # fields make the message walkable; it proves nothing about comprehension.
    decoder = DiameterGeneric()
    try:
        decoder.from_bytes(original[: header['length']])
        pycrate_status = 'ok (length fields allow a structural walk)'
    except PycrateErr as exc:
        pycrate_status = 'failed: %s' % exc
        structural_errors.append({
            'path': '<message>',
            'code': StructuralError.PYCRATE_DECODE_ERROR,
            'detail': str(exc),
            })
    # layer 2: capability review over the same original bytes
    observations: List[AVPObservation] = []
    duplicates: List[Dict[str, object]] = []
    unknown_optional: List[AVPObservation] = []
    unknown_mandatory: List[AVPObservation] = []
    try:
        observations, errors, duplicates, unknown_optional, \
            unknown_mandatory = _walk_level(
                body, registry, [], DIAMETER_HDR_LEN, deep_scan)
        structural_errors.extend(errors)
    except ReviewError as exc:
        structural_errors.append({
            'path': ' / '.join(exc.path) or '<message>',
            'code': exc.code,
            'detail': exc.detail,
            })
    body_consumed = not structural_errors and sum(
        obs.wire_length for obs in observations) == len(body)
    if structural_errors or unknown_mandatory:
        verdict = Verdict.NOT_UNDERSTOOD
    elif unknown_optional:
        verdict = Verdict.PARTIALLY_UNDERSTOOD
    else:
        verdict = Verdict.FULLY_UNDERSTOOD
    return ReviewResult(
        verdict, original, header, pycrate_status, observations,
        structural_errors, duplicates, unknown_optional,
        unknown_mandatory, body_consumed)


#------------------------------------------------------------------------------#
# offline message builders (used by tests and by the demonstration script)
#------------------------------------------------------------------------------#

def build_avp(code, data, vendor_id=VENDOR_IETF, m=0, p=0,
              padding_byte=b'\x00') -> bytes:
    """Serialize one AVP with RFC 6733 32-bit alignment padding."""

    if not isinstance(data, (bytes, bytearray)):
        raise TypeError('AVP data must be bytes')
    flag_v = 1 if vendor_id != VENDOR_IETF else 0
    header_len = AVP_HDR_LEN_V if flag_v else AVP_HDR_LEN
    declared = header_len + len(data)
    flags = ((flag_v & 1) << 7) | ((m & 1) << 6) | ((p & 1) << 5)
    out = bytearray()
    out += code.to_bytes(4, 'big')
    out.append(flags)
    out += declared.to_bytes(3, 'big')
    if flag_v:
        out += vendor_id.to_bytes(4, 'big')
    out += bytes(data)
    padding = (-declared) % 4
    if padding:
        out += padding_byte * padding
    return bytes(out)


def build_message(cmd, avps, app_id=0, r=1, p=0, e=0, t=0,
                  hop_by_hop=0x11223344, end_to_end=0x55667788) -> bytes:
    """Serialize a Diameter message with the given list of raw AVPs."""

    body = b''.join(avps)
    length = DIAMETER_HDR_LEN + len(body)
    flags = ((r & 1) << 7) | ((p & 1) << 6) | ((e & 1) << 5) | ((t & 1) << 4)
    header = bytearray()
    header.append(1)
    header += length.to_bytes(3, 'big')
    header.append(flags)
    header += (cmd & 0x00FFFFFF).to_bytes(3, 'big')
    header += app_id.to_bytes(4, 'big')
    header += hop_by_hop.to_bytes(4, 'big')
    header += end_to_end.to_bytes(4, 'big')
    return bytes(header) + body
