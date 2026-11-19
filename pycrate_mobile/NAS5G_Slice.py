# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.1
# *
# * Copyright 2026. P1Sec.
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
# * File Name : pycrate_mobile/NAS5G_Slice.py
# * Created : 2026-11-19
# * Authors : P1Sec
# *--------------------------------------------------------
#*/

"""Evidence model and limited policy checks for 5G NAS network slices.

This module interprets S-NSSAI values as they appear in observed 5GMM
messages (TS 24.501).  It deliberately does not treat a decoded value as an
authorization: every statement carries the message and IE path that produced
it, and only an Allowed NSSAI received in a completed registration procedure
can establish a local authorization.

Design rules, from TS 24.501 9.11.2.8:

* an S-NSSAI is 1, 2, 4, 5, 6, 7 or 8 octets long in an NSSAI IE;
* SST is mandatory, SD is optional (0 or 3 octets);
* a missing SD is NOT the same identity as an explicit SD of 0;
* the mapped home S-NSSAI is a separate tuple and never replaces the
  serving/visited identity;
* a value whose length or field layout cannot be represented exactly is kept
  unknown rather than normalised to a shorter or wider identity.

Public entry points:

* ``decode_snssai`` / ``SNSSAIEvidence``: canonical single identity;
* ``SNSliceProcedure``: one observed registration/configuration procedure;
* ``SNSliceAnalyzer``: consumes messages in observation order and builds a
  ``SNSliceManifest``;
* ``SNSliceManifest``: requests, network claims, rejections and confirmed
  local authorizations with their exact provenance.
"""

from binascii import hexlify

from pycrate_core.elt    import Element
from pycrate_core.utils  import PycrateErr, bytes_types

from .NAS             import parse_NAS5G
from .TS24501_IE      import SNSSAI, FGSTAI


__all__ = [
    'SNSSAIEvidence',
    'SNSliceItem',
    'SNSliceObservation',
    'SNSliceProcedure',
    'SNSliceManifest',
    'SNSliceAnalyzer',
    'SNSlicePolicyError',
    'decode_snssai',
    'decode_nssai',
    'decode_rejected_nssai',
    'decode_ext_rejected_nssai',
    'extract_slice_fields',
    'analyze_nas_messages',
    'REGISTRATION_REQUEST_TYPES',
    ]


#------------------------------------------------------------------------------#
# Constants
#------------------------------------------------------------------------------#

# 5GS registration type values (TS 24.501 9.11.3.7)
REGISTRATION_REQUEST_TYPES = {
    1 : 'initial registration',
    2 : 'mobility registration updating',
    3 : 'periodic registration updating',
    4 : 'emergency registration',
    5 : 'reserved',
    6 : 'reserved',
    7 : 'reserved',
    }

_MSG_REG_REQUEST      = '5GMMRegistrationRequest'
_MSG_REG_ACCEPT       = '5GMMRegistrationAccept'
_MSG_REG_COMPLETE     = '5GMMRegistrationComplete'
_MSG_REG_REJECT       = '5GMMRegistrationReject'
_MSG_CONFIG_CMD       = '5GMMConfigurationUpdateCommand'
_MSG_CONFIG_COMPLETE  = '5GMMConfigurationUpdateComplete'
_MSG_MT_DEREG_REQUEST = '5GMMMTDeregistrationRequest'
_MSG_UL_TRANSPORT     = '5GMMULNASTransport'
_MSG_DL_TRANSPORT     = '5GMMDLNASTransport'
_MSG_SEC_PROT         = '5GMMSecProtNASMessage'

# S-NSSAI is 1, 2, 4, 5, 6, 7 or 8 octets in an NSSAI IE (TS 24.501 9.11.2.8).
# Only 1, 4, 5 and 8 give a complete serving or home identity.  2, 6 and 7
# are retained as exact raw bytes but are not accepted as an exact identity.
_VALID_SNSSAI_LENGTHS = frozenset((1, 2, 4, 5, 6, 7, 8))

_REJECTED_CAUSES = {
    0 : 'S-NSSAI not available in the current PLMN or SNPN',
    1 : 'S-NSSAI not available in the current registration area',
    2 : 'network slice specific authentication and authorization pending',
    }

# Message classes that may be embedded in a NAS container.  Importing the
# dispatcher tables lazily keeps this module usable on its own.
_MESSAGE_CLASS_NAMES = None


def _message_class_names():
    global _MESSAGE_CLASS_NAMES
    if _MESSAGE_CLASS_NAMES is None:
        names = {
            _MSG_REG_REQUEST, _MSG_REG_ACCEPT, _MSG_REG_COMPLETE,
            _MSG_REG_REJECT, _MSG_CONFIG_CMD, _MSG_CONFIG_COMPLETE,
            _MSG_MT_DEREG_REQUEST, _MSG_UL_TRANSPORT, _MSG_DL_TRANSPORT,
            '5GMMMODeregistrationRequest', '5GMMMODeregistrationAccept',
            '5GMMMTDeregistrationAccept', '5GMMServiceRequest',
            '5GMMServiceAccept', '5GMMServiceReject',
            '5GMMControlPlaneServiceRequest', '5GMMStatus',
            '5GMMNotification', '5GMMNotificationResponse',
            '5GMMAuthenticationRequest', '5GMMAuthenticationResponse',
            '5GMMAuthenticationResult', '5GMMAuthenticationReject',
            '5GMMIdentityRequest', '5GMMIdentityResponse',
            '5GMMSecurityModeCommand', '5GMMSecurityModeComplete',
            '5GMMSecurityModeReject',
            '5GMMNetworkSliceSpecAuthCommand',
            '5GMMNetworkSliceSpecAuthComplete',
            '5GMMNetworkSliceSpecAuthResult',
            '5GSMPDUSessionEstabRequest', '5GSMPDUSessionEstabAccept',
            '5GSMPDUSessionEstabReject',
            '5GSMPDUSessionModificationRequest',
            '5GSMPDUSessionModificationCommand',
            '5GSMPDUSessionModificationComplete',
            '5GSMPDUSessionModificationReject',
            '5GSMPDUSessionModificationCommandReject',
            '5GSMPDUSessionReleaseRequest', '5GSMPDUSessionReleaseReject',
            '5GSMPDUSessionReleaseCommand', '5GSMPDUSessionReleaseComplete',
            '5GSMStatus',
            }
        _MESSAGE_CLASS_NAMES = names
    return _MESSAGE_CLASS_NAMES


class SNSlicePolicyError(PycrateErr):
    """Raised when a policy rule would accept an unknown slice identity."""


#------------------------------------------------------------------------------#
# S-NSSAI evidence
#------------------------------------------------------------------------------#

def _bytes_to_uint(buf):
    val = 0
    for octet in buf:
        val = (val << 8) | octet
    return val


def _hex(raw):
    return hexlify(raw).decode('ascii') if raw is not None else None


class SNSSAIEvidence(object):
    """Canonical evidence for one S-NSSAI.

    Attributes:
        sst: integer, or None when the value is unknown
        sd: integer for a present 3-octet SD, None when the SD is absent
        sd_present: True only when a 3-octet SD has been decoded
        mapped_sst: integer for a mapped home SST, or None
        mapped_sd: integer for a complete mapped home SD, or None
        mapped_sd_present: True only when the mapped SD is complete
        raw: exact bytes of this S-NSSAI
        length: len(raw)
        valid: True when the exact shape is a complete TS 24.501 form
        unknown: list of human-readable reasons part of it is not usable
    """

    __slots__ = (
        'sst', 'sd', 'sd_present', 'mapped_sst', 'mapped_sd',
        'mapped_sd_present', 'raw', 'length', 'valid', 'unknown',
        )

    def __init__(self, raw, sst=None, sd=None, sd_present=False,
                 mapped_sst=None, mapped_sd=None, mapped_sd_present=False,
                 valid=False, unknown=None):
        self.raw = bytes(raw)
        self.length = len(self.raw)
        self.sst = sst
        self.sd = sd
        self.sd_present = sd_present
        self.mapped_sst = mapped_sst
        self.mapped_sd = mapped_sd
        self.mapped_sd_present = mapped_sd_present
        self.valid = valid
        self.unknown = list(unknown or ())

    #--------------------------------------------------------------------------#
    # identity
    #--------------------------------------------------------------------------#

    @property
    def identity(self):
        """Exact serving/visited (SST, SD) tuple, or None when unknown.

        SD is None when absent and 0 when explicitly encoded as 000000.
        """
        if not self.valid or self.sst is None:
            return None
        return (self.sst, self.sd)

    @property
    def mapped_identity(self):
        """Mapped home (SST, SD) tuple, or None when not present.

        An incomplete mapped SD is reported as (SST, None) but the evidence is
        kept invalid, so it can never be used as an exact home match.
        """
        if self.mapped_sst is None:
            return None
        return (self.mapped_sst, self.mapped_sd if self.mapped_sd_present else None)

    def canonical_key(self):
        """Hashable exact identity: SST, SD presence/value and mapping."""
        return (
            self.sst,
            self.sd_present,
            self.sd,
            self.mapped_sst,
            self.mapped_sd_present,
            self.mapped_sd,
            self.raw,
            )

    def __eq__(self, other):
        if not isinstance(other, SNSSAIEvidence):
            return NotImplemented
        return (self.valid == other.valid
                and self.canonical_key() == other.canonical_key())

    def __ne__(self, other):
        eq = self.__eq__(other)
        return eq if eq is NotImplemented else not eq

    def __hash__(self):
        return hash((self.valid, self.canonical_key()))

    def same_serving_slice(self, other):
        """True when both values denote the same serving/visited slice."""
        if not isinstance(other, SNSSAIEvidence):
            return False
        return (self.valid and other.valid
                and self.identity is not None
                and self.identity == other.identity)

    def same_home_slice(self, other):
        """True when both values denote the same mapped home slice."""
        if not isinstance(other, SNSSAIEvidence):
            return False
        return (self.valid and other.valid
                and self.mapped_identity is not None
                and self.mapped_identity == other.mapped_identity)

    #--------------------------------------------------------------------------#
    # presentation
    #--------------------------------------------------------------------------#

    def format_sd(self):
        if not self.sd_present:
            return 'absent'
        return '0x%06x' % self.sd

    def format_mapped(self):
        if self.mapped_sst is None:
            return 'absent'
        if self.mapped_sd_present:
            return '%d/0x%06x' % (self.mapped_sst, self.mapped_sd)
        return '%d/absent' % self.mapped_sst

    def describe(self):
        """Human-readable exact identity, including non-identity details."""
        if self.sst is None:
            return 'unknown(0x%s)' % hexlify(self.raw).decode('ascii')
        txt = 'SST=%d, SD=%s' % (self.sst, self.format_sd())
        if self.mapped_sst is not None:
            txt += ', mapped=%s' % self.format_mapped()
        return txt

    def __repr__(self):
        return '<SNSSAIEvidence %s>' % self.describe()

    def to_dict(self):
        """JSON-friendly manifest entry. Raw bytes are hex-encoded."""
        return {
            'sst'              : self.sst,
            'sd'               : self.sd,
            'sd_present'       : self.sd_present,
            'mapped_sst'       : self.mapped_sst,
            'mapped_sd'        : self.mapped_sd,
            'mapped_sd_present': self.mapped_sd_present,
            'raw'              : _hex(self.raw),
            'length'           : self.length,
            'valid'            : self.valid,
            'identity'         : self.identity,
            'mapped_identity'  : self.mapped_identity,
            'description'      : self.describe(),
            'unknown'          : list(self.unknown),
            }


def decode_snssai(raw):
    """Build SNSSAIEvidence from the exact bytes of one S-NSSAI.

    Args:
        raw: bytes of the S-NSSAI value, excluding any NSSAI length octet

    Returns:
        SNSSAIEvidence
    """
    if not isinstance(raw, bytes_types):
        raise(SNSlicePolicyError('S-NSSAI: bytes are expected'))
    raw = bytes(raw)
    if len(raw) not in _VALID_SNSSAI_LENGTHS:
        return SNSSAIEvidence(
            raw, sst=raw[0] if raw else None, valid=False,
            unknown=['invalid S-NSSAI length %d octets' % len(raw)])

    if len(raw) in (1, 4, 5, 8):
        try:
            snssai = SNSSAI()
            snssai.from_bytes(raw)
        except Exception:
            return SNSSAIEvidence(
                raw, sst=raw[0], valid=False,
                unknown=['pycrate cannot decode this S-NSSAI shape'])
        ev = SNSSAIEvidence(raw)
        ev.sst = snssai['SST'].get_val()
        if not snssai['SD'].get_trans():
            ev.sd = snssai['SD'].get_val()
            ev.sd_present = True
        if not snssai['MappedHPLMNSST'].get_trans():
            ev.mapped_sst = snssai['MappedHPLMNSST'].get_val()
        if not snssai['MappedHPLMNSD'].get_trans():
            ev.mapped_sd = snssai['MappedHPLMNSD'].get_val()
            ev.mapped_sd_present = True
        ev.valid = True
        return ev

    # Length 2: SST + one octet.  pycrate currently decodes 16-bit values as
    # SST + MappedHPLMNSST, which is not a valid home mapping.  Keep it exact
    # and never manufacture a 3-octet SD.
    if len(raw) == 2:
        return SNSSAIEvidence(
            raw, sst=raw[0], valid=False,
            unknown=['2-octet S-NSSAI: partial SD is not an exact identity'])

    # Length 6/7: partial mapped SD.  Keep the serving SST/SD exact, but the
    # home identity is incomplete and must not be used for a home match.
    ev = SNSSAIEvidence(
        raw, sst=raw[0], sd=_bytes_to_uint(raw[1:4]), sd_present=True,
        mapped_sst=raw[4], valid=False,
        unknown=['partial mapped SD (%d octets) is not an exact home identity'
                 % (len(raw) - 5)])
    return ev


#------------------------------------------------------------------------------#
# NSSAI and Rejected NSSAI decoding
#------------------------------------------------------------------------------#

def _element_value_bytes(ie):
    """Return the exact V bytes of a Type4TLV/Type3TV IE, or None."""
    if ie is None or ie.get_trans():
        return None
    try:
        if ie[-1]._name != 'V':
            return ie[-1].to_bytes()
    except Exception:
        pass
    try:
        return ie['V'].to_bytes()
    except Exception:
        pass
    try:
        val = ie[-1].get_val()
        if isinstance(val, bytes_types):
            return bytes(val)
    except Exception:
        pass
    return None


def _snssai_value_bytes(ie):
    """Return the exact S-NSSAI bytes from a Type4TLV carrying one SNSSAI."""
    if ie is None or ie.get_trans():
        return None
    try:
        if ie[-1]._name == 'SNSSAI':
            return ie[-1].to_bytes()
    except Exception:
        pass
    return _element_value_bytes(ie)


def _nssai_value_bytes(ie):
    """Return the exact V bytes of a NSSAI Type4TLV, or None."""
    if ie is None or ie.get_trans():
        return None
    try:
        if ie[-1].__class__.__name__ == 'NSSAI':
            return ie[-1].to_bytes()
    except Exception:
        pass
    return _element_value_bytes(ie)


def _rejected_value_bytes(ie):
    """Return the exact V bytes of a Rejected NSSAI Type4TLV, or None."""
    if ie is None or ie.get_trans():
        return None
    try:
        if ie[-1].__class__.__name__ in ('RejectedNSSAI', 'ExtRejectedNSSAI'):
            return ie[-1].to_bytes()
    except Exception:
        pass
    return _element_value_bytes(ie)


def _decode_nssai_raw(raw):
    """Strict manual NSSAI TLV walk, preserving every length and truncation."""
    out, issues = [], []
    off = 0
    while off < len(raw):
        length = raw[off]
        off += 1
        if length == 0:
            issues.append('zero-length S-NSSAI at offset %d' % (off - 1))
            out.append(SNSSAIEvidence(b'', valid=False,
                                      unknown=['zero-length S-NSSAI']))
            continue
        if off + length > len(raw):
            issues.append('truncated S-NSSAI: length %d exceeds remaining '
                          '%d bytes' % (length, len(raw) - off))
            out.append(SNSSAIEvidence(raw[off:], valid=False,
                                      unknown=['truncated S-NSSAI']))
            break
        body = raw[off:off + length]
        off += length
        ev = decode_snssai(body)
        if not ev.valid:
            issues.extend(ev.unknown)
        out.append(ev)
    return out, issues


def decode_nssai(value):
    """Decode a NSSAI (or Allowed/Configured/Pending/Mapped NSSAI) value.

    Args:
        value: the V part of the IE, either bytes or an already decoded
               pycrate element

    Returns:
        (list of SNSSAIEvidence, list of decode issues)
    """
    if isinstance(value, Element):
        raw = _nssai_value_bytes(value)
        if raw is None:
            return [], ['unable to extract the NSSAI value']
    else:
        raw = bytes(value)
    if not raw:
        return [], []
    return _decode_nssai_raw(raw)


def decode_rejected_nssai(value):
    """Decode a Rejected NSSAI value into (evidence, cause) entries.

    Args:
        value: V bytes of a Rejected NSSAI IE, or a decoded pycrate element

    Returns:
        (list of (SNSSAIEvidence, cause_int), list of issues)
    """
    if isinstance(value, Element):
        raw = _rejected_value_bytes(value)
        if raw is None:
            return [], ['unable to extract the Rejected NSSAI value']
    else:
        raw = bytes(value)
    out, issues = [], []
    off = 0
    while off < len(raw):
        # TS 24.501 9.11.3.46: one nibble length, one nibble cause
        head = raw[off]
        off += 1
        length = head >> 4
        cause = head & 0xf
        if length == 0:
            issues.append('zero-length rejected S-NSSAI at offset %d' % (off - 1))
            out.append((SNSSAIEvidence(b'', valid=False,
                                       unknown=['zero-length rejected S-NSSAI']),
                        cause))
            continue
        if off + length > len(raw):
            issues.append('truncated rejected S-NSSAI: length %d exceeds '
                          'remaining %d bytes' % (length, len(raw) - off))
            out.append((SNSSAIEvidence(raw[off:], valid=False,
                                       unknown=['truncated rejected S-NSSAI']),
                        cause))
            break
        body = raw[off:off + length]
        off += length
        ev = decode_snssai(body)
        if not ev.valid:
            issues.extend(ev.unknown)
        out.append((ev, cause))
    return out, issues


def decode_ext_rejected_nssai(value):
    """Decode an Extended Rejected NSSAI value into (evidence, cause) entries.

    TS 24.501 9.11.3.75.  The value starts with one octet:
        spare(1) | Type(3) | Num(4)
    A BackOffTimer is present when Type == 1, then Num+1 Rejected NSSAI
    entries follow.  The module only needs the entries; the timer is
    retained as raw bits in the evidence provenance by the caller.

    Args:
        value: V bytes of the Extended Rejected NSSAI IE

    Returns:
        (list of (SNSSAIEvidence, cause_int), list of issues)
    """
    raw = bytes(value)
    if len(raw) < 2:
        return [], ['truncated extended rejected NSSAI header']
    head = raw[0]
    typ = (head >> 4) & 0x7
    num = head & 0xf
    off = 1
    if typ == 1:
        if len(raw) < off + 1:
            return [], ['truncated extended rejected NSSAI back-off timer']
        off += 1
    out, issues = [], []
    count = num + 1
    for _ in range(count):
        if off >= len(raw):
            issues.append('extended rejected NSSAI ends before all entries')
            break
        h = raw[off]
        off += 1
        length = h >> 4
        cause = h & 0xf
        if length == 0 or off + length > len(raw):
            issues.append('truncated extended rejected S-NSSAI')
            out.append((SNSSAIEvidence(raw[off:], valid=False,
                                       unknown=['truncated extended rejected '
                                                'S-NSSAI']), cause))
            break
        body = raw[off:off + length]
        off += length
        ev = decode_snssai(body)
        if not ev.valid:
            issues.extend(ev.unknown)
        out.append((ev, cause))
    return out, issues


def extract_slice_fields(msg):
    """Extract all slice-bearing fields from one decoded 5GMM message.

    Returns:
        dict mapping field names to ``(entries, issues)`` where entries are
        SNSSAIEvidence (or (evidence, cause) for RejectedNSSAI).
    """
    result = {}
    for field in ('NSSAI', 'AllowedNSSAI', 'ConfiguredNSSAI',
                  'PendingNSSAI', 'MappedNSSAI'):
        ie = _child(msg, field)
        if ie is not None and not ie.get_trans():
            result[field] = decode_nssai(ie)
    ie = _child(msg, 'RejectedNSSAI')
    if ie is not None and not ie.get_trans():
        result['RejectedNSSAI'] = decode_rejected_nssai(ie)
    ie = _child(msg, 'ExtRejectedNSSAI')
    if ie is not None and not ie.get_trans():
        raw = _element_value_bytes(ie)
        if raw is None:
            result['ExtRejectedNSSAI'] = ([], ['unable to extract the '
                                               'Extended Rejected NSSAI value'])
        else:
            result['ExtRejectedNSSAI'] = decode_ext_rejected_nssai(raw)
    ie = _child(msg, 'SNSSAI')
    if ie is not None and not ie.get_trans():
        raw = _snssai_value_bytes(ie)
        if raw is None:
            result['SNSSAI'] = ([], ['unable to extract the SNSSAI value'])
        else:
            ev = decode_snssai(raw)
            result['SNSSAI'] = ([ev], [] if ev.valid else list(ev.unknown))
    return result


def _child(env, name):
    try:
        if name in env._by_name:
            return env[name]
    except Exception:
        pass
    return None


def _raw_bytes(elt):
    try:
        return elt.to_bytes()
    except Exception:
        return b''


def _message_type(elt):
    head = _child(elt, '5GMMHeader') or _child(elt, '5GMMHeaderSec')
    if head is not None:
        typ = _child(head, 'Type')
        if typ is not None:
            try:
                return typ.get_val()
            except Exception:
                pass
    return None


def _message_plmn(msg):
    """Extract a serving PLMN from TAI/TAI-list IEs, when present."""
    for name in ('TAI', '5GSTAIList'):
        ie = _child(msg, name)
        if ie is None or ie.get_trans():
            continue
        raw = _element_value_bytes(ie)
        if raw is None:
            continue
        try:
            if name == 'TAI':
                tai = FGSTAI()
                tai.from_bytes(raw)
                return tai.decode()[0]
            from .TS24501_IE import FGSTAIList
            tais = FGSTAIList()
            tais.from_bytes(raw)
            values = sorted(tais.get_tai())
            if values:
                return values[0][0]
        except Exception:
            continue
    return None


def _message_registration_type(msg):
    ie = _child(msg, '5GSRegType')
    if ie is None or ie.get_trans():
        return None
    try:
        return ie['V'].get_val()
    except Exception:
        return None


def _registration_type_name(value):
    if value is None:
        return None
    return REGISTRATION_REQUEST_TYPES.get(value, 'type %s' % value)


#------------------------------------------------------------------------------#
# Observations and procedures
#------------------------------------------------------------------------------#

_STATUS_UNKNOWN = 'unknown'
_STATUS_UNCONFIRMED = 'network_claim'
_STATUS_CONFIRMED = 'authorized'
_STATUS_REJECTED = 'rejected'
_STATUS_SUPERSEDED = 'superseded'
_STATUS_CONFLICT = 'conflict'
_STATUS_CLAIM = 'configuration_claim'


class SNSliceItem(object):
    """One S-NSSAI entry with its container and message provenance.

    ``kind`` is one of 'requested', 'allowed', 'rejected', 'configured',
    'pending', 'mapped', 'serving'.  ``status`` distinguishes a network
    declaration from a locally confirmed authorization.
    """

    __slots__ = (
        'index', 'kind', 'evidence', 'message_index', 'message_name',
        'field', 'entry_index', 'registration_index', 'secured', 'nested_in',
        'cause', 'status',
        )

    def __init__(self, index, kind, evidence, message_index, message_name,
                 field, entry_index, registration_index=None, secured=False,
                 nested_in=None, cause=None, status=_STATUS_UNKNOWN):
        self.index = index
        self.kind = kind
        self.evidence = evidence
        self.message_index = message_index
        self.message_name = message_name
        self.field = field
        self.entry_index = entry_index
        self.registration_index = registration_index
        self.secured = secured
        self.nested_in = nested_in
        self.cause = cause
        self.status = status

    @property
    def identity(self):
        return self.evidence.identity

    def to_dict(self):
        return {
            'index'             : self.index,
            'kind'              : self.kind,
            'status'            : self.status,
            'identity'          : self.identity,
            'evidence'          : self.evidence.to_dict(),
            'message_index'     : self.message_index,
            'message_name'      : self.message_name,
            'field'             : self.field,
            'entry_index'       : self.entry_index,
            'registration_index': self.registration_index,
            'secured'           : self.secured,
            'nested_in'         : self.nested_in,
            'cause'             : self.cause,
            'cause_text'        : _REJECTED_CAUSES.get(self.cause)
                                  if self.cause is not None else None,
            }

    def __repr__(self):
        return '<SNSliceItem %s %s from message %s (%s)>' % (
            self.kind, self.evidence.describe(),
            self.message_name, self.message_index)


class SNSliceObservation(object):
    """One NSSAI-bearing field found in one observed message."""

    __slots__ = (
        'index', 'message_index', 'message_name', 'message_type',
        'direction', 'field', 'role', 'value', 'entries', 'issues',
        'secured', 'nested_in', 'procedure', 'security_context',
        )

    def __init__(self, index, message_index, message_name, message_type,
                 direction, field, role, value, entries, issues,
                 secured=False, nested_in=None, procedure=None,
                 security_context=None):
        self.index = index
        self.message_index = message_index
        self.message_name = message_name
        self.message_type = message_type
        self.direction = direction
        self.field = field
        self.role = role
        self.value = value
        self.entries = entries
        self.issues = list(issues)
        self.secured = secured
        self.nested_in = nested_in
        self.procedure = procedure
        self.security_context = security_context

    def to_dict(self):
        return {
            'index'             : self.index,
            'message_index'     : self.message_index,
            'message_name'      : self.message_name,
            'message_type'      : self.message_type,
            'direction'         : self.direction,
            'field'             : self.field,
            'role'              : self.role,
            'value'             : _hex(self.value),
            'entries'           : [e.to_dict() for e in self.entries],
            'issues'            : list(self.issues),
            'secured'           : self.secured,
            'security_context'  : self.security_context,
            'nested_in'         : self.nested_in,
            'procedure'         : self.procedure,
            }

    def __repr__(self):
        return '<SNSliceObservation %s %s>' % (self.message_name, self.field)


class SNSliceProcedure(object):
    """One registration (or configuration-update) procedure."""

    __slots__ = (
        'index', 'kind', 'registration_type', 'state', 'direction',
        'request_indices', 'accept_indices', 'complete_indices',
        'reject_indices', 'config_indices', 'config_complete_indices',
        'requested', 'allowed_claims', 'allowed_confirmed', 'rejected',
        'configured', 'pending', 'mapped', 'serving', 'unknown',
        'serving_plmn', 'home_plmn', 'messages', 'security_context',
        )

    def __init__(self, index, kind='registration'):
        self.index = index
        self.kind = kind
        self.registration_type = None
        self.state = 'open'
        self.direction = None
        self.request_indices = []
        self.accept_indices = []
        self.complete_indices = []
        self.reject_indices = []
        self.config_indices = []
        self.config_complete_indices = []
        self.requested = []
        self.allowed_claims = []
        self.allowed_confirmed = []
        self.rejected = []
        self.configured = []
        self.pending = []
        self.mapped = []
        self.serving = []
        self.unknown = []
        self.serving_plmn = None
        self.home_plmn = None
        self.messages = []
        self.security_context = None

    @property
    def confirmed(self):
        return self.state == 'confirmed'

    def get_mapped(self, identity):
        """Return mapped home items paired with a serving identity.

        The Mapped NSSAI observed in a Registration Request is parallel to
        the requested NSSAI.  Pairing is by entry index, never by a looser
        byte or substring comparison.
        """
        out = []
        for req in self.requested:
            if req.identity != identity:
                continue
            for mapped in self.mapped:
                if mapped.entry_index == req.entry_index:
                    out.append(mapped)
        return out

    def get_rejection(self, identity):
        for item in self.rejected:
            if item.identity == identity:
                return item
        return None

    def to_dict(self):
        return {
            'index'                  : self.index,
            'kind'                   : self.kind,
            'registration_type'      : self.registration_type,
            'state'                  : self.state,
            'direction'              : self.direction,
            'request_indices'        : list(self.request_indices),
            'accept_indices'         : list(self.accept_indices),
            'complete_indices'       : list(self.complete_indices),
            'reject_indices'         : list(self.reject_indices),
            'config_indices'         : list(self.config_indices),
            'config_complete_indices': list(self.config_complete_indices),
            'serving_plmn'           : self.serving_plmn,
            'home_plmn'              : self.home_plmn,
            'security_context'       : self.security_context,
            'requested'              : [i.to_dict() for i in self.requested],
            'allowed_claims'         : [i.to_dict() for i in self.allowed_claims],
            'allowed_confirmed'      : [i.to_dict() for i in self.allowed_confirmed],
            'rejected'               : [i.to_dict() for i in self.rejected],
            'configured'             : [i.to_dict() for i in self.configured],
            'pending'                : [i.to_dict() for i in self.pending],
            'mapped'                 : [i.to_dict() for i in self.mapped],
            'serving'                : [i.to_dict() for i in self.serving],
            'unknown'                : list(self.unknown),
            'messages'               : list(self.messages),
            }


class SNSliceManifest(object):
    """Complete evidence set built from observed 5GMM messages."""

    def __init__(self):
        self.observations = []
        self.procedures = []
        self.messages = []
        self.issues = []
        self.items = []
        self._item_index = 0

    #--------------------------------------------------------------------------#
    # internal helpers
    #--------------------------------------------------------------------------#

    def _add_message(self, name, typ, direction, raw, nested_in, index,
                     security_context=None):
        self.messages.append({
            'index'            : index,
            'name'             : name,
            'type'             : typ,
            'direction'        : direction,
            'raw'              : _hex(raw),
            'nested_in'        : nested_in,
            'security_context' : security_context,
            })
        return index

    def _add_procedure(self, proc):
        self.procedures.append(proc)
        return proc

    def _new_item(self, kind, evidence, message_index, message_name, field,
                  entry_index, registration_index=None, secured=False,
                  nested_in=None, cause=None, status=None):
        self._item_index += 1
        if status is None:
            status = _STATUS_UNKNOWN
        item = SNSliceItem(
            self._item_index, kind, evidence, message_index, message_name,
            field, entry_index, registration_index, secured, nested_in,
            cause, status)
        self.items.append(item)
        return item

    #--------------------------------------------------------------------------#
    # queries
    #--------------------------------------------------------------------------#

    def get_authorizations(self):
        """Return confirmed local authorization items."""
        return [i for i in self.items if i.status == _STATUS_CONFIRMED]

    def get_items(self, kind=None, status=None):
        out = list(self.items)
        if kind is not None:
            out = [i for i in out if i.kind == kind]
        if status is not None:
            out = [i for i in out if i.status == status]
        return out

    def get_requests(self):
        return self.get_items(kind='requested')

    def get_network_claims(self):
        """Allowed NSSAI declarations not backed by a completed procedure."""
        return [i for i in self.get_items(kind='allowed')
                if i.status in (_STATUS_UNCONFIRMED, _STATUS_CLAIM)]

    def get_rejections(self):
        return self.get_items(kind='rejected')

    def find(self, identity, kind=None, status=None):
        """Return all items matching an exact (SST, SD) identity."""
        return [i for i in self.get_items(kind=kind, status=status)
                if i.identity == identity]

    def is_authorized(self, identity, procedure_index=None):
        """True only when a confirmed item has this exact identity.

        A value merely present in a request, in a rejected list, in a
        configuration update or in an unconfirmed Allowed NSSAI is not an
        authorization.
        """
        _check_identity(identity)
        for item in self.items:
            if item.status != _STATUS_CONFIRMED or item.identity != identity:
                continue
            if procedure_index is None or \
                    item.registration_index == procedure_index:
                return True
        return False

    def check(self, identity, procedure_index=None):
        """Explain whether an exact identity is locally authorized."""
        _check_identity(identity)
        for item in self.items:
            if item.status == _STATUS_CONFIRMED and item.identity == identity:
                if procedure_index is None or \
                        item.registration_index == procedure_index:
                    return {
                        'allowed'           : True,
                        'reason'            : 'authorized',
                        'identity'          : identity,
                        'procedure_index'   : item.registration_index,
                        'message_index'     : item.message_index,
                        'message_name'      : item.message_name,
                        'field'             : item.field,
                        'secured'           : item.secured,
                        }
        candidates = [i for i in self.items if i.identity == identity]
        if procedure_index is not None:
            candidates = [i for i in candidates
                          if i.registration_index == procedure_index]
        for reason, kind, status in (
                ('rejected_in_procedure', 'rejected', None),
                ('superseded_authorization', 'allowed', _STATUS_SUPERSEDED),
                ('unconfirmed_allowed_claim', 'allowed', _STATUS_UNCONFIRMED),
                ('configuration_claim_only', 'allowed', None),
                ('requested_only', 'requested', None)):
            for item in candidates:
                if item.kind != kind:
                    continue
                if status is not None and item.status != status:
                    continue
                if kind == 'allowed' and item.status == _STATUS_CONFIRMED:
                    continue
                return {
                    'allowed'       : False,
                    'reason'        : reason,
                    'identity'      : identity,
                    'procedure_index': item.registration_index,
                    'message_index' : item.message_index,
                    'message_name'  : item.message_name,
                    'field'         : item.field,
                    }
        return {
            'allowed'   : False,
            'reason'    : 'not_authorized',
            'identity'  : identity,
            }

    #--------------------------------------------------------------------------#
    # presentation
    #--------------------------------------------------------------------------#

    def to_dict(self):
        return {
            'messages'      : list(self.messages),
            'observations'  : [o.to_dict() for o in self.observations],
            'procedures'    : [p.to_dict() for p in self.procedures],
            'items'         : [i.to_dict() for i in self.items],
            'authorizations': [i.to_dict() for i in self.get_authorizations()],
            'issues'        : list(self.issues),
            }

    def __repr__(self):
        return ('<SNSliceManifest %d messages, %d procedures, '
                '%d confirmed authorizations>') % (
            len(self.messages), len(self.procedures),
            len(self.get_authorizations()))

    def __str__(self):
        lines = [
            '5G NAS slice evidence manifest',
            '  messages: %d, procedures: %d, confirmed authorizations: %d' % (
                len(self.messages), len(self.procedures),
                len(self.get_authorizations())),
            ]
        if self.issues:
            lines.append('  issues:')
            lines.extend('    - %s' % i for i in self.issues)
        if not self.procedures:
            lines.append('  no registration procedure observed')
        for proc in self.procedures:
            lines.append('  procedure %d (%s, %s, state=%s)' % (
                proc.index, proc.kind, proc.registration_type, proc.state))
            if proc.serving_plmn:
                lines.append('    serving PLMN: %s' % proc.serving_plmn)
            if proc.home_plmn:
                lines.append('    home PLMN: %s' % proc.home_plmn)
            for label, items in (
                    ('requested:', proc.requested),
                    ('allowed claim:', proc.allowed_claims),
                    ('authorized:', proc.allowed_confirmed),
                    ('rejected:', proc.rejected),
                    ('configured:', proc.configured),
                    ('pending:', proc.pending),
                    ('mapped:', proc.mapped)):
                for item in items:
                    lines.append('    %-16s %s  [message %d %s]' % (
                        label, item.evidence.describe(),
                        item.message_index, item.message_name))
            for issue in proc.unknown:
                lines.append('    unknown:         %s' % issue)
        return '\n'.join(lines)


def _check_identity(identity):
    if not isinstance(identity, tuple) or len(identity) != 2:
        raise(SNSlicePolicyError(
            'slice identity must be a (SST, SD) tuple where SD is None when '
            'absent and 0 when explicitly zero'))
    sst, sd = identity
    if not isinstance(sst, int) or isinstance(sst, bool) \
            or not 0 <= sst <= 0xff:
        raise(SNSlicePolicyError(
            'slice identity SST must be an integer in 0..255, got %r' % (sst,)))
    if sd is not None and (not isinstance(sd, int) or isinstance(sd, bool)
                           or not 0 <= sd <= 0xffffff):
        raise(SNSlicePolicyError(
            'slice identity SD must be None or an integer in 0..0xffffff, '
            'got %r' % (sd,)))


#------------------------------------------------------------------------------#
# Analyzer
#------------------------------------------------------------------------------#

class SNSliceAnalyzer(object):
    """Consume observed NAS messages in order and build a slice manifest.

    Args:
        home_plmn: optional home PLMN string (e.g. '00101').  A home mapping
                   is only reported against this or a PLMN observed in the
                   same procedure; the module never guesses which observed
                   PLMN is the home one.
        require_complete: when True (default), an Allowed NSSAI becomes a
                   local authorization only after Registration Complete has
                   been observed.  When False, a Registration Accept alone is
                   enough.

    Usage:
        analyzer = SNSliceAnalyzer(home_plmn='00101')
        for direction, pdu in transcript:
            analyzer.add_message(pdu, direction=direction)
        manifest = analyzer.result()
    """

    def __init__(self, home_plmn=None, require_complete=True):
        self.home_plmn = home_plmn
        self.require_complete = require_complete
        self.manifest = SNSliceManifest()
        self._procedure = None          # current registration procedure
        self._config_procedure = None   # current configuration procedure
        self._message_index = 0
        self._observation_index = 0

    #--------------------------------------------------------------------------#
    # public API
    #--------------------------------------------------------------------------#

    def add_message(self, msg, direction=None, nested_in=None):
        """Add one already-decoded message or raw 5G NAS bytes.

        Args:
            msg: pycrate Element instance, or bytes to parse with parse_NAS5G
            direction: 'ul', 'dl' or None (kept as observed)
            nested_in: description of the enclosing message when the same
                       bytes were observed inside a NAS container

        Returns:
            the message index, or None when raw bytes could not be parsed
        """
        if isinstance(msg, (bytes, bytearray)):
            parsed, err = parse_NAS5G(bytes(msg))
            if err != 0 or parsed is None:
                self._message_index += 1
                self.manifest.issues.append(
                    'message %d: unable to parse 5G NAS (error %s)' % (
                        self._message_index, err))
                return None
            msg = parsed
        self._message_index += 1
        index = self._message_index
        name = getattr(msg, '_name', msg.__class__.__name__)
        typ = _message_type(msg)
        raw = _raw_bytes(msg)
        secured = name == _MSG_SEC_PROT or nested_in is not None
        self.manifest._add_message(
            name, typ, direction, raw, nested_in, index,
            security_context='protected' if secured else 'plain')
        self._process(msg, name, typ, direction, nested_in, index, secured)
        return index

    def add_messages(self, msgs, direction=None):
        """Add several messages in observation order."""
        for msg in msgs:
            self.add_message(msg, direction=direction)
        return self.manifest

    def add_bytes(self, buf, direction=None):
        """Parse and add raw bytes as one observed message."""
        return self.add_message(buf, direction=direction)

    def result(self):
        """Finalize open procedures and return the manifest."""
        self._finalize()
        return self.manifest

    #--------------------------------------------------------------------------#
    # procedures
    #--------------------------------------------------------------------------#

    def _new_procedure(self, kind='registration'):
        prev = self._procedure if kind == 'registration' else self._config_procedure
        if prev is not None and prev.state == 'open':
            prev.state = 'superseded'
            self.manifest.issues.append(
                'procedure %d: superseded by a new %s procedure'
                % (prev.index, kind))
        proc = SNSliceProcedure(len(self.manifest.procedures) + 1, kind)
        proc.home_plmn = self.home_plmn
        self.manifest._add_procedure(proc)
        if kind == 'registration':
            self._procedure = proc
        else:
            self._config_procedure = proc
        return proc

    def _ensure_registration(self, fresh=False):
        proc = self._procedure
        if fresh or proc is None or proc.state != 'open':
            return self._new_procedure('registration')
        return proc

    def _ensure_configuration(self):
        proc = self._config_procedure
        if proc is None or proc.state != 'open':
            return self._new_procedure('configuration')
        return proc

    def _supersede_authorizations(self):
        for item in self.manifest.items:
            if item.status == _STATUS_CONFIRMED:
                item.status = _STATUS_SUPERSEDED

    def _finalize(self):
        proc = self._procedure
        if proc is not None and proc.state == 'open':
            if proc.accept_indices and not proc.complete_indices:
                if self.require_complete:
                    proc.state = 'unconfirmed'
                else:
                    self._promote_claims(proc)
                    proc.state = 'confirmed'
            elif proc.reject_indices:
                proc.state = 'rejected'
            elif proc.request_indices:
                proc.state = 'unanswered'
        cfg = self._config_procedure
        if cfg is not None and cfg.state == 'open':
            cfg.state = 'observed' if cfg.config_complete_indices else 'unconfirmed'
        self._procedure = None
        self._config_procedure = None

    #--------------------------------------------------------------------------#
    # message dispatch
    #--------------------------------------------------------------------------#

    def _process(self, msg, name, typ, direction, nested_in, index, secured):
        if name == _MSG_SEC_PROT:
            # the security wrapper's inner NAS message has already been
            # decoded in-place by parse_NAS5G; process it without creating a
            # second message record for the same bytes.
            inner = self._inner_message(msg)
            if inner is not None:
                self._dispatch(inner, index, secured,
                               nested_in='%s message %d' % (name, index))
            return
        if name in (_MSG_UL_TRANSPORT, _MSG_DL_TRANSPORT):
            inner = self._inner_message(msg)
            if inner is not None:
                self._dispatch(inner, index, secured,
                               nested_in='%s message %d' % (name, index))
            self._extract_message(msg, name, typ, direction, index, secured,
                                  nested_in)
            return
        self._dispatch(msg, index, secured, nested_in)

    def _inner_message(self, msg):
        """Return the decoded inner NAS message from a container, if any."""
        names = _message_class_names()
        for cand in getattr(msg, '_content', ()):
            n = getattr(cand, '_name', '')
            if n in names:
                return cand
        for field in ('NASContainer', 'PayloadContainer'):
            cand = _child(msg, field)
            if cand is None:
                continue
            for sub in getattr(cand, '_content', ()):
                if getattr(sub, '_name', '') in names:
                    return sub
        return None

    def _dispatch(self, msg, message_index, secured, nested_in=None):
        name = getattr(msg, '_name', msg.__class__.__name__)
        typ = _message_type(msg)
        if name == _MSG_REG_REQUEST:
            self._on_registration_request(msg, name, typ, message_index, secured,
                                          nested_in)
        elif name == _MSG_REG_ACCEPT:
            self._on_registration_accept(msg, name, typ, message_index, secured,
                                         nested_in)
        elif name == _MSG_REG_COMPLETE:
            self._on_registration_complete(msg, name, message_index)
        elif name == _MSG_REG_REJECT:
            self._on_registration_reject(msg, name, typ, message_index, secured,
                                         nested_in)
        elif name == _MSG_CONFIG_CMD:
            self._on_configuration_update(msg, name, typ, message_index, secured,
                                          nested_in)
        elif name == _MSG_CONFIG_COMPLETE:
            self._on_configuration_complete(msg, name, message_index)
        elif name == _MSG_MT_DEREG_REQUEST:
            self._on_deregistration(msg, name, message_index)
        else:
            self._extract_message(msg, name, typ, None, message_index, secured,
                                  nested_in)

    #--------------------------------------------------------------------------#
    # procedure handlers
    #--------------------------------------------------------------------------#

    def _on_registration_request(self, msg, name, typ, message_index, secured,
                                 nested_in=None):
        # A new registration request starts a fresh procedure: any Allowed
        # NSSAI confirmed under an earlier procedure is no longer current,
        # even if the new request/accept has not been observed yet.
        self._supersede_authorizations()
        proc = self._new_procedure('registration')
        proc.request_indices.append(message_index)
        proc.messages.append(message_index)
        proc.security_context = 'protected' if secured else 'plain'
        reg_type = _message_registration_type(msg)
        proc.registration_type = _registration_type_name(reg_type)
        plmn = _message_plmn(msg)
        if plmn is not None:
            proc.serving_plmn = plmn
        self._extract_message(msg, name, typ, 'ul', message_index, secured,
                              nested_in, proc=proc)

    def _on_registration_accept(self, msg, name, typ, message_index, secured,
                                nested_in=None):
        # A Registration Accept is always part of a registration procedure.
        # If the previous one is already complete, this is a new procedure and
        # supersedes its authorizations even when the new request was not
        # captured.
        proc = self._procedure
        if proc is not None and proc.state != 'open':
            self._supersede_authorizations()
            proc = self._new_procedure('registration')
        else:
            proc = self._ensure_registration()
        proc.accept_indices.append(message_index)
        proc.messages.append(message_index)
        plmn = _message_plmn(msg)
        if plmn is not None:
            proc.serving_plmn = plmn
        self._extract_message(msg, name, typ, 'dl', message_index, secured,
                              nested_in, proc=proc)

    def _on_registration_complete(self, msg, name, message_index):
        proc = self._procedure
        if proc is None or proc.state != 'open' or not proc.accept_indices:
            self.manifest.issues.append(
                'message %d: registration complete without an observed '
                'registration accept in the current procedure' % message_index)
            if proc is not None:
                proc.messages.append(message_index)
            return
        proc.complete_indices.append(message_index)
        proc.messages.append(message_index)
        self._promote_claims(proc)
        proc.state = 'confirmed'

    def _on_registration_reject(self, msg, name, typ, message_index, secured,
                                nested_in=None):
        proc = self._procedure
        if proc is None or proc.state != 'open':
            # A standalone reject also ends the previous authorization state:
            # it cannot be assumed that the old Allowed list survived.
            self._supersede_authorizations()
            proc = self._new_procedure('registration')
        proc.reject_indices.append(message_index)
        proc.messages.append(message_index)
        self._extract_message(msg, name, typ, 'dl', message_index, secured,
                              nested_in, proc=proc)
        proc.state = 'rejected'

    def _on_configuration_update(self, msg, name, typ, message_index, secured,
                                 nested_in=None):
        proc = self._ensure_configuration()
        proc.config_indices.append(message_index)
        proc.messages.append(message_index)
        self._extract_message(msg, name, typ, 'dl', message_index, secured,
                              nested_in, proc=proc)

    def _on_configuration_complete(self, msg, name, message_index):
        proc = self._config_procedure
        if proc is not None:
            proc.config_complete_indices.append(message_index)
            proc.messages.append(message_index)
            proc.state = 'observed'

    def _on_deregistration(self, msg, name, message_index):
        proc = self._procedure
        if proc is not None:
            proc.messages.append(message_index)
            proc.state = 'deregistered'
        # De-registration revokes the slice authorizations established by
        # the procedure it terminates.  Keep the Rejected NSSAI, if any, as
        # an explicit rejection tied to this observed message.
        self._supersede_authorizations()
        self._extract_message(msg, name, _message_type(msg), 'dl',
                              message_index, False, None, proc=proc)

    #--------------------------------------------------------------------------#
    # extraction
    #--------------------------------------------------------------------------#

    def _field_value_bytes(self, msg, field):
        ie = _child(msg, field)
        if ie is None:
            return None
        if field == 'SNSSAI':
            return _snssai_value_bytes(ie)
        if field in ('RejectedNSSAI', 'ExtRejectedNSSAI'):
            return _rejected_value_bytes(ie)
        return _nssai_value_bytes(ie)

    def _extract_message(self, msg, name, typ, direction, message_index,
                         secured, nested_in, proc=None):
        if proc is None:
            proc = self._procedure
        proc_index = proc.index if proc is not None else None
        fields = extract_slice_fields(msg)
        for field in ('NSSAI', 'MappedNSSAI', 'AllowedNSSAI',
                      'ConfiguredNSSAI', 'PendingNSSAI', 'RejectedNSSAI',
                      'ExtRejectedNSSAI', 'SNSSAI'):
            if field not in fields:
                continue
            entries, issues = fields[field]
            raw_value = self._field_value_bytes(msg, field)
            self._observation_index += 1
            obs = SNSliceObservation(
                self._observation_index, message_index, name, typ, direction,
                field, _role_for(field), raw_value,
                [e[0] if isinstance(e, tuple) else e for e in entries],
                issues, secured=secured, nested_in=nested_in,
                procedure=proc_index)
            self.manifest.observations.append(obs)
            if proc is not None and issues:
                proc.unknown.extend(issues)
            for entry_index, entry in enumerate(entries):
                cause = None
                if isinstance(entry, tuple):
                    entry, cause = entry
                self._record_entry(proc, field, entry, cause, message_index,
                                   name, entry_index, secured, nested_in)

    def _record_entry(self, proc, field, ev, cause, message_index, name,
                      entry_index, secured, nested_in):
        kind, status = _kind_status_for(field)
        if kind is None:
            return
        if kind == 'allowed' and name == _MSG_CONFIG_CMD:
            # A Configuration Update Command can declare Allowed NSSAI, but
            # that is a network policy claim, not a registration completion.
            status = _STATUS_CLAIM
        proc_index = proc.index if proc is not None else None
        item = self.manifest._new_item(
            kind, ev, message_index, name, field, entry_index,
            registration_index=proc_index, secured=secured,
            nested_in=nested_in, cause=cause, status=status)
        if proc is not None:
            if kind == 'requested':
                proc.requested.append(item)
            elif kind == 'allowed':
                proc.allowed_claims.append(item)
            elif kind == 'rejected':
                proc.rejected.append(item)
            elif kind == 'configured':
                proc.configured.append(item)
            elif kind == 'pending':
                proc.pending.append(item)
            elif kind == 'mapped':
                proc.mapped.append(item)
            elif kind == 'serving':
                proc.serving.append(item)
        return item

    #--------------------------------------------------------------------------#
    # confirmation
    #--------------------------------------------------------------------------#

    def _promote_claims(self, proc):
        """Promote Allowed NSSAI claims in one completed procedure.

        Only Allowed NSSAI from a Registration Accept can be promoted.
        Configuration Update Command Allowed NSSAI stays a network claim, and
        Old/superseded procedures never contribute to the current state.
        """
        rejected = set(i.identity for i in proc.rejected
                       if i.identity is not None)
        for item in proc.allowed_claims:
            if item.status == _STATUS_CONFIRMED:
                continue
            if item.message_name != _MSG_REG_ACCEPT:
                continue
            if not item.evidence.valid or item.identity is None:
                proc.unknown.append(
                    'allowed NSSAI entry from message %d is not an exact '
                    'identity: %s' % (item.message_index,
                                      item.evidence.describe()))
                continue
            if item.identity in rejected:
                # The same exact identity cannot be both allowed and
                # rejected in one procedure.  Keep the contradiction visible
                # and never promote it to an authorization.
                item.status = _STATUS_CONFLICT
                proc.unknown.append(
                    'message %d: S-NSSAI %s appears in both Allowed and '
                    'Rejected NSSAI' % (item.message_index,
                                        item.evidence.describe()))
                continue
            if any(i.identity == item.identity
                   for i in proc.allowed_confirmed):
                continue
            item.status = _STATUS_CONFIRMED
            proc.allowed_confirmed.append(item)


def _role_for(field):
    return {
        'NSSAI'         : 'requested',
        'MappedNSSAI'   : 'mapped',
        'AllowedNSSAI'  : 'allowed',
        'ConfiguredNSSAI': 'configured',
        'PendingNSSAI'  : 'pending',
        'RejectedNSSAI' : 'rejected',
        'ExtRejectedNSSAI': 'rejected',
        'SNSSAI'        : 'serving',
        }.get(field, 'unknown')


def _kind_status_for(field):
    role = _role_for(field)
    if role in ('requested', 'rejected', 'configured', 'pending', 'mapped',
                'serving'):
        return role, (_STATUS_REJECTED if role == 'rejected'
                      else _STATUS_UNKNOWN)
    if role == 'allowed':
        return 'allowed', _STATUS_UNCONFIRMED
    return None, None


def analyze_nas_messages(messages, home_plmn=None, require_complete=True,
                         direction=None):
    """Convenience helper: analyze an iterable of messages or raw PDUs.

    Args:
        messages: iterable of pycrate messages or raw bytes
        home_plmn: optional home PLMN
        require_complete: see SNSliceAnalyzer
        direction: optional direction applied to every message

    Returns:
        SNSliceManifest
    """
    analyzer = SNSliceAnalyzer(home_plmn=home_plmn,
                               require_complete=require_complete)
    for msg in messages:
        analyzer.add_message(msg, direction=direction)
    return analyzer.result()
