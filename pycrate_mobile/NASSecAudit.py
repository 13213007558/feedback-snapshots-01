# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.1
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
# *--------------------------------------------------------
# * File Name : pycrate_mobile/NASSecAudit.py
# * Created : 2026-11-19
# * Authors : pycrate contributors
# *--------------------------------------------------------
#*/

"""
Offline consistency audit of a captured 5G NAS security mode negotiation.

The audit answers one question: does the algorithm selected in the Security
Mode Command (SMC) agree with what the UE declared it supports, and how much
of each statement is actually protected?

Three evidence levels are deliberately kept apart, because conflating them is
how a benign capture turns into a false downgrade report:

* ``cleartext``: the field was observed in a NAS message with security header
  type 0. Its value is a claim on the wire, not an authenticated statement.
  The UE security capability in an initial Registration Request is always in
  this class (TS 24.501, section 4.4.6).
* ``authenticated``: the field was observed inside an integrity protected NAS
  message and its MAC was recomputed and matched, using a supplied K_NASint
  and the full 32-bit NAS COUNT.
* ``unverified``: the field was observed inside an integrity protected
  envelope, but the MAC could not be checked (no key, no 32-bit COUNT, null
  or unsupported integrity algorithm). The value is still what the capture
  contains; it must never be reported as verified.

Nothing here concludes that a downgrade happened. The report states whether
the observed statements agree, at which evidence level, and which missing
piece would be needed to move a warning to a conclusion. A weak or null
algorithm on its own is reported as an observation only.

Capture format, a JSON object::

    {
      "procedure": "initial-registration",
      "ue": "suci-0-001-01-0000-0-0-0000000001",
      "keys": {"K_NASint": "000102030405060708090a0b0c0d0e0f"},
      "algorithms": {"integrity": 2},
      "records": [
        {"n": 1, "dir": "UL", "count": 0, "pdu": "7e004170..."},
        {"n": 2, "dir": "DL", "count": 5, "pdu": "7e035d..."},
        {"n": 3, "dir": "DL", "gap": "Security Mode Command not captured"}
      ]
    }

Per-record ``integrity_alg`` overrides the transcript-wide value; this is
needed when the SMC itself is missing from the capture. A record may also
carry ``K_NASint``, ``label``, ``procedure`` and ``ue``. The latter two are
used to detect records that do not belong to the same procedure or UE.
"""

import json
import os

from binascii import unhexlify, hexlify

from pycrate_crypto.AESCMAC import nas_mac

from .NAS5G import parse_NAS5G


__all__ = ['TranscriptError', 'Finding', 'AuditReport', 'audit_transcript',
           'audit_file', 'load_transcript', 'EVIDENCE_LEVELS',
           'STATUS_CONSISTENT', 'STATUS_WEAK_CONSISTENT', 'STATUS_INCONSISTENT',
           'STATUS_INSUFFICIENT']


#------------------------------------------------------------------------------#
# vocabulary
#------------------------------------------------------------------------------#

EVIDENCE_CLEARTEXT     = 'cleartext'
EVIDENCE_AUTHENTICATED = 'authenticated'
EVIDENCE_UNVERIFIED    = 'unverified'
EVIDENCE_OPAQUE        = 'opaque'
EVIDENCE_ABSENT        = 'absent'

EVIDENCE_LEVELS = (EVIDENCE_ABSENT, EVIDENCE_OPAQUE, EVIDENCE_CLEARTEXT,
                   EVIDENCE_UNVERIFIED, EVIDENCE_AUTHENTICATED)

STATUS_CONSISTENT      = 'consistent'
STATUS_WEAK_CONSISTENT = 'weak_but_consistent'
STATUS_INCONSISTENT    = 'inconsistent'
STATUS_INSUFFICIENT    = 'insufficient_evidence'

# MAC check outcomes. "Not attempted" is a distinct value, never a success.
MAC_VERIFIED        = 'verified'
MAC_FAILED          = 'failed'
MAC_CLEARTEXT       = 'not_attempted_cleartext'
MAC_NO_KEY          = 'not_attempted_no_key'
MAC_NO_COUNT        = 'not_attempted_no_count'
MAC_COUNT_MISMATCH  = 'not_attempted_count_mismatch'
MAC_NULL_INTEGRITY  = 'not_attempted_null_integrity'
MAC_UNSUPPORTED_ALG = 'not_attempted_unsupported_algorithm'
MAC_UNKNOWN_ALG     = 'not_attempted_algorithm_unknown'

_SEC_HDR_NAMES = {
    0 : 'no security',
    1 : 'integrity protected',
    2 : 'integrity protected and ciphered',
    3 : 'integrity protected, new security context',
    4 : 'integrity protected and ciphered, new security context',
    }

_CIPH_NAMES = {0:'5G-EA0', 1:'5G-EA1', 2:'5G-EA2', 3:'5G-EA3'}
_INTEG_NAMES = {0:'5G-IA0', 1:'5G-IA1', 2:'5G-IA2', 3:'5G-IA3'}

_CIPH_BITS = ('5G-EA0', '5G-EA1_128', '5G-EA2_128', '5G-EA3_128')
_INTEG_BITS = ('5G-IA0', '5G-IA1_128', '5G-IA2_128', '5G-IA3_128')

# integrity algorithms this module can verify (AES-CMAC based)
_VERIFIABLE_INTEG = {2}

_MAC_NOT_CHECKED = (
    MAC_NO_KEY, MAC_NO_COUNT, MAC_COUNT_MISMATCH, MAC_NULL_INTEGRITY,
    MAC_UNSUPPORTED_ALG, MAC_UNKNOWN_ALG)


class TranscriptError(Exception):
    """Raised when a transcript cannot be read or has no usable records."""
    pass


#------------------------------------------------------------------------------#
# findings and report
#------------------------------------------------------------------------------#

class Finding(object):
    """One audit observation.
    
    `fields` lists the exact NAS fields the finding concerns, each with the
    evidence level at which its value was observed and a description of its
    protection state. `missing` lists the evidence that would be needed to
    turn the observation into a conclusion.
    """
    
    def __init__(self, code, severity, summary, fields=None, missing=None,
                 detail=None):
        self.code     = code
        self.severity = severity
        self.summary  = summary
        self.fields   = fields or []
        self.missing  = missing or []
        self.detail   = detail
    
    def to_dict(self):
        return {'code': self.code, 'severity': self.severity,
                'summary': self.summary,
                'fields': [dict(f) for f in self.fields],
                'missing': list(self.missing), 'detail': self.detail}
    
    def render(self, indent='  '):
        out = ['%s[%-7s] %s: %s' % (indent, self.severity.upper(), self.code,
                                    self.summary)]
        for f in self.fields:
            out.append('%s  - %s = %s' % (indent, f['field'], f['value']))
            out.append('%s    evidence: %s; protection: %s'
                       % (indent, f['evidence'], f['protection']))
        if self.detail:
            out.append('%s  note: %s' % (indent, self.detail))
        for m in self.missing:
            out.append('%s  missing to confirm: %s' % (indent, m))
        return '\n'.join(out)


class AuditReport(object):
    """Result of :func:`audit_transcript`."""
    
    def __init__(self, transcript=None):
        self.transcript   = transcript or {}
        self.procedure    = self.transcript.get('procedure')
        self.ue           = self.transcript.get('ue')
        self.messages     = []
        self.declarations = {}
        self.selection    = None
        self.findings     = []
        self.conclusion   = {
            'status'                        : STATUS_INSUFFICIENT,
            'confirmed_downgrade'           : False,
            'confirmed_capability_replacement': False,
            'summary'                       : 'no analysis performed',
            'missing_evidence'              : [],
            }
        self._state = {}
    
    def add(self, code, severity, summary, fields=None, missing=None,
            detail=None):
        f = Finding(code, severity, summary, fields, missing, detail)
        self.findings.append(f)
        return f
    
    @property
    def warnings(self):
        return [f for f in self.findings
                if f.severity in ('warning', 'error')]
    
    def findings_by_code(self, code):
        return [f for f in self.findings if f.code == code]
    
    def to_dict(self):
        return {
            'source'      : self.transcript.get('_path'),
            'procedure'   : self.procedure,
            'ue'          : self.ue,
            'messages'    : [dict(m) for m in self.messages],
            'declarations': _public(self.declarations),
            'selection'   : _public(self.selection),
            'findings'    : [f.to_dict() for f in self.findings],
            'conclusion'  : dict(self.conclusion),
            }
    
    def render(self):
        out = []
        src = self.transcript.get('_path')
        if src:
            out.append('[+] transcript: %s' % src)
        out.append('[+] procedure: %s, ue: %s' % (self.procedure, self.ue))
        out.append('')
        out.append('[+] messages')
        if not self.messages:
            out.append('  (none)')
        for m in self.messages:
            if m.get('gap'):
                out.append('  %-3s %-2s %-8s %s' % (m['n'], m['dir'], 'GAP',
                                                    m['gap']))
            elif m.get('error'):
                out.append('  %-3s %-2s %-8s %s' % (m['n'], m['dir'], 'ERROR',
                                                    m['error']))
            else:
                out.append('  %-3s %-2s %-32s sec-hdr %i (%s)' % (
                    m['n'], m['dir'], m['name'], m['sec_hdr'],
                    _SEC_HDR_NAMES.get(m['sec_hdr'], '?')))
                out.append('      evidence: %-13s mac: %s'
                           % (m.get('evidence'), m.get('mac_status')))
                cap = m.get('ue_sec_cap')
                if cap:
                    out.append('      UE security capability: %s'
                               % _cap_text(cap))
        out.append('')
        out.append('[+] declarations')
        if not self.declarations:
            out.append('  (none)')
        for key in ('registration_request', 'smc_echo'):
            d = self.declarations.get(key)
            if not d:
                continue
            out.append('  - %s' % d['source'])
            out.append('      %s' % _cap_text(d))
            out.append('      evidence: %s; %s'
                       % (d['evidence'], d['protection']))
        out.append('')
        out.append('[+] selection')
        if not self.selection:
            out.append('  (no Security Mode Command observed)')
        else:
            out.append('  - record %s: ciphering %s, integrity %s'
                       % (self.selection['record'],
                          self.selection['ciphering_name'],
                          self.selection['integrity_name']))
            out.append('      evidence: %s; %s'
                       % (self.selection['evidence'],
                          self.selection['protection']))
        out.append('')
        out.append('[+] findings')
        if not self.findings:
            out.append('  (none)')
        for f in self.findings:
            out.append(f.render())
        out.append('')
        out.append('[+] conclusion: %s' % self.conclusion['status'])
        out.append('    confirmed capability replacement: %s'
                   % ('yes' if self.conclusion.get(
                       'confirmed_capability_replacement') else 'no'))
        out.append('    confirmed downgrade: %s'
                   % ('yes' if self.conclusion.get('confirmed_downgrade')
                      else 'no'))
        out.append('    %s' % self.conclusion['summary'])
        for m in self.conclusion.get('missing_evidence', []):
            out.append('    missing: %s' % m)
        return '\n'.join(out)


def _public(obj):
    if obj is None:
        return None
    if isinstance(obj, dict):
        return {k:_public(v) for k, v in obj.items() if k != 'raw'}
    if isinstance(obj, (list, tuple)):
        return [_public(v) for v in obj]
    return obj


def _cap_text(cap):
    bits = (cap or {}).get('bits')
    if not bits:
        return 'undecodable'
    ciph  = [_CIPH_NAMES[i] for i, n in enumerate(_CIPH_BITS) if bits.get(n)]
    integ = [_INTEG_NAMES[i] for i, n in enumerate(_INTEG_BITS) if bits.get(n)]
    return 'ciphering [%s], integrity [%s]' % (
        ', '.join(ciph) or 'none', ', '.join(integ) or 'none')


#------------------------------------------------------------------------------#
# transcript loading
#------------------------------------------------------------------------------#

def load_transcript(src):
    """Load a transcript from a path or return an already parsed dict.
    
    Args:
        src: file path (str / os.PathLike) or dict
    
    Returns:
        dict with a ``_path`` key
    """
    if isinstance(src, dict):
        tr = dict(src)
        tr.setdefault('_path', None)
        return tr
    path = os.fspath(src)
    try:
        with open(path, 'r') as fd:
            tr = json.load(fd)
    except (OSError, ValueError) as err:
        raise TranscriptError('unable to read transcript %r: %r' % (path, err))
    if not isinstance(tr, dict) or not isinstance(tr.get('records'), list):
        raise TranscriptError('transcript %r has no "records" list' % path)
    tr['_path'] = path
    return tr


def audit_file(src):
    """Load and audit a transcript file. See :func:`audit_transcript`."""
    return audit_transcript(load_transcript(src))


#------------------------------------------------------------------------------#
# record decoding
#------------------------------------------------------------------------------#

class _Record(object):
    
    def __init__(self, n, direction):
        self.n          = n
        self.dir        = direction
        self.label      = None
        self.gap        = None
        self.error      = None
        self.raw        = None
        self.outer      = None
        self.inner      = None
        self.sec_hdr    = 0
        self.name       = None
        self.type       = None
        self.mac        = None
        self.seqn       = None
        self.count      = None
        self.key        = None
        self.alg        = None
        self.mac_status = None
        self.mac_detail = None
        self.procedure  = None
        self.ue         = None


def _decode_record(rec, index):
    r = _Record(rec.get('n', index + 1), str(rec.get('dir', '?')).upper())
    r.label     = rec.get('label')
    r.procedure = rec.get('procedure')
    r.ue        = rec.get('ue')
    if 'gap' in rec:
        r.gap = str(rec['gap'])
        return r
    hexbuf = rec.get('pdu') or rec.get('nas')
    if not hexbuf:
        r.error = 'record has neither "pdu" nor "nas"'
        return r
    try:
        raw = unhexlify(str(hexbuf).replace(' ', '').replace(':', ''))
    except Exception as err:
        r.error = 'invalid hexadecimal PDU: %r' % (err,)
        return r
    r.raw = raw
    if not raw:
        r.error = 'empty PDU'
        return r
    if raw[0] != 126:
        if raw[0] & 0xf == 7:
            r.error = ('EPS NAS (EMM) record; this audit covers 5GMM '
                       '(TS 24.501) only')
        else:
            r.error = 'unsupported NAS protocol discriminator 0x%02x' % raw[0]
        return r
    outer, err = parse_NAS5G(raw, inner=False)
    if err != 0 or outer is None:
        r.error = 'pycrate NAS5G decode error %i' % err
        return r
    r.outer = outer
    try:
        r.sec_hdr = int(outer[0]['SecHdr'].get_val())
    except Exception:
        r.sec_hdr = 0
    if outer._name != '5GMMSecProtNASMessage':
        r.inner = outer
    else:
        try:
            r.mac  = outer['MAC'].get_val()
            r.seqn = int(outer['Seqn'].get_val())
        except Exception:
            r.mac  = None
            r.seqn = None
        if r.sec_hdr in (2, 4):
            r.error = ('ciphered NAS payload: without K_NASenc the plaintext '
                       'cannot be audited')
            return r
        try:
            innerbuf = outer['NASMessage'].get_val()
        except Exception:
            r.error = 'security protected message without a NAS payload'
            return r
        inner, err = parse_NAS5G(innerbuf, inner=False)
        if err != 0 or inner is None:
            r.error = 'inner NAS decode error %i' % err
            return r
        r.inner = inner
    r.name = r.inner._name
    try:
        r.type = int(r.inner[0]['Type'].get_val())
    except Exception:
        r.type = None
    return r


def _get_ie(msg, name):
    try:
        return msg[name]
    except Exception:
        return None


def _read_cap(msg):
    """Return the UE security capability carried by `msg`, or None if absent.
    
    A present but undecodable IE returns ``{'bits': None, 'present': True}``:
    present-but-unreadable is not the same as absent.
    """
    ie = _get_ie(msg, 'UESecCap')
    if ie is None:
        return None
    try:
        if ie.get_trans():
            return None
    except Exception:
        pass
    last = ie[-1]
    if getattr(last, '_name', None) != 'UESecCap':
        raw = None
        try:
            raw = last.get_val()
        except Exception:
            pass
        return {'bits': None, 'present': True, 'raw': raw}
    bits = {}
    for elt in last._content:
        name = getattr(elt, '_name', '')
        if name == 'spare':
            continue
        try:
            bits[name] = int(elt.get_val())
        except Exception:
            continue
    return {'bits': bits, 'present': True, 'raw': last.to_bytes()}


def _read_algos(msg):
    ie = _get_ie(msg, 'NASSecAlgo')
    if ie is None:
        return None
    last = ie[-1]
    if getattr(last, '_name', None) == 'NASSecAlgo':
        try:
            return (int(last['CiphAlgo'].get_val()),
                    int(last['IntegAlgo'].get_val()))
        except Exception:
            return None
    try:
        raw = last.get_val()
    except Exception:
        raw = None
    if isinstance(raw, (bytes, bytearray)) and raw:
        return (raw[0] >> 4, raw[0] & 0xf)
    return None


#------------------------------------------------------------------------------#
# MAC verification
#------------------------------------------------------------------------------#

def _verify_mac(rec, key, count, alg):
    """Return (status, detail).
    
    Never returns MAC_VERIFIED for a check that was not performed.
    """
    if rec.sec_hdr in (0, None):
        return MAC_CLEARTEXT, 'security header type 0, no MAC field'
    if rec.sec_hdr in (2, 4):
        return MAC_UNSUPPORTED_ALG, 'ciphered payload was not decrypted'
    if alg is None:
        return MAC_UNKNOWN_ALG, 'integrity algorithm not known for this record'
    if alg == 0:
        return MAC_NULL_INTEGRITY, ('5G-IA0: no MAC is computed; the four MAC '
                                    'octets carry no integrity proof')
    if alg not in _VERIFIABLE_INTEG:
        if alg in (1, 3):
            return MAC_UNSUPPORTED_ALG, ('5G-IA%i uses SNOW/ZUC, not available '
                                         'in this offline verifier' % alg)
        return MAC_UNSUPPORTED_ALG, 'reserved integrity algorithm %i' % alg
    if key is None:
        return MAC_NO_KEY, 'no K_NASint supplied for this record'
    if count is None:
        return MAC_NO_COUNT, ('32-bit NAS COUNT not supplied; the 8-bit Seqn '
                              'alone cannot reconstruct it')
    if rec.seqn is None:
        return MAC_UNSUPPORTED_ALG, 'no Seqn field in the security header'
    if (count & 0xff) != rec.seqn:
        return MAC_COUNT_MISMATCH, ('COUNT 0x%08x low byte 0x%02x differs from '
                                    'Seqn 0x%02x' % (count, count & 0xff,
                                                     rec.seqn))
    direction = 0 if rec.dir == 'UL' else 1
    computed = nas_mac(key, count, 1, direction,
                       bytes((rec.seqn,)) + bytes(rec.raw_inner))
    if computed == rec.mac:
        return MAC_VERIFIED, '5G-IA2 MAC matched at COUNT 0x%08x' % count
    return MAC_FAILED, ('5G-IA2 MAC mismatch at COUNT 0x%08x: computed %s, '
                        'received %s' % (count,
                                         hexlify(computed).decode(),
                                         hexlify(rec.mac).decode()))


#------------------------------------------------------------------------------#
# helpers
#------------------------------------------------------------------------------#

def _norm_bytes(val):
    if val is None:
        return None
    if isinstance(val, (bytes, bytearray)):
        return bytes(val)
    try:
        return unhexlify(str(val).replace(' ', '').replace(':', ''))
    except Exception:
        return None


def _norm_int(val):
    if val is None or isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val
    try:
        return int(str(val), 0)
    except ValueError:
        return None


def _field(name, value, evidence, protection):
    return {'field': name, 'value': value, 'evidence': evidence,
            'protection': protection}


def _record_evidence(rec):
    if rec.sec_hdr == 0:
        return EVIDENCE_CLEARTEXT
    if rec.mac_status == MAC_VERIFIED:
        return EVIDENCE_AUTHENTICATED
    return EVIDENCE_UNVERIFIED


def _protection_text(rec):
    if rec.sec_hdr == 0:
        return 'security header type 0: cleartext, no NAS integrity'
    extra = {
        MAC_VERIFIED        : 'MAC verified',
        MAC_FAILED          : 'MAC FAILED',
        MAC_NO_KEY          : 'MAC not checked: no K_NASint',
        MAC_NO_COUNT        : 'MAC not checked: no 32-bit NAS COUNT',
        MAC_COUNT_MISMATCH  : 'MAC not checked: COUNT/Seqn mismatch',
        MAC_NULL_INTEGRITY  : '5G-IA0: no MAC exists to verify',
        MAC_UNSUPPORTED_ALG : 'MAC not checked: algorithm not covered here',
        MAC_UNKNOWN_ALG     : 'MAC not checked: integrity algorithm unknown',
        }.get(rec.mac_status, 'MAC not checked')
    return 'security header %i (%s), %s' % (
        rec.sec_hdr, _SEC_HDR_NAMES.get(rec.sec_hdr, '?'), extra)


def _protection_of(decl):
    return decl.get('protection', 'unknown')


def _offers(bits, algo, kind):
    """True/False when `bits` is usable, None when the capability is unknown."""
    if not bits:
        return None
    if not 0 <= algo <= 3:
        return None
    names = _CIPH_BITS if kind == 'ciph' else _INTEG_BITS
    return bool(bits.get(names[algo]))


def _cap_diff(a, b):
    out = []
    for names, short in ((_CIPH_BITS, _CIPH_NAMES), (_INTEG_BITS, _INTEG_NAMES)):
        for i, name in enumerate(names):
            if bool(a.get(name)) != bool(b.get(name)):
                out.append('%s %i->%i' % (short[i], int(bool(a.get(name))),
                                          int(bool(b.get(name)))))
    return out


#------------------------------------------------------------------------------#
# audit
#------------------------------------------------------------------------------#

def audit_transcript(src):
    """Audit one captured registration procedure.
    
    Args:
        src: transcript dict or path to a JSON transcript
    
    Returns:
        AuditReport
    """
    tr  = load_transcript(src)
    rep = AuditReport(tr)
    keys = tr.get('keys') or {}
    tr_algos = tr.get('algorithms') or {}
    default_alg = _norm_int(tr_algos.get('integrity'))
    default_key = _norm_bytes(keys.get('K_NASint'))
    
    records = tr.get('records') or []
    if not records:
        raise TranscriptError('transcript has an empty "records" list')
    
    decoded = []
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            raise TranscriptError('record %i is not an object' % (i + 1))
        d = _decode_record(rec, i)
        d.count = _norm_int(rec.get('count'))
        d.alg   = _norm_int(rec.get('integrity_alg'))
        d.key   = (_norm_bytes(rec.get('K_NASint'))
                   or (_norm_bytes(keys.get('K_NASint_ul'))
                       if d.dir == 'UL' else None)
                   or default_key)
        if d.outer is not None and d.outer._name == '5GMMSecProtNASMessage':
            try:
                d.raw_inner = d.outer['NASMessage'].get_val()
            except Exception:
                d.raw_inner = b''
        else:
            d.raw_inner = None
        decoded.append(d)
    
    # resolve the active integrity algorithm in capture order: the last SMC at
    # or before a record determines the context that protects it
    active_alg = default_alg
    for d in decoded:
        if d.gap or d.inner is None:
            continue
        if d.name == '5GMMSecurityModeCommand':
            sel = _read_algos(d.inner)
            if sel is not None:
                active_alg = sel[1]
        if d.alg is None:
            d.alg = active_alg
        if d.outer is not None:
            d.mac_status, d.mac_detail = _verify_mac(d, d.key, d.count, d.alg)
        else:
            d.mac_status, d.mac_detail = MAC_CLEARTEXT, 'security header type 0'
    
    _collect_declarations(rep, decoded)
    _check_structure(rep, decoded)
    _check_identity(rep, decoded)
    _check_capability_evidence(rep)
    if rep.selection is None:
        _conclude_no_selection(rep, decoded, rep.declarations)
    else:
        _check_selection(rep, decoded, rep.declarations)
    return rep


def _collect_declarations(rep, decoded):
    ue_decl = echo_decl = None
    sel = None
    for d in decoded:
        entry = {'n': d.n, 'dir': d.dir, 'sec_hdr': d.sec_hdr,
                 'mac_status': d.mac_status, 'name': d.name, 'type': d.type,
                 'label': d.label}
        if d.gap:
            entry['gap'] = d.gap
            rep.messages.append(entry)
            continue
        if d.inner is None:
            entry['error'] = d.error or 'no readable NAS payload'
            entry['name'] = None
            rep.messages.append(entry)
            continue
        entry['evidence'] = _record_evidence(d)
        cap = _read_cap(d.inner)
        if cap:
            entry['ue_sec_cap'] = {'bits': cap['bits'],
                                   'present': cap['present']}
        rep.messages.append(entry)
        evidence = _record_evidence(d)
        if d.name == '5GMMRegistrationRequest':
            rep.add('registration-request', 'info',
                    'Registration Request observed at record %s' % d.n,
                    fields=[_field('record.%s.name' % d.n,
                                   '5GMMRegistrationRequest',
                                   EVIDENCE_CLEARTEXT if d.sec_hdr == 0
                                   else evidence,
                                   _protection_text(d))])
            if cap:
                ue_decl = {'source': 'Registration Request, record %s (UL)'
                                     % d.n,
                           'bits': cap['bits'], 'raw': cap['raw'],
                           'evidence': evidence,
                           'protection': _protection_text(d),
                           'record': d.n}
                if cap['bits'] is None:
                    rep.add('capability-undecodable', 'warning',
                            'the UE security capability IE is present but its '
                            'value could not be decoded',
                            fields=[_field('RegistrationRequest.UESecCap',
                                           'undecodable', evidence,
                                           _protection_text(d))],
                            missing=['a complete copy of the Registration '
                                     'Request PDU'])
        if d.name == '5GMMSecurityModeCommand':
            algos = _read_algos(d.inner)
            if cap:
                echo_decl = {'source': 'Security Mode Command, record %s (DL), '
                                       'UE security capability echo' % d.n,
                             'bits': cap['bits'], 'raw': cap['raw'],
                             'evidence': evidence,
                             'protection': _protection_text(d),
                             'record': d.n}
            if algos is not None:
                sel = {'record': d.n, 'ciphering': algos[0],
                       'integrity': algos[1],
                       'ciphering_name': _CIPH_NAMES.get(algos[0],
                                                         '5G-EA%i' % algos[0]),
                       'integrity_name': _INTEG_NAMES.get(algos[1],
                                                          '5G-IA%i' % algos[1]),
                       'evidence': evidence,
                       'protection': _protection_text(d),
                       'mac_status': d.mac_status}
    rep.declarations = {}
    if ue_decl:
        rep.declarations['registration_request'] = ue_decl
    if echo_decl:
        rep.declarations['smc_echo'] = echo_decl
    rep.selection = sel


def _check_structure(rep, decoded):
    for d in decoded:
        if d.gap:
            rep.add('capture-gap', 'warning',
                    'record %s (%s) is a capture gap: %s' % (d.n, d.dir, d.gap),
                    fields=[_field('record.%s.pdu' % d.n, 'not captured',
                                   EVIDENCE_ABSENT, 'absent from the capture')],
                    missing=['the missing NAS PDU and its framing metadata'])
        elif d.error and d.inner is None:
            ev = EVIDENCE_OPAQUE
            rep.add('decode-error', 'error',
                    'record %s (%s): %s' % (d.n, d.dir, d.error),
                    fields=[_field('record.%s.pdu' % d.n, 'unreadable', ev,
                                   'no readable plaintext NAS payload')],
                    missing=['the plaintext NAS PDU, or the key material '
                             'needed to decrypt it'])
        elif d.mac_status == MAC_FAILED:
            rep.add('mac-failed', 'error',
                    'record %s (%s) integrity check FAILED' % (d.n, d.dir),
                    fields=[_field('record.%s.MAC' % d.n,
                                   hexlify(d.mac).decode(), EVIDENCE_UNVERIFIED,
                                   d.mac_detail)],
                    missing=['the correct K_NASint and COUNT, or an independent '
                             'copy of the PDU to distinguish capture corruption '
                             'from tampering'])
        elif d.mac_status in _MAC_NOT_CHECKED:
            rep.add('mac-unchecked', 'info',
                    'record %s (%s) is integrity protected but its MAC was not '
                    'checked' % (d.n, d.dir),
                    fields=[_field('record.%s.MAC' % d.n,
                                   hexlify(d.mac).decode()
                                   if d.mac else 'absent',
                                   EVIDENCE_UNVERIFIED, _protection_text(d))],
                    missing=[{
                        MAC_NO_KEY         : 'K_NASint for the active 5G NAS '
                                             'security context',
                        MAC_NO_COUNT       : 'the 32-bit NAS COUNT for this '
                                             'record (Seqn is only 8 bits)',
                        MAC_COUNT_MISMATCH : 'a consistent 32-bit NAS COUNT and '
                                             'Seqn pair',
                        MAC_NULL_INTEGRITY : 'nothing: 5G-IA0 defines no MAC, '
                                             'so no integrity can be proven',
                        MAC_UNSUPPORTED_ALG: 'a verifier for the negotiated '
                                             'integrity algorithm',
                        MAC_UNKNOWN_ALG    : 'the Security Mode Command '
                                             'that determines the active '
                                             'integrity algorithm, and the '
                                             '32-bit NAS COUNT for this record',
                        }[d.mac_status]])


def _check_identity(rep, decoded):
    for d in decoded:
        if d.gap:
            continue
        if d.procedure and rep.procedure and d.procedure != rep.procedure:
            rep.add('procedure-mismatch', 'warning',
                    'record %s declares procedure %r but the transcript is %r'
                    % (d.n, d.procedure, rep.procedure),
                    fields=[_field('record.%s.procedure' % d.n, d.procedure,
                                   EVIDENCE_CLEARTEXT, 'capture metadata')],
                    missing=['a capture of the complete procedure this record '
                             'belongs to, with its own Security Mode Command'])
        if d.ue and rep.ue and d.ue != rep.ue:
            rep.add('ue-mismatch', 'warning',
                    'record %s declares UE %r but the transcript is %r'
                    % (d.n, d.ue, rep.ue),
                    fields=[_field('record.%s.ue' % d.n, d.ue,
                                   EVIDENCE_CLEARTEXT, 'capture metadata')],
                    missing=['a capture that keeps one UE identity per '
                             'procedure'])
    if rep.selection is not None:
        rep.add('smc-identity-binding', 'info',
                'the Security Mode Command carries no UE identity: its link '
                'to the Registration Request rests only on capture framing',
                fields=[_field('SecurityModeCommand.UEIdentity', 'absent',
                               EVIDENCE_ABSENT,
                               'the SMC has no UE identity field')],
                detail='association must be established by session id or '
                       'record order, not by a protocol field')


def _check_capability_evidence(rep):
    ue_decl = rep.declarations.get('registration_request')
    echo_decl = rep.declarations.get('smc_echo')
    if ue_decl is None:
        rep.add('capability-absent', 'warning',
                'no UE security capability was observed in a Registration '
                'Request',
                fields=[_field('RegistrationRequest.UESecCap', 'absent',
                               EVIDENCE_ABSENT,
                               'IE not present in the capture')],
                missing=['the Registration Request with its UESecCap IE, or a '
                         'later authenticated re-declaration'])
    elif ue_decl['evidence'] == EVIDENCE_UNVERIFIED:
        rep.add('capability-unverified', 'warning',
                'the UE security capability declaration is inside an '
                'integrity protected message, but its MAC was not verified',
                fields=[_field('RegistrationRequest.UESecCap',
                               _cap_text(ue_decl), EVIDENCE_UNVERIFIED,
                               _protection_of(ue_decl))],
                missing=['K_NASint and the 32-bit NAS COUNT for that record'])
    elif ue_decl['evidence'] == EVIDENCE_CLEARTEXT:
        rep.add('capability-cleartext', 'info',
                'the UE security capability was declared in cleartext: it is a '
                'statement on the wire, not an authenticated one',
                fields=[_field('RegistrationRequest.UESecCap',
                               _cap_text(ue_decl), EVIDENCE_CLEARTEXT,
                               _protection_of(ue_decl))],
                detail='TS 24.501, section 4.4.6 keeps UESecCap in cleartext '
                       'in the initial Registration Request by design')
    if echo_decl is not None and echo_decl['evidence'] != EVIDENCE_AUTHENTICATED:
        rep.add('echo-unauthenticated', 'warning',
                'the UE security capability echo in the Security Mode Command '
                'is not authenticated',
                fields=[_field('SecurityModeCommand.UESecCap',
                               _cap_text(echo_decl), echo_decl['evidence'],
                               _protection_of(echo_decl))],
                missing=['K_NASint and the 32-bit NAS COUNT, to verify the SMC '
                         'MAC under the selected integrity algorithm'])


def _check_selection(rep, decoded, decls):
    ue_decl   = decls.get('registration_request')
    echo_decl = decls.get('smc_echo')
    sel       = rep.selection
    ciph, integ = sel['ciphering'], sel['integrity']
    smc_ev = sel['evidence']
    smc_rec = next((d for d in decoded
                    if d.name == '5GMMSecurityModeCommand'), None)

    ue_ev = ue_decl['evidence'] if ue_decl else None
    echo_ev = echo_decl['evidence'] if echo_decl else None
    weak = (ciph == 0 or integ == 0)

    # 1. the protection carried by the SMC must be coherent with the algorithm
    # it selects: 5G-IA0 defines no MAC, so a non-zero MAC field is anomalous
    if smc_rec is not None and integ == 0 and \
            smc_rec.mac not in (None, b'\0\0\0\0'):
        rep.add('null-integrity-with-mac', 'warning',
                'the Security Mode Command selects 5G-IA0 but carries a '
                'non-zero MAC field',
                fields=[_field('SecurityModeCommand.NASSecAlgo.IntegAlgo',
                               '5G-IA0', smc_ev, _protection_text(smc_rec)),
                        _field('SecurityModeCommand.MAC',
                               hexlify(smc_rec.mac).decode(), smc_ev,
                               'non-zero, although 5G-IA0 defines no MAC')],
                missing=['the SMC as transmitted by the AMF, to tell a '
                         'malformed SMC from a rewritten one'])

    # 2. per-field comparison, reported regardless of the overall conclusion
    echo_c = _offers(echo_decl['bits'] if echo_decl else None, ciph, 'ciph')
    echo_i = _offers(echo_decl['bits'] if echo_decl else None, integ, 'ia')
    decl_c = _offers(ue_decl['bits'] if ue_decl else None, ciph, 'ciph')
    decl_i = _offers(ue_decl['bits'] if ue_decl else None, integ, 'ia')

    not_echoed = []
    if echo_c is False:
        not_echoed.append(('ciphering', ciph))
    if echo_i is False:
        not_echoed.append(('integrity', integ))
    if not_echoed:
        fields = []
        for kind, algo in not_echoed:
            fields.append(_field(
                'SecurityModeCommand.UESecCap.%s' %
                (('5G-EA%i' if kind == 'ciphering' else '5G-IA%i') % algo),
                0, echo_ev, _protection_of(echo_decl)))
            fields.append(_field(
                'SecurityModeCommand.NASSecAlgo.%s' %
                ('CiphAlgo' if kind == 'ciphering' else 'IntegAlgo'),
                '%s (%i)' % ((sel['ciphering_name'] if kind == 'ciphering'
                              else sel['integrity_name']), algo),
                smc_ev, _protection_of(sel)))
        rep.add('selection-not-echoed', 'warning',
                'the Security Mode Command selects an algorithm that its own '
                'UE capability echo does not contain',
                fields=fields,
                detail='the echo is the capability the AMF says it received; '
                       'a mismatch means the echo or the selection was '
                       'rewritten')

    not_offered = []
    if decl_c is False:
        not_offered.append('ciphering')
    if decl_i is False:
        not_offered.append('integrity')
    if not_offered:
        fields = []
        for kind in not_offered:
            algo = ciph if kind == 'ciphering' else integ
            fields.append(_field(
                'RegistrationRequest.UESecCap.%s' %
                (('5G-EA%i' if kind == 'ciphering' else '5G-IA%i') % algo),
                0, ue_ev, _protection_of(ue_decl)))
            fields.append(_field(
                'SecurityModeCommand.NASSecAlgo.%s' %
                ('CiphAlgo' if kind == 'ciphering' else 'IntegAlgo'),
                '%s (%i)' % ((sel['ciphering_name'] if kind == 'ciphering'
                              else sel['integrity_name']), algo),
                smc_ev, _protection_of(sel)))
        rep.add('selection-not-declared', 'warning',
                'the Security Mode Command selects an algorithm absent from '
                'the UE declaration',
                fields=fields,
                detail='the declaration is the capability the UE says it '
                       'holds; the selection is outside it')

    drift = []
    if ue_decl and echo_decl and ue_decl['bits'] is not None and \
            echo_decl['bits'] is not None:
        drift = _cap_diff(ue_decl['bits'], echo_decl['bits'])
        if drift:
            rep.add('capability-echo-drift', 'warning',
                    'the capability echo differs from the UE declaration: %s'
                    % ', '.join(drift),
                    fields=[_field('RegistrationRequest.UESecCap',
                                   _cap_text(ue_decl), ue_ev,
                                   _protection_of(ue_decl)),
                            _field('SecurityModeCommand.UESecCap',
                                   _cap_text(echo_decl), echo_ev,
                                   _protection_of(echo_decl))],
                    missing=['an independent copy of the UE capability on the '
                             'AMF/NGAP side, to show which bytes were rewritten'],
                    detail='a narrowed echo is also what a legitimate network '
                           'does when it restricts the offered set; by itself '
                           'it is not a downgrade')

    # 3. weak selection is an observation, never a conclusion by itself
    if weak:
        rep.add('weak-selection', 'info',
                'the selection includes a null algorithm (%s / %s)'
                % (sel['ciphering_name'], sel['integrity_name']),
                fields=[_field('SecurityModeCommand.NASSecAlgo.CiphAlgo',
                               '%s (%i)' % (sel['ciphering_name'], ciph),
                               smc_ev, _protection_of(sel)),
                        _field('SecurityModeCommand.NASSecAlgo.IntegAlgo',
                               '%s (%i)' % (sel['integrity_name'], integ),
                               smc_ev, _protection_of(sel))],
                detail='a null algorithm is not by itself evidence of a '
                       'downgrade: it is legitimate when both sides only '
                       'support null, or for emergency services')

    # 4. contradiction analysis
    contradiction = bool(drift or not_echoed or not_offered)
    both_auth = (ue_ev == EVIDENCE_AUTHENTICATED and
                 smc_ev == EVIDENCE_AUTHENTICATED)
    st = rep._state
    st['weak'] = weak
    st['contradiction'] = contradiction
    st['ue_ev'] = ue_ev
    st['smc_ev'] = smc_ev

    if ue_decl is None or ue_decl['bits'] is None:
        st['case'] = 'no-declaration'
        rep.add('declaration-unusable', 'warning',
                'no readable UE security capability declaration is available, '
                'so the selection cannot be compared with it',
                fields=[_field('RegistrationRequest.UESecCap', 'unusable',
                               ue_ev or EVIDENCE_ABSENT,
                               _protection_of(ue_decl) if ue_decl
                               else 'absent from the capture')],
                missing=['the Registration Request with a decodable UESecCap '
                         'IE'])
    elif not contradiction:
        if decl_c is not None and decl_i is not None:
            rep.add('selection-supported', 'info',
                    'the selected algorithms are present in the UE declaration '
                    'and in the SMC echo',
                    fields=[_field('RegistrationRequest.UESecCap',
                                   _cap_text(ue_decl), ue_ev,
                                   _protection_of(ue_decl)),
                            _field('SecurityModeCommand.NASSecAlgo',
                                   '%s / %s' % (sel['ciphering_name'],
                                                sel['integrity_name']),
                                   smc_ev, _protection_of(sel))])
        st['case'] = 'weak-consistent' if weak else 'consistent'
    elif both_auth:
        st['case'] = 'replaced-authenticated'
        rep.add('capability-replaced', 'warning',
                'two authenticated statements contradict each other: the UE '
                'declaration and the SMC capability echo/selection disagree',
                fields=[_field('RegistrationRequest.UESecCap',
                               _cap_text(ue_decl), ue_ev,
                               _protection_of(ue_decl)),
                        _field('SecurityModeCommand.UESecCap',
                               _cap_text(echo_decl) if echo_decl else 'absent',
                               echo_ev, _protection_of(echo_decl)),
                        _field('SecurityModeCommand.NASSecAlgo',
                               '%s / %s' % (sel['ciphering_name'],
                                            sel['integrity_name']),
                               smc_ev, _protection_of(sel))],
                missing=['an independent AMF or gNB trace of the same '
                         'procedure, to locate the hop where the capability '
                         'changed',
                         'the operator security policy or AMF configuration, '
                         'to tell a deliberate restriction from an attack'],
                detail='the replacement is inside this capture; which entity '
                       'performed it is not visible in NAS alone, and an '
                       'authorised test may deliberately narrow capabilities')
    elif smc_ev == EVIDENCE_AUTHENTICATED:
        st['case'] = 'replaced-unresolved'
        rep.add('capability-replaced', 'warning',
                'the authenticated Security Mode Command contradicts the '
                'cleartext UE declaration; the side that changed is unresolved',
                fields=[_field('RegistrationRequest.UESecCap',
                               _cap_text(ue_decl) if ue_decl else 'absent',
                               ue_ev, _protection_of(ue_decl)),
                        _field('SecurityModeCommand.UESecCap',
                               _cap_text(echo_decl) if echo_decl else 'absent',
                               echo_ev, _protection_of(echo_decl)),
                        _field('SecurityModeCommand.NASSecAlgo',
                               '%s / %s' % (sel['ciphering_name'],
                                            sel['integrity_name']),
                               smc_ev, _protection_of(sel))],
                detail='the UE statement is cleartext by design in an initial '
                       'Registration Request, so it cannot outrank the SMC')
    elif ue_ev == EVIDENCE_AUTHENTICATED:
        st['case'] = 'smc-unverified'
        rep.add('capability-mismatch-unverified', 'warning',
                'an authenticated UE declaration is contradicted by a '
                'Security Mode Command whose MAC was not verified',
                fields=[_field('RegistrationRequest.UESecCap',
                               _cap_text(ue_decl), ue_ev,
                               _protection_of(ue_decl)),
                        _field('SecurityModeCommand.NASSecAlgo',
                               '%s / %s' % (sel['ciphering_name'],
                                            sel['integrity_name']),
                               smc_ev, _protection_of(sel))],
                detail='the SMC is not authenticated, so it may itself be the '
                       'rewritten message')
    else:
        st['case'] = 'unresolved'
        rep.add('capability-mismatch-unverified', 'warning',
                'a capability mismatch is visible, but neither statement is '
                'authenticated',
                fields=[_field('RegistrationRequest.UESecCap',
                               _cap_text(ue_decl) if ue_decl else 'absent',
                               ue_ev, _protection_of(ue_decl)),
                        _field('SecurityModeCommand.NASSecAlgo',
                               '%s / %s' % (sel['ciphering_name'],
                                            sel['integrity_name']),
                               smc_ev, _protection_of(sel))])

    _conclude_selection(rep, ue_decl, echo_decl, sel)


def _conclude_selection(rep, ue_decl, echo_decl, sel):
    st = rep._state
    case = st.get('case')
    missing = []
    if st.get('ue_ev') != EVIDENCE_AUTHENTICATED:
        missing.append('an authenticated UE capability statement: the '
                       'declaration used here is cleartext')
    if st.get('smc_ev') != EVIDENCE_AUTHENTICATED:
        missing.append('an authenticated SMC: %s' % sel['protection'])

    if case == 'no-declaration':
        status = STATUS_INSUFFICIENT
        summary = ('an algorithm selection was observed but no usable UE '
                   'capability declaration is available, so consistency '
                   'cannot be evaluated')
        missing += ['the Registration Request with a decodable UESecCap IE']
    elif case == 'replaced-authenticated':
        status = STATUS_INCONSISTENT
        summary = ('both the UE declaration and the Security Mode Command are '
                   'authenticated and they contradict each other: a capability '
                   'replacement inside this capture is confirmed, but a '
                   'downgrade is not')
        missing += ['an independent AMF or gNB trace of the same procedure, to '
                    'locate where the capability changed',
                    'the operator security policy, to tell a deliberate '
                    'restriction from an attack']
    elif case == 'replaced-unresolved':
        status = STATUS_INCONSISTENT
        summary = ('the authenticated Security Mode Command contradicts the '
                   'cleartext UE declaration; an inconsistency is confirmed, '
                   'the side that changed is not, and no downgrade is claimed')
        missing += ['an independent copy of the Registration Request PDU at '
                    'the AMF/NGAP side',
                    'proof that the SMC belongs to this Registration Request '
                    '(the SMC carries no UE identity)']
    elif case == 'smc-unverified':
        status = STATUS_INCONSISTENT
        summary = ('an authenticated UE declaration is contradicted by an SMC '
                   'whose MAC could not be verified; the mismatch is visible, '
                   'the SMC itself may be the rewritten message')
        missing += ['a verifiable integrity algorithm on the SMC, or an '
                    'independent AMF/NGAP trace of the same procedure']
    elif case == 'unresolved':
        status = STATUS_INSUFFICIENT
        summary = ('a capability mismatch is visible, but neither statement is '
                   'authenticated; no conclusion is drawn')
        missing += ['an authenticated UE capability statement']
    elif case == 'weak-consistent':
        status = STATUS_WEAK_CONSISTENT
        summary = ('the selection includes a null algorithm, but the observed '
                   'statements agree; a weak choice alone is not a downgrade')
        missing += ['the operator security policy or the AMF configuration, to '
                    'tell a deliberate null-algorithm choice from a downgrade']
    else:
        status = STATUS_CONSISTENT
        summary = ('the selected algorithms are supported by the UE '
                   'declaration and the SMC echo; no inconsistency')

    rep.conclusion = {
        'status'                          : status,
        'confirmed_downgrade'             : False,
        'confirmed_capability_replacement': case == 'replaced-authenticated',
        'summary'                         : summary,
        'missing_evidence'                : missing,
        }


def _conclude_no_selection(rep, decoded, decls):
    smc_gap = any(d.gap and 'security mode' in (d.gap or '').lower()
                  for d in decoded)
    missing = ['the Security Mode Command PDU for this procedure']
    if smc_gap:
        missing.append('the capture gap is not evidence of a downgrade: '
                       'without the SMC no algorithm choice was observed')
    ue_decl = decls.get('registration_request')
    if ue_decl is None or ue_decl['evidence'] != EVIDENCE_AUTHENTICATED:
        missing.append('an authenticated UE capability statement')
    rep.conclusion = {
        'status'                          : STATUS_INSUFFICIENT,
        'confirmed_downgrade'             : False,
        'confirmed_capability_replacement': False,
        'summary'                         : ('no algorithm selection was '
                                             'observed, so consistency cannot '
                                             'be evaluated; the missing '
                                             'Security Mode Command is '
                                             'reported as missing evidence, '
                                             'not as a downgrade'),
        'missing_evidence'                : missing,
        }
