# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.8
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
# * File Name : pycrate_mobile/TCAPReassembly.py
# * Created : 2026-11-19
# *--------------------------------------------------------
#*/

"""Offline TCAP dialogue reassembly on top of the pycrate ASN.1 objects.

Why a single transaction-ID dictionary merges dialogues
-------------------------------------------------------
TCAP identifies a dialogue with two short, endpoint-local IDs: the originating
transaction ID (OTID) chosen by the initiator and the destination transaction
ID (DTID) chosen by the responder.  Each ID is 1 to 4 bytes (ITU-T Q.773).
They are meaningful only inside one endpoint pair:

* two unrelated endpoint pairs may both use ``0x0001``;
* one endpoint pair may reuse ``0x0001`` after a dialogue reached End or Abort;
* End and Abort carry only the peer's ID, so ownership depends on direction.

Keying a dictionary on one ID therefore joins unrelated dialogues.  This module
scopes every association to an unordered endpoint pair and stores, per
dialogue, which transaction ID each endpoint owns::

    owned = {"10.0.0.1": b"\\x00\\x01", "10.0.0.2": b"\\x00\\x03"}

A message matches a dialogue when the sender-owned ID (OTID) and the
receiver-owned ID (DTID) agree on every side where the dialogue already knows
an ID.  A disagreement on either side rejects the candidate even if the other
ID matches, which is what prevents a reused peer ID from merging dialogues.

Operation arguments are deliberately not retained or compared: component
summaries keep only component kind, invoke ID, opcode and error code.  Equal
arguments are not evidence that two messages belong to the same dialogue.

Entry points
------------
::

    decode_tcap_message(buf, index=0, src='A', dst='B', timestamp=None)
    Reassembler().process(messages)   -> ReassemblyResult
    single_id_groups(messages)        -> naive one-ID grouping for comparison
    demo_scenario()                   -> built-in demonstration capture
"""

from binascii import unhexlify, hexlify

from pycrate_asn1dir.TCAP_MAP import TCAP_MAP_Messages
from pycrate_asn1rt.glob import GLOBAL

# TCAP_RAW declares a module named TCAPMessages like TCAP_MAP does, and loading
# it replaces the registry entry that TCAP_MAP's resolved references point to.
# Import it lazily once and restore the registry so decoding with either module
# keeps working, including in processes that import both (e.g. the test suite).
_TCAP_RAW_MESSAGES = None


def _tcap_raw_messages():
    global _TCAP_RAW_MESSAGES
    if _TCAP_RAW_MESSAGES is None:
        registry = GLOBAL.MOD
        saved = registry['TCAPMessages'] if 'TCAPMessages' in registry else None
        from pycrate_asn1dir.TCAP_RAW import TCAP_Messages as raw
        if saved is not None:
            registry['TCAPMessages'] = saved
        _TCAP_RAW_MESSAGES = raw
    return _TCAP_RAW_MESSAGES


BEGIN = 'Begin'
CONTINUE = 'Continue'
END = 'End'
ABORT = 'Abort'
UNIDIRECTIONAL = 'Unidirectional'
MESSAGE_KINDS = (BEGIN, CONTINUE, END, ABORT, UNIDIRECTIONAL)

FOLLOWUP_KINDS = (CONTINUE, END, ABORT)
TERMINAL_KINDS = frozenset((END, ABORT))

#: Maximum transaction ID size in bytes, per ITU-T Q.773 (1..4).
MAX_TID_LEN = 4

#: Matching weights.  A pair match (both sides known and equal) scores 4, a
#: single-side match scores 2.  Scores never create a link from arguments.
SENDER_MATCH = 2
PEER_MATCH = 2


class DecodeError(Exception):
    """Raised when a buffer cannot be decoded as TCAP at all."""


#------------------------------------------------------------------------------#
# small helpers
#------------------------------------------------------------------------------#

def tid_text(tid):
    """Return an uppercase hexadecimal label for a transaction ID."""
    if tid is None:
        return None
    if isinstance(tid, str):
        return tid.upper()
    return hexlify(tid).decode('ascii').upper()


def _as_bytes(tid):
    if tid is None or isinstance(tid, bytes):
        return tid
    if isinstance(tid, bytearray):
        return bytes(tid)
    if isinstance(tid, str):
        return unhexlify(tid)
    return bytes(tid)


def _jsonable(value):
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return hexlify(value).decode('ascii').upper()
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return dict((str(key), _jsonable(item)) for key, item in value.items())
    return str(value)


def _read_tlv(buf, pos):
    if pos + 2 > len(buf):
        raise DecodeError('truncated tag/length at offset %d' % pos)
    tag = buf[pos]
    pos += 1
    first = buf[pos]
    pos += 1
    if first & 0x80:
        count = first & 0x7f
        if count == 0 or count > 4 or pos + count > len(buf):
            raise DecodeError('invalid length prefix at offset %d' % (pos - 1))
        length = int.from_bytes(buf[pos:pos + count], 'big')
        pos += count
    else:
        length = first
    end = pos + length
    if end > len(buf):
        raise DecodeError('truncated value at offset %d' % pos)
    return tag, buf[pos:end], end


#------------------------------------------------------------------------------#
# message model
#------------------------------------------------------------------------------#

class Evidence(object):
    """One reason supporting an association or annotating a decision."""

    __slots__ = ('code', 'detail')

    def __init__(self, code, detail):
        self.code = code
        self.detail = detail

    def to_dict(self):
        return {'code': self.code, 'detail': self.detail}

    def __repr__(self):
        return '<%s: %s>' % (self.code, self.detail)


class TcapMessage(object):
    """A normalized TCAP message.

    Attributes:
        index: position in the input sequence (0-based)
        timestamp: caller supplied timestamp or None
        src: source endpoint label
        dst: destination endpoint label
        kind: Begin, Continue, End, Abort or Unidirectional
        otid: sender-owned transaction ID (bytes) or None
        dtid: receiver-owned transaction ID (bytes) or None
        components: summaries without operation arguments
        dialogue_context: application-context OID or None
        abort_cause: decoded abort cause or None
        raw: original BER bytes
        decode_layer: 'map', 'tcap' or 'structural'
        warnings: decoding anomalies
        direction: 'forward', 'reverse' or 'unknown' once attached
        dialogue_id: owning dialogue once attached
        link_strength: 'anchor', 'pair', 'single' or 'late'
        link_evidence: list of Evidence explaining the link
    """

    __slots__ = ('index', 'timestamp', 'src', 'dst', 'kind', 'otid', 'dtid',
                 'components', 'dialogue_context', 'abort_cause', 'raw',
                 'decode_layer', 'warnings', 'direction', 'dialogue_id',
                 'link_strength', 'link_evidence')

    def __init__(self, index, src, dst, kind, otid=None, dtid=None,
                 timestamp=None, components=None, dialogue_context=None,
                 abort_cause=None, raw=None, decode_layer='map', warnings=None):
        self.index = index
        self.timestamp = timestamp
        self.src = str(src)
        self.dst = str(dst)
        self.kind = kind
        self.otid = _as_bytes(otid)
        self.dtid = _as_bytes(dtid)
        self.components = components or []
        self.dialogue_context = dialogue_context
        self.abort_cause = abort_cause
        self.raw = raw
        self.decode_layer = decode_layer
        self.warnings = list(warnings or [])
        self.direction = None
        self.dialogue_id = None
        self.link_strength = None
        self.link_evidence = []

    def to_dict(self):
        return {
            'index': self.index,
            'timestamp': _jsonable(self.timestamp),
            'src': self.src,
            'dst': self.dst,
            'direction': self.direction,
            'dialogue_id': self.dialogue_id,
            'kind': self.kind,
            'otid': tid_text(self.otid),
            'dtid': tid_text(self.dtid),
            'components': _jsonable(self.components),
            'dialogue_context': _jsonable(list(self.dialogue_context))
                if self.dialogue_context else None,
            'abort_cause': _jsonable(self.abort_cause),
            'decode_layer': self.decode_layer,
            'link_strength': self.link_strength,
            'link_evidence': [e.to_dict() for e in self.link_evidence],
            'warnings': list(self.warnings),
        }

    def __repr__(self):
        return '<TcapMessage %d %s %s->%s otid=%s dtid=%s>' % (
            self.index, self.kind, self.src, self.dst,
            tid_text(self.otid), tid_text(self.dtid))


class Dialogue(object):
    """A reassembled TCAP dialogue.

    IDs are stored per owning endpoint in ``owned``, which is independent of
    the direction of any single message.  The initiator is known from the Begin
    that established the dialogue; for an orphaned dialogue (observed only from
    a Continue) it stays None and the dialogue is flagged uncertain.
    """

    __slots__ = ('dialogue_id', 'endpoints', 'owned', 'initiator', 'responder',
                 'state', 'end_reason', 'abort_cause', 'messages',
                 'late_messages', 'uncertain', 'uncertainty', 'unterminated',
                 'reused_with', 'confidence', 'evidence')

    def __init__(self, dialogue_id, endpoints, uncertain=False):
        self.dialogue_id = dialogue_id
        self.endpoints = tuple(endpoints)
        self.owned = {}
        self.initiator = None
        self.responder = None
        self.state = 'open'
        self.end_reason = None
        self.abort_cause = None
        self.messages = []
        self.late_messages = []
        self.uncertain = uncertain
        self.uncertainty = []
        self.unterminated = False
        self.reused_with = []
        self.confidence = 'strong'
        self.evidence = []

    def add_uncertainty(self, reason):
        self.uncertain = True
        if reason not in self.uncertainty:
            self.uncertainty.append(reason)

    def direction(self, msg):
        if self.initiator is None:
            return 'unknown'
        return 'forward' if msg.src == self.initiator else 'reverse'

    def observe(self, msg, evidence, strength):
        msg.direction = self.direction(msg)
        msg.dialogue_id = self.dialogue_id
        msg.link_strength = strength
        msg.link_evidence = list(evidence)
        self.messages.append(msg)
        self.evidence.extend(evidence)
        if msg.kind in TERMINAL_KINDS:
            self.state = 'closed'
            self.end_reason = msg.kind
            if msg.kind == ABORT:
                self.abort_cause = msg.abort_cause

    def observe_late(self, msg, evidence):
        msg.direction = self.direction(msg)
        msg.dialogue_id = self.dialogue_id
        msg.link_strength = 'late'
        msg.link_evidence = list(evidence)
        self.late_messages.append(msg)
        self.evidence.extend(evidence)

    def interval(self):
        stamps = [m.timestamp for m in self.messages + self.late_messages
                  if m.timestamp is not None]
        if not stamps:
            return (None, None)
        try:
            return (min(stamps), max(stamps))
        except TypeError:
            return (stamps[0], stamps[-1])

    def to_dict(self):
        start, stop = self.interval()
        return {
            'dialogue_id': self.dialogue_id,
            'endpoints': list(self.endpoints),
            'initiator': self.initiator,
            'responder': self.responder,
            'owned_ids': dict((ep, tid_text(tid))
                              for ep, tid in self.owned.items()),
            'state': self.state,
            'end_reason': self.end_reason,
            'abort_cause': _jsonable(self.abort_cause),
            'unterminated': self.unterminated,
            'uncertain': self.uncertain,
            'uncertainty': list(self.uncertainty),
            'confidence': self.confidence,
            'reused_with': list(self.reused_with),
            'observation_interval': {'start': _jsonable(start),
                                     'stop': _jsonable(stop)},
            'messages': [m.to_dict() for m in self.messages],
            'late_messages': [m.to_dict() for m in self.late_messages],
            'evidence': [e.to_dict() for e in self.evidence],
        }

    def summary_line(self):
        start, stop = self.interval()
        ids = ','.join('%s=%s' % (ep, tid_text(tid) or '-')
                       for ep, tid in sorted(self.owned.items()))
        return ('%s [%s] %s state=%s%s confidence=%s msgs=%d late=%d '
                'interval=%s..%s'
                % (self.dialogue_id, ' <-> '.join(self.endpoints), ids,
                   self.state, ' UNCERTAIN' if self.uncertain else '',
                   self.confidence, len(self.messages),
                   len(self.late_messages), start, stop))


class ReassemblyResult(object):

    __slots__ = ('dialogues', 'unresolved', 'messages', 'scopes')

    def __init__(self, dialogues, unresolved, messages, scopes):
        self.dialogues = dialogues
        self.unresolved = unresolved
        self.messages = messages
        self.scopes = scopes

    def to_dict(self):
        return {
            'scopes': self.scopes,
            'dialogues': [d.to_dict() for d in self.dialogues],
            'unresolved': self.unresolved,
            'naive_single_id_groups': single_id_groups(self.messages),
            'statistics': {
                'messages': len(self.messages),
                'dialogues': len(self.dialogues),
                'unresolved': len(self.unresolved),
                'late_messages': sum(len(d.late_messages) for d in self.dialogues),
                'uncertain_dialogues': sum(1 for d in self.dialogues if d.uncertain),
            },
        }


#------------------------------------------------------------------------------#
# decoding
#------------------------------------------------------------------------------#

def _component_summary(value):
    """Summarize components while dropping operation arguments."""
    out = []
    if not isinstance(value, list):
        return out
    for item in value:
        try:
            tag, comp = item
        except Exception:
            out.append({'kind': str(item)})
            continue
        if tag != 'basicROS' or not isinstance(comp, tuple) or len(comp) != 2:
            out.append({'kind': str(tag)})
            continue
        kind, body = comp
        summary = {'kind': str(kind)}
        if isinstance(body, dict):
            inv = body.get('invokeId')
            if isinstance(inv, tuple) and len(inv) == 2:
                summary['invoke_id'] = _jsonable(inv[1])
            op = body.get('opcode')
            if isinstance(op, tuple) and len(op) == 2:
                summary['opcode'] = {'kind': str(op[0]), 'value': _jsonable(op[1])}
            err = body.get('errorCode')
            if isinstance(err, tuple) and len(err) == 2:
                summary['error_code'] = {'kind': str(err[0]),
                                         'value': _jsonable(err[1])}
        out.append(summary)
    return out


def _dialogue_context(value):
    dp = value.get('dialoguePortion')
    if not isinstance(dp, dict):
        return None
    enc = dp.get('encoding')
    if not isinstance(enc, tuple) or len(enc) != 2:
        return None
    pdu = enc[1]
    if not isinstance(pdu, tuple):
        return None
    body = pdu[1] if len(pdu) == 2 else pdu[0]
    if isinstance(body, tuple) and len(body) == 2:
        body = body[1]
    if isinstance(body, dict):
        ctx = body.get('application-context-name')
        if isinstance(ctx, tuple):
            return tuple(ctx)
    return None


def _abort_cause(value):
    reason = value.get('reason')
    if not isinstance(reason, tuple) or len(reason) != 2:
        return None
    tag, cause = reason
    if isinstance(cause, tuple) and len(cause) == 1:
        cause = cause[0]
    return {'kind': str(tag), 'value': _jsonable(cause)}


def _structural_decode(buf):
    """Recover the transaction portion by walking BER TLVs.

    Used when the MAP module rejects an out-of-range MAP parameter or when an
    ID violates the 1..4 byte constraint.  Components are not decoded, but the
    message type and IDs, which drive reassembly, are recovered.
    """
    if not buf:
        raise DecodeError('empty buffer')
    tag, body, _ = _read_tlv(buf, 0)
    kinds = {0x61: UNIDIRECTIONAL, 0x62: BEGIN, 0x64: END,
             0x65: CONTINUE, 0x67: ABORT}
    if tag not in kinds:
        raise DecodeError('not a TCAP message (tag 0x%02X)' % tag)
    kind = kinds[tag]
    otid = dtid = None
    warnings = []
    pos = 0
    while pos < len(body):
        ctag, cval, pos = _read_tlv(body, pos)
        if ctag == 0x48:
            otid = cval
        elif ctag == 0x49:
            dtid = cval
    for name, tid in (('OTID', otid), ('DTID', dtid)):
        if tid is not None and not 1 <= len(tid) <= MAX_TID_LEN:
            warnings.append('%s length %d outside 1..%d'
                            % (name, len(tid), MAX_TID_LEN))
    return {'kind': kind, 'otid': otid, 'dtid': dtid,
            'components': [], 'dialogue_context': None, 'abort_cause': None,
            'decode_layer': 'structural', 'warnings': warnings}


def decode_tcap_message(buf, index=0, src='A', dst='B', timestamp=None):
    """Decode one TCAP message into a TcapMessage.

    The MAP-aware module is tried first so operation names resolve.  If it
    rejects the message (typically an out-of-range MAP parameter), the
    transaction-only module is used.  If both reject it, a structural TLV walk
    recovers the transaction portion.  Non-TCAP input raises DecodeError.

    Args:
        buf: BER bytes or a hexadecimal string
        index: caller supplied sequence number
        src, dst: endpoint labels used for scoping and direction
        timestamp: caller supplied timestamp (any comparable value)
    """
    if isinstance(buf, str):
        try:
            buf = unhexlify(buf)
        except Exception as err:
            raise DecodeError('invalid hex input: %s' % err)

    map_error = None
    try:
        obj = TCAP_MAP_Messages.TCAP_MAP_Message
        obj.from_ber(buf)
        kind, body = obj.get_val()
        layer = 'map'
    except Exception as err:
        map_error = '%s: %s' % (type(err).__name__, err)
        try:
            obj = _tcap_raw_messages().TCAP_Message
            obj.from_ber(buf)
            kind, body = obj.get_val()
            layer = 'tcap'
        except Exception:
            struct = _structural_decode(buf)
            msg = TcapMessage(index, src, dst, struct['kind'],
                              otid=struct['otid'], dtid=struct['dtid'],
                              timestamp=timestamp,
                              components=struct['components'],
                              dialogue_context=struct['dialogue_context'],
                              abort_cause=struct['abort_cause'],
                              raw=buf, decode_layer='structural',
                              warnings=struct['warnings'])
            msg.warnings.append('MAP and TCAP decoders rejected the message; '
                                'structural TLV walk used')
            return msg

    body = body or {}
    kind = str(kind)
    kind = kind[:1].upper() + kind[1:].lower()
    if kind == 'Unidirectional':
        kind = UNIDIRECTIONAL
    if kind not in MESSAGE_KINDS:
        raise DecodeError('unsupported TCAP message type %r' % kind)

    otid = _as_bytes(body.get('otid')) if body.get('otid') is not None else None
    dtid = _as_bytes(body.get('dtid')) if body.get('dtid') is not None else None
    warnings = []
    for name, tid in (('OTID', otid), ('DTID', dtid)):
        if tid is not None and not 1 <= len(tid) <= MAX_TID_LEN:
            warnings.append('%s length %d outside 1..%d'
                            % (name, len(tid), MAX_TID_LEN))

    msg = TcapMessage(index, src, dst, kind, otid=otid, dtid=dtid,
                      timestamp=timestamp,
                      components=_component_summary(body.get('components')),
                      dialogue_context=_dialogue_context(body),
                      abort_cause=_abort_cause(body) if kind == ABORT else None,
                      raw=buf, decode_layer=layer, warnings=warnings)
    if map_error:
        msg.warnings.append('MAP decoder rejected the message (%s); '
                            'transaction-only decoder used' % map_error)
    return msg


#------------------------------------------------------------------------------#
# reassembly
#------------------------------------------------------------------------------#

def scope_key(src, dst):
    """Return the unordered endpoint-pair key that scopes transaction IDs."""
    return tuple(sorted((str(src), str(dst))))


def _id_length_issues(msg):
    issues = []
    for field, tid in (('OTID', msg.otid), ('DTID', msg.dtid)):
        if tid is not None and not 1 <= len(tid) <= MAX_TID_LEN:
            issues.append('%s length %d outside 1..%d'
                          % (field, len(tid), MAX_TID_LEN))
    return issues


class Reassembler(object):
    """Associate decoded TCAP messages into dialogues.

    Steps:

    1. Partition by unordered endpoint pair; IDs never cross scopes.
    2. Begin establishes a new dialogue and records the initiator-owned ID.
       A reused ID links the dialogues (``reused_with``) but never merges
       them.
    3. Continue records both endpoint-owned IDs.  End and Abort record the
       receiver-owned ID and close the dialogue.
    4. Follow-up messages match on sender-owned and receiver-owned IDs,
       rejecting any candidate where a known ID disagrees.  On a tie, a single
       open candidate is preferred over closed ones (a closed dialogue cannot
       accept a new in-dialogue message); otherwise the message stays
       unresolved with all candidates listed.
    5. A message matching only a closed dialogue is retained as a late
       message on that dialogue.
    6. A Continue with no match opens an uncertain orphan dialogue, because it
       carries both IDs and can anchor later messages when a Begin is missing.
       An End/Abort with no match stays unresolved: one ID is not enough to
       establish a dialogue.
    7. At the end, still-open dialogues are marked unterminated, and the
       observation interval of each dialogue is reported.
    """

    def process(self, messages):
        self._dialogues = []
        self._unresolved = []
        self._scopes = {}
        for msg in messages:
            if msg.kind not in MESSAGE_KINDS:
                self._unresolved.append(self._entry(
                    msg, 'unsupported message type',
                    'kind %r is not a TCAP message type' % msg.kind))
                continue
            key = scope_key(msg.src, msg.dst)
            self._scopes.setdefault(key, []).append(msg)
            if msg.kind == BEGIN:
                self._begin(msg, key)
            elif msg.kind == UNIDIRECTIONAL:
                self._unidirectional(msg, key)
            else:
                self._followup(msg, key)
        self._finalize()
        scope_info = [{'endpoints': list(key),
                       'messages': len(msgs),
                       'dialogues': [d.dialogue_id for d in self._dialogues
                                     if d.endpoints == key]}
                      for key, msgs in self._scopes.items()]
        return ReassemblyResult(self._dialogues, self._unresolved,
                                list(messages), scope_info)

    # -- creation --------------------------------------------------------- #

    def _new_dialogue(self, endpoints, uncertain=False):
        dia = Dialogue('D%04d' % (len(self._dialogues) + 1), endpoints,
                       uncertain=uncertain)
        self._dialogues.append(dia)
        return dia

    def _scope_dialogues(self, key):
        return [d for d in self._dialogues if d.endpoints == key]

    def _begin(self, msg, key):
        if msg.otid is None:
            self._unresolved.append(self._entry(
                msg, 'Begin without OTID',
                'a Begin must carry an originating transaction ID'))
            return
        # The endpoint pair is unordered, but the dialogue needs a stable
        # forward direction.  The Begin defines it, so normalize the message
        # direction to the scope order instead of trusting the caller's
        # src/dst ordering.
        if msg.src != key[0]:
            msg.src, msg.dst = msg.dst, msg.src
            msg.warnings.append('Begin direction normalized to endpoint order')
        # A Begin can arrive after a Continue for the same dialogue when the
        # capture is out of order.  If exactly one uncertain orphan in this
        # scope has no initiator yet and its ID for this sender matches, adopt
        # it: the Begin supplies the missing direction without inventing one.
        orphans = [d for d in self._scope_dialogues(key)
                   if d.initiator is None and d.state == 'open'
                   and d.owned.get(msg.src) == msg.otid]
        if len(orphans) == 1:
            dia = orphans[0]
            dia.initiator = msg.src
            dia.responder = msg.dst
            retained = [text for text in dia.uncertainty
                        if 'Begin not observed' not in text]
            dia.uncertainty = retained
            dia.uncertain = bool(retained)
            dia.evidence.append(Evidence(
                'begin-adopts-orphan',
                'Begin supplied the missing direction for the orphan dialogue '
                'anchored by an earlier Continue'))
            dia.observe(msg, [Evidence('begin-starts-dialogue',
                                       'Begin establishes the dialogue direction')],
                        'anchor')
            return
        if len(orphans) > 1:
            self._unresolved.append(self._entry(
                msg, 'ambiguous orphan adoption',
                'OTID %s matches several orphan dialogues without an initiator: '
                '%s' % (tid_text(msg.otid),
                        ', '.join(d.dialogue_id for d in orphans)),
                [d.dialogue_id for d in orphans]))
            return
        prior = [d for d in self._scope_dialogues(key)
                 if d.owned.get(msg.src) == msg.otid]
        dia = self._new_dialogue(key)
        dia.initiator = msg.src
        dia.responder = msg.dst
        dia.owned[msg.src] = msg.otid
        evidence = [Evidence('begin-starts-dialogue',
                             'Begin establishes a new dialogue')]
        for old in prior:
            if old.dialogue_id not in dia.reused_with:
                dia.reused_with.append(old.dialogue_id)
            if dia.dialogue_id not in old.reused_with:
                old.reused_with.append(dia.dialogue_id)
            evidence.append(Evidence(
                'id-reused',
                'OTID %s was already used by %s'
                % (tid_text(msg.otid), old.dialogue_id)))
            if old.state == 'closed':
                evidence.append(Evidence(
                    'id-reused-after-terminal',
                    '%s already ended as %s'
                    % (old.dialogue_id, old.end_reason)))
            else:
                evidence.append(Evidence(
                    'id-reused-while-open',
                    '%s was still open when %s reused its ID'
                    % (old.dialogue_id, dia.dialogue_id)))
                dia.add_uncertainty('transaction ID reused while %s was open'
                                    % old.dialogue_id)
        issues = _id_length_issues(msg)
        for issue in issues:
            evidence.append(Evidence('nonconformant-id-length', issue))
            dia.add_uncertainty(issue)
        dia.observe(msg, evidence, 'anchor')

    def _unidirectional(self, msg, key):
        dia = self._new_dialogue(key)
        evidence = [Evidence('unidirectional',
                             'Unidirectional message has no transaction state')]
        if msg.otid is not None:
            dia.owned[msg.src] = msg.otid
        if msg.dtid is not None:
            dia.owned[msg.dst] = msg.dtid
        dia.observe(msg, evidence, 'anchor')
        dia.state = 'closed'
        dia.end_reason = UNIDIRECTIONAL

    # -- matching --------------------------------------------------------- #

    def _match(self, dia, msg):
        """Score ``msg`` against ``dia``; return (score, evidence, conflict).

        OTID must equal the ID owned by ``msg.src`` and DTID the ID owned by
        ``msg.dst``.  A known ID that differs is a hard conflict even when the
        other ID matches, because a dialogue has exactly one ID per endpoint.

        End and Abort carry no OTID.  The packet source identifies the sender,
        but that is not independent evidence: every dialogue in the scope
        shares the same endpoint pair, so the sender's own ID contributes no
        score.  Such a message is linked by its peer ID alone and reported as
        a ``single``-strength link.
        """
        score = 0
        evidence = []
        conflict = False
        if msg.otid is not None:
            known = dia.owned.get(msg.src)
            if known is not None:
                if known == msg.otid:
                    score += SENDER_MATCH
                    evidence.append(Evidence(
                        'sender-id-match',
                        'OTID %s equals the ID %s owns in %s'
                        % (tid_text(msg.otid), msg.src, dia.dialogue_id)))
                else:
                    conflict = True
                    evidence.append(Evidence(
                        'sender-id-conflict',
                        'OTID %s differs from %s owned by %s in %s'
                        % (tid_text(msg.otid), tid_text(known), msg.src,
                           dia.dialogue_id)))
        if msg.dtid is not None:
            known = dia.owned.get(msg.dst)
            if known is not None:
                if known == msg.dtid:
                    score += PEER_MATCH
                    evidence.append(Evidence(
                        'peer-id-match',
                        'DTID %s equals the ID %s owns in %s'
                        % (tid_text(msg.dtid), msg.dst, dia.dialogue_id)))
                else:
                    conflict = True
                    evidence.append(Evidence(
                        'peer-id-conflict',
                        'DTID %s differs from %s owned by %s in %s'
                        % (tid_text(msg.dtid), tid_text(known), msg.dst,
                           dia.dialogue_id)))
        if conflict:
            return 0, evidence, True
        if msg.kind in TERMINAL_KINDS and msg.otid is None:
            # End/Abort name only the peer ID.  The packet source tells us who
            # sent it, but that is not independent evidence: every dialogue in
            # this scope shares the same endpoint pair.  The sender's owned ID
            # must therefore not contribute a score; the peer-ID match alone
            # decides, and a tie between dialogues stays unresolved unless an
            # open dialogue can be preferred.
            evidence.append(Evidence(
                'sender-id-absent',
                '%s carries no OTID; only the peer ID is available for '
                'matching %s' % (msg.kind, dia.dialogue_id)))
        return score, evidence, False

    def _followup(self, msg, key):
        scored = []
        conflicts = []
        for dia in self._scope_dialogues(key):
            score, evidence, conflict = self._match(dia, msg)
            if conflict:
                conflicts.append((dia.dialogue_id, evidence))
            elif score:
                scored.append((score, dia, evidence))
        if not scored:
            self._no_match(msg, key, conflicts)
            return

        best = max(item[0] for item in scored)
        top = [item for item in scored if item[0] == best]
        if len(top) == 1:
            self._attach(msg, top[0])
            return

        # A tie on IDs alone.  One state-based distinction is still sound:
        # a dialogue that already reached End/Abort cannot accept a new
        # in-dialogue message, so a message that would re-open it is late.
        # When exactly one tied candidate is open, prefer it and record the
        # state evidence explicitly.  Otherwise leave the message unresolved:
        # preferring a closed dialogue, the most recent one, or one with
        # similar operation arguments would be a guess.
        open_top = [item for item in top if item[1].state == 'open']
        if len(open_top) == 1:
            evidence = list(open_top[0][2])
            evidence.append(Evidence(
                'open-dialogue-preferred',
                'IDs match %s equally; only %s is open, the others already '
                'reached End/Abort'
                % (', '.join(item[1].dialogue_id for item in top),
                   open_top[0][1].dialogue_id)))
            self._attach(msg, (open_top[0][0], open_top[0][1], evidence))
            return
        candidates = [item[1].dialogue_id for item in top]
        states = sorted(set(item[1].state for item in top))
        reason = ('ambiguous open association' if 'open' in states
                  else 'ambiguous late message')
        self._unresolved.append(self._entry(
            msg, reason,
            'IDs match dialogues %s equally and they are in the same state; '
            'only one TCAP ID is available or it was reused, so no unique '
            'link can be proven' % ', '.join(candidates),
            candidates))

    def _attach(self, msg, item):
        score, dia, evidence = item
        evidence = list(evidence)
        if dia.state == 'closed':
            evidence.append(Evidence(
                'late-after-terminal',
                '%s arrived after %s ended as %s; kept as a late message'
                % (msg.kind, dia.dialogue_id, dia.end_reason)))
            dia.observe_late(msg, evidence)
            return
        strength = 'pair' if score >= SENDER_MATCH + PEER_MATCH else 'single'
        # Learn IDs that the dialogue did not know yet.
        if msg.otid is not None and msg.src not in dia.owned:
            dia.owned[msg.src] = msg.otid
            evidence.append(Evidence('sender-id-learned',
                                     'learned that %s owns %s'
                                     % (msg.src, tid_text(msg.otid))))
        if msg.dtid is not None and msg.dst not in dia.owned:
            dia.owned[msg.dst] = msg.dtid
            evidence.append(Evidence('peer-id-learned',
                                     'learned that %s owns %s'
                                     % (msg.dst, tid_text(msg.dtid))))
        if msg.otid is not None and msg.dtid is not None and msg.otid == msg.dtid:
            dia.add_uncertainty(
                'OTID and DTID are equal (%s); the ID is not a distinguishing '
                'pair' % tid_text(msg.otid))
        issues = _id_length_issues(msg)
        for issue in issues:
            dia.add_uncertainty(issue)
            evidence.append(Evidence('nonconformant-id-length', issue))
        if strength == 'single':
            evidence.append(Evidence(
                'single-id-link',
                'only one side of the dialogue was known when the message '
                'was matched'))
        dia.observe(msg, evidence, strength)

    def _no_match(self, msg, key, conflicts):
        if msg.kind == CONTINUE and msg.otid is not None and msg.dtid is not None:
            dia = self._new_dialogue(key, uncertain=True)
            dia.owned[msg.src] = msg.otid
            dia.owned[msg.dst] = msg.dtid
            if msg.otid == msg.dtid:
                dia.add_uncertainty(
                    'both endpoints use the same transaction ID %s; the ID '
                    'cannot distinguish them' % tid_text(msg.otid))
            if conflicts:
                dia.add_uncertainty(
                    'Continue conflicts with %s; treated as a separate '
                    'uncertain dialogue'
                    % ', '.join(did for did, _ in conflicts))
                reason = ('Continue carries both endpoint IDs but conflicts '
                          'with existing dialogues on one side; opened an '
                          'uncertain dialogue instead of merging')
            else:
                dia.add_uncertainty('Begin not observed; dialogue anchored '
                                    'by a Continue')
                reason = ('Continue carries both endpoint IDs; opened an '
                          'uncertain dialogue because no Begin was observed')
            evidence = [Evidence('orphan-anchor', reason)]
            for did, detail in conflicts:
                for item in detail:
                    evidence.append(Evidence('conflict-with-' + did,
                                             item.detail))
            issues = _id_length_issues(msg)
            for issue in issues:
                dia.add_uncertainty(issue)
                evidence.append(Evidence('nonconformant-id-length', issue))
            dia.observe(msg, evidence, 'anchor')
            return
        if msg.kind in TERMINAL_KINDS:
            detail = ('%s carries only the peer ID %s; one ID is not enough '
                      'to establish a dialogue'
                      % (msg.kind, tid_text(msg.dtid)))
        else:
            detail = 'no dialogue in endpoint pair %s owns these IDs' % (
                ' <-> '.join(key))
        self._unresolved.append(self._entry(
            msg, 'unknown transaction', detail))

    # -- finalization ----------------------------------------------------- #

    def _finalize(self):
        for dia in self._dialogues:
            if dia.state == 'open':
                dia.unterminated = True
                dia.evidence.append(Evidence(
                    'unterminated-at-capture-end',
                    'no End or Abort observed before the capture ended'))
            for msg in dia.messages:
                for text in _id_length_issues(msg):
                    dia.add_uncertainty(text)
            if dia.uncertain:
                dia.confidence = 'uncertain'
            elif dia.initiator is None:
                dia.confidence = 'weak'
            else:
                dia.confidence = 'strong'

    def _entry(self, msg, reason, detail, candidates=None):
        return {
            'message': msg.to_dict(),
            'reason': reason,
            'detail': detail,
            'candidates': candidates or [],
        }


#------------------------------------------------------------------------------#
# naive comparison and demonstration
#------------------------------------------------------------------------------#

def single_id_groups(messages):
    """Group messages by each transaction ID alone, the naive approach.

    This reproduces the bug the reassembler avoids: a message joins every group
    for every ID it carries, regardless of endpoint pair or dialogue state.
    """
    groups = {}
    for msg in messages:
        for field, tid in (('OTID', msg.otid), ('DTID', msg.dtid)):
            if tid is None:
                continue
            label = tid_text(tid)
            group = groups.setdefault(label, {
                'id': label, 'messages': [], 'fields': [], 'dialogues': []})
            group['messages'].append(msg.index)
            group['fields'].append('%s@%d' % (field, msg.index))
            if msg.dialogue_id is not None:
                group['dialogues'].append(msg.dialogue_id)
    out = []
    for label in sorted(groups):
        group = groups[label]
        group['dialogues'] = sorted(set(group['dialogues']))
        out.append(group)
    return out


def _tlv(tag, content):
    length = len(content)
    if length < 0x80:
        return bytes([tag, length]) + content
    if length < 0x100:
        return bytes([tag, 0x81, length]) + content
    return bytes([tag, 0x82, length >> 8, length & 0xff]) + content


def _demo_begin(otid):
    return _tlv(0x62, _tlv(0x48, otid)).hex().upper()


def _demo_continue(otid, dtid):
    return _tlv(0x65, _tlv(0x48, otid) + _tlv(0x49, dtid)).hex().upper()


def _demo_end(dtid):
    return _tlv(0x64, _tlv(0x49, dtid)).hex().upper()


def _demo_abort(dtid):
    return _tlv(0x67, _tlv(0x49, dtid)).hex().upper()


def demo_scenario():
    """Return a demonstration capture that exercises the hard cases.

    The capture contains:

    * D1 on A/B with IDs 0001/0002, ended normally;
    * D2 on the same A/B pair reusing OTID 0001 but using responder ID 0003;
    * a late Continue for D2 after its End;
    * D3 on C/D reusing the same short IDs 0001/0002 as D1;
    * D4 observed only from a Continue (missing Begin) on E/F;
    * D5 ending with Abort on G/H;
    * D6 with a non-conformant five-byte transaction ID on I/J;
    * a stray End on K/L that cannot be attached.

    Each entry is a dict with ``label``, ``src``, ``dst``, ``timestamp`` and
    ``hex``.  The messages are minimal TCAP transaction portions; no MAP
    arguments are needed for reassembly.
    """
    return [
        {'label': 'D1 Begin', 'src': 'A', 'dst': 'B', 'timestamp': 100.0,
         'hex': _demo_begin(b'\x00\x01')},
        {'label': 'D1 Continue', 'src': 'B', 'dst': 'A', 'timestamp': 110.0,
         'hex': _demo_continue(b'\x00\x02', b'\x00\x01')},
        {'label': 'D1 End', 'src': 'B', 'dst': 'A', 'timestamp': 130.0,
         'hex': _demo_end(b'\x00\x01')},
        {'label': 'D2 Begin (OTID 0001 reused)', 'src': 'A', 'dst': 'B',
         'timestamp': 200.0, 'hex': _demo_begin(b'\x00\x01')},
        {'label': 'D2 Continue', 'src': 'B', 'dst': 'A', 'timestamp': 210.0,
         'hex': _demo_continue(b'\x00\x03', b'\x00\x01')},
        {'label': 'D2 Continue', 'src': 'A', 'dst': 'B', 'timestamp': 220.0,
         'hex': _demo_continue(b'\x00\x01', b'\x00\x03')},
        {'label': 'D2 End', 'src': 'A', 'dst': 'B', 'timestamp': 230.0,
         'hex': _demo_end(b'\x00\x03')},
        {'label': 'D2 late Continue after End', 'src': 'B', 'dst': 'A',
         'timestamp': 300.0, 'hex': _demo_continue(b'\x00\x03', b'\x00\x01')},
        {'label': 'D3 Begin (same IDs, other endpoints)', 'src': 'C',
         'dst': 'D', 'timestamp': 400.0, 'hex': _demo_begin(b'\x00\x01')},
        {'label': 'D3 Continue', 'src': 'D', 'dst': 'C', 'timestamp': 410.0,
         'hex': _demo_continue(b'\x00\x02', b'\x00\x01')},
        {'label': 'D3 End', 'src': 'D', 'dst': 'C', 'timestamp': 430.0,
         'hex': _demo_end(b'\x00\x01')},
        {'label': 'D4 Continue without Begin', 'src': 'F', 'dst': 'E',
         'timestamp': 500.0, 'hex': _demo_continue(b'\x00\x04', b'\x00\x05')},
        {'label': 'D4 End', 'src': 'F', 'dst': 'E', 'timestamp': 520.0,
         'hex': _demo_end(b'\x00\x05')},
        {'label': 'D5 Begin', 'src': 'G', 'dst': 'H', 'timestamp': 600.0,
         'hex': _demo_begin(b'\x00\x07')},
        {'label': 'D5 Continue', 'src': 'H', 'dst': 'G', 'timestamp': 605.0,
         'hex': _demo_continue(b'\x00\x08', b'\x00\x07')},
        {'label': 'D5 Abort', 'src': 'H', 'dst': 'G', 'timestamp': 610.0,
         'hex': _demo_abort(b'\x00\x07')},
        {'label': 'D5 late Continue after Abort', 'src': 'H', 'dst': 'G',
         'timestamp': 700.0, 'hex': _demo_continue(b'\x00\x08', b'\x00\x07')},
        {'label': 'D6 Begin with 5-byte ID', 'src': 'I', 'dst': 'J',
         'timestamp': 700.0,
         'hex': _demo_begin(b'\x01\x02\x03\x04\x05')},
        {'label': 'D6 End with 5-byte ID', 'src': 'J', 'dst': 'I',
         'timestamp': 710.0,
         'hex': _demo_end(b'\x01\x02\x03\x04\x05')},
        {'label': 'stray End', 'src': 'L', 'dst': 'K', 'timestamp': 800.0,
         'hex': _demo_end(b'\x00\xAA')},
    ]


def load_scenario(scenario):
    """Decode a scenario list (as returned by demo_scenario) into messages."""
    messages = []
    for index, entry in enumerate(scenario):
        messages.append(decode_tcap_message(
            entry['hex'], index=index, src=entry.get('src', 'A'),
            dst=entry.get('dst', 'B'), timestamp=entry.get('timestamp')))
    return messages
