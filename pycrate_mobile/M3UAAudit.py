# -*- coding: UTF-8 -*-

"""Offline M3UA state / DATA correlation for SIGTRAN transcripts.

The module replays a capture and answers one question for every DATA message:
was a valid ASP/AS state actually observed, for the same endpoint pair and
Routing Context, before this DATA arrived?

The model is evidence-bound:

* state is scoped to the endpoint pair observed in the capture and to a
  Routing Context, never to an assumed global network view;
* if a scope has no observed state, a DATA yields `INSUFFICIENT_EVIDENCE`
  rather than an invented violation, which is how a capture that starts in
  the middle of an association is reported;
* retransmissions are recognised as repeated DATA in the same direction and
  are reported separately from ordering violations;
* only an observed transition to a state that forbids DATA (for example an
  ASP that was established and then made inactive) yields `VIOLATION`.

The report never asserts maliciousness.  It lists the observed messages each
verdict relies on, and states explicitly when the capture cannot support a
conclusion.
"""

__all__ = [
    'ASP_UP', 'ASP_DOWN', 'AS_ACTIVE', 'AS_INACTIVE', 'AS_PENDING',
    'EVIDENCE_SUFFICIENT', 'EVIDENCE_INSUFFICIENT', 'EVIDENCE_VIOLATION',
    'VERDICT_OK', 'VERDICT_RETRANSMISSION',
    'VERDICT_INSUFFICIENT', 'VERDICT_VIOLATION',
    'AuditFinding', 'M3UAAudit',
    'message_name', 'audit_m3ua_transcript', 'parse_hex_transcript',
    'format_report',
    ]


import re

from binascii import unhexlify, hexlify

from .M3UA import (
    M3UATag,
    parse_M3UA,
    ERR_M3UA_BUF_TOO_SHORT,
    ERR_M3UA_BUF_INVALID,
    ERR_M3UA_TYPE_NONEXIST,
    ERR_M3UA_MAND_PRM_MISS,
    )


#------------------------------------------------------------------------------#
# Vocabulary
#------------------------------------------------------------------------------#

# ASP maintenance state, per association.
ASP_UP   = 'ASP-UP'
ASP_DOWN = 'ASP-DOWN'

# AS traffic state, per association and Routing Context.
AS_ACTIVE   = 'AS-ACTIVE'
AS_INACTIVE = 'AS-INACTIVE'
AS_PENDING  = 'AS-PENDING'

# what the capture can support
EVIDENCE_SUFFICIENT   = 'sufficient'
EVIDENCE_INSUFFICIENT = 'insufficient'
EVIDENCE_VIOLATION    = 'violation'

# DATA verdicts
VERDICT_OK             = 'OK'
VERDICT_RETRANSMISSION = 'RETRANSMISSION'
VERDICT_INSUFFICIENT   = 'INSUFFICIENT_EVIDENCE'
VERDICT_VIOLATION      = 'VIOLATION'


# M3UA message classes and types, RFC 4666 section 3
_CLASS_MGMT  = 0
_CLASS_TRANS = 1
_CLASS_SSNM  = 2
_CLASS_ASPSM = 3
_CLASS_ASPTM = 4
_CLASS_RKM   = 9

_DATA = 1

_ASPSM_UP      = 1
_ASPSM_DOWN    = 2
_ASPSM_BEAT    = 3
_ASPSM_UPACK   = 4
_ASPSM_DOWNACK = 5
_ASPSM_BEATACK = 6

_ASPTM_ACTIVE      = 1
_ASPTM_INACTIVE    = 2
_ASPTM_ACTIVEACK   = 3
_ASPTM_INACTIVEACK = 4

_NTFY = 1

_MSG_NAMES = {
    (0, 0) : 'ERR',
    (0, 1) : 'NTFY',
    (1, 1) : 'DATA',
    (2, 1) : 'DUNA',
    (2, 2) : 'DAVA',
    (2, 3) : 'DAUD',
    (2, 4) : 'SCON',
    (2, 5) : 'DUPU',
    (2, 6) : 'DRST',
    (3, 1) : 'ASPUP',
    (3, 2) : 'ASPDOWN',
    (3, 3) : 'BEAT',
    (3, 4) : 'ASPUP-ACK',
    (3, 5) : 'ASPDOWN-ACK',
    (3, 6) : 'BEAT-ACK',
    (4, 1) : 'ASPACTIVE',
    (4, 2) : 'ASPINACTIVE',
    (4, 3) : 'ASPACTIVE-ACK',
    (4, 4) : 'ASPINACTIVE-ACK',
    (9, 1) : 'REGREQ',
    (9, 2) : 'REGRSP',
    (9, 3) : 'DEREGREQ',
    (9, 4) : 'DEREGRSP',
    }

_DECODE_ERRORS = {
    ERR_M3UA_BUF_TOO_SHORT : 'buffer too short',
    ERR_M3UA_BUF_INVALID   : 'invalid M3UA buffer',
    ERR_M3UA_TYPE_NONEXIST : 'unsupported M3UA class/type',
    ERR_M3UA_MAND_PRM_MISS : 'missing mandatory parameter',
    }

_TAG_NAMES = dict((tag.value, tag.name) for tag in M3UATag)

_STAT_AS = {2 : AS_INACTIVE, 3 : AS_ACTIVE, 4 : AS_PENDING}
_STAT_OTHER = {
    1 : 'Insufficient ASP Resources Active in AS',
    2 : 'Alternate ASP Active',
    3 : 'ASP Failure',
    }

_TRAFFIC_MODE = {1 : 'Override', 2 : 'Loadshare', 3 : 'Broadcast'}


def message_name(cls, typ):
    """return the M3UA message name for a class / type pair
    """
    return _MSG_NAMES.get((cls, typ), '%d/%d' % (cls, typ))



def _routing_contexts(msg):
    """return the ordered list of Routing Context values carried by `msg`
    """
    out = []
    for prm in msg[1].get_prm_list(M3UATag.RoutingContext):
        out.extend(prm.get_val())
    return out


def _status(msg):
    prm = msg[1].get_prm_first(M3UATag.Status)
    return None if prm is None else prm.get_val()


def _prm_dict(prm):
    """describe one M3UA parameter for the report
    """
    tag      = prm[0].get_val()
    out = {
        'tag'    : tag,
        'name'   : _TAG_NAMES.get(tag, 'Tag-%d' % tag),
        'length' : prm[1].get_val(),
        }
    val = prm[2]
    if tag == M3UATag.RoutingContext:
        out['value'] = list(val.get_val())
    elif tag == M3UATag.ProtocolData:
        fields = val.get_val()
        out['value'] = {
            'OPC': fields[0], 'DPC': fields[1], 'SI': fields[2],
            'NI' : fields[3], 'MP': fields[4], 'SLS': fields[5],
            'data': hexlify(fields[6]).decode(),
            }
    elif tag == M3UATag.Status:
        fields = val.get_val()
        styp, sinfo = fields[0], fields[1]
        out['value'] = {
            'type': styp,
            'info': sinfo,
            'label': (_STAT_AS.get(sinfo) if styp == 1
                      else _STAT_OTHER.get(sinfo)),
            }
    elif tag == M3UATag.TrafficModeType:
        tmt = val.get_val()
        out['value'] = tmt
        out['label'] = _TRAFFIC_MODE.get(tmt)
    elif tag in (M3UATag.ASPId, M3UATag.CorrelationId, M3UATag.ErrorCode,
                 M3UATag.RegStatus, M3UATag.DeregStatus,
                 M3UATag.ConcernedDPC, M3UATag.CongestionInd):
        out['value'] = val.get_val()
    elif tag in (M3UATag.HeartbeatData, M3UATag.DiagnosticInfo):
        out['value'] = hexlify(val.to_bytes()).decode()
    else:
        try:
            v = val.get_val()
        except Exception:
            v = None
        if isinstance(v, bytes):
            v = hexlify(v).decode()
        out['value'] = v
    return out


#------------------------------------------------------------------------------#
# Observed state
#------------------------------------------------------------------------------#

class _ASState(object):
    """observed traffic state for one Routing Context of one association
    
    `refs` lists the transcript indices that support the current state; a
    state change replaces them, a confirmation appends to them.
    """
    
    __slots__ = ('state', 'refs', 'why')
    
    def __init__(self, state, seq, why):
        self.state = state
        self.refs  = [seq]
        self.why   = why
    
    def update(self, state, seq, why):
        if self.state == state:
            self.refs.append(seq)
        else:
            self.state = state
            self.refs  = [seq]
        self.why = why


class _Association(object):
    """state observed for one unordered endpoint pair
    
    M3UA AS state belongs to the ASP of the association, whichever direction
    a DATA message travels.  `asp_endpoint` records the side whose ASP state
    was observed; ACKs are interpreted from the peer towards that side.
    """
    
    __slots__ = ('key', 'endpoints', 'asp_endpoint', 'asp_state', 'asp_refs',
                 'asp_why', 'as_states', 'first_seq', 'last_seq')
    
    def __init__(self, key, endpoints, seq):
        self.key          = key
        self.endpoints    = endpoints
        self.asp_endpoint = None
        self.asp_state    = None
        self.asp_refs     = []
        self.asp_why      = None
        self.as_states    = {}
        self.first_seq    = seq
        self.last_seq     = seq
    
    def set_asp(self, endpoint, state, seq, why):
        if self.asp_endpoint == endpoint and self.asp_state == state:
            self.asp_refs.append(seq)
        else:
            self.asp_endpoint = endpoint
            self.asp_state    = state
            self.asp_refs     = [seq]
        self.asp_why = why
    
    def set_as(self, rc, state, seq, why):
        st = self.as_states.get(rc)
        if st is None:
            self.as_states[rc] = _ASState(state, seq, why)
        else:
            st.update(state, seq, why)
    
    def invalidate_as(self, seq, why):
        for st in self.as_states.values():
            st.update(AS_INACTIVE, seq, why)
    
    def clear_as(self):
        self.as_states = {}
    
    def label(self):
        if self.endpoints[0] is None and self.endpoints[1] is None:
            return 'default'
        return '%s<->%s' % (self.endpoints[0], self.endpoints[1])


#------------------------------------------------------------------------------#
# Findings
#------------------------------------------------------------------------------#

class AuditFinding(object):
    """one verdict for one DATA message, tied to observed message indices
    """
    
    __slots__ = ('index', 'source', 'destination', 'routing_contexts',
                 'verdict', 'evidence', 'reason', 'refs')
    
    def __init__(self, index, source, destination, routing_contexts,
                 verdict, evidence, reason, refs):
        self.index            = index
        self.source           = source
        self.destination      = destination
        self.routing_contexts = routing_contexts
        self.verdict          = verdict
        self.evidence         = evidence
        self.reason           = reason
        self.refs             = tuple(refs)
    
    def to_dict(self):
        return {
            'index'            : self.index,
            'message'          : 'DATA',
            'source'           : self.source,
            'destination'      : self.destination,
            'routing_contexts' : list(self.routing_contexts),
            'verdict'          : self.verdict,
            'evidence'         : self.evidence,
            'reason'           : self.reason,
            'refs'             : list(self.refs),
            }
    
    def __repr__(self):
        return '<AuditFinding #%d %s %s>' % (self.index, self.verdict,
                                             self.reason)


#------------------------------------------------------------------------------#
# Auditor
#------------------------------------------------------------------------------#

class M3UAAudit(object):
    """replay an M3UA transcript and correlate DATA with observed state
    
    Messages are fed one at a time with `feed()`, optionally with source and
    destination endpoint labels.  Endpoints should identify the transport
    association (for example `10.0.0.1:2905`); when they are omitted, all
    messages share a single default association and the report can only
    correlate messages with each other, not with an endpoint.
    """
    
    def __init__(self):
        self._assocs   = []
        self._index    = 0
        self._msgs     = []
        self._findings = []
        self._anomalies = []
        # exact copies seen per direction, for DATA retransmission detection
        self._seen_data = {}
        # exact copies seen for control messages
        self._seen_ctrl = {}
    
    # -- public API -----------------------------------------------------------
    
    def feed(self, buf, src=None, dst=None):
        """process one M3UA message
        
        `buf` may be raw bytes or a pre-parsed pycrate M3UA message.  Return
        the `AuditFinding` when the message is DATA, else None.
        """
        self._index += 1
        seq = self._index
        msg, err = self._decode(buf)
        if isinstance(buf, (bytes, bytearray)):
            raw = bytes(buf)
        else:
            raw = buf.to_bytes()
        entry = {
            'index' : seq,
            'src'   : src,
            'dst'   : dst,
            'msg'   : msg,
            'raw'   : raw,
            'error' : err,
            'note'  : None,
            'retransmission' : False,
            }
        self._msgs.append(entry)
        if err:
            return None
        cls = msg[0][2].get_val()
        typ = msg[0][3].get_val()
        entry['class'] = cls
        entry['type']  = typ
        entry['name']  = message_name(cls, typ)
        assoc = self._assoc(src, dst, seq)
        if (cls, typ) == (_CLASS_TRANS, _DATA):
            return self._on_data(seq, msg, assoc, entry)
        self._on_control(seq, msg, cls, typ, assoc, entry)
        return None
    
    def report(self):
        """return the transcript report as a dict
        """
        findings = [f.to_dict() for f in self._findings]
        summary = {
            'messages'      : len(self._msgs),
            'decode_errors' : sum(1 for m in self._msgs if m['error']),
            'data'          : len(self._findings),
            'ok'            : sum(1 for f in findings
                                  if f['verdict'] == VERDICT_OK),
            'retransmitted' : sum(1 for f in findings
                                  if f['verdict'] == VERDICT_RETRANSMISSION),
            'insufficient'  : sum(1 for f in findings
                                  if f['verdict'] == VERDICT_INSUFFICIENT),
            'violations'    : sum(1 for f in findings
                                  if f['verdict'] == VERDICT_VIOLATION),
            'control_anomalies': len(self._anomalies),
            }
        return {
            'summary'     : summary,
            'messages'    : [self._msg_dict(m) for m in self._msgs],
            'findings'    : findings,
            'anomalies'   : list(self._anomalies),
            'associations': [self._assoc_dict(a) for a in self._assocs],
            }
    
    # -- decoding -------------------------------------------------------------
    
    def _decode(self, buf):
        if isinstance(buf, (bytes, bytearray)):
            msg, err = parse_M3UA(bytes(buf))
            if msg is None and not err:
                # defensive: never turn an undecodable message into state
                return None, ERR_M3UA_BUF_INVALID
            return msg, err
        return buf, 0
    
    def _msg_dict(self, entry):
        out = {
            'index'       : entry['index'],
            'source'      : entry['src'],
            'destination' : entry['dst'],
            'class'       : entry.get('class'),
            'type'        : entry.get('type'),
            'name'        : entry.get('name'),
            'routing_contexts': [],
            'retransmission': entry['retransmission'],
            'note'        : entry['note'],
            'error'       : None,
            }
        if entry['error']:
            out['error'] = _DECODE_ERRORS.get(entry['error'],
                                              str(entry['error']))
            return out
        msg = entry['msg']
        out['routing_contexts'] = _routing_contexts(msg)
        out['parameters'] = [_prm_dict(p) for p in msg[1]]
        return out
    
    def _assoc_dict(self, assoc):
        return {
            'endpoints'    : list(assoc.endpoints),
            'label'        : assoc.label(),
            'asp_endpoint' : assoc.asp_endpoint,
            'asp_state'    : assoc.asp_state,
            'asp_refs'     : list(assoc.asp_refs),
            'first_message': assoc.first_seq,
            'last_message' : assoc.last_seq,
            'traffic'      : dict(
                (('default' if rc is None else str(rc)),
                 {'state': st.state, 'refs': list(st.refs), 'why': st.why})
                for rc, st in assoc.as_states.items()),
            }
    
    # -- association lookup ---------------------------------------------------
    
    def _assoc(self, src, dst, seq):
        if src is None or dst is None:
            key = (src, dst)
            endpoints = (src, dst)
        else:
            key = tuple(sorted((str(src), str(dst))))
            endpoints = key
        for assoc in self._assocs:
            if assoc.key == key:
                assoc.last_seq = seq
                return assoc
        assoc = _Association(key, endpoints, seq)
        self._assocs.append(assoc)
        return assoc
    
    # -- DATA ----------------------------------------------------------------
    
    def _on_data(self, seq, msg, assoc, entry):
        rcs = _routing_contexts(msg)
        # exact byte copy in the same direction
        sig = (entry['src'], entry['dst'], entry['raw'])
        prior = self._seen_data.get(sig)
        if prior is not None:
            entry['retransmission'] = True
        else:
            self._seen_data[sig] = seq
        #
        outcomes = self._eval_data(seq, assoc, rcs)
        verdict, evidence, reason, refs = _combine(outcomes)
        if prior is not None:
            prev = self._finding_at(prior)
            pv = prev.verdict if prev is not None else 'unknown'
            if verdict == VERDICT_OK:
                verdict = VERDICT_RETRANSMISSION
            reason = 'exact copy of DATA #%d (original verdict %s); %s' \
                     % (prior, pv, reason)
            refs = tuple([prior] + list(refs))
        finding = AuditFinding(seq, entry['src'], entry['dst'], rcs,
                               verdict, evidence, reason, refs)
        self._findings.append(finding)
        entry['finding'] = finding
        return finding
    
    def _finding_at(self, seq):
        for finding in self._findings:
            if finding.index == seq:
                return finding
        return None
    
    def _eval_data(self, seq, assoc, rcs):
        """return a list of per-Routing-Context outcome tuples
        """
        if rcs:
            return [self._eval_rc(seq, assoc, rc) for rc in rcs]
        # DATA without Routing Context belongs to the default AS: it cannot
        # borrow the state observed for an explicit Routing Context.
        default = assoc.as_states.get(None)
        if default is not None:
            return [self._eval_rc(seq, assoc, None)]
        known = [rc for rc in assoc.as_states if rc is not None]
        if known and assoc.asp_state == ASP_DOWN:
            refs = list(assoc.asp_refs)
            for rc in sorted(known):
                refs.extend(assoc.as_states[rc].refs)
            refs.append(seq)
            return [(VERDICT_VIOLATION, EVIDENCE_VIOLATION,
                     'ASP-DOWN observed at %s before DATA without a Routing '
                     'Context' % _refs_text(assoc.asp_refs), refs)]
        if known:
            refs = list(assoc.asp_refs)
            for rc in sorted(known):
                refs.extend(assoc.as_states[rc].refs)
            refs.append(seq)
            other = ', '.join('RC=%s is %s' % (rc, assoc.as_states[rc].state)
                              for rc in sorted(known))
            return [(VERDICT_INSUFFICIENT, EVIDENCE_INSUFFICIENT,
                     'DATA carries no Routing Context, so it belongs to the '
                     'default AS, whose state was not observed; the capture '
                     'only shows %s, which cannot be mapped to this DATA'
                     % other, refs)]
        if known:
            refs = [seq] + [assoc.as_states[rc].refs[-1]
                            for rc in sorted(known)]
            return [(VERDICT_INSUFFICIENT, EVIDENCE_INSUFFICIENT,
                     'DATA carries no Routing Context and no default AS state '
                     'was observed; the capture shows only explicit Routing '
                     'Contexts (%s), which cannot be mapped to this DATA'
                     % ', '.join('RC=%s' % rc for rc in sorted(known)), refs)]
        # no traffic state at all for this association
        if assoc.asp_state == ASP_DOWN:
            refs = list(assoc.asp_refs) + [seq]
            return [(VERDICT_VIOLATION, EVIDENCE_VIOLATION,
                     'ASP-DOWN observed at %s before DATA'
                     % _refs_text(assoc.asp_refs), refs)]
        if assoc.asp_state == ASP_UP:
            # ASP-UP is not an AS activation.  A missing activation handshake
            # is missing evidence, never proof of an illegal order.
            refs = list(assoc.asp_refs) + [seq]
            return [(VERDICT_INSUFFICIENT, EVIDENCE_INSUFFICIENT,
                     'ASP-UP observed at %s but no AS-ACTIVE for the default '
                     'Routing Context; the activation handshake is missing '
                     'from the capture, so the ordering is unproven'
                     % _refs_text(assoc.asp_refs), refs)]
        return [(VERDICT_INSUFFICIENT, EVIDENCE_INSUFFICIENT,
                 'no ASP or AS state was observed for this association before '
                 'DATA; the capture may start in the middle of an association',
                 [seq])]
    
    def _eval_rc(self, seq, assoc, rc):
        st = assoc.as_states.get(rc)
        if assoc.asp_state == ASP_DOWN:
            refs = list(assoc.asp_refs)
            if st is not None:
                refs.extend(st.refs)
            refs.append(seq)
            return (VERDICT_VIOLATION, EVIDENCE_VIOLATION,
                    'ASP-DOWN observed at %s before DATA'
                    % _refs_text(assoc.asp_refs), refs)
        if st is not None and st.state == AS_PENDING:
            refs = list(assoc.asp_refs) + list(st.refs) + [seq]
            return (VERDICT_INSUFFICIENT, EVIDENCE_INSUFFICIENT,
                    'Routing Context %s was observed AS-PENDING at %s; M3UA '
                    'permits traffic in flight during pending state, so this '
                    'DATA cannot be called illegal' % (_rc_text(rc),
                                                       _refs_text(st.refs)),
                    refs)
        if st is not None and st.state == AS_INACTIVE:
            refs = list(assoc.asp_refs) + list(st.refs) + [seq]
            return (VERDICT_VIOLATION, EVIDENCE_VIOLATION,
                    'Routing Context %s was observed AS-INACTIVE at %s before '
                    'DATA' % (_rc_text(rc), _refs_text(st.refs)), refs)
        if st is not None and st.state == AS_ACTIVE:
            refs = list(assoc.asp_refs) + list(st.refs) + [seq]
            if assoc.asp_refs:
                why = 'ASP-UP observed at %s and Routing Context %s observed ' \
                      'AS-ACTIVE at %s' \
                      % (_refs_text(assoc.asp_refs), _rc_text(rc),
                         _refs_text(st.refs))
            else:
                why = 'Routing Context %s observed AS-ACTIVE at %s; ASP-UP ' \
                      'is implied but was not separately observed' \
                      % (_rc_text(rc), _refs_text(st.refs))
            return (VERDICT_OK, EVIDENCE_SUFFICIENT, why, refs)
        # no AS state for this RC
        if assoc.asp_state == ASP_UP:
            others = sorted(str(x) for x in assoc.as_states
                            if x is not None
                            and assoc.as_states[x].state == AS_ACTIVE)
            extra = ''
            if others:
                extra = '; AS-ACTIVE was observed only for RC=%s' \
                        % ','.join(others)
            refs = list(assoc.asp_refs) + [seq]
            for x in others:
                refs.extend(assoc.as_states[int(x)].refs)
            return (VERDICT_INSUFFICIENT, EVIDENCE_INSUFFICIENT,
                    'ASP-UP observed at %s but no AS-ACTIVE was observed for '
                    'Routing Context %s; the activation handshake is missing '
                    'from the capture, so the ordering is unproven%s'
                    % (_refs_text(assoc.asp_refs), _rc_text(rc), extra), refs)
        return (VERDICT_INSUFFICIENT, EVIDENCE_INSUFFICIENT,
                'no state was observed for Routing Context %s before DATA; '
                'the capture may start in the middle of an association'
                % _rc_text(rc), [seq])
    
    # -- control state --------------------------------------------------------
    
    def _on_control(self, seq, msg, cls, typ, assoc, entry):
        rcs = _routing_contexts(msg)
        #
        # exact control retransmission, reported but idempotent
        sig = (entry['src'], entry['dst'], entry['raw'])
        if sig in self._seen_ctrl:
            entry['retransmission'] = True
            entry['note'] = 'repeat of %s #%d' \
                            % (entry['name'], self._seen_ctrl[sig])
        else:
            self._seen_ctrl[sig] = seq
        #
        if cls == _CLASS_ASPSM:
            self._on_aspsm(seq, msg, typ, assoc, entry)
        elif cls == _CLASS_ASPTM:
            self._on_asptm(seq, msg, typ, assoc, entry, rcs)
        elif cls == _CLASS_MGMT and typ == _NTFY:
            self._on_ntfy(seq, msg, assoc, entry, rcs)
        elif cls == _CLASS_SSNM:
            entry['note'] = entry['note'] or \
                'destination-level SSNM, no ASP/AS state change'
        elif cls == _CLASS_RKM:
            entry['note'] = entry['note'] or \
                'routing-key management, no ASP/AS state change'
        else:
            entry['note'] = entry['note'] or 'no ASP/AS state change'
    
    def _on_aspsm(self, seq, msg, typ, assoc, entry):
        if typ == _ASPSM_UP:
            # a new ASP session resets traffic state; a repeat does not
            if assoc.asp_state != ASP_UP or assoc.asp_endpoint != entry['src']:
                assoc.clear_as()
            assoc.set_asp(entry['src'], ASP_UP, seq, 'ASP-UP observed')
            entry['note'] = 'ASP-UP observed for %s' % entry['src']
        elif typ == _ASPSM_DOWN:
            assoc.set_asp(entry['src'], ASP_DOWN, seq, 'ASP-DOWN observed')
            assoc.invalidate_as(seq, 'invalidated by ASP-DOWN')
            entry['note'] = 'ASP-DOWN observed; AS traffic state invalidated'
        elif typ == _ASPSM_UPACK:
            side = entry['dst']
            if assoc.asp_state == ASP_DOWN:
                self._anomaly(seq, 'ASP-UP-ACK observed after ASP-DOWN',
                              [assoc.asp_refs[-1], seq])
            assoc.set_asp(side, ASP_UP, seq, 'ASP-UP-ACK observed')
            entry['note'] = 'ASP-UP-ACK confirms ASP-UP for %s' % side
        elif typ == _ASPSM_DOWNACK:
            side = entry['dst']
            assoc.set_asp(side, ASP_DOWN, seq, 'ASP-DOWN-ACK observed')
            assoc.invalidate_as(seq, 'invalidated by ASP-DOWN-ACK')
            entry['note'] = 'ASP-DOWN-ACK confirms ASP-DOWN for %s' % side
        else:
            entry['note'] = entry['note'] or 'no AS state change'
    
    def _on_asptm(self, seq, msg, typ, assoc, entry, rcs):
        active = typ in (_ASPTM_ACTIVE, _ASPTM_ACTIVEACK)
        if active and rcs:
            for rc in rcs:
                assoc.set_as(rc, AS_ACTIVE, seq, 'ASP-ACTIVE observed')
            entry['note'] = 'AS-ACTIVE observed for RC=%s' \
                            % ','.join(map(str, rcs))
        elif active:
            assoc.set_as(None, AS_ACTIVE, seq, 'ASP-ACTIVE observed')
            entry['note'] = 'AS-ACTIVE observed for the default Routing Context'
        elif not active and rcs:
            for rc in rcs:
                assoc.set_as(rc, AS_INACTIVE, seq, 'ASP-INACTIVE observed')
            entry['note'] = 'AS-INACTIVE observed for RC=%s' \
                            % ','.join(map(str, rcs))
        elif not active:
            assoc.set_as(None, AS_INACTIVE, seq, 'ASP-INACTIVE observed')
            entry['note'] = 'AS-INACTIVE observed for the default Routing Context'
        if active and assoc.asp_state == ASP_DOWN:
            self._anomaly(seq, 'ASP traffic activation observed after ASP-DOWN',
                          [assoc.asp_refs[-1], seq])
        if active and assoc.asp_state is None:
            entry['note'] += '; ASP state not observed in this capture'
    
    def _on_ntfy(self, seq, msg, assoc, entry, rcs):
        status = _status(msg)
        if status is None:
            entry['note'] = 'NTFY without Status parameter'
            return
        styp, sinfo = status[0], status[1]
        if styp == 2 and sinfo == 3:
            # ASP failure: the AS enters AS-PENDING; traffic already in flight
            # remains possible, so observed state becomes pending, not illegal.
            for rc in (rcs or list(assoc.as_states) or [None]):
                if rc in assoc.as_states:
                    assoc.set_as(rc, AS_PENDING, seq, 'NTFY ASP Failure')
            entry['note'] = 'NTFY ASP Failure observed; AS state marked pending'
            return
        if styp != 1:
            entry['note'] = 'NTFY status type %d, no AS state change' % styp
            return
        # NTFY is sent by the SGP towards the ASP: the ASP is the destination
        state = {2 : AS_INACTIVE, 3 : AS_ACTIVE, 4 : AS_PENDING}.get(sinfo)
        if state is None:
            entry['note'] = 'NTFY %s does not establish ACTIVE/INACTIVE' \
                            % _STAT_AS.get(sinfo, 'info-%d' % sinfo)
            return
        for rc in (rcs or [None]):
            assoc.set_as(rc, state, seq, 'NTFY %s observed'
                         % _STAT_AS.get(sinfo))
        entry['note'] = 'NTFY %s observed for %s' \
                        % (_STAT_AS.get(sinfo), _rcs_text(rcs))
    
    def _anomaly(self, seq, text, refs):
        self._anomalies.append({
            'index': seq,
            'text' : text,
            'refs' : list(refs),
            })


#------------------------------------------------------------------------------#
# Helpers
#------------------------------------------------------------------------------#

def _rc_text(rc):
    return 'default' if rc is None else str(rc)


def _rcs_text(rcs):
    return 'the default Routing Context' if not rcs \
           else 'RC=%s' % ','.join(map(str, rcs))


def _refs_text(refs):
    return ', '.join('#%d' % r for r in refs) if refs else 'no message'


def _combine(outcomes):
    """combine per-Routing-Context outcomes into one DATA verdict
    """
    verdicts = [o[0] for o in outcomes]
    refs = []
    for o in outcomes:
        refs.extend(o[3])
    # keep first occurrence order, current message last
    seen = set()
    uniq = []
    for r in refs:
        if r not in seen:
            seen.add(r)
            uniq.append(r)
    reason = '; '.join(o[2] for o in outcomes)
    if VERDICT_VIOLATION in verdicts:
        return VERDICT_VIOLATION, EVIDENCE_VIOLATION, reason, uniq
    if all(v == VERDICT_OK for v in verdicts):
        return VERDICT_OK, EVIDENCE_SUFFICIENT, reason, uniq
    return VERDICT_INSUFFICIENT, EVIDENCE_INSUFFICIENT, reason, uniq


#------------------------------------------------------------------------------#
# Transcript parsing and reporting
#------------------------------------------------------------------------------#

def parse_hex_transcript(text):
    """parse a short hexadecimal transcript
    
    Accepted lines:
    * `SRC -> DST: HEX` or `SRC -> DST HEX`
    * `HEX` alone, when endpoints are not known
    * blank lines and lines starting with `#` or `//` are ignored
    * an optional leading `N.` or `N:` sequence number is ignored
    
    Return a list of dicts with `bytes` (raw bytes), `source` and
    `destination` (or None).
    """
    out = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#') or line.startswith('//'):
            continue
        # strip a leading sequence number only when it is clearly separate
        # from the payload ("10.0.0.1:..." must not lose its first octet)
        line = re.sub(r'^\d+\s*[.):]\s+', '', line)
        match = re.match(r'^(\S+)\s*(?:->|=>)\s*(\S+?)\s*:?\s*'
                         r'([0-9a-fA-F][0-9a-fA-F\s]*)$', line)
        if match:
            src, dst, hx = match.group(1), match.group(2), match.group(3)
        elif re.match(r'^[0-9a-fA-F\s]+$', line):
            src = dst = None
            hx = line
        else:
            raise ValueError('line %d: cannot parse transcript line: %s'
                             % (lineno, raw))
        hx = ''.join(hx.split())
        if len(hx) % 2:
            raise ValueError('line %d: odd number of hexadecimal digits'
                             % lineno)
        try:
            buf = unhexlify(hx)
        except Exception as err:
            raise ValueError('line %d: invalid hexadecimal data: %s'
                             % (lineno, err))
        out.append({'bytes': buf, 'source': src, 'destination': dst,
                    'line': lineno})
    return out


def _normalize_entries(entries):
    if isinstance(entries, str):
        if '\n' in entries or '->' in entries or '=>' in entries:
            return parse_hex_transcript(entries)
        hx = ''.join(entries.split())
        try:
            buf = unhexlify(hx)
        except Exception as err:
            raise ValueError('invalid hexadecimal transcript: %s' % err)
        return [{'bytes': buf, 'source': None, 'destination': None}]
    if isinstance(entries, (bytes, bytearray)):
        return [{'bytes': bytes(entries), 'source': None, 'destination': None}]
    out = []
    for item in entries:
        if isinstance(item, (bytes, bytearray)):
            out.append({'bytes': bytes(item), 'source': None,
                        'destination': None})
        elif isinstance(item, str):
            out.append({'bytes': unhexlify(''.join(item.split())),
                        'source': None, 'destination': None})
        elif isinstance(item, dict):
            if 'bytes' in item:
                buf = item['bytes']
            elif 'hex' in item:
                buf = item['hex']
            elif 'data' in item:
                buf = item['data']
            else:
                raise ValueError('entry without bytes/hex/data: %r' % (item,))
            if isinstance(buf, str):
                buf = unhexlify(''.join(buf.split()))
            out.append({'bytes': bytes(buf),
                        'source': item.get('source'),
                        'destination': item.get('destination')})
        else:
            raise ValueError('unsupported transcript entry: %r' % (item,))
    return out


def audit_m3ua_transcript(entries):
    """audit a transcript and return a report dict
    
    `entries` may be a multiline transcript string, a single hexadecimal
    string, raw bytes, or a list of hex strings / dicts with `bytes` and
    optional `source` and `destination`.
    """
    audit = M3UAAudit()
    for entry in _normalize_entries(entries):
        audit.feed(entry['bytes'], entry.get('source'),
                   entry.get('destination'))
    return audit.report()


def format_report(report):
    """render a report dict as readable text, citing observed messages
    """
    lines = []
    summary = report['summary']
    lines.append('M3UA transcript audit (capture-local evidence only)')
    lines.append('  state is scoped to the observed endpoint pairs and Routing')
    lines.append('  Contexts; no external or complete network state is assumed')
    lines.append('  messages: %d, DATA: %d, decode errors: %d'
                 % (summary['messages'], summary['data'],
                    summary['decode_errors']))
    lines.append('  DATA verdicts: OK=%d, RETRANSMISSION=%d, '
                 'INSUFFICIENT_EVIDENCE=%d, VIOLATION=%d'
                 % (summary['ok'], summary['retransmitted'],
                    summary['insufficient'], summary['violations']))
    if summary['control_anomalies']:
        lines.append('  control anomalies: %d' % summary['control_anomalies'])
    lines.append('')
    lines.append('Observed messages:')
    for msg in report['messages']:
        rcs = msg['routing_contexts']
        rct = '' if not rcs else ' RC=%s' % ','.join(map(str, rcs))
        err = '' if not msg['error'] else ' [decode error: %s]' % msg['error']
        rt = ' [repeat]' if msg.get('retransmission') else ''
        lines.append('  #%d %s%s%s%s%s'
                     % (msg['index'],
                        ('%s -> %s ' % (msg['source'], msg['destination']))
                        if msg['source'] is not None or
                        msg['destination'] is not None else '',
                        msg['name'] or 'UNKNOWN', rct, rt, err))
        if msg.get('note'):
            lines.append('       note: %s' % msg['note'])
    if report['anomalies']:
        lines.append('')
        lines.append('Control ordering anomalies:')
        for anomaly in report['anomalies']:
            lines.append('  #%d %s (refs: %s)'
                         % (anomaly['index'], anomaly['text'],
                            _refs_text(anomaly['refs'])))
    lines.append('')
    lines.append('DATA findings:')
    if not report['findings']:
        lines.append('  none')
    for finding in report['findings']:
        rcs = finding['routing_contexts']
        rct = '' if not rcs else ' RC=%s' % ','.join(map(str, rcs))
        lines.append('  #%d DATA%s -> %s'
                     % (finding['index'], rct, finding['verdict']))
        lines.append('       evidence: %s' % finding['evidence'])
        lines.append('       reason: %s' % finding['reason'])
        lines.append('       refs: %s' % _refs_text(finding['refs']))
        for ref in finding['refs']:
            if ref == finding['index']:
                continue
            for msg in report['messages']:
                if msg['index'] == ref:
                    mr = '' if not msg['routing_contexts'] \
                         else ' RC=%s' % ','.join(map(str,
                                                      msg['routing_contexts']))
                    lines.append('         #%d %s%s'
                                 % (msg['index'], msg['name'], mr))
                    break
    lines.append('')
    lines.append('Observed association state at end of transcript:')
    if not report['associations']:
        lines.append('  none')
    for assoc in report['associations']:
        lines.append('  %s: ASP=%s%s'
                     % (assoc['label'], assoc['asp_state'] or 'unknown',
                        '' if not assoc['asp_refs'] else
                        ' (refs %s)' % _refs_text(assoc['asp_refs'])))
        if assoc['traffic']:
            for rc, st in sorted(assoc['traffic'].items()):
                lines.append('      RC=%s: %s (refs %s)'
                             % (rc, st['state'], _refs_text(st['refs'])))
        else:
            lines.append('      no AS state observed')
    return '\n'.join(lines)
