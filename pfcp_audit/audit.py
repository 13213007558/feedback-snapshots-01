"""Endpoint-allocation audit over parsed PFCP session messages.

The auditor correlates, per F-SEID:

* CreatePDR/UpdatePDR requests carrying F-TEID IEs (specified endpoint or
  CH/CHID allocation request, with optional CHOOSE_ID),
* CreatedPDR/UpdatedPDR responses carrying the allocated F-TEID IEs,
* top-level Cause and FailedRuleID evidence for rejected or partial responses.

All correlation keys include the F-SEID.  The same CHOOSE_ID value reused under
a different session is a separate selection group and can never satisfy the
other session's request.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pycrate_mobile.TS29244_PFCP as pfcp

from .evidence import (
    EndpointEvidence,
    EndpointState,
    GroupEvidence,
    IEPath,
    SelectionGroupKey,
    SessionEvidence,
    Verdict,
)
from .fteid import FTEIDKind, FTEIDLayout, LayoutAnomaly, inspect_fteid

T = pfcp.PFCPIEType
MSG = pfcp.PFCPMsgType

REQUEST_TYPES = frozenset({
    MSG.PFCPSessionEstablishmentReq.value,
    MSG.PFCPSessionModificationReq.value,
})
RESPONSE_TYPES = frozenset({
    MSG.PFCPSessionEstablishmentResp.value,
    MSG.PFCPSessionModificationResp.value,
})
REQUEST_PDR_TYPES = frozenset({T.CreatePDR.value, T.UpdatePDR.value})
RESPONSE_PDR_TYPES = frozenset({T.CreatedPDR.value, T.UpdatedPDR.value})

CAUSE_ACCEPTED = frozenset({1, 2})
CAUSE_PARTIAL = frozenset({3})


@dataclass
class AuditResult:
    """Outcome of auditing one transcript (possibly several sessions)."""

    sessions: Dict[int, SessionEvidence] = field(default_factory=dict)
    parse_failures: List[Dict[str, Any]] = field(default_factory=list)
    cross_session_violations: List[Dict[str, Any]] = field(default_factory=list)
    type_names: Dict[int, str] = field(default_factory=dict)

    def endpoint(self, seid: int, pdr_id: int) -> Optional[EndpointEvidence]:
        session = self.sessions.get(seid)
        if session is None:
            return None
        return session.endpoints.get(pdr_id)

    def verdicts_for(self, seid: int, pdr_id: int) -> List[Verdict]:
        endpoint = self.endpoint(seid, pdr_id)
        if endpoint is None:
            return []
        return self._endpoint_verdicts(endpoint)

    def _endpoint_verdicts(self, endpoint: EndpointEvidence) -> List[Verdict]:
        if endpoint.anomalies:
            return [Verdict.LAYOUT_INVALID]
        if endpoint.state == EndpointState.ALLOCATION_CONFIRMED:
            return [Verdict.ALLOCATION_CONFIRMED]
        if endpoint.state == EndpointState.SPECIFIED:
            return [Verdict.SPECIFIED_ENDPOINT]
        if endpoint.response_cause is not None and endpoint.response_cause not in CAUSE_ACCEPTED:
            return [Verdict.RESPONSE_FAILED]
        return [Verdict.ALLOCATION_REQUESTED, Verdict.RESPONSE_MISSING]

    def all_verdicts(self) -> Dict[Tuple[int, int], List[Verdict]]:
        return {
            endpoint.key: self._endpoint_verdicts(endpoint)
            for session in self.sessions.values()
            for endpoint in session.endpoints.values()
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            'sessions': {
                '0x%x' % seid: session.to_dict(self.type_names)
                for seid, session in sorted(self.sessions.items())
            },
            'endpoint_verdicts': {
                '0x%x:%d' % (seid, pdr_id): [v.value for v in verdicts]
                for (seid, pdr_id), verdicts in sorted(self.all_verdicts().items())
            },
            'parse_failures': list(self.parse_failures),
            'cross_session_violations': list(self.cross_session_violations),
        }


class EndpointAuditor:
    """Accumulates endpoint evidence from a stream of PFCP message bytes."""

    def __init__(self) -> None:
        self.result = AuditResult(type_names={t.value: t.name for t in T})
        self._raw_messages: List[Tuple[int, bytes]] = []

    # ------------------------------------------------------------------ input
    def add_message(self, buf: bytes, label: Optional[str] = None) -> None:
        msg, err = pfcp.parse_PFCP(bytes(buf))
        if msg is None or err != 0:
            self.result.parse_failures.append(
                {'label': label, 'error': int(err), 'length': len(buf)}
            )
            return
        self._raw_messages.append((msg['Hdr']['Type'].get_val(), bytes(buf)))
        self._ingest(msg, bytes(buf), label)

    def add_messages(self, buffers: Iterable[bytes]) -> None:
        for buf in buffers:
            self.add_message(buf)

    # -------------------------------------------------------------- traversal
    def _ingest(self, msg: pfcp.PFCPMsg, raw: bytes, label: Optional[str]) -> None:
        msg_type = msg['Hdr']['Type'].get_val()
        seq = msg['Hdr']['SeqNum'].get_val()
        header_len = msg['Hdr'].get_len()

        seid = self._session_seid(msg)
        if seid is None:
            self.result.parse_failures.append({
                'label': label,
                'error': -1,
                'reason': 'session message without usable F-SEID/SEID',
            })
            return
        session = self._session(seid)

        if msg_type in REQUEST_TYPES:
            session.request_seqs.append(seq)
        elif msg_type in RESPONSE_TYPES:
            session.response_seqs.append(seq)

        offset = header_len
        for top_ie in msg[1]:
            self._walk(
                top_ie, [top_ie['Type'].get_val()], offset, raw,
                session, msg_type, seq, None,
            )
            offset += top_ie.get_len()

    def _walk(
        self,
        ie: pfcp.PFCPIE,
        path_types: List[int],
        abs_offset: int,
        raw: bytes,
        session: SessionEvidence,
        msg_type: int,
        seq: int,
        enclosing_pdr_id: Optional[int],
    ) -> None:
        ie_type = ie['Type'].get_val()
        ie_len = ie.get_len()
        index = self._ie_index(session, ie_type, path_types)
        path = IEPath(list(path_types), index, abs_offset, ie_len)

        if ie_type == T.FSEID.value and isinstance(ie['Data'], pfcp.FSEID):
            session.fseid_path = path

        if ie_type == T.Cause.value and len(path_types) == 1:
            try:
                session.global_cause = int(ie['Data'].get_val())
            except Exception:
                pass

        data = ie['Data']
        if isinstance(data, pfcp.PFCPIEs):
            # The PDR id is carried by a sibling PDRID IE; resolve it while we
            # hold the grouped IE directly instead of walking get_env() later,
            # which would trigger pycrate lazy re-parsing during iteration.
            if ie_type in (REQUEST_PDR_TYPES | RESPONSE_PDR_TYPES):
                enclosing_pdr_id = self._read_pdr_id(data)
            # Children live inside this IE's Data area, which starts after the
            # Type/Len[/EID] header; siblings advance by the whole child length.
            child_offset = abs_offset + self._ie_header_len(ie)
            for child in data:
                self._walk(
                    child, path_types + [child['Type'].get_val()], child_offset,
                    raw, session, msg_type, seq, enclosing_pdr_id,
                )
                child_offset += child.get_len()
        elif ie_type == T.FTEID.value:
            self._record_fteid(
                path, ie, raw, session, msg_type, seq, enclosing_pdr_id
            )

    @staticmethod
    def _read_pdr_id(grouped: pfcp.PFCPIEs) -> Optional[int]:
        for child in grouped:
            if child['Type'].get_val() == T.PDRID.value:
                try:
                    return int(child['Data']['Val'].get_val())
                except Exception:
                    return None
        return None

    def _record_fteid(
        self,
        path: IEPath,
        ie: pfcp.PFCPIE,
        raw: bytes,
        session: SessionEvidence,
        msg_type: int,
        seq: int,
        pdr_id: Optional[int],
    ) -> None:
        value_bytes = self._ie_value_bytes(ie, raw, path)
        layout = inspect_fteid(value_bytes)
        if pdr_id is None:
            # F-TEID outside any PDR (e.g. forwarding parameters) is out of the
            # endpoint-allocation scope; keep nothing rather than guessing.
            return

        if msg_type in REQUEST_TYPES:
            self._record_request_fteid(session, pdr_id, seq, msg_type, path, layout)
        elif msg_type in RESPONSE_TYPES:
            self._record_response_fteid(session, pdr_id, seq, msg_type, path, layout)

    def _record_request_fteid(
        self,
        session: SessionEvidence,
        pdr_id: int,
        seq: int,
        msg_type: int,
        path: IEPath,
        layout: FTEIDLayout,
    ) -> None:
        existing = session.endpoints.get(pdr_id)
        if existing is not None and existing.side == 'request':
            existing.notes.append(
                'duplicate request F-TEID for PDR %d at %s' % (pdr_id, path.render())
            )
        # On the request side CHID without CH is not a legal allocation option
        # (TS 29.244): CHID only qualifies the CH selection mechanism.
        if layout.flags['CHID'] and not layout.flags['CH']:
            layout.anomalies.append(LayoutAnomaly.CHID_WITHOUT_CH)
        if layout.kind == FTEIDKind.ALLOCATION_REQUEST:
            state = EndpointState.ALLOCATION_REQUESTED
            group_key: Optional[SelectionGroupKey] = (
                layout.choose_id, layout.flags['CHID']
            )
        elif layout.kind == FTEIDKind.SPECIFIED:
            state = EndpointState.SPECIFIED
            group_key = None
        else:
            state = EndpointState.INCONCLUSIVE
            group_key = None

        evidence = EndpointEvidence(
            session_seid=session.session_seid,
            pdr_id=pdr_id,
            side='request',
            sequence_number=seq,
            message_type=msg_type,
            ie_path=path,
            layout=layout,
            state=state,
            anomalies=list(layout.anomalies),
            group_key=group_key,
        )
        session.endpoints[pdr_id] = evidence
        if group_key is not None:
            new_group = GroupEvidence(
                session_seid=session.session_seid,
                group_key=group_key,
            )
            group = session.groups.setdefault(group_key, new_group)
            if pdr_id in group.member_pdr_ids:
                evidence.notes.append(
                    'PDR %d appears more than once in selection group %s'
                    % (pdr_id, self._group_label(group_key))
                )
                group.verdicts.append(Verdict.DUPLICATE_REUSE_ID)
            group.member_pdr_ids.append(pdr_id)
            group.member_paths.append(path)

    def _record_response_fteid(
        self,
        session: SessionEvidence,
        pdr_id: int,
        seq: int,
        msg_type: int,
        path: IEPath,
        layout: FTEIDLayout,
    ) -> None:
        evidence = session.endpoints.get(pdr_id)
        if evidence is None:
            # A CreatedPDR for a PDR absent from any captured request must not
            # create an endpoint out of thin air.
            session.notes.append(
                'response F-TEID for unknown PDR %d at %s retained as orphan evidence'
                % (pdr_id, path.render())
            )
            orphan = EndpointEvidence(
                session_seid=session.session_seid,
                pdr_id=pdr_id,
                side='response',
                sequence_number=seq,
                message_type=msg_type,
                ie_path=path,
                layout=layout,
                state=EndpointState.INCONCLUSIVE,
                anomalies=list(layout.anomalies),
                notes=['no matching request PDR in captured transcript'],
            )
            session.endpoints.setdefault(pdr_id, orphan)
            return

        if layout.kind == FTEIDKind.ALLOCATION_REQUEST:
            # A response must clear CH and carry the allocated TEID/address;
            # CH still set means no endpoint was actually allocated.
            evidence.notes.append(
                'response F-TEID for PDR %d still carries CH=1; no endpoint allocated'
                % pdr_id
            )
            evidence.state = EndpointState.INCONCLUSIVE
            return

        if layout.anomalies:
            evidence.anomalies.extend(layout.anomalies)
            evidence.state = EndpointState.INCONCLUSIVE
            evidence.response_path = path
            evidence.response_layout = layout
            evidence.response_sequence_number = seq
            return

        evidence.response_path = path
        evidence.response_layout = layout
        evidence.response_sequence_number = seq
        evidence.response_cause = session.global_cause
        if evidence.state == EndpointState.ALLOCATION_REQUESTED:
            evidence.state = EndpointState.ALLOCATION_CONFIRMED
            if evidence.group_key is not None:
                group = session.groups[evidence.group_key]
                group.confirmed_layouts.append(layout)
        else:
            # A response F-TEID on a specified PDR is echoed endpoint evidence,
            # not an allocation; the request-side state is preserved.
            evidence.notes.append('response F-TEID echoes a specified endpoint')

    # ------------------------------------------------------------ correlation
    def finalize(self) -> AuditResult:
        """Apply response causes, group checks and session isolation."""
        for session in self.result.sessions.values():
            self._apply_causes(session)
            self._check_groups(session)
            self._check_partial_capture(session)
        self._check_session_isolation()
        return self.result

    def _apply_causes(self, session: SessionEvidence) -> None:
        accepted = session.global_cause is None or session.global_cause in CAUSE_ACCEPTED \
            or session.global_cause in CAUSE_PARTIAL
        for evidence in session.endpoints.values():
            if evidence.side != 'request':
                continue
            if evidence.response_path is not None:
                if session.global_cause is not None and session.global_cause not in CAUSE_ACCEPTED \
                        and session.global_cause not in CAUSE_PARTIAL:
                    evidence.response_cause = session.global_cause
                continue
            if not session.response_seqs:
                # no response captured at all: keep the request state, flag below
                continue
            if not accepted:
                evidence.response_cause = session.global_cause
                evidence.notes.append(
                    'response cause %d rejected the rule set' % session.global_cause
                )
            elif evidence.state == EndpointState.ALLOCATION_REQUESTED:
                evidence.notes.append(
                    'accepted/partial response without a CreatedPDR F-TEID for this PDR'
                )

    def _check_groups(self, session: SessionEvidence) -> None:
        for group in session.groups.values():
            if len(group.member_pdr_ids) != len(set(group.member_pdr_ids)):
                group.verdicts.append(Verdict.DUPLICATE_REUSE_ID)
            distinct = self._distinct_layouts(group.confirmed_layouts)
            if len(distinct) > 1:
                group.verdicts.append(Verdict.GROUP_CONFLICT)
                group.notes.append(
                    'selection group %s confirmed %d distinct endpoints but must share one'
                    % (self._group_label(group.group_key), len(distinct))
                )
            elif distinct and len(group.confirmed_layouts) < len(group.member_pdr_ids):
                group.notes.append(
                    'selection group %s partially confirmed: %d of %d members answered'
                    % (
                        self._group_label(group.group_key),
                        len(group.confirmed_layouts),
                        len(group.member_pdr_ids),
                    )
                )
            if not group.confirmed_layouts:
                group.verdicts.append(Verdict.RESPONSE_MISSING)

    def _check_partial_capture(self, session: SessionEvidence) -> None:
        for evidence in session.endpoints.values():
            if evidence.side != 'request':
                continue
            if evidence.state == EndpointState.ALLOCATION_REQUESTED \
                    and evidence.response_path is None and session.response_seqs:
                evidence.notes.append(
                    'response captured but no CreatedPDR F-TEID for this PDR'
                )

    def _check_session_isolation(self) -> None:
        # Groups are keyed by F-SEID internally, so the same CHOOSE_ID value
        # reused under another F-SEID can never satisfy another session's
        # request.  Reusing the numeric id across sessions is legal; here we
        # only assert the structural invariant that each group stays owned by
        # exactly one session and no evidence object crosses that boundary.
        for seid, session in self.result.sessions.items():
            for key, group in session.groups.items():
                if group.session_seid != seid:
                    self.result.cross_session_violations.append({
                        'choose_id': key[0],
                        'session': '0x%x' % seid,
                        'reason': 'selection group escaped its owning session',
                    })
                for pdr_id in group.member_pdr_ids:
                    endpoint = session.endpoints.get(pdr_id)
                    if endpoint is not None and endpoint.session_seid != seid:
                        self.result.cross_session_violations.append({
                            'choose_id': key[0],
                            'session': '0x%x' % seid,
                            'reason': 'endpoint evidence borrowed from another session',
                        })

    # ---------------------------------------------------------------- helpers
    def _session(self, seid: int) -> SessionEvidence:
        return self.result.sessions.setdefault(
            seid, SessionEvidence(session_seid=seid)
        )

    def _session_seid(self, msg: pfcp.PFCPMsg) -> Optional[int]:
        # Requests carry the CP F-SEID as an IE; responses address the session
        # through the header SEID assigned by the CP function.
        if msg['Hdr']['S'].get_val() == 1:
            header_seid = msg['Hdr']['SEID'].get_val()
            if header_seid:
                return header_seid
        for top_ie in msg[1]:
            if top_ie['Type'].get_val() == T.FSEID.value and isinstance(
                top_ie['Data'], pfcp.FSEID
            ):
                return int(top_ie['Data']['SEID'].get_val())
        return None

    @staticmethod
    def _ie_header_len(ie: pfcp.PFCPIE) -> int:
        # Type(2) + Len(2), plus EID(2) when the grouped IE instance bit is set
        return 6 if ie['EID'].get_trans() is False else 4

    @staticmethod
    def _ie_value_bytes(ie: pfcp.PFCPIE, raw: bytes, path: IEPath) -> bytes:
        value_offset = path.byte_offset + EndpointAuditor._ie_header_len(ie)
        value_len = ie['Len'].get_val()
        if ie['EID'].get_trans() is False:
            value_len -= 2
        return raw[value_offset:value_offset + value_len]

    @staticmethod
    def _distinct_layouts(layouts: List[FTEIDLayout]) -> set:
        return {
            (layout.teid, layout.ipv4, layout.ipv6)
            for layout in layouts
            if not layout.anomalies
        }

    @staticmethod
    def _group_label(key: SelectionGroupKey) -> str:
        choose_id, has_chid = key
        return 'CHOOSE_ID=%d' % choose_id if has_chid else 'anonymous-CH'

    def _ie_index(
        self, session: SessionEvidence, ie_type: int, path_types: List[int]
    ) -> int:
        key = tuple(path_types)
        counters = getattr(self, '_path_counters', None)
        if counters is None:
            counters = {}
            self._path_counters = counters
        index = counters.get(key, 0)
        counters[key] = index + 1
        return index


def audit_messages(buffers: Iterable[bytes]) -> AuditResult:
    """Convenience wrapper: audit an iterable of raw PFCP messages."""
    auditor = EndpointAuditor()
    auditor.add_messages(buffers)
    return auditor.finalize()


def audit_transcript(transcript: "Transcript") -> AuditResult:
    """Audit a :class:`~pfcp_audit.transcript.Transcript` with labelled bytes."""
    auditor = EndpointAuditor()
    for message in transcript.messages:
        auditor.add_message(message.bytes, label=message.label)
    return auditor.finalize()
