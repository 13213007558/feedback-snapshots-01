"""Evidence records for PFCP endpoint allocation.

Every record keeps the exact wire positions and IE nesting path that produced
it.  Verdicts describe what the evidence supports; they never claim more than
the captured messages prove.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .fteid import FTEIDLayout, LayoutAnomaly


def _default_type_names() -> Dict[int, str]:
    try:
        import pycrate_mobile.TS29244_PFCP as pfcp
        return {t.value: t.name for t in pfcp.PFCPIEType}
    except Exception:
        return {}


class EndpointState(str, Enum):
    """Three distinct endpoint states required by the audit."""

    SPECIFIED = 'specified'
    ALLOCATION_REQUESTED = 'allocation_requested'
    ALLOCATION_CONFIRMED = 'allocation_confirmed'
    INCONCLUSIVE = 'inconclusive'


class Verdict(str, Enum):
    """Audit outcome for one endpoint reference or one selection group."""

    SPECIFIED_ENDPOINT = 'specified_endpoint'
    ALLOCATION_CONFIRMED = 'allocation_confirmed'
    ALLOCATION_REQUESTED = 'allocation_requested'
    LAYOUT_INVALID = 'layout_invalid'
    RESPONSE_FAILED = 'response_failed'
    RESPONSE_MISSING = 'response_missing'
    GROUP_CONFLICT = 'group_conflict'
    CROSS_SESSION_LEAK = 'cross_session_leak'
    DUPLICATE_REUSE_ID = 'duplicate_reuse_id'


# selection group identity: CHOOSE_ID is only present with CHID set; without
# CHID all CH PDRs of the session form the single, anonymous CH group.
SelectionGroupKey = Tuple[Optional[int], bool]


@dataclass
class IEPath:
    """Location of one IE inside a message, as a chain of IE types."""

    types: List[int]
    ie_index: int
    byte_offset: int
    byte_length: int

    def render(self, type_names: Optional[Dict[int, str]] = None) -> str:
        names = type_names if type_names is not None else _default_type_names()
        return '/'.join(names.get(t, str(t)) for t in self.types)

    def to_dict(self, type_names: Optional[Dict[int, str]] = None) -> Dict[str, Any]:
        return {
            'path': self.render(type_names),
            'ie_index': self.ie_index,
            'byte_offset': self.byte_offset,
            'byte_length': self.byte_length,
        }


@dataclass
class EndpointEvidence:
    """Everything known about one F-TEID reference in one PDR."""

    session_seid: int
    pdr_id: int
    side: str  # 'request' or 'response'
    sequence_number: Optional[int]
    message_type: int
    ie_path: IEPath
    layout: FTEIDLayout
    state: EndpointState
    anomalies: List[LayoutAnomaly] = field(default_factory=list)
    response_path: Optional[IEPath] = None
    response_layout: Optional[FTEIDLayout] = None
    response_cause: Optional[int] = None
    response_sequence_number: Optional[int] = None
    group_key: Optional[SelectionGroupKey] = None
    notes: List[str] = field(default_factory=list)

    @property
    def key(self) -> Tuple[int, int]:
        return self.session_seid, self.pdr_id

    def to_dict(self, type_names: Optional[Dict[int, str]] = None) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            'session_seid': '0x%x' % self.session_seid,
            'pdr_id': self.pdr_id,
            'side': self.side,
            'sequence_number': self.sequence_number,
            'message_type': self.message_type,
            'request_ie': self.ie_path.to_dict(type_names),
            'flags': dict(self.layout.flags),
            'teid': None if self.layout.teid is None else '0x%08x' % self.layout.teid,
            'choose_id': self.layout.choose_id,
            'ipv4': self.layout.ipv4.hex() if self.layout.ipv4 else None,
            'ipv6': self.layout.ipv6.hex() if self.layout.ipv6 else None,
            'state': self.state.value,
            'anomalies': [a.value for a in self.anomalies],
            'group_key': None
            if self.group_key is None
            else {'choose_id': self.group_key[0], 'anonymous': not self.group_key[1]},
            'notes': list(self.notes),
        }
        if self.response_path is not None:
            out['response_ie'] = self.response_path.to_dict(type_names)
            out['response_cause'] = self.response_cause
            out['response_sequence_number'] = self.response_sequence_number
            if self.response_layout is not None:
                out['allocated_teid'] = (
                    None
                    if self.response_layout.teid is None
                    else '0x%08x' % self.response_layout.teid
                )
                out['allocated_ipv4'] = (
                    self.response_layout.ipv4.hex()
                    if self.response_layout.ipv4
                    else None
                )
                out['allocated_ipv6'] = (
                    self.response_layout.ipv6.hex()
                    if self.response_layout.ipv6
                    else None
                )
        return out


@dataclass
class GroupEvidence:
    """Evidence for one CH/CHID selection group inside one session."""

    session_seid: int
    group_key: SelectionGroupKey
    member_pdr_ids: List[int] = field(default_factory=list)
    member_paths: List[IEPath] = field(default_factory=list)
    confirmed_layouts: List[FTEIDLayout] = field(default_factory=list)
    verdicts: List[Verdict] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self, type_names: Optional[Dict[int, str]] = None) -> Dict[str, Any]:
        return {
            'session_seid': '0x%x' % self.session_seid,
            'choose_id': self.group_key[0],
            'anonymous': not self.group_key[1],
            'member_pdr_ids': list(self.member_pdr_ids),
            'member_paths': [p.to_dict(type_names) for p in self.member_paths],
            'distinct_allocated_endpoints': [
                {
                    'teid': None if lay.teid is None else '0x%08x' % lay.teid,
                    'ipv4': lay.ipv4.hex() if lay.ipv4 else None,
                    'ipv6': lay.ipv6.hex() if lay.ipv6 else None,
                }
                for lay in self.confirmed_layouts
            ],
            'verdicts': [v.value for v in self.verdicts],
            'notes': list(self.notes),
        }


@dataclass
class SessionEvidence:
    """All endpoint evidence collected under one F-SEID."""

    session_seid: int
    fseid_path: Optional[IEPath] = None
    request_seqs: List[int] = field(default_factory=list)
    response_seqs: List[int] = field(default_factory=list)
    endpoints: Dict[int, EndpointEvidence] = field(default_factory=dict)
    groups: Dict[SelectionGroupKey, GroupEvidence] = field(default_factory=dict)
    response_cause_by_pdr: Dict[int, int] = field(default_factory=dict)
    global_cause: Optional[int] = None
    notes: List[str] = field(default_factory=list)

    def to_dict(self, type_names: Optional[Dict[int, str]] = None) -> Dict[str, Any]:
        return {
            'session_seid': '0x%x' % self.session_seid,
            'fseid_path': None if self.fseid_path is None else self.fseid_path.to_dict(type_names),
            'request_sequences': list(self.request_seqs),
            'response_sequences': list(self.response_seqs),
            'global_cause': self.global_cause,
            'endpoints': {
                str(pdr_id): ev.to_dict(type_names)
                for pdr_id, ev in sorted(self.endpoints.items())
            },
            'groups': [
                self.groups[key].to_dict(type_names)
                for key in sorted(self.groups, key=lambda k: (-1 if k[0] is None else k[0]))
            ],
            'notes': list(self.notes),
        }
