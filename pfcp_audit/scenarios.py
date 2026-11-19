"""Deterministic PFCP transcripts for the endpoint-allocation evidence checks.

Two sessions interleave the *same* CHOOSE_ID value (CHOOSE_ID=7) so that any
cross-session borrowing is immediately visible.  Three scenarios are produced:

* ``legal``      - every allocation request is confirmed once and shared PDRs
                   reuse the same allocated endpoint;
* ``conflict``   - one selection group is answered with two distinct endpoints
                   (group-internal conflict), plus a rejected response;
* ``incomplete`` - one selection group never gets a response (partial capture),
                   while the other session's successful allocation must not be
                   borrowed to fill the gap.

All messages are real, parseable PFCP messages built with pycrate; the module
also exposes byte-level mutators used by the tests.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import pycrate_mobile.TS29244_PFCP as pfcp

from .transcript import Transcript, TranscriptMessage

T = pfcp.PFCPIEType

# Two sessions, deliberately reusing CHOOSE_ID 7.
SESSION_A = 0x0000000000000111
SESSION_B = 0x0000000000000222
CP_NODE = '10.0.0.2'
UP_NODE = '10.0.0.3'
SHARED_CHOOSE_ID = 7


def _ie(ie_type: int, data: Any = None) -> Dict[str, Any]:
    value: Dict[str, Any] = {'Type': ie_type}
    if data is not None:
        value['Data'] = data
    return value


def _fteid_specified(teid: int, ipv4: str, ipv6: Optional[str] = None) -> Dict[str, Any]:
    value = {
        'CHID': 0,
        'CH': 0,
        'V6': 1 if ipv6 else 0,
        'V4': 1,
        'TEID': teid,
        'IPv4Addr': ipv4,
    }
    if ipv6:
        value['IPv6Addr'] = ipv6
    return value


def _fteid_choose(choose_id: Optional[int]) -> Dict[str, Any]:
    has_chid = choose_id is not None
    value: Dict[str, Any] = {
        'CHID': 1 if has_chid else 0,
        'CH': 1,
        'V6': 0,
        'V4': 0,
    }
    if has_chid:
        value['CHOOSE_ID'] = choose_id
    return value


def _fteid_allocated(
    teid: int,
    ipv4: str,
    choose_id: Optional[int] = SHARED_CHOOSE_ID,
    ipv6: Optional[str] = None,
) -> Dict[str, Any]:
    # Allocation result: CH=0, CHID/CHOOSE_ID echo the request, addresses present.
    has_chid = choose_id is not None
    value = {
        'CHID': 1 if has_chid else 0,
        'CH': 0,
        'V6': 1 if ipv6 else 0,
        'V4': 1,
        'TEID': teid,
        'IPv4Addr': ipv4,
    }
    if has_chid:
        value['CHOOSE_ID'] = choose_id
    if ipv6:
        value['IPv6Addr'] = ipv6
    return value


def _create_pdr(pdr_id: int, fteid: Dict[str, Any]) -> Dict[str, Any]:
    return _ie(T.CreatePDR.value, [
        _ie(T.PDRID.value, {'Val': pdr_id}),
        _ie(T.Precedence.value, {'Val': pdr_id * 10}),
        _ie(T.PDI.value, [
            _ie(T.SourceInterface.value, {'If': 0}),
            _ie(T.FTEID.value, fteid),
        ]),
    ])


def _created_pdr(pdr_id: int, fteid: Dict[str, Any]) -> Dict[str, Any]:
    return _ie(T.CreatedPDR.value, [
        _ie(T.PDRID.value, {'Val': pdr_id}),
        _ie(T.FTEID.value, fteid),
    ])


def _build(
    msg_cls,
    seq: int,
    ies: List[Dict[str, Any]],
    seid: Optional[int] = None,
) -> bytes:
    msg = msg_cls()
    msg[1].set_val(ies)
    msg['Hdr']['SeqNum'].set_val(seq)
    if seid is not None and msg['Hdr']['S'].get_val() == 1:
        msg['Hdr']['SEID'].set_val(seid)
    return msg.to_bytes()


def _establishment_request(
    seid: int, seq: int, pdrs: List[Tuple[int, Dict[str, Any]]]
) -> bytes:
    ies = [
        _ie(T.NodeID.value, {'Type': 0, 'Val': CP_NODE}),
        _ie(T.FSEID.value, {
            'V4': 1, 'V6': 0, 'SEID': seid, 'IPv4Addr': CP_NODE,
        }),
    ]
    for pdr_id, fteid in pdrs:
        ies.append(_create_pdr(pdr_id, fteid))
    ies.append(_ie(T.CreateFAR.value, [
        _ie(T.FARID.value, {'Val': 1}),
        _ie(T.ApplyAction.value, {'Octet1': {'FORW': 1}}),
    ]))
    return _build(pfcp.PFCPSessionEstablishmentReq, seq, ies)


def _establishment_response(
    seid: int,
    seq: int,
    cause: int,
    created: List[Tuple[int, Dict[str, Any]]],
) -> bytes:
    ies = [
        _ie(T.NodeID.value, {'Type': 0, 'Val': UP_NODE}),
        _ie(T.Cause.value, cause),
    ]
    for pdr_id, fteid in created:
        ies.append(_created_pdr(pdr_id, fteid))
    return _build(pfcp.PFCPSessionEstablishmentResp, seq, ies, seid=seid)


# --------------------------------------------------------------- transcript A
def legal_transcript() -> Transcript:
    """Both sessions get legal, internally consistent allocations."""
    req_a = _establishment_request(SESSION_A, 100, [
        (10, _fteid_specified(0x01020304, '192.0.2.11')),
        (20, _fteid_choose(SHARED_CHOOSE_ID)),
        (30, _fteid_choose(SHARED_CHOOSE_ID)),
    ])
    req_b = _establishment_request(SESSION_B, 200, [
        (40, _fteid_choose(SHARED_CHOOSE_ID)),
        (50, _fteid_specified(0x05060708, '192.0.2.50', '2001:db8::50')),
    ])
    # Session A: both CH PDRs share one allocated endpoint.
    rsp_a = _establishment_response(SESSION_A, 101, 1, [
        (20, _fteid_allocated(0xAAAA0001, '198.51.100.10')),
        (30, _fteid_allocated(0xAAAA0001, '198.51.100.10')),
    ])
    # Session B: distinct allocation under the same CHOOSE_ID value.
    rsp_b = _establishment_response(SESSION_B, 201, 1, [
        (40, _fteid_allocated(0xBBBB0002, '198.51.100.20')),
    ])
    return Transcript(
        name='legal',
        description='legal allocations; shared group in A, dual-stack specified PDR in B',
        messages=[
            TranscriptMessage('A-req', 'request', req_a),
            TranscriptMessage('B-req', 'request', req_b),
            TranscriptMessage('A-rsp', 'response', rsp_a),
            TranscriptMessage('B-rsp', 'response', rsp_b),
        ],
    )


# --------------------------------------------------------------- transcript B
def conflict_transcript() -> Transcript:
    """Group-internal conflict and an explicit rejection are preserved."""
    req_a = _establishment_request(SESSION_A, 110, [
        (21, _fteid_choose(SHARED_CHOOSE_ID)),
        (31, _fteid_choose(SHARED_CHOOSE_ID)),
        (61, _fteid_choose(None)),  # anonymous CH group, no CHOOSE_ID
    ])
    req_b = _establishment_request(SESSION_B, 210, [
        (41, _fteid_choose(SHARED_CHOOSE_ID)),
    ])
    # Conflict: same group answered with two different TEIDs/addresses.
    rsp_a = _establishment_response(SESSION_A, 111, 3, [
        (21, _fteid_allocated(0xCCCC0001, '198.51.100.31')),
        (31, _fteid_allocated(0xCCCC0002, '198.51.100.32')),
    ])
    # Session B rejected outright: no CreatedPDR, cause 75 (no resources).
    rsp_b = _establishment_response(SESSION_B, 211, 75, [])
    return Transcript(
        name='conflict',
        description='shared group answered inconsistently; session B rejected',
        messages=[
            TranscriptMessage('A-req', 'request', req_a),
            TranscriptMessage('B-req', 'request', req_b),
            TranscriptMessage('A-rsp', 'response', rsp_a),
            TranscriptMessage('B-rsp', 'response', rsp_b),
        ],
    )


# --------------------------------------------------------------- transcript C
def incomplete_transcript() -> Transcript:
    """One session's group gets no response; the other succeeds."""
    req_a = _establishment_request(SESSION_A, 120, [
        (22, _fteid_choose(SHARED_CHOOSE_ID)),
        (32, _fteid_choose(SHARED_CHOOSE_ID)),
    ])
    req_b = _establishment_request(SESSION_B, 220, [
        (42, _fteid_choose(SHARED_CHOOSE_ID)),
    ])
    # Only B answers; A's response is missing from the capture.
    rsp_b = _establishment_response(SESSION_B, 221, 1, [
        (42, _fteid_allocated(0xDDDD0003, '198.51.100.40')),
    ])
    return Transcript(
        name='incomplete',
        description='session A response absent; session B allocation must not be borrowed',
        messages=[
            TranscriptMessage('A-req', 'request', req_a),
            TranscriptMessage('B-req', 'request', req_b),
            TranscriptMessage('B-rsp', 'response', rsp_b),
        ],
    )


def all_transcripts() -> List[Transcript]:
    return [legal_transcript(), conflict_transcript(), incomplete_transcript()]
