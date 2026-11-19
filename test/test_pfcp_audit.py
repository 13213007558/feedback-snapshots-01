"""Evidence checks for PFCP F-TEID endpoint allocation (TS 29.244).

These tests never equate a parseable F-TEID with an installed tunnel: they
assert the three endpoint states (specified / allocation requested /
allocation confirmed), strict conditional field layout, selection-group
sharing, failures, partial captures and F-SEID isolation, including byte-level
flag mutations.
"""

import json

import pytest

import pycrate_mobile.TS29244_PFCP as pfcp
from pfcp_audit import (
    EndpointState,
    LayoutAnomaly,
    Verdict,
    audit_messages,
    audit_transcript,
    load_transcript,
)
from pfcp_audit.audit import EndpointAuditor
from pfcp_audit.fteid import inspect_fteid
from pfcp_audit.mutation import clear_flag, flip_flag
from pfcp_audit.scenarios import (
    SESSION_A,
    SESSION_B,
    SHARED_CHOOSE_ID,
    all_transcripts,
    conflict_transcript,
    incomplete_transcript,
    legal_transcript,
)
from pfcp_audit.transcript import TranscriptMessage

T = pfcp.PFCPIEType


# ------------------------------------------------------------- F-TEID layout
def test_specified_ipv4_layout():
    layout = inspect_fteid(bytes.fromhex('01112233440a000001'))
    assert layout.valid
    assert layout.kind.value == 'specified'
    assert layout.teid == 0x11223344
    assert layout.ipv4 == bytes([10, 0, 0, 1])
    assert layout.ipv6 is None
    assert layout.pycrate_consistent


def test_dual_address_layout_is_ordered():
    # flags V4|V6, then TEID, IPv4, IPv6: 1+4+4+16 = 25 bytes
    raw = bytes.fromhex(
        '03aabbccdd0a01010120010db8000000000000000000000001')
    layout = inspect_fteid(raw)
    assert layout.valid
    assert layout.expected_len == 25
    assert layout.ipv4 == bytes([10, 1, 1, 1])
    expected_v6 = bytes([0x20, 0x01, 0x0D, 0xB8]) + b'\x00' * 11 + b'\x01'
    assert layout.ipv6 == expected_v6
    assert len(layout.ipv6) == 16
    assert layout.pycrate_consistent


def test_choose_with_choose_id_has_no_address_or_teid():
    layout = inspect_fteid(bytes.fromhex('0c07'))
    assert layout.valid
    assert layout.kind.value == 'allocation_request'
    assert layout.flags['CH'] and layout.flags['CHID']
    assert layout.choose_id == SHARED_CHOOSE_ID
    assert layout.teid is None and not layout.addresses()
    # A missing address under CH must not be invented as a zero address.
    assert layout.ipv4 is None and layout.ipv6 is None


def test_choose_without_choose_id_is_single_flag_byte():
    layout = inspect_fteid(bytes.fromhex('04'))
    assert layout.valid
    assert layout.kind.value == 'allocation_request'
    assert layout.choose_id is None
    assert layout.expected_len == 1


def test_choosing_zero_address_is_not_silently_accepted():
    layout = inspect_fteid(bytes.fromhex('011122334400000000'))
    assert not layout.valid
    assert LayoutAnomaly.ZERO_IPV4 in layout.anomalies
    # The zero bytes are still recorded as present, not dropped.
    assert layout.ipv4 == b'\x00\x00\x00\x00'


def test_ch_cleared_must_not_read_choose_id_as_address():
    # 0c07 (CH|CHID, CHOOSE_ID=7) with CH cleared: TEID/address are now
    # required but only one value byte follows, so it must be truncated rather
    # than misreading byte 0x07 as an address.
    mutated = bytearray.fromhex('0c07')
    mutated[0] &= ~0x04
    layout = inspect_fteid(bytes(mutated))
    assert not layout.valid
    assert LayoutAnomaly.TRUNCATED in layout.anomalies
    assert layout.ipv4 is None and layout.ipv6 is None
    assert layout.kind.value == 'unknown'


def test_v4_cleared_leaves_address_unparsed():
    # Explicit IPv4 endpoint with the V4 presence bit cleared: the following
    # four bytes must not be interpreted as an address.
    mutated = bytearray.fromhex('01112233440a000001')
    mutated[0] &= ~0x01
    layout = inspect_fteid(bytes(mutated))
    assert not layout.valid
    assert LayoutAnomaly.NO_ADDRESS_FLAG in layout.anomalies
    assert layout.ipv4 is None


def test_address_flag_under_ch_is_anomaly():
    layout = inspect_fteid(bytes.fromhex('0d09'))
    assert layout.kind.value == 'allocation_request'
    assert LayoutAnomaly.ADDR_FLAG_WITH_CH in layout.anomalies
    assert not layout.addresses()


def test_empty_and_trailing_bytes_are_evidence():
    assert LayoutAnomaly.EMPTY in inspect_fteid(b'').anomalies
    trailing = inspect_fteid(bytes.fromhex('0409'))
    assert LayoutAnomaly.TRAILING_BYTES in trailing.anomalies


def test_truncated_layout_never_exposes_partial_address():
    # CHID promises a CHOOSE_ID byte that is not on the wire.
    missing_choose_id = inspect_fteid(bytes.fromhex('0c'))
    assert not missing_choose_id.valid
    assert LayoutAnomaly.TRUNCATED in missing_choose_id.anomalies
    assert missing_choose_id.choose_id is None

    # Explicit IPv4 endpoint cut short: no address may be fabricated.
    truncated = inspect_fteid(bytes.fromhex('01112233440a00'))
    assert not truncated.valid
    assert LayoutAnomaly.TRUNCATED in truncated.anomalies
    assert truncated.ipv4 is None and truncated.kind.value == 'unknown'


def test_response_kept_ch_set_cannot_confirm_allocation():
    auditor = EndpointAuditor()
    transcript = legal_transcript()
    # Replace the allocated F-TEID flags byte with CH still set (CH|CHID only).
    baseline = audit_transcript(transcript)
    response = bytearray(transcript.messages[2].bytes)
    path = baseline.sessions[SESSION_A].endpoints[20].response_path
    flags_offset = path.byte_offset + 4
    response[flags_offset] = 0x0C
    auditor.add_message(transcript.messages[0].bytes, 'A-req')
    auditor.add_message(bytes(response), 'A-rsp-bad')
    result = auditor.finalize()
    evidence = result.sessions[SESSION_A].endpoints[20]
    assert evidence.state == EndpointState.INCONCLUSIVE
    assert evidence.response_layout is None
    assert Verdict.LAYOUT_INVALID not in result.verdicts_for(SESSION_A, 20)


# ---------------------------------------------------------------- legal case
def test_legal_transcript_states_and_group_sharing():
    result = audit_transcript(legal_transcript())
    verdicts = result.all_verdicts()

    assert verdicts[(SESSION_A, 10)] == [Verdict.SPECIFIED_ENDPOINT]
    assert verdicts[(SESSION_A, 20)] == [Verdict.ALLOCATION_CONFIRMED]
    assert verdicts[(SESSION_A, 30)] == [Verdict.ALLOCATION_CONFIRMED]
    assert verdicts[(SESSION_B, 40)] == [Verdict.ALLOCATION_CONFIRMED]
    assert verdicts[(SESSION_B, 50)] == [Verdict.SPECIFIED_ENDPOINT]

    group_a = result.sessions[SESSION_A].groups[(SHARED_CHOOSE_ID, True)]
    # Both PDRs in the same selection group share one allocated endpoint.
    assert group_a.member_pdr_ids == [20, 30]
    distinct = {(lay.teid, lay.ipv4) for lay in group_a.confirmed_layouts}
    assert len(distinct) == 1
    assert not group_a.verdicts

    group_b = result.sessions[SESSION_B].groups[(SHARED_CHOOSE_ID, True)]
    # Same CHOOSE_ID value but a different, session-specific allocation.
    assert group_b.confirmed_layouts[0].teid != group_a.confirmed_layouts[0].teid
    assert not result.cross_session_violations


def test_request_and_response_ie_paths_are_recorded():
    result = audit_transcript(legal_transcript())
    evidence = result.sessions[SESSION_A].endpoints[20]
    assert evidence.ie_path.render() == 'CreatePDR/PDI/FTEID'
    assert evidence.response_path is not None
    assert evidence.response_path.render() == 'CreatedPDR/FTEID'
    assert evidence.sequence_number == 100
    assert evidence.response_sequence_number == 101
    assert evidence.response_cause == 1
    assert evidence.response_layout.teid == 0xAAAA0001
    # Request-side choose F-TEID carries no TEID even after confirmation.
    assert evidence.layout.teid is None


def test_fseid_path_is_recorded_per_session():
    result = audit_transcript(legal_transcript())
    for seid in (SESSION_A, SESSION_B):
        path = result.sessions[seid].fseid_path
        assert path is not None and path.render() == 'FSEID'


# ------------------------------------------------------------- conflict case
def test_conflict_marks_group_conflict_and_failure():
    result = audit_transcript(conflict_transcript())
    session_a = result.sessions[SESSION_A]
    group = session_a.groups[(SHARED_CHOOSE_ID, True)]
    assert Verdict.GROUP_CONFLICT in group.verdicts
    distinct = {(lay.teid, lay.ipv4) for lay in group.confirmed_layouts}
    assert len(distinct) == 2

    # The anonymous CH group got no CreatedPDR in the partial response.
    assert Verdict.RESPONSE_MISSING in session_a.groups[(None, False)].verdicts

    # Session B was rejected: no confirmed endpoint, cause retained.
    verdicts = result.all_verdicts()
    assert verdicts[(SESSION_B, 41)] == [Verdict.RESPONSE_FAILED]
    rejected = result.sessions[SESSION_B].endpoints[41]
    assert rejected.response_cause == 75
    assert rejected.state == EndpointState.ALLOCATION_REQUESTED


# ----------------------------------------------------------- incomplete case
def test_incomplete_capture_never_borrows_other_session():
    result = audit_transcript(incomplete_transcript())
    session_a = result.sessions[SESSION_A]
    session_b = result.sessions[SESSION_B]

    for pdr_id in (22, 32):
        evidence = session_a.endpoints[pdr_id]
        assert evidence.state == EndpointState.ALLOCATION_REQUESTED
        assert evidence.response_path is None
        assert Verdict.RESPONSE_MISSING in result.verdicts_for(SESSION_A, pdr_id)

    # B succeeded; its endpoint must not appear anywhere under A.
    allocated_b = session_b.endpoints[42].response_layout.teid
    blob = json.dumps(session_a.to_dict())
    assert ('%08x' % allocated_b) not in blob
    assert session_b.endpoints[42].state == EndpointState.ALLOCATION_CONFIRMED


# ------------------------------------------------------------------ mutations
def _choose_fteid_path(result, seid, pdr_id):
    return result.sessions[seid].endpoints[pdr_id].ie_path


def test_ch_flag_flip_prevents_fake_tunnel_confirmation():
    transcript = legal_transcript()
    baseline = audit_transcript(transcript)
    path = _choose_fteid_path(baseline, SESSION_A, 20)
    request = transcript.messages[0].bytes
    mutated, offset = clear_flag(request, path, 'CH')
    assert request[offset] & 0x04  # original had CH set
    assert not (mutated[offset] & 0x04)

    # Audit the mutated request together with the genuine response: the
    # malformed request can never be treated as a confirmed allocation.
    mutated_transcript = [mutated] + [m.bytes for m in transcript.messages[1:]]
    result = audit_messages(mutated_transcript)
    evidence = result.sessions[SESSION_A].endpoints[20]
    assert evidence.state != EndpointState.ALLOCATION_CONFIRMED
    assert evidence.anomalies
    # The byte after the flags byte is not mislabelled as an IPv4 address.
    assert evidence.layout.ipv4 is None


def test_v4_presence_flip_keeps_following_bytes_non_address():
    transcript = legal_transcript()
    baseline = audit_transcript(transcript)
    path = baseline.sessions[SESSION_A].endpoints[10].ie_path
    mutated, _ = flip_flag(transcript.messages[0].bytes, path, 'V4')
    result = audit_messages([mutated])
    layout = result.sessions[SESSION_A].endpoints[10].layout
    assert LayoutAnomaly.NO_ADDRESS_FLAG in layout.anomalies
    assert layout.ipv4 is None and layout.ipv6 is None


def test_cross_session_success_cannot_satisfy_request():
    # Only B's response is present; re-auditing must keep every A PDR open.
    result = audit_transcript(incomplete_transcript())
    for pdr_id in (22, 32):
        assert result.sessions[SESSION_A].endpoints[pdr_id].response_path is None
    assert result.sessions[SESSION_B].endpoints[42].response_path is not None


# ------------------------------------------------------- duplicate / reuse id
def test_duplicate_pdr_id_in_group_is_flagged():
    auditor = EndpointAuditor()
    transcript = legal_transcript()
    # Re-feed the same request message: the same PDR id re-enters its group.
    auditor.add_message(transcript.messages[0].bytes, 'A-req-1')
    auditor.add_message(transcript.messages[0].bytes, 'A-req-2')
    result = auditor.finalize()
    group = result.sessions[SESSION_A].groups[(SHARED_CHOOSE_ID, True)]
    assert Verdict.DUPLICATE_REUSE_ID in group.verdicts


# ------------------------------------------------------------- parse handling
def test_unparseable_bytes_are_recorded_not_raised():
    auditor = EndpointAuditor()
    auditor.add_message(b'\x00\x00not a pfcp message', label='garbage')
    result = auditor.finalize()
    assert result.parse_failures and result.parse_failures[0]['label'] == 'garbage'
    assert not result.sessions


def test_transcript_loader_hex_roundtrip():
    transcript = legal_transcript()
    spec = transcript.to_dict()
    loaded = load_transcript(spec)
    assert [m.bytes for m in loaded] == [m.bytes for m in transcript]
    assert all(isinstance(m, TranscriptMessage) for m in loaded)


def test_every_transcript_is_real_pfcp_and_roundtrips():
    for transcript in all_transcripts():
        for message in transcript:
            parsed, err = pfcp.parse_PFCP(message.bytes)
            assert err == 0
            assert parsed.to_bytes() == message.bytes


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
