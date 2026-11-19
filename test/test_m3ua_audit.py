# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.5
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
# * File Name : test/test_m3ua_audit.py
# * Created : 2026-11-19
# * Authors : pycrate contributors
# *--------------------------------------------------------
#*/

import os
from binascii import unhexlify

from pycrate_mobile.M3UA import (
    M3UA_ASPUp, M3UA_ASPUpAck, M3UA_ASPDown, M3UA_ASPDownAck,
    M3UA_ASPAct, M3UA_ASPActAck, M3UA_ASPInact, M3UA_ASPInactAck,
    M3UA_DATA, M3UA_NTFY, M3UA_BEAT, M3UA_BEATAck, M3UATag,
    )
from pycrate_mobile.M3UAAudit import (
    M3UAAudit, audit_m3ua_transcript, format_report, parse_hex_transcript,
    VERDICT_OK, VERDICT_RETRANSMISSION, VERDICT_INSUFFICIENT,
    VERDICT_VIOLATION, EVIDENCE_SUFFICIENT, EVIDENCE_INSUFFICIENT,
    EVIDENCE_VIOLATION, AS_PENDING,
    )


#------------------------------------------------------------------------------#
# Fixture messages, built with pycrate's own M3UA encoder
#------------------------------------------------------------------------------#

def _encode(cls, prms=()):
    msg = cls()
    msg[1].clear()
    for tag, val in prms:
        msg[1].add_prm(tag, val)
    return msg.to_bytes()


def _data(rc, payload=b'\x01\x02\x03'):
    prms = []
    if rc is not None:
        prms.append((M3UATag.RoutingContext, [rc]))
    prms.append((M3UATag.ProtocolData, [301, 310, 3, 2, 0, 10, payload]))
    return _encode(M3UA_DATA, prms)


ASPUP     = _encode(M3UA_ASPUp, [(M3UATag.ASPId, 1)])
ASPUP_ACK = _encode(M3UA_ASPUpAck)
ASPDOWN   = _encode(M3UA_ASPDown)
ASPDOWN_ACK = _encode(M3UA_ASPDownAck)
ASPACT_7  = _encode(M3UA_ASPAct, [(M3UATag.TrafficModeType, 2),
                                  (M3UATag.RoutingContext, [7])])
ASPACTACK_7 = _encode(M3UA_ASPActAck, [(M3UATag.TrafficModeType, 2),
                                       (M3UATag.RoutingContext, [7])])
ASPINACT_7 = _encode(M3UA_ASPInact, [(M3UATag.RoutingContext, [7])])
ASPINACTACK_7 = _encode(M3UA_ASPInactAck, [(M3UATag.RoutingContext, [7])])
ASPACT_78 = _encode(M3UA_ASPAct, [(M3UATag.TrafficModeType, 2),
                                  (M3UATag.RoutingContext, [7, 8])])
ASPACTACK_78 = _encode(M3UA_ASPActAck, [(M3UATag.TrafficModeType, 2),
                                        (M3UATag.RoutingContext, [7, 8])])
NTFY_INACT_7 = _encode(M3UA_NTFY, [(M3UATag.Status, [1, 2]),
                                   (M3UATag.RoutingContext, [7])])
NTFY_ACT_7 = _encode(M3UA_NTFY, [(M3UATag.Status, [1, 3]),
                                 (M3UATag.RoutingContext, [7])])
BEAT      = _encode(M3UA_BEAT)
BEATACK   = _encode(M3UA_BEATAck)
DATA_7    = _data(7)
DATA_7B   = _data(7, b'\x01\x02\x04')
DATA_8    = _data(8)
DATA_NORC = _data(None)


def _text(*items):
    return '\n'.join('%s -> %s: %s' % (src, dst, msg.hex())
                     for src, dst, msg in items)


_RES = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    'res', 'm3ua_audit')


def _load(name):
    with open(os.path.join(_RES, name)) as fd:
        return fd.read()


# transcript 1: a complete, normal activation
NORMAL = _text(
    ('10.0.0.1:2905', '10.0.0.2:2905', ASPUP),
    ('10.0.0.2:2905', '10.0.0.1:2905', ASPUP_ACK),
    ('10.0.0.1:2905', '10.0.0.2:2905', ASPACT_7),
    ('10.0.0.2:2905', '10.0.0.1:2905', ASPACTACK_7),
    ('10.0.0.1:2905', '10.0.0.2:2905', DATA_7),
    )

# transcript 2: activation, then deactivation, then DATA
DEACTIVATED = _text(
    ('10.0.0.1:2905', '10.0.0.2:2905', ASPUP),
    ('10.0.0.2:2905', '10.0.0.1:2905', ASPUP_ACK),
    ('10.0.0.1:2905', '10.0.0.2:2905', ASPACT_7),
    ('10.0.0.2:2905', '10.0.0.1:2905', ASPACTACK_7),
    ('10.0.0.1:2905', '10.0.0.2:2905', ASPINACT_7),
    ('10.0.0.2:2905', '10.0.0.1:2905', ASPINACTACK_7),
    ('10.0.0.1:2905', '10.0.0.2:2905', DATA_7),
    )

# transcript 3: capture starts after activation has already happened
MID_CAPTURE = _text(
    ('10.0.0.1:2905', '10.0.0.2:2905', DATA_7),
    ('10.0.0.1:2905', '10.0.0.2:2905', DATA_7B),
    )


#------------------------------------------------------------------------------#
# Fixture sanity
#------------------------------------------------------------------------------#

def test_fixtures_decode():
    from pycrate_mobile.M3UA import parse_M3UA
    for pdu in (ASPUP, ASPUP_ACK, ASPDOWN, ASPDOWN_ACK, ASPACT_7,
                ASPACTACK_7, ASPINACT_7, ASPINACTACK_7, ASPACT_78,
                ASPACTACK_78, NTFY_INACT_7, NTFY_ACT_7, BEAT, BEATACK,
                DATA_7, DATA_7B, DATA_8, DATA_NORC):
        msg, err = parse_M3UA(pdu)
        assert err == 0, pdu.hex()
        assert msg.to_bytes() == pdu


def test_transcript_parser():
    entries = parse_hex_transcript(NORMAL)
    assert len(entries) == 5
    assert entries[0]['source'] == '10.0.0.1:2905'
    assert entries[0]['destination'] == '10.0.0.2:2905'
    assert entries[0]['bytes'] == ASPUP
    # plain hex, comments, numbering and arrow without colon
    entries = parse_hex_transcript(
        '# comment\n'
        '1. %s\n'
        '  // another comment\n'
        'A => B %s\n' % (ASPUP.hex(), DATA_7.hex()))
    assert len(entries) == 2
    assert entries[0]['source'] is None
    assert entries[1]['source'] == 'A'
    assert entries[1]['destination'] == 'B'


#------------------------------------------------------------------------------#
# The three acceptance transcripts
#------------------------------------------------------------------------------#

def test_normal_activation_is_ok():
    report = audit_m3ua_transcript(NORMAL)
    assert report['summary']['messages'] == 5
    assert report['summary']['data'] == 1
    assert report['summary']['violations'] == 0
    assert report['summary']['insufficient'] == 0
    finding, = report['findings']
    assert finding['index'] == 5
    assert finding['verdict'] == VERDICT_OK
    assert finding['evidence'] == EVIDENCE_SUFFICIENT
    assert finding['routing_contexts'] == [7]
    # the verdict must cite the activation messages, not just itself
    assert finding['refs'][0] == 1
    assert 3 in finding['refs'] and 4 in finding['refs']
    assert 'AS-ACTIVE' in finding['reason']


def test_data_after_deactivation_is_violation():
    report = audit_m3ua_transcript(DEACTIVATED)
    assert report['summary']['ok'] == 0
    assert report['summary']['violations'] == 1
    finding, = report['findings']
    assert finding['index'] == 7
    assert finding['verdict'] == VERDICT_VIOLATION
    assert finding['evidence'] == EVIDENCE_VIOLATION
    # it must point at the observed deactivation, not at an assumption
    assert 5 in finding['refs'] and 6 in finding['refs']
    assert 'AS-INACTIVE' in finding['reason']


def test_mid_capture_is_insufficient_not_violation():
    report = audit_m3ua_transcript(MID_CAPTURE)
    assert report['summary']['violations'] == 0
    assert report['summary']['insufficient'] == 2
    for finding in report['findings']:
        assert finding['verdict'] == VERDICT_INSUFFICIENT
        assert finding['evidence'] == EVIDENCE_INSUFFICIENT
        assert 'middle of an association' in finding['reason']
        # the only evidence is the DATA itself: nothing earlier was observed
        assert finding['refs'] == [finding['index']]


#------------------------------------------------------------------------------#
# Evidence boundaries
#------------------------------------------------------------------------------#

def test_missing_activation_is_insufficient():
    # ASP-UP and its ACK were observed, but ASP-ACTIVE was not.  A missing
    # activation handshake only supports "unproven", never a violation.
    report = audit_m3ua_transcript(_text(
        ('A', 'B', ASPUP), ('B', 'A', ASPUP_ACK), ('A', 'B', DATA_7)))
    finding, = report['findings']
    assert finding['verdict'] == VERDICT_INSUFFICIENT
    assert 'activation handshake is missing' in finding['reason']
    assert 1 in finding['refs'] and 2 in finding['refs']


def test_activation_not_observed_only_from_ack_is_insufficient():
    report = audit_m3ua_transcript(_text(
        ('B', 'A', ASPUP_ACK), ('A', 'B', DATA_7)))
    finding, = report['findings']
    assert finding['verdict'] == VERDICT_INSUFFICIENT


def test_data_before_any_handshake_is_insufficient():
    # Only DATA, then a handshake later: the DATA itself is the first thing
    # observed, so its ordering cannot be judged.
    report = audit_m3ua_transcript(_text(
        ('A', 'B', DATA_7), ('A', 'B', ASPUP), ('B', 'A', ASPUP_ACK),
        ('A', 'B', ASPACT_7), ('B', 'A', ASPACTACK_7)))
    first, = [f for f in report['findings'] if f['index'] == 1]
    assert first['verdict'] == VERDICT_INSUFFICIENT
    assert first['refs'] == [1]


def test_asp_down_before_data_is_violation():
    report = audit_m3ua_transcript(_text(
        ('A', 'B', ASPUP), ('B', 'A', ASPUP_ACK),
        ('A', 'B', ASPDOWN), ('B', 'A', ASPDOWN_ACK),
        ('A', 'B', DATA_7)))
    finding, = report['findings']
    assert finding['verdict'] == VERDICT_VIOLATION
    assert 'ASP-DOWN' in finding['reason']
    assert 3 in finding['refs']


def test_ntfy_inactive_is_observed_state_change():
    report = audit_m3ua_transcript(_text(
        ('A', 'B', ASPUP), ('B', 'A', ASPUP_ACK),
        ('A', 'B', ASPACT_7), ('B', 'A', ASPACTACK_7),
        ('B', 'A', NTFY_INACT_7), ('A', 'B', DATA_7)))
    finding, = report['findings']
    assert finding['verdict'] == VERDICT_VIOLATION
    assert 5 in finding['refs']


def test_ntfy_active_establishes_state():
    report = audit_m3ua_transcript(_text(
        ('B', 'A', NTFY_ACT_7), ('A', 'B', DATA_7)))
    finding, = report['findings']
    assert finding['verdict'] == VERDICT_OK
    assert 'implied' in finding['reason']


def test_endpoint_pair_isolated():
    # the activation belongs to A<->B; DATA on C<->D has no observed state
    report = audit_m3ua_transcript(_text(
        ('A', 'B', ASPUP), ('B', 'A', ASPUP_ACK),
        ('A', 'B', ASPACT_7), ('B', 'A', ASPACTACK_7),
        ('C', 'D', DATA_7)))
    finding, = report['findings']
    assert finding['verdict'] == VERDICT_INSUFFICIENT
    assert finding['source'] == 'C'


def test_heartbeat_is_not_activation():
    report = audit_m3ua_transcript(_text(
        ('A', 'B', BEAT), ('B', 'A', BEATACK), ('A', 'B', DATA_7)))
    finding, = report['findings']
    assert finding['verdict'] == VERDICT_INSUFFICIENT


def test_data_on_another_routing_context():
    # RC=7 and RC=8 were activated, DATA on RC=9 is unobserved
    report = audit_m3ua_transcript(_text(
        ('A', 'B', ASPUP), ('B', 'A', ASPUP_ACK),
        ('A', 'B', ASPACT_78), ('B', 'A', ASPACTACK_78),
        ('A', 'B', _data(9))))
    finding, = report['findings']
    assert finding['verdict'] == VERDICT_INSUFFICIENT
    assert 'Routing Context 9' in finding['reason']
    # the report must also say which contexts were active, as counter-evidence
    assert 'RC=7,8' in finding['reason']
    assert 3 in finding['refs'] and 4 in finding['refs']


def test_data_without_routing_context_never_borrows_other_rc():
    report = audit_m3ua_transcript(_text(
        ('A', 'B', ASPUP), ('B', 'A', ASPUP_ACK),
        ('A', 'B', ASPACT_7), ('B', 'A', ASPACTACK_7),
        ('A', 'B', DATA_NORC)))
    finding, = report['findings']
    assert finding['verdict'] == VERDICT_INSUFFICIENT
    assert finding['routing_contexts'] == []


def test_repeated_data_is_retransmission():
    report = audit_m3ua_transcript(_text(
        ('A', 'B', ASPUP), ('B', 'A', ASPUP_ACK),
        ('A', 'B', ASPACT_7), ('B', 'A', ASPACTACK_7),
        ('A', 'B', DATA_7), ('A', 'B', DATA_7)))
    first, second = report['findings']
    assert first['verdict'] == VERDICT_OK
    assert second['verdict'] == VERDICT_RETRANSMISSION
    assert first['index'] in second['refs']
    # a different payload is a new DATA, not a retransmission
    report = audit_m3ua_transcript(_text(
        ('A', 'B', ASPUP), ('B', 'A', ASPUP_ACK),
        ('A', 'B', ASPACT_7), ('B', 'A', ASPACTACK_7),
        ('A', 'B', DATA_7), ('A', 'B', DATA_7B)))
    assert [f['verdict'] for f in report['findings']] == \
           [VERDICT_OK, VERDICT_OK]


def test_duplicate_control_is_reported_but_idempotent():
    report = audit_m3ua_transcript(_text(
        ('A', 'B', ASPUP), ('A', 'B', ASPUP),
        ('B', 'A', ASPUP_ACK),
        ('A', 'B', ASPACT_7), ('B', 'A', ASPACTACK_7),
        ('A', 'B', DATA_7)))
    assert report['messages'][1]['retransmission'] is True
    finding, = report['findings']
    assert finding['verdict'] == VERDICT_OK


def test_multiple_rcs_in_one_data():
    msg_78 = _data(7)
    report = audit_m3ua_transcript(_text(
        ('A', 'B', ASPUP), ('B', 'A', ASPUP_ACK),
        ('A', 'B', ASPACT_7), ('B', 'A', ASPACTACK_7),
        ('A', 'B', _encode(M3UA_DATA, [
            (M3UATag.RoutingContext, [7, 8]),
            (M3UATag.ProtocolData, [301, 310, 3, 2, 0, 10, b'\x01'])]))))
    finding, = report['findings']
    # RC=7 is active, RC=8 was never observed: mixed evidence is insufficient
    assert finding['routing_contexts'] == [7, 8]
    assert finding['verdict'] == VERDICT_INSUFFICIENT


def test_decode_error_is_not_traffic():
    report = audit_m3ua_transcript([
        {'bytes': unhexlify('01000101'), 'source': 'A', 'destination': 'B'},
        {'bytes': ASPUP, 'source': 'A', 'destination': 'B'},
        ])
    assert report['summary']['decode_errors'] == 1
    assert report['summary']['data'] == 0
    assert report['messages'][0]['error'] == 'buffer too short'


#------------------------------------------------------------------------------#
# API and rendering
#------------------------------------------------------------------------------#

def test_feed_api_and_incremental_state():
    audit = M3UAAudit()
    assert audit.feed(ASPUP, 'A', 'B') is None
    assert audit.feed(ASPUP_ACK, 'B', 'A') is None
    assert audit.feed(ASPACT_7, 'A', 'B') is None
    assert audit.feed(ASPACTACK_7, 'B', 'A') is None
    finding = audit.feed(DATA_7, 'A', 'B')
    assert finding.verdict == VERDICT_OK
    # pre-parsed messages are accepted too
    from pycrate_mobile.M3UA import parse_M3UA
    msg, err = parse_M3UA(DATA_7)
    assert err == 0
    finding = audit.feed(msg, 'A', 'B')
    assert finding.verdict == VERDICT_RETRANSMISSION


def test_report_is_json_serialisable():
    import json
    report = audit_m3ua_transcript(DEACTIVATED)
    text = json.dumps(report)
    assert 'VIOLATION' in text
    reloaded = json.loads(text)
    assert reloaded['findings'][0]['refs'] == report['findings'][0]['refs']


def test_format_report_cites_messages():
    report = audit_m3ua_transcript(DEACTIVATED)
    text = format_report(report)
    assert '#7 DATA' in text
    assert 'VIOLATION' in text
    assert '#5 ASPINACTIVE' in text
    assert 'capture-local evidence' in text
    # every finding ref except the DATA itself is rendered with its message
    assert '#1 ASPUP' in text


def test_shipped_transcripts():
    # the three short acceptance transcripts shipped with the repository
    report = audit_m3ua_transcript(_load('normal_activation.txt'))
    assert report['summary']['ok'] == 1
    assert report['summary']['violations'] == 0

    report = audit_m3ua_transcript(_load('data_after_deactivation.txt'))
    assert report['summary']['violations'] == 1
    assert report['summary']['insufficient'] == 0

    report = audit_m3ua_transcript(_load('mid_capture.txt'))
    assert report['summary']['violations'] == 0
    assert report['summary']['insufficient'] == 2


def test_ntfy_asp_failure_is_pending_not_illegal():
    ntfy = _encode(M3UA_NTFY, [(M3UATag.Status, [2, 3]),
                               (M3UATag.RoutingContext, [7])])
    report = audit_m3ua_transcript(_text(
        ('A', 'B', ASPUP), ('B', 'A', ASPUP_ACK),
        ('A', 'B', ASPACT_7), ('B', 'A', ASPACTACK_7),
        ('B', 'A', ntfy), ('A', 'B', DATA_7)))
    finding, = report['findings']
    assert finding['verdict'] == VERDICT_INSUFFICIENT
    assert 'AS-PENDING' in finding['reason']
    assoc, = report['associations']
    assert assoc['traffic']['7']['state'] == AS_PENDING


def test_ntfy_as_pending_is_not_illegal():
    ntfy = _encode(M3UA_NTFY, [(M3UATag.Status, [1, 4]),
                               (M3UATag.RoutingContext, [7])])
    report = audit_m3ua_transcript(_text(
        ('A', 'B', ASPUP), ('B', 'A', ASPUP_ACK),
        ('A', 'B', ASPACT_7), ('B', 'A', ASPACTACK_7),
        ('B', 'A', ntfy), ('A', 'B', DATA_7)))
    finding, = report['findings']
    assert finding['verdict'] == VERDICT_INSUFFICIENT
    assert 'AS-PENDING' in finding['reason']


def test_new_asp_session_resets_traffic_state():
    # B drives a new ASP session; the activation observed for A is stale
    report = audit_m3ua_transcript(_text(
        ('A', 'B', ASPUP), ('B', 'A', ASPUP_ACK),
        ('A', 'B', ASPACT_7), ('B', 'A', ASPACTACK_7),
        ('B', 'A', ASPUP), ('A', 'B', ASPUP_ACK),
        ('A', 'B', DATA_7)))
    finding, = report['findings']
    assert finding['verdict'] == VERDICT_INSUFFICIENT


def test_no_findings_for_control_only():
    report = audit_m3ua_transcript(_text(
        ('A', 'B', ASPUP), ('B', 'A', ASPUP_ACK)))
    assert report['findings'] == []
    assert report['summary']['data'] == 0


if __name__ == '__main__':
    test_fixtures_decode()
    test_transcript_parser()
    test_normal_activation_is_ok()
    test_data_after_deactivation_is_violation()
    test_mid_capture_is_insufficient_not_violation()
    test_missing_activation_is_insufficient()
    test_activation_not_observed_only_from_ack_is_insufficient()
    test_data_before_any_handshake_is_insufficient()
    test_asp_down_before_data_is_violation()
    test_ntfy_inactive_is_observed_state_change()
    test_ntfy_active_establishes_state()
    test_endpoint_pair_isolated()
    test_heartbeat_is_not_activation()
    test_data_on_another_routing_context()
    test_data_without_routing_context_never_borrows_other_rc()
    test_repeated_data_is_retransmission()
    test_duplicate_control_is_reported_but_idempotent()
    test_multiple_rcs_in_one_data()
    test_decode_error_is_not_traffic()
    test_feed_api_and_incremental_state()
    test_report_is_json_serialisable()
    test_format_report_cites_messages()
    test_shipped_transcripts()
    test_ntfy_asp_failure_is_pending_not_illegal()
    test_ntfy_as_pending_is_not_illegal()
    test_new_asp_session_resets_traffic_state()
    test_no_findings_for_control_only()
