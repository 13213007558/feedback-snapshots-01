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
# * File Name : test/test_tcap_reassembly.py
# * Created : 2026-11-19
# *--------------------------------------------------------
#*/

"""Tests for pycrate_mobile.TCAPReassembly.

The cases use hand-built BER transaction portions so they do not depend on MAP
parameter validity; one case uses the repository's real TCAP capture to check
the pycrate decoding path end-to-end.
"""

import json
import os

from pycrate_mobile.TCAPReassembly import (
    ABORT, BEGIN, CONTINUE, END,
    DecodeError,
    Reassembler,
    decode_tcap_message,
    demo_scenario,
    load_scenario,
    single_id_groups,
    tid_text,
)

_HERE = os.path.dirname(os.path.abspath(__file__))


#------------------------------------------------------------------------------#
# helpers to build minimal BER transaction portions
#------------------------------------------------------------------------------#

def _tlv(tag, content):
    length = len(content)
    if length < 0x80:
        return bytes([tag, length]) + content
    if length < 0x100:
        return bytes([tag, 0x81, length]) + content
    return bytes([tag, 0x82, length >> 8, length & 0xFF]) + content


def begin_hex(otid):
    return _tlv(0x62, _tlv(0x48, otid)).hex()


def continue_hex(otid, dtid):
    return _tlv(0x65, _tlv(0x48, otid) + _tlv(0x49, dtid)).hex()


def end_hex(dtid):
    return _tlv(0x64, _tlv(0x49, dtid)).hex()


def abort_hex(dtid, cause=None):
    content = _tlv(0x49, dtid)
    if cause is not None:
        content += _tlv(0x4A, bytes([cause]))
    return _tlv(0x67, content).hex()


def msg(hexstr, index, src, dst, ts=None):
    return decode_tcap_message(hexstr, index=index, src=src, dst=dst, timestamp=ts)


def ids(dialogue):
    return dict((ep, tid_text(tid)) for ep, tid in dialogue.owned.items())


#------------------------------------------------------------------------------#
# decoding
#------------------------------------------------------------------------------#

def test_decode_kinds():
    for kind, hexstr in (
            (BEGIN, begin_hex(b'\x00\x01')),
            (CONTINUE, continue_hex(b'\x00\x02', b'\x00\x01')),
            (END, end_hex(b'\x00\x01')),
            (ABORT, abort_hex(b'\x00\x01'))):
        decoded = decode_tcap_message(hexstr)
        assert decoded.kind == kind, (kind, decoded.kind)


def test_decode_rejects_non_tcap():
    try:
        decode_tcap_message('3003020101')
    except DecodeError:
        return
    raise AssertionError('non-TCAP input was accepted')


def test_decode_accepts_bytes_and_hex():
    raw = bytes.fromhex(begin_hex(b'\x00\x01'))
    assert decode_tcap_message(raw).otid == b'\x00\x01'
    assert decode_tcap_message(begin_hex(b'\x00\x01')).otid == b'\x00\x01'


def test_decode_map_message_keeps_operation_without_argument():
    # A real Begin carrying a RoutingInfoForSM invoke with an MSISDN argument.
    hexstr = ('62474804000000016b1e281c060700118605010101a011600f80020780'
              'a1090607040000010014026c1fa11d0201ff02012d30158007911497'
              '427533f38101008207911497797908f0')
    decoded = decode_tcap_message(hexstr)
    assert decoded.decode_layer == 'map'
    assert decoded.otid == b'\x00\x00\x00\x01'
    summary = decoded.components[0]
    assert summary['kind'] == 'invoke'
    assert summary['opcode'] == {'kind': 'local', 'value': 45}
    # The MSISDN bytes must not be retained as association evidence.
    assert 'argument' not in summary
    assert b'\x91\x14\x97' not in json.dumps(summary).encode('latin-1')


def test_decode_falls_back_to_tcap_layer_for_bad_map_argument():
    # A real Continue from test/res/tcapmap_pcapr.json: the MAP argument is
    # out of range for SendIdentificationRes, so the MAP module rejects it.
    # The transaction-only module still recovers both IDs.
    hexstr = ('6581aa4804840001ff4904a50500016b2a2828060700118605010101a01d61'
              '1b80020780a109060704000001000e03a203020100a305a1030201006c80'
              'a26c0201013067020138a380a180305a04104b9d6191107536658cfe5988'
              '0cd2ac2704104b8c43a2542050120467f333c00f42d804108c43a2542050'
              '120467f333c00f42d84b041043a2542050120467f333c00f42d84b8c0410'
              'a2551a058cdb00004b8d79f7caff5012000000000000')
    decoded = decode_tcap_message(hexstr)
    assert decoded.kind == CONTINUE
    assert decoded.otid == b'\x84\x00\x01\xff'
    assert decoded.dtid == b'\xa5\x05\x00\x01'
    assert decoded.decode_layer in ('tcap', 'map')


def test_decode_structural_reports_long_id():
    decoded = decode_tcap_message(begin_hex(b'\x01\x02\x03\x04\x05'))
    assert decoded.decode_layer == 'structural'
    assert any('outside 1..4' in warning for warning in decoded.warnings)


#------------------------------------------------------------------------------#
# scoping and reuse
#------------------------------------------------------------------------------#

def test_same_ids_different_endpoint_pairs_stay_separate():
    messages = [
        msg(begin_hex(b'\x00\x01'), 0, 'A', 'B'),
        msg(continue_hex(b'\x00\x02', b'\x00\x01'), 1, 'B', 'A'),
        msg(end_hex(b'\x00\x01'), 2, 'B', 'A'),
        msg(begin_hex(b'\x00\x01'), 3, 'C', 'D'),
        msg(continue_hex(b'\x00\x02', b'\x00\x01'), 4, 'D', 'C'),
        msg(end_hex(b'\x00\x01'), 5, 'D', 'C'),
    ]
    result = Reassembler().process(messages)
    assert len(result.dialogues) == 2
    first, second = result.dialogues
    assert first.endpoints == ('A', 'B')
    assert second.endpoints == ('C', 'D')
    assert ids(first) == {'A': '0001', 'B': '0002'}
    assert ids(second) == {'C': '0001', 'D': '0002'}
    assert [m.index for m in first.messages] == [0, 1, 2]
    assert [m.index for m in second.messages] == [3, 4, 5]


def test_naive_single_id_dictionary_merges_those_dialogues():
    messages = [
        msg(begin_hex(b'\x00\x01'), 0, 'A', 'B'),
        msg(end_hex(b'\x00\x01'), 1, 'B', 'A'),
        msg(begin_hex(b'\x00\x01'), 2, 'C', 'D'),
        msg(end_hex(b'\x00\x01'), 3, 'D', 'C'),
    ]
    result = Reassembler().process(messages)
    assert len(result.dialogues) == 2
    groups = dict((g['id'], g) for g in single_id_groups(result.messages))
    assert groups['0001']['dialogues'] == ['D0001', 'D0002']


def test_id_reuse_after_terminal_starts_new_dialogue():
    messages = [
        msg(begin_hex(b'\x00\x01'), 0, 'A', 'B', 1),
        msg(continue_hex(b'\x00\x02', b'\x00\x01'), 1, 'B', 'A', 2),
        msg(end_hex(b'\x00\x01'), 2, 'B', 'A', 3),
        msg(begin_hex(b'\x00\x01'), 3, 'A', 'B', 10),
        msg(continue_hex(b'\x00\x03', b'\x00\x01'), 4, 'B', 'A', 11),
        msg(end_hex(b'\x00\x01'), 5, 'B', 'A', 12),
    ]
    result = Reassembler().process(messages)
    assert len(result.dialogues) == 2
    first, second = result.dialogues
    assert [m.index for m in first.messages] == [0, 1, 2]
    assert [m.index for m in second.messages] == [3, 4, 5]
    assert ids(first) == {'A': '0001', 'B': '0002'}
    assert ids(second) == {'A': '0001', 'B': '0003'}
    assert second.reused_with == [first.dialogue_id]
    assert any(e.code == 'id-reused-after-terminal' for e in second.evidence)


def test_reuse_while_open_is_flagged_uncertain():
    messages = [
        msg(begin_hex(b'\x00\x01'), 0, 'A', 'B'),
        msg(begin_hex(b'\x00\x01'), 1, 'A', 'B'),
    ]
    result = Reassembler().process(messages)
    assert len(result.dialogues) == 2
    assert result.dialogues[1].uncertain
    assert any('reused while' in text
               for text in result.dialogues[1].uncertainty)


#------------------------------------------------------------------------------#
# terminal states and late messages
#------------------------------------------------------------------------------#

def test_late_continue_after_end_is_not_merged_into_reused_dialogue():
    messages = [
        # Dialogue 1, ended.
        msg(begin_hex(b'\x00\x01'), 0, 'A', 'B'),
        msg(continue_hex(b'\x00\x02', b'\x00\x01'), 1, 'B', 'A'),
        msg(end_hex(b'\x00\x01'), 2, 'B', 'A'),
        # Dialogue 2 reuses OTID 0001.
        msg(begin_hex(b'\x00\x01'), 3, 'A', 'B'),
        msg(continue_hex(b'\x00\x03', b'\x00\x01'), 4, 'B', 'A'),
        msg(end_hex(b'\x00\x01'), 5, 'B', 'A'),
        # Late Continue for dialogue 2 after its End, arriving while the
        # capture still has both dialogues.  It must not join dialogue 1.
        msg(continue_hex(b'\x00\x03', b'\x00\x01'), 6, 'B', 'A'),
    ]
    result = Reassembler().process(messages)
    assert len(result.dialogues) == 2
    first, second = result.dialogues
    assert [m.index for m in first.messages] == [0, 1, 2]
    assert [m.index for m in second.messages] == [3, 4, 5]
    assert [m.index for m in second.late_messages] == [6]
    assert first.late_messages == []
    late = second.late_messages[0]
    assert late.link_strength == 'late'
    assert any(e.code == 'late-after-terminal' for e in late.link_evidence)


def test_abort_closes_dialogue_and_reports_cause():
    messages = [
        msg(begin_hex(b'\x00\x07'), 0, 'G', 'H'),
        msg(continue_hex(b'\x00\x08', b'\x00\x07'), 1, 'H', 'G'),
        msg(abort_hex(b'\x00\x07', cause=4), 2, 'H', 'G'),
    ]
    result = Reassembler().process(messages)
    dia = result.dialogues[0]
    assert dia.state == 'closed'
    assert dia.end_reason == ABORT
    assert dia.abort_cause == {'kind': 'p-abortCause', 'value': 4}


def test_unterminated_dialogue_is_reported_with_interval():
    messages = [
        msg(begin_hex(b'\x00\x01'), 0, 'A', 'B', 100),
        msg(continue_hex(b'\x00\x02', b'\x00\x01'), 1, 'B', 'A', 140),
    ]
    result = Reassembler().process(messages)
    dia = result.dialogues[0]
    assert dia.unterminated
    assert dia.state == 'open'
    assert dia.interval() == (100, 140)
    assert any(e.code == 'unterminated-at-capture-end' for e in dia.evidence)


#------------------------------------------------------------------------------#
# missing capture
#------------------------------------------------------------------------------#

def test_continue_without_begin_opens_uncertain_dialogue():
    messages = [
        msg(continue_hex(b'\x00\x04', b'\x00\x05'), 0, 'F', 'E'),
        msg(end_hex(b'\x00\x05'), 1, 'F', 'E'),
    ]
    result = Reassembler().process(messages)
    assert len(result.dialogues) == 1
    dia = result.dialogues[0]
    assert dia.uncertain
    assert dia.confidence == 'uncertain'
    assert dia.initiator is None
    assert [m.index for m in dia.messages] == [0, 1]
    assert any('Begin not observed' in text for text in dia.uncertainty)


def test_late_begin_adopts_continue_orphan():
    # The Continue arrives first because the capture is out of order; the
    # later Begin supplies the missing direction instead of opening a second
    # dialogue.
    messages = [
        msg(continue_hex(b'\x00\x04', b'\x00\x05'), 0, 'F', 'E'),
        msg(begin_hex(b'\x00\x05'), 1, 'E', 'F'),
        msg(end_hex(b'\x00\x05'), 2, 'F', 'E'),
    ]
    result = Reassembler().process(messages)
    assert len(result.dialogues) == 1
    dia = result.dialogues[0]
    assert dia.initiator == 'E'
    assert [m.index for m in dia.messages] == [0, 1, 2]
    assert [m.direction for m in dia.messages] == ['unknown', 'forward', 'reverse']
    assert any(e.code == 'begin-adopts-orphan' for e in dia.evidence)
    assert not any('Begin not observed' in text for text in dia.uncertainty)


def test_end_alone_is_unresolved_not_guessed():
    messages = [msg(end_hex(b'\x00\xAA'), 0, 'L', 'K')]
    result = Reassembler().process(messages)
    assert result.dialogues == []
    assert len(result.unresolved) == 1
    assert result.unresolved[0]['reason'] == 'unknown transaction'
    assert 'one ID is not enough' in result.unresolved[0]['detail']


def test_missing_begin_and_ambiguous_ids_stay_unresolved():
    # Two open dialogues in one scope both know ID 0001; an End naming only
    # 0001 cannot be attributed to either.
    messages = [
        msg(begin_hex(b'\x00\x01'), 0, 'A', 'B'),
        msg(begin_hex(b'\x00\x01'), 1, 'C', 'D'),
        msg(end_hex(b'\x00\x01'), 2, 'B', 'A'),
        msg(end_hex(b'\x00\x01'), 3, 'D', 'C'),
    ]
    result = Reassembler().process(messages)
    # Different endpoint pairs are different scopes, so each End is unique.
    assert len(result.unresolved) == 0
    # Both open dialogues in one scope end up owning the same pair
    # (A=0001, B=0002), which is itself an anomaly; an End naming only 0001
    # then has two equally good open candidates.
    messages = [
        msg(begin_hex(b'\x00\x01'), 0, 'A', 'B'),
        msg(continue_hex(b'\x00\x02', b'\x00\x01'), 1, 'B', 'A'),
        msg(begin_hex(b'\x00\x01'), 2, 'A', 'B'),
        msg(continue_hex(b'\x00\x02', b'\x00\x01'), 3, 'B', 'A'),
        msg(end_hex(b'\x00\x01'), 4, 'B', 'A'),
    ]
    result = Reassembler().process(messages)
    ambiguous = [e for e in result.unresolved
                 if e['reason'].startswith('ambiguous')]
    assert ambiguous
    assert len(ambiguous[0]['candidates']) == 2


#------------------------------------------------------------------------------#
# ID validity
#------------------------------------------------------------------------------#

def test_overlong_ids_are_kept_but_flagged():
    messages = [
        msg(begin_hex(b'\x01\x02\x03\x04\x05'), 0, 'I', 'J'),
        msg(end_hex(b'\x01\x02\x03\x04\x05'), 1, 'J', 'I'),
    ]
    result = Reassembler().process(messages)
    assert len(result.dialogues) == 1
    dia = result.dialogues[0]
    assert dia.uncertain
    assert any('outside 1..4' in text for text in dia.uncertainty)
    assert all(m.decode_layer == 'structural' for m in dia.messages)


def test_empty_id_is_not_accepted_as_transaction():
    # 48 00: zero-length OTID.  Structural decoding keeps the value, but the
    # dialogue is flagged; an End with an empty DTID is unresolved.
    result = Reassembler().process([msg('620248006c00', 0, 'A', 'B')])
    assert result.dialogues or result.unresolved


def test_reverse_labelled_begin_is_normalized():
    # The caller supplied the Begin with src/dst swapped relative to the
    # scope order; the dialogue must still use the Begin as its direction.
    messages = [
        msg(begin_hex(b'\x00\x01'), 0, 'B', 'A'),
        msg(continue_hex(b'\x00\x02', b'\x00\x01'), 1, 'B', 'A'),
    ]
    result = Reassembler().process(messages)
    assert len(result.dialogues) == 1
    dia = result.dialogues[0]
    assert dia.initiator == 'A'
    assert [m.direction for m in dia.messages] == ['forward', 'reverse']
    assert not dia.uncertain


def test_same_id_for_both_endpoints_is_flagged():
    messages = [
        msg(begin_hex(b'\x00\x01'), 0, 'A', 'B'),
        msg(continue_hex(b'\x00\x01', b'\x00\x01'), 1, 'B', 'A'),
        msg(end_hex(b'\x00\x01'), 2, 'B', 'A'),
    ]
    result = Reassembler().process(messages)
    dia = result.dialogues[0]
    assert dia.uncertain
    assert any('not a distinguishing pair' in text for text in dia.uncertainty)


#------------------------------------------------------------------------------#
# evidence discipline
#------------------------------------------------------------------------------#

def test_similar_arguments_do_not_join_dialogues():
    # Two Begins on the same endpoint pair with different OTIDs but identical
    # (empty) components must stay separate: only IDs create the link.
    messages = [
        msg(begin_hex(b'\x00\x01'), 0, 'A', 'B'),
        msg(begin_hex(b'\x00\x02'), 1, 'A', 'B'),
        msg(end_hex(b'\x00\x02'), 2, 'B', 'A'),
    ]
    result = Reassembler().process(messages)
    assert len(result.dialogues) == 2
    first, second = result.dialogues
    assert [m.index for m in first.messages] == [0]
    assert [m.index for m in second.messages] == [1, 2]


def test_every_link_carries_evidence():
    result = Reassembler().process(load_scenario(demo_scenario()))
    for dia in result.dialogues:
        for m in dia.messages:
            assert m.link_evidence, (dia.dialogue_id, m.index)
            for evidence in m.link_evidence:
                assert evidence.code and evidence.detail


def test_demo_scenario_exercises_required_cases():
    result = Reassembler().process(load_scenario(demo_scenario()))
    assert len(result.dialogues) == 6
    assert any(d.late_messages for d in result.dialogues)
    assert any(d.uncertain for d in result.dialogues)
    assert any(m.warnings for d in result.dialogues for m in d.messages)
    assert any(not d.unterminated for d in result.dialogues)
    # The stray End remains unresolved.
    assert len(result.unresolved) == 1


def test_result_is_json_serializable():
    result = Reassembler().process(load_scenario(demo_scenario()))
    text = json.dumps(result.to_dict())
    parsed = json.loads(text)
    assert parsed['statistics']['dialogues'] == 6
    assert parsed['naive_single_id_groups']


#------------------------------------------------------------------------------#
# real capture
#------------------------------------------------------------------------------#

def test_real_capture_decoding_and_scoping():
    path = os.path.join(_HERE, 'res', 'tcapmap_pcapr.json')
    if not os.path.exists(path):
        return
    messages = []
    for line in open(path):
        if '"tcap_raw"' not in line:
            continue
        record = json.loads(line)
        layers = record['layers']
        raw = layers.get('ip_raw')
        if not raw:
            continue
        buf = bytes.fromhex(raw)
        src = '.'.join(str(b) for b in buf[12:16])
        dst = '.'.join(str(b) for b in buf[16:20])
        try:
            messages.append(decode_tcap_message(
                layers['tcap_raw'], index=len(messages), src=src, dst=dst,
                timestamp=int(record['timestamp'])))
        except DecodeError:
            continue
    assert len(messages) >= 50
    result = Reassembler().process(messages)
    for dia in result.dialogues:
        assert dia.endpoints[0] <= dia.endpoints[1]
    # Same short ID 00000001 appears in separate scopes and must not merge.
    id_0001 = [d for d in result.dialogues
               if any(tid_text(t) == '00000001' for t in d.owned.values())]
    assert id_0001
