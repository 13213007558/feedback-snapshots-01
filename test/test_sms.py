# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.6
# *
# * Copyright 2023. Benoit Michau. P1Sec.
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
# * File Name : test/test_sms.py
# * Created : 2023-11-20
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from binascii   import unhexlify
from timeit     import timeit

from pycrate_mobile.TS23040_SMS import *

# SMS 7 bit character together with UDH requires complex alignment and padding
# Here is a harness test to ensure everything gets encoded / decoded properly

def test_tpudh(I=28, J=8):
    for i in range(0, I):
        for j in range(0, J):
            txt = i*'A'
            enc = SMS_SUBMIT(val={
                'TP_UDHI': 1,
                'TP_DA'  : {'Num': '33123456'},
                'TP_DCS' : {'Group': 0, 'Charset': 0, 'Class': 0},
                'TP_UD'  : {
                    'UDH' : {'UDH': [{'T': 2, 'V': j*b'\0'}]},
                    'UD'  : txt
                }})
            buf = enc.to_bytes()
            dec = SMS_SUBMIT()
            dec.from_bytes(buf)
            assert( dec['TP_UD']['UD'].decode() in (txt, txt+'\r') )


# For more real-cases testing, here are some wireshark filters to collect such kind of SMS
# gsm_sms.tp-dcs == 0 and gsm_sms.dis_field_udh.user_data_header_length != 6 and gsm_sms.ie_identifier != 0x00
# gsm_sms.dis_field_udh.gsm.fill_bits == 0x0 and gsm_sms.ie_identifier != 0x00


def test_perf_sms():
    
    print('[+] SMS_SUBMIT encoding and decoding with GSM 7-bit and TP-UDH')
    Ta = timeit(test_tpudh, number=5)
    print('test_tpudh: {0:.4f}'.format(Ta))


if __name__ == '__main__':
    test_perf_sms()



#------------------------------------------------------------------------------#
# Concatenated SMS reassembly, keyed on the full group identity
#------------------------------------------------------------------------------#

from pycrate_mobile.TS23040_SMS_Concat import (
    SMSConcatAssembler, assemble_concat_sms, reassemble_concat_sms,
    ISSUE_PID_CONFLICT,
    STATE_COMPLETE, STATE_INCOMPLETE, STATE_CONFLICT,
    ISSUE_DUPLICATE_CONFLICT, ISSUE_DUPLICATE_IDENTICAL, ISSUE_TOTAL_CONFLICT,
    ISSUE_MISSING_SEGMENTS,
    )


def _mt_tpdu(origin, ref, total, seq, text, ref16=False, ports=None,
             charset=0, group=0):
    ies = [{'T': 8, 'V': {'MsgRef': ref, 'MsgParts': total, 'MsgNum': seq}}
           if ref16 else
           {'T': 0, 'V': {'MsgRef': ref, 'MsgParts': total, 'MsgNum': seq}}]
    if ports is not None:
        dest, src = ports
        if dest > 0xFF or src > 0xFF:
            ies.append({'T': 5, 'V': {'Dest': dest, 'Origin': src}})
        else:
            ies.append({'T': 4, 'V': {'Dest': dest, 'Origin': src}})
    tp = SMS_DELIVER(val={
        'TP_UDHI': 1,
        'TP_OA'  : {'Num': origin},
        'TP_DCS' : {'Group': group, 'Charset': charset, 'Class': 0},
        'TP_UD'  : {'UDH': {'UDH': ies}, 'UD': text}})
    return tp.to_bytes()


def _mo_tpdu(dest, ref, total, seq, text):
    tp = SMS_SUBMIT(val={
        'TP_UDHI': 1,
        'TP_DA'  : {'Num': dest},
        'TP_DCS' : {'Group': 0, 'Charset': 0, 'Class': 0},
        'TP_UD'  : {'UDH': {'UDH': [
            {'T': 0, 'V': {'MsgRef': ref, 'MsgParts': total, 'MsgNum': seq}}]},
                    'UD': text}})
    return tp.to_bytes()


def test_concat_same_reference_two_senders():
    sender_a, sender_b = '11111', '22222'
    transcript = [
        _mt_tpdu(sender_a, 5, 2, 1, 'AAA'),
        _mt_tpdu(sender_b, 5, 2, 1, 'BBB'),
        _mt_tpdu(sender_a, 5, 2, 2, 'aaa'),
        _mt_tpdu(sender_b, 5, 2, 2, 'bbb'),
        ]
    assembler = assemble_concat_sms(transcript)
    messages = assembler.messages
    assert len(messages) == 2
    assert all(m.state == STATE_COMPLETE for m in messages)
    by_origin = {m.originator: m for m in messages}
    assert set(by_origin) == {sender_a, sender_b}
    assert by_origin[sender_a].text == 'AAAaaa'
    assert by_origin[sender_b].text == 'BBBbbb'
    # every segment remains individually retrievable
    for message in messages:
        assert [s.concat_seq for s in message.segments] == [1, 2]
        for segment in message.segments:
            assert segment.raw_tpdu in transcript
            assert segment.originator == message.originator


def test_concat_same_reference_is_not_a_global_key():
    transcript = [
        _mt_tpdu('11111', 7, 1, 1, 'one'),
        _mt_tpdu('22222', 7, 1, 1, 'two'),
        ]
    messages = reassemble_concat_sms(transcript)
    assert len(messages) == 2
    assert {m.text for m in messages} == {'one', 'two'}


def test_concat_duplicate_conflicting_segment_is_not_resolved():
    transcript = [
        _mt_tpdu('11111', 9, 2, 1, 'first'),
        _mt_tpdu('11111', 9, 2, 1, 'second'),
        _mt_tpdu('11111', 9, 2, 2, 'tail'),
        ]
    message = reassemble_concat_sms(transcript)[0]
    assert message.state == STATE_CONFLICT
    assert ISSUE_DUPLICATE_CONFLICT in message.issues
    # no arrival-order winner: no complete text at all
    assert message.text is None
    # both conflicting variants remain available for review
    variants = message.for_seq(1)
    assert len(variants) == 2
    assert {v.text for v in variants} == {'first', 'second'}
    assert message.segment(1) is None


def test_concat_duplicate_identical_segment():
    transcript = [
        _mt_tpdu('11111', 10, 2, 1, 'same'),
        _mt_tpdu('11111', 10, 2, 1, 'same'),
        _mt_tpdu('11111', 10, 2, 2, 'end'),
        ]
    message = reassemble_concat_sms(transcript)[0]
    assert message.state == STATE_COMPLETE
    assert ISSUE_DUPLICATE_IDENTICAL in message.issues
    assert message.text == 'sameend'
    assert len(message.for_seq(1)) == 2


def test_concat_conflicting_total_segment_count():
    transcript = [
        _mt_tpdu('11111', 11, 2, 1, 'x'),
        _mt_tpdu('11111', 11, 3, 2, 'y'),
        ]
    message = reassemble_concat_sms(transcript)[0]
    assert message.state == STATE_CONFLICT
    assert ISSUE_TOTAL_CONFLICT in message.issues
    assert message.totals == (2, 3)
    assert message.total is None
    assert message.missing is None
    assert message.text is None


def test_concat_missing_segment_is_incomplete():
    transcript = [_mt_tpdu('11111', 12, 3, 1, 'one')]
    message = reassemble_concat_sms(transcript)[0]
    assert message.state == STATE_INCOMPLETE
    assert ISSUE_MISSING_SEGMENTS in message.issues
    assert message.missing == (2, 3)
    assert message.text is None


def test_concat_reference_width_separates_groups():
    # Same 8-bit value 5 and 16-bit value 5 are different concatenations.
    transcript = [
        _mt_tpdu('11111', 5, 1, 1, 'short'),
        _mt_tpdu('11111', 5, 1, 1, 'wide', ref16=True),
        ]
    messages = reassemble_concat_sms(transcript)
    assert len(messages) == 2
    assert {m.reference_form for m in messages} == {'8-bit', '16-bit'}
    assert {m.text for m in messages} == {'short', 'wide'}


def test_concat_port_and_dcs_separate_groups():
    transcript = [
        _mt_tpdu('11111', 5, 1, 1, 'wap', ports=(9200, 2948)),
        _mt_tpdu('11111', 5, 1, 1, 'other', ports=(1111, 2222)),
        _mt_tpdu('11111', 5, 1, 1, 'ucs', charset=2),
        ]
    messages = reassemble_concat_sms(transcript)
    assert len(messages) == 3
    assert {m.text for m in messages} == {'wap', 'other', 'ucs'}
    ports = {m.ports for m in messages if m.ports is not None}
    assert ports == {(9200, 2948), (1111, 2222)}


def test_concat_mo_requires_origin_and_keeps_evidence():
    tpdu = _mo_tpdu('99999', 3, 1, 1, 'momo')
    assembler = assemble_concat_sms([tpdu])
    assert assembler.messages == ()
    assert len(assembler.rejected) == 1
    assert assembler.rejected[0].reason == 'origin_required'
    assert assembler.rejected[0].raw_tpdu == tpdu
    # supplying the origin yields a complete MO message
    assembler = assemble_concat_sms([{'tpdu': tpdu, 'origin': '11111'}])
    message = assembler.messages[0]
    assert message.direction == 'MO'
    assert message.originator == '11111'
    assert message.text == 'momo'


def test_concat_bad_input_is_rejected_not_merged():
    non_concat = SMS_DELIVER(val={
        'TP_OA': {'Num': '11111'},
        'TP_DCS': {'Group': 0, 'Charset': 0, 'Class': 0},
        'TP_UD': {'UD': 'plain'}}).to_bytes()
    assembler = assemble_concat_sms([non_concat])
    assert assembler.messages == ()
    assert assembler.rejected[0].reason == 'not_concatenated'
    assert assembler.rejected[0].raw_tpdu == non_concat


def test_concat_per_segment_lookup():
    transcript = [
        _mt_tpdu('11111', 13, 2, 1, 'AAA'),
        _mt_tpdu('22222', 13, 2, 1, 'BBB'),
        _mt_tpdu('11111', 13, 2, 2, 'aaa'),
        _mt_tpdu('22222', 13, 2, 2, 'bbb'),
        ]
    assembler = assemble_concat_sms(transcript)
    messages = assembler.messages_for_reference(13)
    assert len(messages) == 2
    for message in messages:
        assert message.text is not None
        for segment in message.segments:
            assert segment.raw_tpdu in transcript
            assert segment.key.reference == 13


def test_concat_ucs2_split_across_segment_boundary():
    full = SMS_DELIVER(val={
        'TP_UDHI': 1,
        'TP_OA'  : {'Num': '11111'},
        'TP_DCS' : {'Group': 0, 'Charset': 2, 'Class': 0},
        'TP_UD'  : {'UDH': {'UDH': [
            {'T': 0, 'V': {'MsgRef': 14, 'MsgParts': 2, 'MsgNum': 1}}]},
                    'UD': '你好'}})
    parsed = SMS_DELIVER()
    parsed.from_bytes(full.to_bytes())
    body = parsed['TP_UD']['UD'].get_val()

    def segment(seq, payload):
        return SMS_DELIVER(val={
            'TP_UDHI': 1,
            'TP_OA'  : {'Num': '11111'},
            'TP_DCS' : {'Group': 0, 'Charset': 2, 'Class': 0},
            'TP_UD'  : {'UDH': {'UDH': [
                {'T': 0, 'V': {'MsgRef': 14, 'MsgParts': 2, 'MsgNum': seq}}]},
                        'UD': payload}}).to_bytes()

    # Split in the middle of a UCS2 character: no segment decodes on its own.
    transcript = [segment(1, body[:3]), segment(2, body[3:])]
    message = reassemble_concat_sms(transcript)[0]
    assert message.state == STATE_COMPLETE
    assert message.text == '你好'
    assert message.body_bytes == body


def test_concat_pid_conflict_is_held_for_review():
    def segment(seq, text, pid):
        return SMS_DELIVER(val={
            'TP_UDHI': 1,
            'TP_OA'  : {'Num': '11111'},
            'TP_PID' : {'Format': 1, 'Protocol': pid},
            'TP_DCS' : {'Group': 0, 'Charset': 0, 'Class': 0},
            'TP_UD'  : {'UDH': {'UDH': [
                {'T': 0, 'V': {'MsgRef': 15, 'MsgParts': 2, 'MsgNum': seq}}]},
                        'UD': text}}).to_bytes()
    message = reassemble_concat_sms([
        segment(1, 'left', 0), segment(2, 'right', 1)])[0]
    assert message.state == STATE_CONFLICT
    assert ISSUE_PID_CONFLICT in message.issues
    assert message.text is None


def test_sms_concat():
    """Run every concatenation-reassembly check (used by test_pycrate)."""
    test_concat_same_reference_two_senders()
    test_concat_same_reference_is_not_a_global_key()
    test_concat_duplicate_conflicting_segment_is_not_resolved()
    test_concat_duplicate_identical_segment()
    test_concat_conflicting_total_segment_count()
    test_concat_missing_segment_is_incomplete()
    test_concat_reference_width_separates_groups()
    test_concat_port_and_dcs_separate_groups()
    test_concat_mo_requires_origin_and_keeps_evidence()
    test_concat_bad_input_is_rejected_not_merged()
    test_concat_per_segment_lookup()
    test_concat_ucs2_split_across_segment_boundary()
    test_concat_pid_conflict_is_held_for_review()
