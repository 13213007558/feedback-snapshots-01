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
# * File Name : test/test_nas_secaudit.py
# * Created : 2026-11-19
# * Authors : pycrate contributors
# *--------------------------------------------------------
#*/

import os
import json

from binascii import unhexlify, hexlify

from pycrate_crypto.AESCMAC import aes128_encrypt, cmac, nas_mac
from pycrate_mobile.NASSecAudit import (
    audit_transcript, audit_file, TranscriptError,
    STATUS_CONSISTENT, STATUS_WEAK_CONSISTENT, STATUS_INCONSISTENT,
    STATUS_INSUFFICIENT, EVIDENCE_CLEARTEXT, EVIDENCE_AUTHENTICATED,
    EVIDENCE_UNVERIFIED)
from pycrate_mobile.TS24501_FGMM import (
    FGMMRegistrationRequest, FGMMSecurityModeCommand, FGMMSecProtNASMessage)

RES = os.path.join('.', 'test', 'res', 'nas-secaudit')
KEY = bytes.fromhex('000102030405060708090a0b0c0d0e0f')


def _cap(ea, ia):
    return tuple([(ea>>i)&1 for i in range(3,-1,-1)] + [0]*4 +
                 [(ia>>i)&1 for i in range(3,-1,-1)] + [0]*4)


def _rr(ea, ia, regtype=1):
    m = FGMMRegistrationRequest()
    m['NAS_KSI'].set_val((7,))
    m['5GSRegType'].set_val({'V': (0, regtype)})
    m['5GSID'].set_val({'V': {'Type': 1, 'Fmt': 0,
        'Value': {'PLMN': '00101', 'RoutingInd': '0000',
                  'Output': '000000001'}}})
    m['UESecCap'].set_val({'V': _cap(ea, ia)})
    m['UESecCap'].set_trans(False)
    return hexlify(m.to_bytes()).decode()


def _smc(ea, ia, eea, eia):
    m = FGMMSecurityModeCommand()
    m['NASSecAlgo']['V'].set_val(bytes([(ea << 4) | ia]))
    m['NAS_KSI'].set_val((0, 0))
    m['UESecCap'].set_val({'V': _cap(eea, eia)})
    m['UESecCap'].set_trans(False)
    return m.to_bytes()


def _protect(inner, sec_hdr, count, direction, mac=None, key=KEY):
    if mac is None:
        mac = nas_mac(key, count, 1, direction,
                      bytes([count & 0xff]) + inner)
    w = FGMMSecProtNASMessage()
    w[0]['SecHdr'].set_val(sec_hdr)
    w['MAC'].set_val(mac)
    w['Seqn'].set_val(count & 0xff)
    w['NASMessage'].set_val(inner)
    return hexlify(w.to_bytes()).decode()


def test_aes_cmac_vectors():
    # FIPS-197 C.1
    key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    pt  = bytes.fromhex('00112233445566778899aabbccddeeff')
    assert aes128_encrypt(key, pt) == \
        bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
    # RFC 4493, all four examples
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    vectors = (
        (b'', 'bb1d6929e95937287fa37d129b756746'),
        ('6bc1bee22e409f96e93d7e117393172a',
         '070a16b46b4d4144f79bdd9dd04a287c'),
        ('6bc1bee22e409f96e93d7e117393172a'
         'ae2d8a571e03ac9c9eb76fac45af8e51',
         'ce0cbf1738f4df6428b1d93bf12081c9'),
        ('6bc1bee22e409f96e93d7e117393172a'
         'ae2d8a571e03ac9c9eb76fac45af8e51'
         '30c81c46a35ce411e5fbc1191a0a52ef'
         'f69f2445df4f9b17ad2b417be66c3710',
         '51f0bebf7e3b9d92fc49741779363cfe'),
        )
    for msg, expected in vectors:
        assert cmac(key, unhexlify(msg)) == unhexlify(expected)
    # NAS MAC layout: COUNT | BEARER | DIRECTION | 4 zero octets | message
    mac = nas_mac(KEY, 0x01020304, 1, 1, b'\x07\x41')
    expected = cmac(KEY, bytes.fromhex('01020304' '01' '01' '00000000')
                    + b'\x07\x41')[:4]
    assert mac == expected


def test_missing_key_is_not_a_pass():
    # a record with a MAC field but no key must never report verified
    tr = {'procedure': 'p', 'ue': 'u', 'algorithms': {'integrity': 2},
          'records': [{'n': 1, 'dir': 'DL', 'count': 0,
                       'pdu': '7e0301020304007e005d220002f0f0'}]}
    rep = audit_transcript(tr)
    assert rep.messages[0]['mac_status'].startswith('not_attempted')
    assert rep.conclusion['confirmed_downgrade'] is False


def test_null_integrity_is_not_a_pass():
    # 5G-IA0 defines no MAC; zero bytes must not be read as a valid check
    smc = _smc(0, 0, 0b1000, 0b1000)
    pdu = _protect(smc, 3, 0, 1, mac=b'\0\0\0\0')
    tr = {'procedure': 'p', 'ue': 'u', 'algorithms': {'integrity': 0},
          'records': [{'n': 1, 'dir': 'DL', 'count': 0, 'pdu': pdu}]}
    rep = audit_transcript(tr)
    assert rep.messages[0]['mac_status'] == 'not_attempted_null_integrity'


def test_wrong_count_blocks_verification():
    tr = {'procedure': 'p', 'ue': 'u', 'keys': {'K_NASint': KEY.hex()},
          'algorithms': {'integrity': 2},
          'records': [{'n': 1, 'dir': 'DL', 'count': 0x105,
                       'pdu': '7e0300000000007e005d220002f0f0'}]}
    rep = audit_transcript(tr)
    assert rep.messages[0]['mac_status'] == 'not_attempted_count_mismatch'


def test_normal_transcript():
    rep = audit_file(os.path.join(RES, 'normal.json'))
    assert rep.conclusion['status'] == STATUS_CONSISTENT
    assert rep.conclusion['confirmed_downgrade'] is False
    d = rep.declarations
    assert d['registration_request']['evidence'] == EVIDENCE_CLEARTEXT
    assert d['smc_echo']['evidence'] == EVIDENCE_AUTHENTICATED
    assert rep.selection['ciphering'] == 2 and rep.selection['integrity'] == 2
    assert not [f for f in rep.findings if f.severity in ('warning', 'error')]


def test_capability_replaced_transcript():
    rep = audit_file(os.path.join(RES, 'capability-replaced.json'))
    assert rep.conclusion['status'] == STATUS_INCONSISTENT
    # a capability replacement is shown, but no downgrade is asserted
    assert rep.conclusion['confirmed_capability_replacement'] is True
    assert rep.conclusion['confirmed_downgrade'] is False
    codes = {f.code for f in rep.warnings}
    assert 'capability-echo-drift' in codes
    # the narrowed echo still covers the selected EA0/IA2, so the contradiction
    # is between the capability declarations, not against the selection itself
    assert 'selection-not-echoed' not in codes
    drift = rep.findings_by_code('capability-echo-drift')[0]
    # the warning names the exact fields and their state
    names = [f['field'] for f in drift.fields]
    assert 'RegistrationRequest.UESecCap' in names
    assert 'SecurityModeCommand.UESecCap' in names
    assert all(f['evidence'] == EVIDENCE_AUTHENTICATED for f in drift.fields)


def test_capture_gap_transcript():
    rep = audit_file(os.path.join(RES, 'capture-gap.json'))
    assert rep.conclusion['status'] == STATUS_INSUFFICIENT
    assert rep.conclusion['confirmed_downgrade'] is False
    assert rep.selection is None
    codes = {f.code for f in rep.warnings}
    assert 'capture-gap' in codes
    # the later protected message must not be counted as verified
    after = [m for m in rep.messages if m.get('n') == 3][0]
    assert after['evidence'] == EVIDENCE_UNVERIFIED
    assert after['mac_status'].startswith('not_attempted')


def test_weak_but_consistent_is_not_a_downgrade():
    # a UE that only holds null algorithms, a matching echo and a null
    # selection: weak, but nothing in the capture is inconsistent
    rr  = _rr(0b1000, 0b1000)
    smc = _smc(0, 0, 0b1000, 0b1000)
    tr = {'procedure': 'p', 'ue': 'u',
          'records': [{'n': 1, 'dir': 'UL', 'count': 0, 'pdu': rr},
                      {'n': 2, 'dir': 'DL', 'count': 0,
                       'pdu': _protect(smc, 3, 0, 1, mac=b'\0\0\0\0')}]}
    rep = audit_transcript(tr)
    assert rep.conclusion['status'] == STATUS_WEAK_CONSISTENT
    assert rep.conclusion['confirmed_downgrade'] is False
    assert rep.findings_by_code('weak-selection')


def test_smc_selecting_null_with_nonzero_mac():
    # IA0 selected but MAC bytes present: flagged, not silently accepted
    smc = _smc(0, 0, 0b1000, 0b1000)
    pdu = _protect(smc, 3, 0, 1, mac=unhexlify('aabbccdd'))
    tr = {'procedure': 'p', 'ue': 'u', 'algorithms': {'integrity': 0},
          'records': [{'n': 1, 'dir': 'DL', 'count': 0, 'pdu': pdu}]}
    rep = audit_transcript(tr)
    assert rep.findings_by_code('null-integrity-with-mac')
    assert rep.conclusion['confirmed_downgrade'] is False


def test_ciphered_payload_is_opaque():
    tr = {'procedure': 'p', 'ue': 'u', 'algorithms': {'integrity': 2},
          'records': [{'n': 1, 'dir': 'DL', 'count': 0,
                       'pdu': '7e02aabbccdd00' '7e005d220002f0f0'}]}
    rep = audit_transcript(tr)
    assert rep.messages[0].get('error')
    assert rep.conclusion['status'] == STATUS_INSUFFICIENT


def test_record_from_other_procedure_is_flagged():
    tr = {'procedure': 'initial-registration', 'ue': 'u',
          'algorithms': {'integrity': 2},
          'records': [{'n': 1, 'dir': 'UL', 'procedure': 'tau',
                       'pdu': '7e004171000d0100f1100000000000000000f12e02f0f0'}]}
    rep = audit_transcript(tr)
    assert rep.findings_by_code('procedure-mismatch')


def test_transcript_error_cases():
    for bad in ({}, {'records': 'nope'}):
        try:
            audit_transcript(bad)
        except TranscriptError:
            pass
        else:
            raise AssertionError('TranscriptError not raised for %r' % (bad,))
    # invalid hex and non-5G protocols become findings, not exceptions
    tr = {'procedure': 'p', 'ue': 'u',
          'records': [{'n': 1, 'dir': 'UL', 'pdu': 'zz'},
                      {'n': 2, 'dir': 'UL', 'pdu': '0741710b'}]}
    rep = audit_transcript(tr)
    assert len(rep.messages) == 2
    assert all(m.get('error') for m in rep.messages)
    assert rep.conclusion['status'] == STATUS_INSUFFICIENT


def test_cli_exit_codes():
    from tools.pycrate_nas_secaudit import main
    assert main([os.path.join(RES, 'normal.json'), '-q']) == 0
    assert main([os.path.join(RES, 'capability-replaced.json'), '-q']) == 1
    assert main([os.path.join(RES, 'capture-gap.json'), '-q']) == 1
    assert main(['/nonexistent/transcript.json', '-q']) == 2


def test_json_report_is_serialisable():
    rep = audit_file(os.path.join(RES, 'capability-replaced.json'))
    text = json.dumps(rep.to_dict(), sort_keys=True)
    assert 'capability-replaced' in text
    assert json.loads(text)['conclusion']['confirmed_downgrade'] is False


def test_selection_without_declaration_is_insufficient():
    # a verified SMC on its own says what was chosen, not whether it matches
    smc = _smc(2, 2, 0b1111, 0b1111)
    pdu = _protect(smc, 3, 0, 1)
    tr = {'procedure': 'p', 'ue': 'u', 'keys': {'K_NASint': KEY.hex()},
          'algorithms': {'integrity': 2},
          'records': [{'n': 1, 'dir': 'DL', 'count': 0, 'pdu': pdu}]}
    rep = audit_transcript(tr)
    assert rep.selection['evidence'] == EVIDENCE_AUTHENTICATED
    assert rep.conclusion['status'] == STATUS_INSUFFICIENT
    assert rep.conclusion['confirmed_downgrade'] is False
    assert 'declaration-unusable' in {f.code for f in rep.warnings}
    assert 'capability-absent' in {f.code for f in rep.warnings}


def test_unverifiable_declaration_is_flagged():
    # an integrity protected declaration without key material is not verified
    rr = _rr(0b1110, 0b1110)
    raw = unhexlify(rr)
    pdu = _protect(raw, 1, 3, 0)
    tr = {'procedure': 'p', 'ue': 'u',
          'records': [{'n': 1, 'dir': 'UL', 'count': 3, 'pdu': pdu}]}
    rep = audit_transcript(tr)
    decl = rep.declarations['registration_request']
    assert decl['evidence'] == EVIDENCE_UNVERIFIED
    assert 'capability-unverified' in {f.code for f in rep.warnings}


def test_wrong_key_fails_and_does_not_downgrade_to_unverified():
    smc = _smc(2, 2, 0b1111, 0b1111)
    pdu = _protect(smc, 3, 0, 1, key=b'\x11' * 16)
    tr = {'procedure': 'p', 'ue': 'u',
          'keys': {'K_NASint': KEY.hex()}, 'algorithms': {'integrity': 2},
          'records': [{'n': 1, 'dir': 'DL', 'count': 0, 'pdu': pdu}]}
    rep = audit_transcript(tr)
    assert rep.messages[0]['mac_status'] == 'failed'
    assert 'mac-failed' in {f.code for f in rep.warnings}
    assert rep.selection['evidence'] == EVIDENCE_UNVERIFIED


def test_capability_echo_drift_is_reported_even_when_selection_matches():
    # echo narrowed to EA0 only, selection EA0/IA2: echo covers the selection,
    # yet the drift against the declaration must still surface
    rr  = _rr(0b1110, 0b1110)
    smc = _smc(0, 2, 0b1000, 0b0010)
    tr = {'procedure': 'p', 'ue': 'u', 'keys': {'K_NASint': KEY.hex()},
          'algorithms': {'integrity': 2},
          'records': [{'n': 1, 'dir': 'UL', 'count': 0, 'pdu': rr},
                      {'n': 2, 'dir': 'DL', 'count': 0,
                       'pdu': _protect(smc, 3, 0, 1)}]}
    rep = audit_transcript(tr)
    assert rep.findings_by_code('capability-echo-drift')
    assert not rep.findings_by_code('selection-not-echoed')
    # the declaration here is cleartext, so the inconsistency is confirmed but
    # the side that rewrote the capability is not
    assert rep.conclusion['status'] == STATUS_INCONSISTENT
    assert rep.conclusion['confirmed_capability_replacement'] is False
    assert rep.conclusion['confirmed_downgrade'] is False
