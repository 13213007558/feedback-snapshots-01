# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# *
# * Test transcript for structured 5G NAS identity redaction (NAS5GRedact).
# *
# * This library is free software; you can redistribute it and/or
# * modify it under the terms of the GNU Lesser General Public
# * License as published by the Free Software Foundation; either
# * version 2.1 of the License, or (at your option) any later version.
# */

import json

import pytest

from pycrate_mobile.NAS5G    import parse_NAS5G
from pycrate_mobile.TS24501_FGMM import (
    FGMMRegistrationRequest,
    FGMMIdentityResponse,
    FGMMSecProtNASMessage,
    FGMMMODeregistrationRequest,
    )
from pycrate_mobile.TS24501_IE import (
    FGSID,
    FGSIDSUPI,
    FGSIDTYPE,
    FGSIDFMT,
    )
from pycrate_mobile.NAS5GRedact import (
    redact_message,
    SubjectClass,
    RedactionKeyError,
    )


# a transcript-wide caller key: aliases of correlated identifiers are derived
# from it, and it never appears in any export
KEY = b'transcript-redaction-key-0123456789'

# clear-text / protected identifiers used to build the transcript
IMSI_MSIN       = '1234567890'
IMSI_FULL       = '20869' + IMSI_MSIN
SUCI_ROUTING    = '1234'
SUCI_HNPKID     = 2
ECIES_EPHEM_PK  = b'\x11' * 32
ECIES_CIPHER    = b'\xbe\xef' * 8
ECIES_MAC       = b'\x22' * 8
GUTI_TMSI       = 0x11223344
GUTI_TMSI_HEX   = '%08x' % GUTI_TMSI
IMEI_DIGITS     = '356938035643809'
IMEISV_DIGITS   = '35693803564380901'
STMSI_TMSI      = 0xaabbccdd
STMSI_TMSI_HEX  = '%08x' % STMSI_TMSI
NAI_USERID      = 'alice'
NAI_REALM       = 'realm.example'
NAI_ECC_CIPHER  = 'bb' * 16
MAC_ADDR        = b'\x0a\x00\x27\x00\x00\x00'
EUI64_ADDR      = b'\xaa' * 8

# every byte-level / digit-level token that must never leave the export branch
FORBIDDEN_TOKENS = (
    IMSI_MSIN,
    IMSI_FULL,
    GUTI_TMSI_HEX,
    IMEI_DIGITS,
    IMEISV_DIGITS,
    STMSI_TMSI_HEX,
    NAI_USERID,
    ECIES_EPHEM_PK.hex(),
    ECIES_CIPHER.hex(),
    ECIES_MAC.hex(),
    NAI_ECC_CIPHER,
    MAC_ADDR.hex(),
    EUI64_ADDR.hex(),
    )


#------------------------------------------------------------------------------#
# Transcript builders
#------------------------------------------------------------------------------#

def _build_registration_request():
    """Registration request carrying a protected SUCI and an additional GUTI.

    Returned after a full encode / parse cycle, as for a captured transcript,
    so both identity IEs are decoded into their structured form.
    """
    msg = FGMMRegistrationRequest()
    suci = FGSID(val={
        'Type': FGSIDTYPE.SUPI,
        'Fmt': FGSIDFMT.IMSI,
        'Value': {
            'PLMN': '20869',
            'RoutingInd': SUCI_ROUTING,
            'ProtSchemeID': 1,
            'HNPKID': SUCI_HNPKID,
            'Output': (ECIES_EPHEM_PK, ECIES_CIPHER, ECIES_MAC),
            },
        })
    msg['5GSID'].set_IE(val=suci.get_val())
    guti = FGSID(val={
        'Type': FGSIDTYPE.GUTI,
        'PLMN': '20869',
        'AMFRegionID': 0xaa,
        'AMFSetID': 0x200,
        'AMFPtr': 0x1f,
        '5GTMSI': GUTI_TMSI,
        })
    msg['AddGUTI'].set_trans(False)
    msg['AddGUTI'].set_val({'T': 0x77, 'V': guti.to_bytes()})
    parsed, err = parse_NAS5G(msg.to_bytes())
    assert err == 0
    return parsed


def _build_null_suci_registration():
    """Registration request with a null-scheme SUCI (clear-text IMSI)."""
    msg = FGMMRegistrationRequest()
    suci = FGSID(val={
        'Type': FGSIDTYPE.SUPI,
        'Fmt': FGSIDFMT.IMSI,
        'Value': {
            'PLMN': '20869',
            'RoutingInd': SUCI_ROUTING,
            'ProtSchemeID': 0,
            'HNPKID': 0,
            'Output': IMSI_MSIN,
            },
        })
    msg['5GSID'].set_IE(val=suci.get_val())
    parsed, err = parse_NAS5G(msg.to_bytes())
    assert err == 0
    return parsed


def _build_identity_response(identity_type=FGSIDTYPE.IMEI, digits=IMEI_DIGITS):
    msg = FGMMIdentityResponse()
    ident = FGSID(val={'Type': identity_type, 'Digits': digits})
    msg['5GSID'].set_IE(val=ident.get_val())
    return msg


def _build_nai_suci(scheme):
    """SUPI/SUCI in NAI format, null-scheme or ECIES protected."""
    supi = FGSIDSUPI()
    if scheme == 0:
        nai = 'type1.rid%s.schid0.userid%s@%s' % (
            SUCI_ROUTING, NAI_USERID, NAI_REALM)
    else:
        nai = ('type1.rid%s.schid1.hnkey%d.ecckey%s.cip%s.mac%s@%s' % (
            SUCI_ROUTING, SUCI_HNPKID, 'aa' * 32, NAI_ECC_CIPHER,
            'cc' * 8, NAI_REALM))
    supi.from_nai(nai)
    return FGSID(val=supi.get_val())


def _build_ul_transport_with_nested_payload():
    """UL NAS transport whose payload container nests a 5GSM message.

    Built from a valid transcript encoding so that `parse_NAS5G` decodes the
    N1 SM payload container into a nested 5GSM element.
    """
    wire = bytes.fromhex(
        '7e00670100072e0602c1000091120681220401000001250706766973696f6e')
    parsed, err = parse_NAS5G(wire)
    assert err == 0
    return parsed


def _build_security_protected_message():
    """Integrity-protected envelope around a deregistration with a 5G-S-TMSI."""
    inner = FGMMMODeregistrationRequest()
    stmsi = FGSID(val={
        'Type': FGSIDTYPE.STMSI,
        'AMFSetID': 0x200,
        'AMFPtr': 0x1f,
        '5GTMSI': STMSI_TMSI,
        })
    inner['5GSID'].set_IE(val=stmsi.get_val())
    sec = FGMMSecProtNASMessage()
    # 1: integrity protected 5GS mobility management message
    sec[0]['SecHdr'].set_val(1)
    sec['NASMessage'].set_val(inner.to_bytes())
    # full encode / parse cycle so the inner NAS message is decoded and the
    # walker can reach the nested 5G-S-TMSI instead of seeing a raw buffer
    parsed, err = parse_NAS5G(sec.to_bytes())
    assert err == 0
    return parsed


def _all_nodes(node, acc):
    acc.append(node)
    if isinstance(node, dict):
        for value in node.values():
            _all_nodes(value, acc)
    elif isinstance(node, list):
        for value in node:
            _all_nodes(value, acc)
    return acc


def _find_identity_nodes(export):
    # identity IE nodes are the structural ones carrying the type plus either
    # allowed metadata or an output; redaction records (flag `redacted`) are
    # nested under them and must not be counted as separate IE nodes
    nodes = [n for n in _all_nodes(export['tree'], [])
             if isinstance(n, dict) and n.get('element') == '5GSID'
             and 'identity_type' in n and not n.get('redacted')]
    unique = {}
    for node in nodes:
        unique[tuple(node['path'])] = node
    return list(unique.values())


def _redactions_by_field(export, field):
    return [r for r in export['redactions'] if r.get('field') == field]


def _assert_no_forbidden_token(export):
    text = json.dumps(export, default=str)
    for token in FORBIDDEN_TOKENS:
        assert token not in text
    # the caller key itself must never be exported
    assert KEY.decode('ascii') not in text


#------------------------------------------------------------------------------#
# Transcript-level tests
#------------------------------------------------------------------------------#

def test_registration_request_suci_and_guti():
    parsed = _build_registration_request()

    export = redact_message(parsed, KEY)
    assert export['message'] == 'FGMMRegistrationRequest'

    identities = _find_identity_nodes(export)
    assert len(identities) == 2

    # --- protected SUCI: routing / scheme metadata stays analyzable ---
    suci = next(n for n in identities if n['format'] == FGSIDFMT.IMSI)
    assert suci['allowed'] == {
        'PLMN': '20869',
        'RoutingInd': SUCI_ROUTING,
        'ProtSchemeID': 1,
        'HNPKID': SUCI_HNPKID,
        }
    suci_rec = _redactions_by_field(export, 'ECIESOutput')
    assert len(suci_rec) == 1
    assert suci_rec[0]['subject_class'] == SubjectClass.PERMANENT_PROT
    # only structural lengths of the protected material survive
    assert suci['output']['components'] == {
        'ECCEphemPK': {'len': 32},
        'CipherText': {'len': 16},
        'MAC': {'len': 8},
        }

    # --- additional GUTI: AMF locator kept, 5G-TMSI aliased ---
    guti = next(n for n in identities if n['identity_type'] == FGSIDTYPE.GUTI)
    assert guti['allowed'] == {
        'PLMN': '20869',
        'AMFRegionID': 0xaa,
        'AMFSetID': 0x200,
        'AMFPtr': 0x1f,
        }
    tmsi_rec = _redactions_by_field(export, '5GTMSI')
    assert len(tmsi_rec) == 1
    assert tmsi_rec[0]['subject_class'] == SubjectClass.TEMPORARY

    _assert_no_forbidden_token(export)


def test_null_scheme_suci_is_clear_text_subject():
    msg = _build_null_suci_registration()
    export = redact_message(msg, KEY)

    suci = next(n for n in _find_identity_nodes(export)
                if n['format'] == FGSIDFMT.IMSI)
    # routing metadata still available for analysis
    assert suci['allowed']['RoutingInd'] == SUCI_ROUTING
    assert suci['allowed']['ProtSchemeID'] == 0

    rec = _redactions_by_field(export, 'MSIN')
    assert len(rec) == 1
    assert rec[0]['subject_class'] == SubjectClass.PERMANENT_PLAIN
    assert rec[0]['clear_text'] is True
    _assert_no_forbidden_token(export)


def test_identity_response_imei():
    msg = _build_identity_response()
    wire = msg.to_bytes()
    parsed, err = parse_NAS5G(wire)
    assert err == 0

    export = redact_message(parsed, KEY)
    rec = _redactions_by_field(export, 'Digits')
    assert len(rec) == 1
    assert rec[0]['subject_class'] == SubjectClass.DEVICE
    assert rec[0]['identity_type'] == FGSIDTYPE.IMEI
    _assert_no_forbidden_token(export)


def test_nested_payload_is_traversed_without_identity_leak():
    msg = _build_ul_transport_with_nested_payload()
    wire = msg.to_bytes()
    parsed, err = parse_NAS5G(wire)
    assert err == 0

    export = redact_message(parsed, KEY)
    text = json.dumps(export, default=str)
    # the nested 5GSM message is present in the structural export
    assert 'FGSMPDUSessionEstabRequest' in text
    # non-identity payload data (DNN "vision") remains analyzable as hex
    assert b'vision'.hex() in text
    # the nested branch carries no redaction (no identity there)
    assert export['redactions'] == []


def test_security_protected_envelope_stmsi():
    msg = _build_security_protected_message()
    wire = msg.to_bytes()
    parsed, err = parse_NAS5G(wire)
    assert err == 0

    export = redact_message(parsed, KEY)
    text = json.dumps(export, default=str)
    # recursion went through the security header into the inner message
    assert 'FGMMMODeregistrationRequest' in text

    rec = _redactions_by_field(export, '5GTMSI')
    assert len(rec) == 1
    assert rec[0]['subject_class'] == SubjectClass.TEMPORARY
    _assert_no_forbidden_token(export)


def test_encrypted_payload_is_not_promoted_to_identity():
    # SecHdr 4: ciphered NAS. The opaque payload is generic traffic, not an
    # identity: it must not be aliased into any trust class nor turned into a
    # clear-text subject.
    wire = bytes.fromhex('7e04fd5a6e42007e005e')
    parsed, err = parse_NAS5G(wire)
    assert err == 0
    export = redact_message(parsed, KEY)
    assert export['redactions'] == []
    # the security header remains analyzable
    text = json.dumps(export, default=str)
    assert '"SecHdr"' in text
    # the ciphered payload stays an untyped buffer with a length only
    assert '"element": "NASMessage"' in text


def test_nai_suci_null_and_protected():
    null_nai = _build_nai_suci(0)
    export_null = redact_message(null_nai, KEY)
    node_null = _find_identity_nodes(export_null)[0]
    assert node_null['allowed'] == {
        'NAIFmt': 1,
        'RoutingInd': SUCI_ROUTING,
        'ProtSchemeID': 0,
        'Realm': NAI_REALM,
        }
    rec_null = _redactions_by_field(export_null, 'UserID')
    assert rec_null[0]['subject_class'] == SubjectClass.PERMANENT_PLAIN
    _assert_no_forbidden_token(export_null)

    ecc_nai = _build_nai_suci(1)
    export_ecc = redact_message(ecc_nai, KEY)
    node_ecc = _find_identity_nodes(export_ecc)[0]
    assert node_ecc['allowed']['ProtSchemeID'] == 1
    assert node_ecc['allowed']['HNPKID'] == SUCI_HNPKID
    assert node_ecc['allowed']['Realm'] == NAI_REALM
    rec_ecc = _redactions_by_field(export_ecc, 'ECIESOutput')
    assert rec_ecc[0]['subject_class'] == SubjectClass.PERMANENT_PROT
    _assert_no_forbidden_token(export_ecc)


#------------------------------------------------------------------------------#
# Trust-domain separation
#------------------------------------------------------------------------------#

def test_aliases_are_deterministic_and_correlated():
    msg1 = _build_identity_response()
    msg2 = _build_identity_response()
    exp1 = redact_message(msg1, KEY)
    exp2 = redact_message(msg2, KEY)
    assert exp1['redactions'][0]['alias'] == exp2['redactions'][0]['alias']


def test_aliases_change_with_the_caller_key():
    msg = _build_identity_response()
    exp1 = redact_message(msg, KEY)
    exp2 = redact_message(msg, b'a-different-transcript-key-9999')
    assert exp1['redactions'][0]['alias'] != exp2['redactions'][0]['alias']


def test_cleartext_and_ciphertext_never_share_alias():
    # same underlying subscriber, two distinct exposure surfaces
    null_msg = _build_null_suci_registration()
    prot_msg = _build_registration_request()
    exp_null = redact_message(null_msg, KEY)
    exp_prot = redact_message(prot_msg, KEY)

    plain_alias = exp_null['redactions'][0]['alias']
    prot_aliases = {r['alias'] for r in exp_prot['redactions']}
    assert plain_alias not in prot_aliases
    assert exp_null['redactions'][0]['subject_tag'] == 'permanent_plain'
    assert all(r['subject_tag'] == 'permanent_protected'
               or r['subject_tag'] == 'temporary'
               for r in exp_prot['redactions'])


def test_temporary_and_permanent_use_distinct_domains():
    reg = _build_registration_request()
    export = redact_message(reg, KEY)
    tags = {r['subject_tag'] for r in export['redactions']}
    assert 'permanent_protected' in tags
    assert 'temporary' in tags
    aliases = [r['alias'] for r in export['redactions']]
    assert len(aliases) == len(set(aliases))


#------------------------------------------------------------------------------#
# All 5GS identity types follow the type-driven policy
#------------------------------------------------------------------------------#

@pytest.mark.parametrize('value, subject_class, field', (
    ({'Type': FGSIDTYPE.IMEI, 'Digits': IMEI_DIGITS},
     SubjectClass.DEVICE, 'Digits'),
    ({'Type': FGSIDTYPE.IMEISV, 'Digits': IMEISV_DIGITS},
     SubjectClass.DEVICE, 'Digits'),
    ({'Type': FGSIDTYPE.STMSI, 'AMFSetID': 0x200, 'AMFPtr': 0x1f,
      '5GTMSI': STMSI_TMSI},
     SubjectClass.TEMPORARY, '5GTMSI'),
    ({'Type': FGSIDTYPE.MAC, 'MAURI': 0, 'MAC': MAC_ADDR},
     SubjectClass.LINKLAYER, 'MAC'),
    ({'Type': FGSIDTYPE.EUI64, 'EUI64': EUI64_ADDR},
     SubjectClass.LINKLAYER, 'EUI64'),
    ))
def test_all_identity_types_are_redacted(value, subject_class, field):
    fgsid = FGSID(val=value)
    export = redact_message(fgsid, KEY)
    rec = _redactions_by_field(export, field)
    assert len(rec) == 1
    assert rec[0]['subject_class'] == subject_class
    _assert_no_forbidden_token(export)


def test_no_identity_type_is_exported_structurally():
    # an IE whose name does not say "identity" is never redacted by name:
    # only decoded FGSID / known identity wrapper types trigger the policy
    fgsid = FGSID(val={'Type': FGSIDTYPE.NO})
    export = redact_message(fgsid, KEY)
    assert export['redactions'] == []
    assert export['tree']['type'] == 'FGSID'


def test_undecoded_identity_ie_never_leaks_raw_bytes():
    # if the inner 5GSID cannot be decoded, the raw identity buffer must be
    # caught by the wrapper-type rule rather than exported as hex
    msg = FGMMRegistrationRequest()
    msg['5GSID'].set_val({'V': b'\xff\xff\xff\xff'})
    parsed, err = parse_NAS5G(msg.to_bytes())
    assert err == 0

    export = redact_message(parsed, KEY)
    assert len(export['redactions']) == 1
    rec = export['redactions'][0]
    assert rec['reason'] == 'undecoded identity IE'
    assert rec['subject_class'] == SubjectClass.PERMANENT_PROT
    assert 'ffffffff' not in json.dumps(export)


#------------------------------------------------------------------------------#
# Non-mutation and API contracts
#------------------------------------------------------------------------------#

def test_input_bytes_and_parsed_object_unchanged():
    parsed = _build_registration_request()
    wire = parsed.to_bytes()

    snapshot = parsed.get_val()
    export = redact_message(parsed, KEY)
    assert export is not None

    # parsed object value and re-encoded bytes are identical after export
    assert parsed.get_val() == snapshot
    assert parsed.to_bytes() == wire


def test_bytes_buffer_input_is_accepted_but_not_modified():
    msg = _build_identity_response()
    wire = bytearray(msg.to_bytes())
    before = bytes(wire)
    export = redact_message(bytes(wire), KEY)
    assert export['message'] == 'FGMMIdentityResponse'
    assert bytes(wire) == before


def test_invalid_key_rejected():
    msg = _build_identity_response()
    with pytest.raises(RedactionKeyError):
        redact_message(msg, b'short')
    with pytest.raises(RedactionKeyError):
        redact_message(msg, 'not-bytes')


def test_export_is_json_serializable():
    export = redact_message(_build_registration_request(), KEY)
    text = json.dumps(export)
    assert isinstance(text, str)
    assert 'alias-' in text


def test_redaction_paths_are_absolute_and_unique():
    export = redact_message(_build_registration_request(), KEY)
    paths = [tuple(r['path']) for r in export['redactions']]
    # every path is rooted within the exported message tree and is unique
    assert all(len(path) >= 2 for path in paths)
    assert len(paths) == len(set(paths))
