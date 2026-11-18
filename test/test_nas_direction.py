# -*- coding: UTF-8 -*-
"""
Direction-mismatch regression tests for NAS message parsing.

The same NAS message type value can map to different structures on the
uplink (MO) and on the downlink (MT). A collector that guesses the wrong
direction may still produce a successful decode and then emit identity or
permission fields (EPSID, IMSI, detach cause, ...) that were never on the
air. These tests pin the contract:

- the parsing direction always comes from explicit capture context
  (parse_NAS_MO / parse_NAS_MT), never from "whichever parse did not fail";
- message types defined for a single direction only must error out (97)
  in the other direction, without leaking any field;
- type values defined in both directions with different structures must
  decode to their respective classes, and swapping direction must not
  silently fabricate fields;
- nested containers (security-protected NAS) inherit the direction of
  the outer capture context;
- unknown message types error out (97) in both directions;
- when the direction is unknown, the report keeps both candidate
  interpretations and marks every field as a candidate, never as a
  direction-confirmed fact.
"""

from binascii import unhexlify

from pycrate_mobile.NAS import parse_NAS_MO, parse_NAS_MT, parse_NAS5G
from pycrate_mobile.TS24301_EMM import (
    EMMTypeMOClasses,
    EMMTypeMTClasses,
    EMMDetachRequestMO,
    EMMDetachRequestMT,
    )
from pycrate_mobile.TS24008_GMM import (
    GMMTypeMOClasses,
    GMMTypeMTClasses,
    )


__all__ = [
    'DIR_MO',
    'DIR_MT',
    'FIELD_CONFIRMED',
    'FIELD_CANDIDATE',
    'FIELD_DIVERGENT',
    'nas_direction_report',
    'confirmed_fields',
    'test_nasdir_dispatch_tables',
    'test_nasdir_single_direction',
    'test_nasdir_same_type_different_structure',
    'test_nasdir_nested_container',
    'test_nasdir_unknown_type',
    'test_nasdir_missing_direction',
    ]


DIR_MO = 'MO' # uplink, UE -> network
DIR_MT = 'MT' # downlink, network -> UE

_DIR_PARSERS = {
    DIR_MO: parse_NAS_MO,
    DIR_MT: parse_NAS_MT,
    }

# field provenance in a report
FIELD_CONFIRMED = 'confirmed' # reliable direction basis (explicit capture context)
FIELD_CANDIDATE = 'candidate' # one directional interpretation, direction unknown
FIELD_DIVERGENT = 'divergent' # candidate present in only one interpretation,
                              # or decoded differently per direction

# markers of identity / permission fields that must never be reported as
# facts without a direction-confirmed decode
IDENTITY_MARKERS = ('EPSID', 'IMSI', 'GUTI', 'SUPI', 'TMSI', 'IMEI')


#------------------------------------------------------------------------------#
# direction-aware parse report
#------------------------------------------------------------------------------#

def _flatten(elt, prefix='', out=None):
    """flattens a parsed message into a {path: value} dict for field-by-field
    comparison"""
    if out is None:
        out = {}
    content = getattr(elt, '_content', None)
    if not isinstance(content, list):
        return out
    for idx, child in enumerate(content):
        name = getattr(child, '_name', None) or child.__class__.__name__
        path = '%s/%d:%s' % (prefix, idx, name) if prefix else '%d:%s' % (idx, name)
        try:
            out[path] = child.get_val()
        except Exception:
            out[path] = None
        _flatten(child, path, out)
    return out


def _parse_candidate(buf, direction):
    msg, err = _DIR_PARSERS[direction](buf)
    return {
        'err'   : err,
        'msg'   : msg._name if msg is not None else None,
        # a failed decode emits no field at all: wrongly decoded numbers
        # must not become security event facts
        'fields': _flatten(msg) if (msg is not None and err == 0) else {},
        }


def nas_direction_report(buf, direction=None):
    """Parses a NAS message bytes' buffer and reports field provenance.

    Args:
        buf: NAS message bytes' buffer
        direction: 'MO' / 'MT' from explicit capture context, or None if
                   the direction is unknown

    Returns:
        dict with:
            direction: the explicit direction, or None
            candidates: per-direction parse outcome (err code, message
                        class name, decoded fields)
            fields: per-field provenance; 'confirmed' only when the
                    direction was explicit and the decode succeeded,
                    'candidate' / 'divergent' otherwise
    """
    if direction not in (None, DIR_MO, DIR_MT):
        raise ValueError('invalid direction: %r' % (direction, ))
    dirs = (direction, ) if direction else (DIR_MO, DIR_MT)
    cands = {d: _parse_candidate(buf, d) for d in dirs}
    fields = {}
    if direction:
        for path, val in cands[direction]['fields'].items():
            fields[path] = {'status': FIELD_CONFIRMED, 'value': val}
    else:
        paths = set()
        for d in dirs:
            paths.update(cands[d]['fields'])
        for path in sorted(paths):
            vals = {d: cands[d]['fields'][path] for d in dirs
                    if path in cands[d]['fields']}
            if len(vals) == 2 and vals[DIR_MO] == vals[DIR_MT]:
                # both interpretations agree on this field, yet without
                # capture context it remains a candidate, not a fact
                status = FIELD_CANDIDATE
            else:
                status = FIELD_DIVERGENT
            fields[path] = {'status': status, 'values': vals}
    return {
        'direction' : direction,
        'candidates': cands,
        'fields'    : fields,
        }


def confirmed_fields(report):
    """returns only the fields with a reliable direction basis"""
    return {p: f['value'] for p, f in report['fields'].items()
            if f['status'] == FIELD_CONFIRMED}


def _identity_paths(fields):
    return [p for p in fields if any(m in p for m in IDENTITY_MARKERS)]


#------------------------------------------------------------------------------#
# short transcripts built from the repo's own uplink / downlink message classes
#------------------------------------------------------------------------------#

def _emm_detach_mo_buf():
    # EMM Detach Request, uplink: carries an EPSID (GUTI) identity
    m = EMMDetachRequestMO()
    m['EPSDetachType']['V'].set_val(1)
    m['EPSID']['V'].set_val(unhexlify('f600000000000000000000'))
    return m.to_bytes()


def _emm_detach_mt_buf():
    # EMM Detach Request, downlink: same type value 69, no identity field
    m = EMMDetachRequestMT()
    m['EPSDetachType']['V'].set_val(1)
    return m.to_bytes()


def _emm_sec_prot_buf(inner):
    # EMM security protected NAS message wrapping a clear-text inner message
    # (security header 1, null MAC, sequence number 1)
    return unhexlify('17') + b'\x00\x00\x00\x00' + b'\x01' + inner


EMM_DETACH_MO = _emm_detach_mo_buf()
EMM_DETACH_MT = _emm_detach_mt_buf()
EMM_SEC_PROT_DETACH_MO = _emm_sec_prot_buf(EMM_DETACH_MO)

# CC Setup uplink transcript, from the existing test vectors in test_mobile.py
CC_SETUP_MO = unhexlify('034504066004020005815e068160000000001502010040080402600400021f00')

# RR Partial Release Complete, uplink-only message type 15
RR_PARTIAL_REL_COMPL = unhexlify('060f')
# RR message type 62, defined on the downlink only
RR_MT_ONLY_TYPE62 = unhexlify('063e')

# GMM Detach Accept, uplink: header-only transcript
GMM_DETACH_ACCEPT_MO = unhexlify('0806')

# undefined message types
EMM_UNKNOWN_TYPE = unhexlify('075a00')
GMM_UNKNOWN_TYPE = unhexlify('086400')
FG_UNKNOWN_TYPE  = unhexlify('7e0040')


#------------------------------------------------------------------------------#
# regression tests
#------------------------------------------------------------------------------#

def test_nasdir_dispatch_tables():
    # same type value, different structure per direction: the dispatchers
    # must stay split per direction
    assert EMMTypeMOClasses[69] is EMMDetachRequestMO
    assert EMMTypeMTClasses[69] is EMMDetachRequestMT
    assert EMMTypeMOClasses[69] is not EMMTypeMTClasses[69]
    for typ in (5, 6):
        assert GMMTypeMOClasses[typ] is not GMMTypeMTClasses[typ]


def test_nasdir_single_direction():
    # uplink-only RR message type: decodes uplink, rejected downlink
    rep = nas_direction_report(RR_PARTIAL_REL_COMPL, direction=DIR_MO)
    assert rep['candidates'][DIR_MO]['err'] == 0
    assert rep['candidates'][DIR_MO]['msg'] == 'RRPartialReleaseComplete'
    assert confirmed_fields(rep)
    #
    rep = nas_direction_report(RR_PARTIAL_REL_COMPL, direction=DIR_MT)
    assert rep['candidates'][DIR_MT]['err'] == 97
    assert rep['candidates'][DIR_MT]['msg'] is None
    assert confirmed_fields(rep) == {}
    # downlink-only RR message type: rejected uplink
    rep = nas_direction_report(RR_MT_ONLY_TYPE62, direction=DIR_MO)
    assert rep['candidates'][DIR_MO]['err'] == 97
    assert confirmed_fields(rep) == {}


def test_nasdir_same_type_different_structure():
    # EMM type 69 uplink: the EPSID identity is direction-confirmed
    rep = nas_direction_report(EMM_DETACH_MO, direction=DIR_MO)
    assert rep['candidates'][DIR_MO]['msg'] == 'EMMDetachRequestMO'
    assert _identity_paths(confirmed_fields(rep))
    # swapped direction: the downlink parser must not emit any field
    # for an uplink detach request
    rep = nas_direction_report(EMM_DETACH_MO, direction=DIR_MT)
    assert rep['candidates'][DIR_MT]['err'] != 0
    assert confirmed_fields(rep) == {}
    # symmetrically, the genuine downlink transcript fails the uplink parser
    rep = nas_direction_report(EMM_DETACH_MT, direction=DIR_MO)
    assert rep['candidates'][DIR_MO]['err'] != 0
    assert confirmed_fields(rep) == {}
    rep = nas_direction_report(EMM_DETACH_MT, direction=DIR_MT)
    assert rep['candidates'][DIR_MT]['msg'] == 'EMMDetachRequestMT'
    assert not _identity_paths(confirmed_fields(rep))
    # CC Setup uplink transcript decodes in both directions, but the
    # field-by-field comparison shows the interpretations diverge
    rep = nas_direction_report(CC_SETUP_MO)
    assert rep['candidates'][DIR_MO]['err'] == 0
    assert rep['candidates'][DIR_MT]['err'] == 0
    assert rep['candidates'][DIR_MO]['msg'] == 'CCSetupMO'
    assert rep['candidates'][DIR_MT]['msg'] == 'CCSetupMT'
    assert rep['candidates'][DIR_MO]['fields'] != rep['candidates'][DIR_MT]['fields']
    divergent = [p for p, f in rep['fields'].items()
                 if f['status'] == FIELD_DIVERGENT]
    assert divergent
    # both parses succeeded, still nothing is direction-confirmed
    assert confirmed_fields(rep) == {}


def test_nasdir_nested_container():
    # security-protected NAS: the inner message inherits the direction
    # of the outer capture context
    rep = nas_direction_report(EMM_SEC_PROT_DETACH_MO, direction=DIR_MO)
    assert rep['candidates'][DIR_MO]['err'] == 0
    assert rep['candidates'][DIR_MO]['msg'] == 'EMMSecProtNASMessage'
    assert _identity_paths(confirmed_fields(rep))
    # swapped direction: the inner uplink detach request does not decode
    # as a downlink message, and no inner field leaks out
    rep = nas_direction_report(EMM_SEC_PROT_DETACH_MO, direction=DIR_MT)
    assert rep['candidates'][DIR_MT]['err'] == 96
    assert confirmed_fields(rep) == {}
    # unknown direction: the inner EPSID identity remains a candidate,
    # it is not a security event fact
    rep = nas_direction_report(EMM_SEC_PROT_DETACH_MO)
    assert rep['candidates'][DIR_MO]['err'] == 0
    assert rep['candidates'][DIR_MT]['err'] == 96
    epsid = _identity_paths(rep['fields'])
    assert epsid
    assert all(rep['fields'][p]['status'] == FIELD_DIVERGENT for p in epsid)
    assert confirmed_fields(rep) == {}


def test_nasdir_unknown_type():
    # undefined message types are rejected in both directions
    for buf in (EMM_UNKNOWN_TYPE, GMM_UNKNOWN_TYPE):
        for direction in (DIR_MO, DIR_MT):
            rep = nas_direction_report(buf, direction=direction)
            assert rep['candidates'][direction]['err'] == 97
            assert rep['candidates'][direction]['msg'] is None
            assert confirmed_fields(rep) == {}
        rep = nas_direction_report(buf)
        assert rep['candidates'][DIR_MO]['err'] == 97
        assert rep['candidates'][DIR_MT]['err'] == 97
        assert rep['fields'] == {}
    # undefined 5GMM message type
    msg, err = parse_NAS5G(FG_UNKNOWN_TYPE)
    assert msg is None
    assert err == 97


def test_nasdir_missing_direction():
    # only the uplink parser succeeds on this transcript: parse success
    # alone must not promote the decoded fields to facts
    rep = nas_direction_report(GMM_DETACH_ACCEPT_MO)
    assert rep['direction'] is None
    assert rep['candidates'][DIR_MO]['err'] == 0
    assert rep['candidates'][DIR_MO]['msg'] == 'GMMDetachAcceptMO'
    assert rep['candidates'][DIR_MT]['err'] != 0
    # both candidate interpretations stay in the report
    assert set(rep['candidates']) == {DIR_MO, DIR_MT}
    assert rep['fields']
    assert confirmed_fields(rep) == {}
    assert all(f['status'] in (FIELD_CANDIDATE, FIELD_DIVERGENT)
               for f in rep['fields'].values())


if __name__ == '__main__':
    test_nasdir_dispatch_tables()
    test_nasdir_single_direction()
    test_nasdir_same_type_different_structure()
    test_nasdir_nested_container()
    test_nasdir_unknown_type()
    test_nasdir_missing_direction()
    print('[+] test_nas_direction: all tests passed')
