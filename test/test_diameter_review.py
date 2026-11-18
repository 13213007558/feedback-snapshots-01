# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Description : unit tests for the Diameter AVP comprehension review layer
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
# * You should have received a copy of the GNU Lesser General Public License
# * along with this library; if not, write to the Free Software Foundation, Inc.,
# * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
# *--------------------------------------------------------
# * File Name : test/test_diameter_review.py
# *--------------------------------------------------------
#*/

"""Offline tests for the Diameter comprehension review layer.

No network access is used anywhere: every message is built locally and the
checker only walks bytes in memory.
"""

import pytest

from pycrate_diameter.DiameterReview import (
    VENDOR_IETF,
    VENDOR_3GPP,
    Disposition,
    Verdict,
    StructuralError,
    AVPIdentity,
    CapRegistry,
    review_message,
    build_avp,
    build_message,
    )


# codes selected so that the numeric value alone is ambiguous on purpose
CODE_ORIGIN_REALM = 264        # known base-protocol AVP, vendor 0
CODE_VENDOR_COLLISION = 264    # same number, different vendor, unknown here
CODE_UNKNOWN_OPTIONAL = 999010
CODE_UNKNOWN_MANDATORY = 999011
CODE_NESTED_GROUPED = 284      # Proxy-Info, grouped per RFC 6733
CODE_PROXY_HOST = 280          # Proxy-Host, DiameterIdentity
CODE_UNKNOWN_NESTED_MANDATORY = 999020
VENDOR_FAKE = 424242


def _registry():
    # small, fully controlled registry: Origin-Realm and Proxy-Info only
    registry = CapRegistry()
    registry.register(CODE_ORIGIN_REALM, VENDOR_IETF, 'Origin-Realm')
    registry.register(CODE_NESTED_GROUPED, VENDOR_IETF,
                      'Proxy-Info', grouped=True)
    registry.register(CODE_PROXY_HOST, VENDOR_IETF, 'Proxy-Host')
    return registry


def test_vendor_id_is_part_of_identity():
    # same numeric code, two different identities must never collide
    base = AVPIdentity(CODE_ORIGIN_REALM, VENDOR_IETF)
    vendor_specific = AVPIdentity(CODE_ORIGIN_REALM, VENDOR_FAKE)
    registry = _registry()
    assert registry.is_known(base)
    assert not registry.is_known(vendor_specific)
    assert registry.get(base).name == 'Origin-Realm'
    assert registry.get(vendor_specific) is None


def test_same_code_different_vendor_message():
    # message 1: base code 264 (known) and vendor 10415 code 264 (unknown,
    # M-set) plus an unknown vendor 424242 code 264 (M-clear)
    avps = [
        build_avp(CODE_ORIGIN_REALM, b'realm.example', m=1),
        build_avp(CODE_VENDOR_COLLISION, b'\x00\x01',
                  vendor_id=VENDOR_3GPP, m=1),
        build_avp(CODE_VENDOR_COLLISION, b'\x00\x02',
                  vendor_id=VENDOR_FAKE, m=0),
        ]
    msg = build_message(271, avps)
    result = review_message(msg, registry=_registry())

    assert result.verdict == Verdict.NOT_UNDERSTOOD
    assert result.original == msg
    assert result.body_consumed
    identities = [obs.identity for obs in result.observations]
    assert identities == [
        AVPIdentity(CODE_ORIGIN_REALM, VENDOR_IETF),
        AVPIdentity(CODE_VENDOR_COLLISION, VENDOR_3GPP),
        AVPIdentity(CODE_VENDOR_COLLISION, VENDOR_FAKE),
        ]
    dispositions = [obs.disposition for obs in result.observations]
    assert dispositions == [
        Disposition.KNOWN,
        Disposition.UNKNOWN_MANDATORY,
        Disposition.UNKNOWN_OPTIONAL,
        ]
    # the base-protocol capability must not cover the vendor extensions
    mandatory = result.unknown_mandatory[0]
    assert mandatory.identity.vendor_id == VENDOR_3GPP
    assert mandatory.flag_v == 1 and mandatory.flag_m == 1
    assert '5010' in mandatory.reason
    optional = result.unknown_optional[0]
    assert optional.identity.vendor_id == VENDOR_FAKE
    assert optional.flag_v == 1 and optional.flag_m == 0


def test_unknown_optional_message_is_only_partially_understood():
    # message 2: a known mandatory AVP and an unknown optional one: the node
    # may skip the latter, but cannot claim full understanding
    avps = [
        build_avp(CODE_ORIGIN_REALM, b'realm.example', m=1),
        build_avp(CODE_UNKNOWN_OPTIONAL, b'ignored', m=0),
        ]
    msg = build_message(271, avps)
    result = review_message(msg, registry=_registry())

    assert result.verdict == Verdict.PARTIALLY_UNDERSTOOD
    assert not result.unknown_mandatory
    skipped = result.unknown_optional[0]
    assert skipped.disposition == Disposition.UNKNOWN_OPTIONAL
    assert skipped.flag_m == 0 and skipped.flag_v == 0
    assert 'ignored' in skipped.reason
    # structural decoding success is reported separately from comprehension
    assert result.pycrate_structural_decode.startswith('ok')


def test_unknown_mandatory_message_is_rejected():
    # message 3: an unknown M-set AVP means a missing required capability
    avps = [
        build_avp(CODE_ORIGIN_REALM, b'realm.example', m=1),
        build_avp(CODE_UNKNOWN_MANDATORY, b'secret', m=1),
        ]
    msg = build_message(271, avps)
    result = review_message(msg, registry=_registry())

    assert result.verdict == Verdict.NOT_UNDERSTOOD
    rejected = result.unknown_mandatory[0]
    assert rejected.identity == AVPIdentity(CODE_UNKNOWN_MANDATORY,
                                            VENDOR_IETF)
    assert rejected.disposition == Disposition.UNKNOWN_MANDATORY
    assert rejected.flag_m == 1
    assert '5010' in rejected.reason
    assert 'DIAMETER_AVP_UNSUPPORTED' in rejected.reason


def test_nested_unknown_mandatory_path_and_grouped_recursion():
    # unknown mandatory AVP nested inside a known grouped AVP (Proxy-Info 284)
    nested = [
        build_avp(CODE_PROXY_HOST, b'proxy.example', m=1),
        build_avp(CODE_UNKNOWN_NESTED_MANDATORY, b'deep', m=1),
        ]
    grouped = build_avp(CODE_NESTED_GROUPED, b''.join(nested), m=1)
    avps = [
        build_avp(CODE_ORIGIN_REALM, b'realm.example', m=1),
        grouped,
        ]
    msg = build_message(271, avps)
    result = review_message(msg, registry=_registry())

    assert result.verdict == Verdict.NOT_UNDERSTOOD
    flat = result.flat_observations()
    nested_mandatory = [obs for obs in result.unknown_mandatory
                        if obs.identity.code == CODE_UNKNOWN_NESTED_MANDATORY][0]
    assert nested_mandatory.path == [
        'AVP(code=284, vendor=IETF(0))#0',
        'AVP(code=999020, vendor=IETF(0))#0',
        ]
    assert 'AVP(code=284' in nested_mandatory.path_str
    # grouped nesting structure is retained
    grouped_obs = result.observations[1]
    assert len(grouped_obs.nested) == 2
    assert [obs.identity.code for obs in grouped_obs.nested] == [
        CODE_PROXY_HOST, CODE_UNKNOWN_NESTED_MANDATORY]
    assert flat[0].disposition == Disposition.KNOWN
    assert flat[-1].disposition == Disposition.UNKNOWN_MANDATORY


def test_m_v_p_flags_padding_and_duplicates_retained():
    payload = b'abc'  # 3 bytes -> one padding byte, wire length 12
    avps = [
        build_avp(CODE_ORIGIN_REALM, payload, m=1, p=1),
        build_avp(CODE_ORIGIN_REALM, payload, m=1, p=1),
        build_avp(CODE_UNKNOWN_OPTIONAL, b'wxyz', vendor_id=VENDOR_FAKE,
                  m=0, p=1),
        ]
    msg = build_message(271, avps)
    result = review_message(msg, registry=_registry())

    first = result.observations[0]
    assert first.flag_m == 1 and first.flag_p == 1 and first.flag_v == 0
    assert first.declared_length == 11
    assert first.data_length == 3
    assert first.padding_length == 1
    assert first.wire_length == 12
    assert first.raw == avps[0]
    vendor_obs = result.observations[2]
    assert vendor_obs.flag_v == 1 and vendor_obs.flag_p == 1
    assert vendor_obs.header_length == 12
    assert vendor_obs.padding_length == 0  # 4-byte data, already aligned
    # duplicate detection keeps every occurrence
    assert len(result.duplicates) == 1
    dup = result.duplicates[0]
    assert dup['count'] == 2 and dup['identity'].startswith('AVP(code=264')
    assert first.same_identity_count == 2
    assert result.observations[1].occurrence == 1


def test_original_bytes_are_retained_verbatim():
    avps = [build_avp(CODE_UNKNOWN_OPTIONAL, b'\xde\xad\xbe\xef', m=0)]
    msg = build_message(271, avps)
    result = review_message(msg, registry=_registry())
    # copy semantics: the review result carries its own equivalent bytes
    assert result.original == msg
    assert result.observations[0].data == b'\xde\xad\xbe\xef'
    # reconstruction from retained raw AVP spans yields the identical body
    assert b''.join(obs.raw for obs in result.observations) == msg[20:]


def test_non_zero_padding_is_flagged_but_length_is_kept():
    avp = build_avp(CODE_ORIGIN_REALM, b'ab', m=1, padding_byte=b'\xff')
    msg = build_message(271, [avp])
    result = review_message(msg, registry=_registry())
    codes = [err['code'] for err in result.structural_errors]
    assert StructuralError.NON_ZERO_PADDING in codes
    assert result.observations[0].padding_length == 2
    # the bad padding byte stays in the retained raw bytes
    assert result.observations[0].raw.endswith(b'\xff\xff')


def test_truncated_avp_is_structural_error():
    good = build_avp(CODE_ORIGIN_REALM, b'realm.example', m=1)
    truncated = build_avp(CODE_UNKNOWN_MANDATORY, b'abcdef', m=1)[:-2]
    msg = build_message(271, [good, truncated])
    result = review_message(msg, registry=_registry())
    assert result.verdict == Verdict.NOT_UNDERSTOOD
    assert any(err['code'] in (
        StructuralError.TRUNCATED_AVP_DATA,
        StructuralError.TRUNCATED_AVP_PADDING,
        StructuralError.PYCRATE_DECODE_ERROR)
        for err in result.structural_errors)
    # observations parsed before the truncation are retained
    assert result.observations
    assert result.observations[0].identity.code == CODE_ORIGIN_REALM
    assert not result.body_consumed


def test_malformed_grouped_avp_is_flagged_with_path():
    # known grouped AVP whose payload cannot be walked as nested AVPs
    grouped = build_avp(CODE_NESTED_GROUPED, b'\x00\x00\x01', m=1)
    msg = build_message(271, [
        build_avp(CODE_ORIGIN_REALM, b'realm.example', m=1), grouped])
    result = review_message(msg, registry=_registry())
    assert result.verdict == Verdict.NOT_UNDERSTOOD
    assert any(err['code'] == StructuralError.MALFORMED_GROUPED
               and 'AVP(code=284' in err['path']
               for err in result.structural_errors)
    assert [obs.identity.code for obs in result.observations] == [
        CODE_ORIGIN_REALM, CODE_NESTED_GROUPED]
    assert not result.body_consumed


def test_diameter_header_flags_are_decoded():
    msg = build_message(271, [
        build_avp(CODE_ORIGIN_REALM, b'realm.example', m=1)],
        r=1, p=1, e=0, t=1, app_id=16777216)
    result = review_message(msg, registry=_registry())
    assert result.header == {
        'version': 1,
        'length': len(msg),
        'R': 1,
        'P': 1,
        'E': 0,
        'T': 1,
        'cmd': 271,
        'app_id': 16777216,
        'hop_by_hop': 0x11223344,
        'end_to_end': 0x55667788,
        }


def test_fully_understood_message():
    nested = [build_avp(CODE_PROXY_HOST, b'proxy.example', m=1)]
    avps = [
        build_avp(CODE_ORIGIN_REALM, b'realm.example', m=1),
        build_avp(CODE_NESTED_GROUPED, b''.join(nested), m=1),
        ]
    result = review_message(build_message(271, avps), registry=_registry())
    assert result.verdict == Verdict.FULLY_UNDERSTOOD
    assert not result.structural_errors
    assert result.body_consumed


def test_skipping_length_is_not_understanding():
    # even when pycrate can walk every length field, an unknown M-set AVP
    # still forces the NOT-UNDERSTOOD verdict
    msg = build_message(271, [
        build_avp(CODE_UNKNOWN_MANDATORY, b'x' * 8, m=1)])
    result = review_message(msg, registry=_registry())
    assert result.pycrate_structural_decode.startswith('ok')
    assert result.verdict == Verdict.NOT_UNDERSTOOD


def test_default_registry_separates_vendor_namespaces():
    registry = CapRegistry()
    registry.register(264, VENDOR_IETF, 'Origin-Realm')
    registry.register(264, VENDOR_3GPP, 'Vendor-Collision-Example')
    base = registry.get(AVPIdentity(264, VENDOR_IETF))
    vendor = registry.get(AVPIdentity(264, VENDOR_3GPP))
    assert base.name != vendor.name
    assert not base.grouped and not vendor.grouped


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
