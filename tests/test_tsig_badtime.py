# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Offline tests for TSIG BADTIME handling.

These tests build every message locally.  They do not change the system clock
and do not use the network.
"""

import time

import pytest

import dns.exception
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.rdtypes.ANY.TSIG
import dns.tsig
import dns.tsigkeyring

KEY_TEXT = "NjHwPsMKjdN++dOfE5iAiQ=="
KEYRING = dns.tsigkeyring.from_text({"keyname.": KEY_TEXT})
KEYNAME = dns.name.from_text("keyname")
KEY = dns.tsig.Key(KEYNAME, KEYRING[KEYNAME], dns.tsig.HMAC_SHA256)


def make_query():
    q = dns.message.make_query("example.", "A")
    q.use_tsig(KEY, KEYNAME)
    q.to_wire()  # set q.mac
    return q


def epoch48(value):
    return int(value).to_bytes(6, "big")


def badtime_response(q, server_time, *, request_mac=None, fudge=300):
    r = dns.message.make_response(q, tsig_error=dns.rcode.BADTIME)
    r.use_tsig(
        KEY,
        KEYNAME,
        fudge=fudge,
        tsig_error=dns.rcode.BADTIME,
        other_data=epoch48(server_time),
    )
    r.request_mac = q.mac if request_mac is None else request_mac
    return r


def parse(wire, q, keyring=KEY):
    return dns.message.from_wire(wire, keyring=keyring, request_mac=q.mac)


def test_normal_response_is_ok():
    q = make_query()
    r = dns.message.make_response(q)
    r.use_tsig(KEY, KEYNAME)
    r.request_mac = q.mac
    parsed = parse(r.to_wire(), q)
    assessment = dns.tsig.assess_tsig_response(q, parsed)
    assert assessment.status is dns.tsig.TSIGResponseStatus.OK
    assert assessment.authenticated
    assert assessment.request_mac_bound
    assert assessment.transaction_bound
    assert assessment.server_time is None
    decision = dns.tsig.decide_tsig_retry(assessment)
    assert decision.action is dns.tsig.TSIGRetryAction.NONE


def test_signed_badtime_is_authenticated_and_bounded():
    q = make_query()
    server_time = int(time.time()) + 3600
    wire = badtime_response(q, server_time).to_wire()
    with pytest.raises(dns.tsig.PeerBadTime) as cm:
        parse(wire, q)
    error = cm.value
    assert error.authenticated
    assert error.server_time == server_time
    assessment = dns.tsig.assess_tsig_error(q, error)
    assert assessment.status is dns.tsig.TSIGResponseStatus.PEER_BAD_TIME
    assert assessment.authenticated
    assert assessment.request_mac_bound
    assert assessment.transaction_bound
    assert assessment.server_time == server_time
    assert assessment.time_source == "other"
    policy = dns.tsig.TSIGRetryPolicy(max_retries=1, max_offset=7200)
    decision = dns.tsig.decide_tsig_retry(assessment, policy=policy)
    assert decision.action is dns.tsig.TSIGRetryAction.RETRY_WITH_TIME_OFFSET
    assert decision.signing_time_offset is not None
    assert abs(decision.signing_time_offset - 3600) <= 2
    exhausted = dns.tsig.decide_tsig_retry(assessment, attempt=1, policy=policy)
    assert exhausted.action is dns.tsig.TSIGRetryAction.NONE


def test_signed_badtime_with_large_offset_needs_operator():
    q = make_query()
    server_time = int(time.time()) + 86400
    with pytest.raises(dns.tsig.PeerBadTime) as cm:
        parse(badtime_response(q, server_time).to_wire(), q)
    assessment = dns.tsig.assess_tsig_error(q, cm.value)
    decision = dns.tsig.decide_tsig_retry(assessment)
    assert decision.action is dns.tsig.TSIGRetryAction.CHECK_LOCAL_CLOCK
    assert decision.signing_time_offset is None


def test_forged_badtime_is_bad_signature_not_peer_badtime():
    q = make_query()
    r = badtime_response(q, int(time.time()) + 3600)
    wire = bytearray(r.to_wire())
    mac = r.tsig[0].mac
    offset = wire.find(mac)
    assert offset >= 0
    wire[offset] ^= 0xFF
    with pytest.raises(dns.tsig.BadSignature) as cm:
        parse(bytes(wire), q)
    assert not isinstance(cm.value, dns.tsig.PeerBadTime)
    assessment = dns.tsig.assess_tsig_error(q, cm.value)
    assert assessment.status is dns.tsig.TSIGResponseStatus.BAD_SIGNATURE
    assert not assessment.authenticated
    assert assessment.server_time is None
    decision = dns.tsig.decide_tsig_retry(assessment)
    assert decision.action is dns.tsig.TSIGRetryAction.NONE


def test_badtime_bound_to_another_request_is_not_accepted():
    q = make_query()
    other = make_query()
    # The response MAC covers the other request's MAC, so validating it
    # against this query fails before any error field is trusted.
    r = badtime_response(q, int(time.time()) + 3600, request_mac=other.mac)
    with pytest.raises(dns.tsig.BadSignature) as cm:
        parse(r.to_wire(), q)
    assessment = dns.tsig.assess_tsig_error(q, cm.value)
    assert assessment.status is dns.tsig.TSIGResponseStatus.BAD_SIGNATURE
    assert not assessment.authenticated
    assert (
        dns.tsig.decide_tsig_retry(assessment).action is dns.tsig.TSIGRetryAction.NONE
    )


def test_badtime_from_a_different_transaction_is_not_trusted():
    q = make_query()
    other = make_query()
    # Valid for *other*, but the caller asks about *q*.  The error is not
    # bound to q's request MAC, so it must not drive q's retry.
    wire = badtime_response(other, int(time.time()) + 3600).to_wire()
    with pytest.raises(dns.tsig.PeerBadTime) as cm:
        dns.message.from_wire(wire, keyring=KEY, request_mac=other.mac)
    assessment = dns.tsig.assess_tsig_error(q, cm.value)
    assert not assessment.request_mac_bound
    assert not assessment.transaction_bound
    assert (
        dns.tsig.decide_tsig_retry(assessment).action is dns.tsig.TSIGRetryAction.NONE
    )


def test_missing_signature_is_distinct():
    q = make_query()
    r = dns.message.make_response(q)
    r.tsig = None
    with pytest.raises(dns.message.MissingTSIG):
        parse(r.to_wire(), q)
    assessment = dns.tsig.assess_tsig_response(q, r)
    assert assessment.status is dns.tsig.TSIGResponseStatus.MISSING_TSIG
    assert not assessment.authenticated


def test_missing_signature_exception_is_classified():
    q = make_query()
    r = dns.message.make_response(q)
    r.tsig = None
    with pytest.raises(dns.message.MissingTSIG) as cm:
        parse(r.to_wire(), q)
    assessment = dns.tsig.assess_tsig_error(q, cm.value)
    assert assessment.status is dns.tsig.TSIGResponseStatus.MISSING_TSIG
    assert assessment.transaction_bound
    assert not assessment.authenticated


def test_local_badtime_is_distinct_from_peer_badtime():
    # A correctly signed response whose Time Signed is stale fails local
    # validation, and the server has not reported an error at all.
    q = make_query()
    r = dns.message.make_response(q)
    r.use_tsig(KEY, KEYNAME)
    r.request_mac = q.mac
    r.tsig_time_offset = 1000
    wire = r.to_wire()
    with pytest.raises(dns.tsig.BadTime) as cm:
        parse(wire, q)
    assert not isinstance(cm.value, dns.tsig.PeerBadTime)
    assessment = dns.tsig.assess_tsig_error(q, cm.value)
    assert assessment.status is dns.tsig.TSIGResponseStatus.LOCAL_BAD_TIME
    assert assessment.authenticated
    assert assessment.error == 0
    decision = dns.tsig.decide_tsig_retry(assessment)
    assert decision.action is dns.tsig.TSIGRetryAction.CHECK_LOCAL_CLOCK


def test_badtime_without_other_data_has_no_server_time():
    q = make_query()
    r = dns.message.make_response(q, tsig_error=dns.rcode.BADTIME)
    r.use_tsig(KEY, KEYNAME, tsig_error=dns.rcode.BADTIME)
    r.request_mac = q.mac
    with pytest.raises(dns.tsig.PeerBadTime) as cm:
        parse(r.to_wire(), q)
    assert cm.value.authenticated
    assert cm.value.server_time is None
    assessment = dns.tsig.assess_tsig_error(q, cm.value)
    assert assessment.server_time is None
    assert (
        dns.tsig.decide_tsig_retry(assessment).action
        is dns.tsig.TSIGRetryAction.CHECK_LOCAL_CLOCK
    )


def test_unsigned_badkey_is_reported_but_unauthenticated():
    q = make_query()
    r = dns.message.make_response(q)
    r.request_mac = q.mac
    tsig = dns.rdtypes.ANY.TSIG.TSIG(
        dns.rdataclass.ANY,
        dns.rdatatype.TSIG,
        dns.tsig.HMAC_SHA256,
        int(time.time()),
        300,
        b"",
        q.id,
        dns.rcode.BADKEY,
        b"",
    )
    r.tsig = dns.rrset.from_rdata(KEYNAME, 0, tsig)
    r.want_tsig_sign = False
    with pytest.raises(dns.tsig.PeerBadKey) as cm:
        parse(r.to_wire(), q)
    assert not cm.value.authenticated
    assessment = dns.tsig.assess_tsig_error(q, cm.value)
    assert assessment.status is dns.tsig.TSIGResponseStatus.PEER_ERROR
    assert not assessment.authenticated
    assert assessment.server_time is None
    assert (
        dns.tsig.decide_tsig_retry(assessment).action is dns.tsig.TSIGRetryAction.NONE
    )


def test_retry_offset_only_changes_signing_time():
    q = make_query()
    original_wire = q.to_wire()
    assert q.tsig_time_offset == 0
    q.tsig_time_offset = 3600
    retry_wire = q.to_wire()
    assert retry_wire != original_wire
    with pytest.raises(dns.tsig.BadTime) as cm:
        dns.message.from_wire(retry_wire, keyring=KEY)
    evidence = cm.value.evidence
    assert evidence is not None
    assert abs(evidence.time_signed - int(time.time())) > 3000
    assert evidence.fudge == q.tsig[0].fudge


def test_unsigned_badtime_with_server_time_cannot_drive_retry():
    q = make_query()
    r = dns.message.make_response(q)
    r.request_mac = q.mac
    tsig = dns.rdtypes.ANY.TSIG.TSIG(
        dns.rdataclass.ANY,
        dns.rdatatype.TSIG,
        dns.tsig.HMAC_SHA256,
        int(time.time()),
        300,
        b"",
        q.id,
        dns.rcode.BADTIME,
        epoch48(int(time.time()) + 3600),
    )
    r.tsig = dns.rrset.from_rdata(KEYNAME, 0, tsig)
    r.want_tsig_sign = False
    with pytest.raises(dns.tsig.BadSignature) as cm:
        parse(r.to_wire(), q)
    assert not isinstance(cm.value, dns.tsig.PeerBadTime)
    assert not cm.value.authenticated
    assessment = dns.tsig.assess_tsig_error(q, cm.value)
    assert assessment.status is dns.tsig.TSIGResponseStatus.BAD_SIGNATURE
    assert assessment.server_time is None
    assert (
        dns.tsig.decide_tsig_retry(assessment).action is dns.tsig.TSIGRetryAction.NONE
    )


def test_response_signed_with_another_key_does_not_drive_retry():
    other_name = dns.name.from_text("other.")
    other_key = dns.tsig.Key(other_name, KEY.secret, dns.tsig.HMAC_SHA256)
    q = make_query()
    r = dns.message.make_response(q)
    r.use_tsig(other_key, tsig_error=dns.rcode.BADTIME)
    r.tsig = dns.rrset.from_rdata(
        other_name,
        0,
        r.tsig[0].replace(other=epoch48(int(time.time()) + 3600)),
    )
    r.request_mac = q.mac
    # A multi-key dict makes from_wire() use the key named by the response.
    # The response MAC is valid for that key, but not for the query's key.
    with pytest.raises(dns.tsig.PeerBadTime) as cm:
        dns.message.from_wire(
            r.to_wire(),
            keyring={KEYNAME: KEY, other_name: other_key},
            request_mac=q.mac,
        )
    assessment = dns.tsig.assess_tsig_error(q, cm.value)
    assert assessment.key_name == other_name
    assert not assessment.authenticated  # not the query's key
    assert assessment.server_time is None
    assert assessment.clock_offset is None
    assert (
        dns.tsig.decide_tsig_retry(assessment).action is dns.tsig.TSIGRetryAction.NONE
    )


def test_error_evidence_does_not_leak_secret():
    q = make_query()
    with pytest.raises(dns.tsig.PeerBadTime) as cm:
        parse(badtime_response(q, int(time.time()) + 60).to_wire(), q)
    evidence = cm.value.evidence
    assert evidence is not None
    rendered = repr(evidence) + str(evidence) + repr(cm.value)
    assert KEY_TEXT not in rendered
    assert KEY.secret.hex() not in rendered
    assert not hasattr(evidence, "secret")


def test_retry_is_a_signing_offset_not_a_clock_change():
    q = make_query()
    server_time = int(time.time()) + 60
    with pytest.raises(dns.tsig.PeerBadTime) as cm:
        parse(badtime_response(q, server_time).to_wire(), q)
    assessment = dns.tsig.assess_tsig_error(q, cm.value)
    decision = dns.tsig.decide_tsig_retry(
        assessment, policy=dns.tsig.TSIGRetryPolicy(max_offset=600)
    )
    assert decision.action is dns.tsig.TSIGRetryAction.RETRY_WITH_TIME_OFFSET
    assert decision.signing_time_offset is not None
    # The only supported mechanism is a per-message signing offset.
    assert not hasattr(dns.tsig, "set_system_time")
    assert not hasattr(dns.message.Message, "set_system_time")
