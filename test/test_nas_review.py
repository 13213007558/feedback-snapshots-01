# -*- coding: UTF-8 -*-
"""Tests for the traffic-review trust accounting in nas_review.

These tests never touch a base station, SIM card or production key: the
integrity verifier is an injected callback (static verdict or a lab HMAC
scheme).  They pin the central rule that a message which merely decodes as a
valid NAS message must never be promoted to authenticated clear text.
"""

import json

import pytest

from pycrate_mobile.TS24501_FGMM import FGMMSecProtNASMessage, FGMMStatus

from nas_review import (
    review_nas5g,
    format_review,
    make_static_verifier,
    make_lab_hmac_verifier,
    apply_lab_hmac,
    make_pycrate_mac_verifier,
    ProtectionState,
    VerificationState,
    InnerParseState,
    TrustState,
    ReviewReason,
)


LAB_SECRET = b"lab-secret-not-a-network-key"


@pytest.fixture(scope="module")
def inner_bytes():
    """One clear-text 5GMM message reused inside every envelope."""
    return FGMMStatus(val={"5GMMCause": b"\x18"}).to_bytes()


def _envelope(sec_hdr, payload, mac=b"\x00\x00\x00\x00", seqn=5):
    msg = FGMMSecProtNASMessage()
    msg["5GMMHeaderSec"].set_val({"EPD": 126, "spare": 0, "SecHdr": sec_hdr})
    msg["MAC"].set_val(mac)
    msg["Seqn"].set_val(seqn)
    msg["NASMessage"].set_val(payload)
    return msg


@pytest.fixture(scope="module")
def plain_pdu(inner_bytes):
    return inner_bytes


@pytest.fixture(scope="module")
def protected_pdu(inner_bytes):
    """Integrity-only envelope (sec hdr 1) with a correct lab MAC."""
    msg = _envelope(1, inner_bytes)
    apply_lab_hmac(msg, LAB_SECRET)
    return msg.to_bytes()


@pytest.fixture(scope="module")
def bad_protected_pdu(inner_bytes):
    """Same readable inner, but the MAC is wrong and ciphering is declared."""
    return _envelope(2, inner_bytes, mac=b"\xde\xad\xbe\xef").to_bytes()


#------------------------------------------------------------------------------#
# the same inner message in three different envelopes must look different
#------------------------------------------------------------------------------#

def test_plain_envelope_is_readable_but_unverified(plain_pdu, inner_bytes):
    result = review_nas5g(plain_pdu, verifier=make_static_verifier(True))
    assert result.protection_state is ProtectionState.PLAINTEXT
    assert result.verification_state is VerificationState.NOT_APPLICABLE
    assert result.trust_state is TrustState.PLAINTEXT_UNVERIFIED
    assert result.reason is ReviewReason.PLAINTEXT_NO_HEADER
    assert result.raw_protected_payload is None
    assert result.outer_message is not None


def test_valid_protected_envelope_is_authenticated(protected_pdu, inner_bytes):
    result = review_nas5g(protected_pdu,
                          verifier=make_lab_hmac_verifier(LAB_SECRET))
    assert result.protection_state is ProtectionState.SECURITY_PROTECTED
    assert result.sec_hdr == 1
    assert result.ciphering_claimed is False
    assert result.verification_state is VerificationState.PASSED
    assert result.trust_state is TrustState.INTEGRITY_VERIFIED
    assert result.inner_parse_state is InnerParseState.PARSED
    assert result.inner_message is not None
    # the raw payload is preserved untouched and equals the original inner
    assert result.raw_protected_payload == inner_bytes


def test_bad_protected_envelope_is_never_trusted_on_format_alone(bad_protected_pdu, inner_bytes):
    result = review_nas5g(bad_protected_pdu,
                          verifier=make_lab_hmac_verifier(LAB_SECRET))
    assert result.protection_state is ProtectionState.SECURITY_PROTECTED
    assert result.sec_hdr == 2
    assert result.ciphering_claimed is True
    # the inner bytes still decode perfectly...
    assert result.inner_parse_state is InnerParseState.PARSED
    assert result.raw_protected_payload == inner_bytes
    # ...but the failed MAC dominates: no authenticated plaintext
    assert result.verification_state is VerificationState.FAILED
    assert result.trust_state is TrustState.INTEGRITY_FAILED
    assert result.reason is ReviewReason.INNER_AFTER_FAILURE


def test_three_envelopes_get_three_distinct_trust_states(
        plain_pdu, protected_pdu, bad_protected_pdu):
    verifier = make_lab_hmac_verifier(LAB_SECRET)
    states = [
        review_nas5g(pdu, verifier=verifier).trust_state
        for pdu in (plain_pdu, protected_pdu, bad_protected_pdu)
    ]
    assert states == [
        TrustState.PLAINTEXT_UNVERIFIED,
        TrustState.INTEGRITY_VERIFIED,
        TrustState.INTEGRITY_FAILED,
    ]


#------------------------------------------------------------------------------#
# integrity unknown: no callback, abstaining callback, raising callback
#------------------------------------------------------------------------------#

def test_no_verifier_keeps_integrity_unknown_even_when_inner_decodes(protected_pdu):
    result = review_nas5g(protected_pdu)
    assert result.verification_state is VerificationState.UNKNOWN
    assert result.trust_state is TrustState.INTEGRITY_UNKNOWN
    assert result.inner_parse_state is InnerParseState.PARSED
    assert result.reason is ReviewReason.VERIFIER_UNAVAILABLE


def test_abstaining_verifier_is_unknown_not_passed(protected_pdu):
    result = review_nas5g(protected_pdu, verifier=make_static_verifier(None))
    assert result.verification_state is VerificationState.UNKNOWN
    assert result.trust_state is TrustState.INTEGRITY_UNKNOWN
    assert result.reason is ReviewReason.VERIFIER_ABSTAINED


def test_verifier_exception_is_caught_and_kept_unknown(protected_pdu):
    def exploding_verifier(_context):
        raise RuntimeError("key store unreachable")

    result = review_nas5g(protected_pdu, verifier=exploding_verifier)
    assert result.verification_state is VerificationState.UNKNOWN
    assert result.trust_state is TrustState.INTEGRITY_UNKNOWN
    assert result.reason is ReviewReason.VERIFIER_ERROR
    assert "key store unreachable" in result.verifier_error


def test_unknown_verdict_with_wrong_secret(protected_pdu):
    result = review_nas5g(protected_pdu,
                          verifier=make_lab_hmac_verifier(b"different-secret"))
    assert result.verification_state is VerificationState.FAILED
    assert result.trust_state is TrustState.INTEGRITY_FAILED


#------------------------------------------------------------------------------#
# null cipher: confirmed only after integrity passes AND inner decodes
#------------------------------------------------------------------------------#

def test_null_cipher_confirmed_only_after_verification(inner_bytes):
    msg = _envelope(2, inner_bytes)
    apply_lab_hmac(msg, LAB_SECRET)
    result = review_nas5g(msg.to_bytes(),
                          verifier=make_lab_hmac_verifier(LAB_SECRET))
    assert result.ciphering_claimed is True
    assert result.verification_state is VerificationState.PASSED
    assert result.trust_state is TrustState.NULL_CIPHER_CONFIRMED
    assert result.reason is ReviewReason.NULL_CIPHER_CONFIRMED


def test_null_cipher_not_confirmed_when_verdict_unknown(inner_bytes):
    msg = _envelope(2, inner_bytes)
    apply_lab_hmac(msg, LAB_SECRET)
    result = review_nas5g(msg.to_bytes())
    # readable inner + ciphering header without a verdict stays speculative
    assert result.trust_state is TrustState.INTEGRITY_UNKNOWN
    assert result.reason is ReviewReason.VERIFIER_UNAVAILABLE


def test_verified_but_opaque_payload_is_not_called_null_cipher(inner_bytes):
    msg = _envelope(2, b"\xff\xff\xff\xff\xff")
    apply_lab_hmac(msg, LAB_SECRET)
    result = review_nas5g(msg.to_bytes(),
                          verifier=make_lab_hmac_verifier(LAB_SECRET))
    assert result.verification_state is VerificationState.PASSED
    assert result.inner_parse_state is InnerParseState.FAILED
    assert result.trust_state is TrustState.INTEGRITY_VERIFIED
    assert result.reason is ReviewReason.CIPHERED_OPAQUE
    assert result.inner_message is None
    assert result.inner_parse_error is not None


#------------------------------------------------------------------------------#
# recorded facts: header declaration, raw payload, inner attempt, MAC/seqn
#------------------------------------------------------------------------------#

def test_result_records_declared_header_and_raw_payload(bad_protected_pdu, inner_bytes):
    result = review_nas5g(bad_protected_pdu,
                          verifier=make_static_verifier(False))
    assert result.sec_hdr == 2
    assert result.sec_hdr_name == "Integrity protected and ciphered"
    assert result.mac == b"\xde\xad\xbe\xef"
    assert result.seqn == 5
    assert result.raw_protected_payload == inner_bytes
    assert result.entire_message == bad_protected_pdu


def test_inner_parse_can_be_disabled_and_never_upgrades_trust(protected_pdu):
    result = review_nas5g(protected_pdu,
                          verifier=make_static_verifier(None),
                          parse_inner=False)
    assert result.inner_parse_state is InnerParseState.NOT_ATTEMPTED
    assert result.inner_message is None
    assert result.raw_protected_payload is not None
    assert result.trust_state is TrustState.INTEGRITY_UNKNOWN


def test_verifier_receives_full_context_without_keys(protected_pdu, inner_bytes):
    seen = {}

    def recording_verifier(context):
        seen.update(context.__dict__)
        return True

    result = review_nas5g(protected_pdu, verifier=recording_verifier)
    assert seen["sec_hdr"] == 1
    assert seen["seqn"] == 5
    assert seen["raw_payload"] == inner_bytes
    assert seen["entire_message"] == protected_pdu
    assert seen["ciphering_claimed"] is False
    assert result.verification_state is VerificationState.PASSED


def test_malformed_envelope_is_reported_as_unparseable():
    result = review_nas5g(b"\x7e\x01\x00")
    assert result.protection_state is ProtectionState.MALFORMED
    assert result.trust_state is TrustState.UNPARSEABLE
    assert result.reason is ReviewReason.MALFORMED_OUTER


def test_truncated_protected_envelope_is_malformed():
    result = review_nas5g(b"\x7e\x01\x64\x00\x00")
    assert result.protection_state is ProtectionState.MALFORMED
    assert result.verification_state is VerificationState.NOT_APPLICABLE
    assert result.inner_message is None


def test_non_bytes_input_is_rejected():
    with pytest.raises(TypeError):
        review_nas5g("7e006418")


def test_to_dict_is_json_serializable_and_hex_encodes_bytes(protected_pdu):
    result = review_nas5g(protected_pdu,
                          verifier=make_lab_hmac_verifier(LAB_SECRET))
    rendered = json.loads(json.dumps(result.to_dict()))
    assert rendered["trust_state"] == TrustState.INTEGRITY_VERIFIED.value
    assert rendered["raw_protected_payload"] == result.raw_protected_payload.hex()
    assert isinstance(rendered["outer_message"], str)


def test_format_review_mentions_every_key_fact(bad_protected_pdu):
    result = review_nas5g(bad_protected_pdu,
                          verifier=make_lab_hmac_verifier(LAB_SECRET))
    text = format_review(result)
    for token in ("protection", "verification", "inner parse", "trust state",
                  "reason", "raw payload", "deadbeef"):
        assert token in text


def test_pycrate_verifier_adapter_fails_cleanly_without_cryptomobile(protected_pdu):
    if hasattr(FGMMSecProtNASMessage, "mac_verify"):
        pytest.skip("CryptoMobile is installed: adapter is expected to work")
    verifier = make_pycrate_mac_verifier(key=16 * b"\x00", fgia=1)
    result = review_nas5g(protected_pdu, verifier=verifier)
    # a missing crypto backend must never be silently treated as verified
    assert result.verification_state is VerificationState.UNKNOWN
    assert result.reason is ReviewReason.VERIFIER_ERROR
    assert result.trust_state is TrustState.INTEGRITY_UNKNOWN
