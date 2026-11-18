# -*- coding: UTF-8 -*-
"""Explicit protection and trust accounting for decoded 5G NAS messages.

A traffic-review backend must never equate "the bytes happen to decode as a
NAS message" with "the message is authenticated".  A 5GMM security header only
*declares* protection: the embedded MAC still has to be verified against a key,
and a null-cipher configuration only means the payload is readable, not that it
can be trusted.  This module wraps :func:`pycrate_mobile.NAS5G.parse_NAS5G` and
returns a :class:`NASReviewResult` that keeps those concerns separate:

* the security header as declared on the wire;
* the raw protected payload, always kept as untouched bytes;
* whether an inner parse was attempted, and its outcome;
* the result of an externally injected integrity verifier;
* a final trust state that is never upgraded by format alone.

Integrity verification is deliberately provided through an injectable
callback (see :data:`VerifierCallback`).  No base station, SIM card or
production key material is required to use or test this module.
"""

from binascii import hexlify
from dataclasses import dataclass
from enum import Enum
from hmac import HMAC, compare_digest
from hashlib import sha256
from typing import Callable, Optional, Any

from pycrate_mobile.NAS5G import parse_NAS5G
from pycrate_mobile.TS24501_FGMM import FGMMSecProtNASMessage
from pycrate_mobile.TS24501_IE import SecHdrType_dict


EPD_5GMM = 126
#: security header values that carry a MAC / sequence number
SECHDR_PROTECTED = (1, 2, 3, 4)
#: integrity and ciphering, payload is only readable if null cipher is used
SECHDR_CIPHERED = (2, 4)


class ProtectionState(str, Enum):
    """What the outer header declares about protection."""
    PLAINTEXT = "plaintext"
    SECURITY_PROTECTED = "security_protected"
    MALFORMED = "malformed"


class VerificationState(str, Enum):
    """Outcome of the external integrity verifier callback."""
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"
    FAILED = "failed"
    PASSED = "passed"


class InnerParseState(str, Enum):
    """Whether the inner payload was fed to the NAS decoder."""
    NOT_ATTEMPTED = "not_attempted"
    PARSED = "parsed"
    FAILED = "failed"


class TrustState(str, Enum):
    """The trust level the backend is allowed to display.

    A successful inner decode never promotes a message on its own: only a
    positive verifier result can do that.
    """
    PLAINTEXT_UNVERIFIED = "plaintext_unverified"
    INTEGRITY_UNKNOWN = "integrity_unknown"
    INTEGRITY_FAILED = "integrity_failed"
    INTEGRITY_VERIFIED = "integrity_verified"
    NULL_CIPHER_CONFIRMED = "null_cipher_confirmed"
    UNPARSEABLE = "unparseable"


class ReviewReason(str, Enum):
    """Stable, machine-readable explanation codes."""
    PLAINTEXT_NO_HEADER = "plaintext_no_security_header"
    MALFORMED_OUTER = "malformed_outer_message"
    VERIFIER_UNAVAILABLE = "no_verifier_callback"
    VERIFIER_ABSTAINED = "verifier_abstained"
    VERIFIER_ERROR = "verifier_callback_error"
    MAC_FAILED = "integrity_check_failed"
    MAC_PASSED = "integrity_check_passed"
    #: speculative decode while integrity is unknown (see explanation text)
    INNER_SPECULATIVE = "inner_parsed_without_verification"
    INNER_AFTER_FAILURE = "inner_parsed_after_failed_verification"
    NULL_CIPHER_CONFIRMED = "null_cipher_confirmed"
    CIPHERED_OPAQUE = "ciphered_payload_opaque"


#: verifier callback: receives the protection context, returns True / False for
#: an explicit verdict or None to abstain (verdict stays unknown)
VerifierCallback = Callable[["VerificationContext"], Optional[bool]]


@dataclass
class VerificationContext:
    """Everything an injected verifier may inspect, without any key material."""
    sec_hdr: int
    sec_hdr_name: str
    mac: bytes
    seqn: int
    raw_payload: bytes
    entire_message: bytes
    ciphering_claimed: bool


@dataclass
class NASReviewResult:
    """Structured review output for a single 5G NAS PDU."""
    protection_state: ProtectionState
    verification_state: VerificationState
    trust_state: TrustState
    inner_parse_state: InnerParseState
    reason: ReviewReason
    explanation: str
    sec_hdr: Optional[int] = None
    sec_hdr_name: Optional[str] = None
    mac: Optional[bytes] = None
    seqn: Optional[int] = None
    ciphering_claimed: bool = False
    raw_protected_payload: Optional[bytes] = None
    outer_message: Any = None
    inner_message: Any = None
    inner_parse_error: Optional[int] = None
    verifier_error: Optional[str] = None
    entire_message: bytes = b""

    def to_dict(self):
        """JSON-friendly rendering (bytes are hex-encoded)."""
        out = {}
        for key, val in self.__dict__.items():
            if isinstance(val, Enum):
                out[key] = val.value
            elif isinstance(val, (bytes, bytearray)):
                out[key] = hexlify(bytes(val)).decode()
            elif key in ("outer_message", "inner_message"):
                out[key] = val.show() if val is not None else None
            else:
                out[key] = val
        return out


def _sec_hdr_name(sec_hdr):
    return SecHdrType_dict.get(sec_hdr, "undefined")


def _malformed(buf, explanation, parse_error=None):
    return NASReviewResult(
        protection_state=ProtectionState.MALFORMED,
        verification_state=VerificationState.NOT_APPLICABLE,
        trust_state=TrustState.UNPARSEABLE,
        inner_parse_state=InnerParseState.NOT_ATTEMPTED,
        reason=ReviewReason.MALFORMED_OUTER,
        explanation=explanation,
        inner_parse_error=parse_error,
        entire_message=bytes(buf),
    )


def _run_verifier(verifier, context):
    """Returns (verification_state, reason, verifier_error)."""
    if verifier is None:
        return VerificationState.UNKNOWN, ReviewReason.VERIFIER_UNAVAILABLE, None
    try:
        verdict = verifier(context)
    except Exception as exc:
        return (
            VerificationState.UNKNOWN,
            ReviewReason.VERIFIER_ERROR,
            "{0}: {1}".format(type(exc).__name__, exc),
        )
    if verdict is None:
        return VerificationState.UNKNOWN, ReviewReason.VERIFIER_ABSTAINED, None
    if bool(verdict):
        return VerificationState.PASSED, ReviewReason.MAC_PASSED, None
    return VerificationState.FAILED, ReviewReason.MAC_FAILED, None


def review_nas5g(buf, verifier=None, parse_inner=True):
    """Review a 5G NAS PDU and account separately for parsing and trust.

    Args:
        buf: raw 5G NAS message bytes.
        verifier: optional :data:`VerifierCallback`.  ``None`` means no verdict
            is available, so integrity stays *unknown* rather than assumed good.
        parse_inner: attempt to decode the inner payload of a protected message.
            The decode is always reported as speculative until integrity passes.

    Returns:
        NASReviewResult
    """
    if not isinstance(buf, (bytes, bytearray)):
        raise TypeError("buf must be bytes, got {0}".format(type(buf).__name__))
    buf = bytes(buf)

    # outer dispatch on the 5GMM header layout (EPD, security header, type)
    if len(buf) < 3:
        return _malformed(buf, "buffer too short for a 5G NAS header")
    epd, sec_hdr_byte, _msg_type = buf[0], buf[1], buf[2]
    sec_hdr = sec_hdr_byte & 0x0F

    if epd != EPD_5GMM or sec_hdr not in SECHDR_PROTECTED:
        return _review_plain(buf, parse_inner)
    return _review_protected(buf, sec_hdr, verifier, parse_inner)


def _review_plain(buf, parse_inner):
    msg, err = parse_NAS5G(buf, inner=bool(parse_inner), sec_hdr=True)
    if err or msg is None:
        return _malformed(
            buf,
            "outer bytes do not form a valid 5G NAS message (NAS error {0})".format(err),
            parse_error=err,
        )
    return NASReviewResult(
        protection_state=ProtectionState.PLAINTEXT,
        verification_state=VerificationState.NOT_APPLICABLE,
        trust_state=TrustState.PLAINTEXT_UNVERIFIED,
        inner_parse_state=InnerParseState.NOT_ATTEMPTED,
        reason=ReviewReason.PLAINTEXT_NO_HEADER,
        explanation=(
            "no security header is present: the message is readable clear text "
            "but carries no MAC, so its origin and integrity cannot be authenticated"
        ),
        sec_hdr=0,
        sec_hdr_name=_sec_hdr_name(0),
        ciphering_claimed=False,
        outer_message=msg,
        entire_message=buf,
    )


def _review_protected(buf, sec_hdr, verifier, parse_inner):
    sec_msg = FGMMSecProtNASMessage()
    try:
        sec_msg.from_bytes(buf)
    except Exception as exc:
        return _malformed(
            buf,
            "security-protected envelope is malformed and cannot be decoded: {0}".format(exc),
        )

    mac = bytes(sec_msg["MAC"].get_val())
    seqn = sec_msg["Seqn"].get_val()
    # always keep the payload exactly as captured; it is never replaced in place
    raw_payload = bytes(sec_msg["NASMessage"].get_val())
    ciphering_claimed = sec_hdr in SECHDR_CIPHERED

    context = VerificationContext(
        sec_hdr=sec_hdr,
        sec_hdr_name=_sec_hdr_name(sec_hdr),
        mac=mac,
        seqn=seqn,
        raw_payload=raw_payload,
        entire_message=buf,
        ciphering_claimed=ciphering_claimed,
    )
    verification_state, reason, verifier_error = _run_verifier(verifier, context)

    inner_msg = None
    inner_err = None
    inner_state = InnerParseState.NOT_ATTEMPTED
    if parse_inner:
        inner_msg, inner_err = parse_NAS5G(raw_payload, inner=True, sec_hdr=True)
        inner_state = InnerParseState.PARSED if inner_msg is not None else InnerParseState.FAILED

    trust_state, final_reason, explanation = _decide_trust(
        sec_hdr, ciphering_claimed, verification_state, reason, inner_state
    )

    return NASReviewResult(
        protection_state=ProtectionState.SECURITY_PROTECTED,
        verification_state=verification_state,
        trust_state=trust_state,
        inner_parse_state=inner_state,
        reason=final_reason,
        explanation=explanation,
        sec_hdr=sec_hdr,
        sec_hdr_name=_sec_hdr_name(sec_hdr),
        mac=mac,
        seqn=seqn,
        ciphering_claimed=ciphering_claimed,
        raw_protected_payload=raw_payload,
        outer_message=sec_msg,
        inner_message=inner_msg,
        inner_parse_error=None if inner_state != InnerParseState.FAILED else inner_err,
        verifier_error=verifier_error,
        entire_message=buf,
    )


def _decide_trust(sec_hdr, ciphering_claimed, verification_state, reason, inner_state):
    inner_ok = inner_state == InnerParseState.PARSED

    if verification_state == VerificationState.FAILED:
        if inner_ok:
            return (
                TrustState.INTEGRITY_FAILED,
                ReviewReason.INNER_AFTER_FAILURE,
                "MAC verification failed; the inner bytes happen to match a NAS "
                "message format but the content is rejected and must not be treated "
                "as authenticated plaintext",
            )
        return (
            TrustState.INTEGRITY_FAILED,
            ReviewReason.MAC_FAILED,
            "MAC verification failed; the protected payload is untrusted",
        )

    if verification_state == VerificationState.UNKNOWN:
        # the verifier reason (no callback / abstained / error) is always kept;
        # a successful inner parse is only reflected in the explanation, never
        # in the trust state or reason
        if inner_ok:
            return (
                TrustState.INTEGRITY_UNKNOWN,
                reason,
                "no integrity verdict is available; the inner payload decodes as a "
                "NAS message but remains speculative and is NOT authenticated"
                + (" (a ciphering header is declared, null cipher is only an assumption)"
                   if ciphering_claimed else ""),
            )
        return (
            TrustState.INTEGRITY_UNKNOWN,
            reason,
            "no integrity verdict is available and the inner payload cannot be "
            "decoded; the message stays untrusted",
        )

    # VerificationState.PASSED: only here may a message gain any trust
    if ciphering_claimed:
        if inner_ok:
            return (
                TrustState.NULL_CIPHER_CONFIRMED,
                ReviewReason.NULL_CIPHER_CONFIRMED,
                "integrity verified and the protected payload decodes despite a "
                "ciphering security header, confirming null cipher is in use; the "
                "clear text is authenticated",
            )
        return (
            TrustState.INTEGRITY_VERIFIED,
            ReviewReason.CIPHERED_OPAQUE,
            "integrity verified, but the payload does not decode as clear text: it "
            "is genuinely ciphered and needs a decryption key before inspection",
        )

    return (
        TrustState.INTEGRITY_VERIFIED,
        ReviewReason.MAC_PASSED,
        "integrity verified; the clear-text inner payload is authenticated",
    )


#------------------------------------------------------------------------------#
# verifier adapters and helpers (no SIM, base station or production key needed)
#------------------------------------------------------------------------------#

def make_static_verifier(decision):
    """Verifier returning a fixed verdict, useful to inject pass/fail/abstain."""
    def _verifier(_context):
        return decision
    return _verifier


def _lab_authenticated_input(context):
    """Message bytes with the 4-byte MAC field zeroed, as authenticated input.

    The on-wire MAC is never part of its own authenticated input; both the
    compute and verify paths must reconstruct the same zeroed byte string.
    """
    zeroed = bytearray(context.entire_message)
    zeroed[2:6] = b"\x00\x00\x00\x00"
    return bytes(zeroed)


def _lab_authenticated_input_from_msg(sec_message):
    """Authenticate-input bytes built from a message before its MAC is set."""
    sec_message["MAC"].set_val(b"\x00\x00\x00\x00")
    return sec_message.to_bytes()


def make_lab_hmac_verifier(secret, digestmod=sha256):
    """HMAC-based verifier for tests and demos.

    This implements a self-contained lab scheme (HMAC over the whole message
    with its MAC field zeroed); it is not a 3GPP 5G-IA algorithm, but exercises
    the exact same verifier contract a production K_nas_int based check would.
    """
    if isinstance(secret, str):
        secret = secret.encode()
    def _verifier(context):
        expected = HMAC(secret, _lab_authenticated_input(context), digestmod).digest()[:4]
        return compare_digest(expected, context.mac)
    return _verifier


def apply_lab_hmac(sec_message, secret, digestmod=sha256):
    """Compute and set the lab HMAC value on a FGMMSecProtNASMessage."""
    if isinstance(secret, str):
        secret = secret.encode()
    authenticated_input = _lab_authenticated_input_from_msg(sec_message)
    mac = HMAC(secret, authenticated_input, digestmod).digest()[:4]
    sec_message["MAC"].set_val(mac)
    return mac


def make_pycrate_mac_verifier(key, fgia, dir=0, seqnoff=0, bearer=1):
    """Adapter over pycrate's ``mac_verify`` for environments with CryptoMobile.

    ``key`` is K_nas_int (16 bytes).  When the CryptoMobile dependency is
    missing, pycrate builds a parser-only 5GMM class without ``mac_verify`` and
    this adapter raises a clear error instead of silently trusting anything.
    """
    def _verifier(context):
        if not hasattr(FGMMSecProtNASMessage, "mac_verify"):
            raise RuntimeError(
                "pycrate was built without CryptoMobile: 5G-IA MAC verification "
                "is unavailable, inject a different verifier"
            )
        sec_msg = FGMMSecProtNASMessage()
        sec_msg.from_bytes(context.entire_message)
        return sec_msg.mac_verify(key=key, dir=dir, fgia=fgia,
                                  seqnoff=seqnoff, bearer=bearer)
    return _verifier


#------------------------------------------------------------------------------#
# display helpers
#------------------------------------------------------------------------------#

def format_review(result):
    """One-screen summary a review backend can show to an operator."""
    lines = [
        "protection      : {0} (sec hdr {1}, {2})".format(
            result.protection_state.value,
            result.sec_hdr if result.sec_hdr is not None else "-",
            result.sec_hdr_name or "-",
        ),
        "ciphering       : {0}".format(
            "claimed by security header" if result.ciphering_claimed else "not claimed"),
        "verification    : {0}".format(result.verification_state.value),
        "inner parse     : {0}".format(result.inner_parse_state.value),
        "trust state     : {0}".format(result.trust_state.value),
        "reason          : {0}".format(result.reason.value),
        "explanation     : {0}".format(result.explanation),
    ]
    if result.mac is not None:
        lines.append("MAC (on wire)   : {0}".format(hexlify(result.mac).decode()))
    if result.seqn is not None:
        lines.append("sequence number : {0}".format(result.seqn))
    if result.raw_protected_payload is not None:
        lines.append("raw payload     : {0}".format(
            hexlify(result.raw_protected_payload).decode()))
    if result.verifier_error:
        lines.append("verifier error  : {0}".format(result.verifier_error))
    if result.inner_parse_state == InnerParseState.FAILED:
        lines.append("inner NAS error : {0}".format(result.inner_parse_error))
    return "\n".join(lines)
