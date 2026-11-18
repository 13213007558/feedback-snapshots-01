"""Reference verifier for the review: signature type never picks the weakest path.

The packet's SignatureType is an untrusted claim. Trusted policy selects the
verifier from the packet namespace and the configured keys; the claim must
agree, or the packet is rejected.
"""

from __future__ import annotations

from ndn import encoding as enc
from ndn import types
from ndn.security import Ed25519Checker, HmacChecker, sha256_digest_checker

PROTECTED_PREFIX = '/protected'
PUBLIC_PREFIX = '/protected/public'

# Namespaces that require publication authority accept only asymmetric keys.
AUTHORITY_TYPES = frozenset({
    enc.SignatureType.ED25519,
    enc.SignatureType.SHA256_WITH_ECDSA,
    enc.SignatureType.SHA256_WITH_RSA,
})
# The public cache accepts integrity-only digests.
INTEGRITY_TYPES = frozenset({enc.SignatureType.DIGEST_SHA256})


def allowed_types(name) -> frozenset[int]:
    """Return the signature types policy permits for *name*."""
    if enc.Name.is_prefix(PROTECTED_PREFIX, name) and not enc.Name.is_prefix(PUBLIC_PREFIX, name):
        return AUTHORITY_TYPES
    if enc.Name.is_prefix(PUBLIC_PREFIX, name):
        return INTEGRITY_TYPES
    return frozenset()


def make_strict_validator(*, hmac_key: bytes, hmac_key_name: str,
                          ed25519_pub: bytes, ed25519_key_name: str):
    """Build a Validator enforcing the review's acceptance rules."""

    async def validate(name, sig, context=None):
        info = sig.signature_info
        if info is None or info.signature_type is None:
            return types.ValidResult.FAIL

        stype = info.signature_type
        if stype not in allowed_types(name):
            return types.ValidResult.FAIL

        if stype == enc.SignatureType.DIGEST_SHA256:
            return await sha256_digest_checker(name, sig, context)

        locator = info.key_locator
        if locator is None or locator.name is None:
            return types.ValidResult.FAIL

        if stype == enc.SignatureType.HMAC_WITH_SHA256:
            if not enc.Name.is_prefix(hmac_key_name, locator.name):
                return types.ValidResult.FAIL
            return await HmacChecker.from_key(hmac_key_name, hmac_key)(name, sig, context)

        if stype == enc.SignatureType.ED25519:
            return await Ed25519Checker.from_key(ed25519_key_name, ed25519_pub)(name, sig, context)

        # ECDSA/RSA need a certificate chain; the LVS validator handles those.
        return types.ValidResult.FAIL

    return validate
