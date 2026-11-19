"""Anti-enumeration SRP server integration built on the pure-Python backend.

The SRP login service must never answer "unknown account" by refusing to issue
a challenge: that response distinguishes registered users from arbitrary
identities and enables username enumeration.  This package answers every
handshake with a challenge drawn from one *public* SRP parameter set.  Unknown
identities are served a deterministic decoy record whose salt and verifier are
bound to a server-side secret and to the queried identity.  A decoy handshake
performs the same cryptographic work as a real one but is hard-flagged so it
can never reach the authenticated business state.
"""

from srp.server.srp_server import (
    AuthenticationFailed,
    SrpServer,
    SrpUserStore,
    HandshakeSession,
    POLICY_HASH_ALG,
    POLICY_NG_TYPE,
    SALT_BYTES,
)

__all__ = (
    "AuthenticationFailed",
    "SrpServer",
    "SrpUserStore",
    "HandshakeSession",
    "POLICY_HASH_ALG",
    "POLICY_NG_TYPE",
    "SALT_BYTES",
)
