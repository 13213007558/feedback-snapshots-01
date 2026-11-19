"""Server-side SRP login integration with decoy challenges against enumeration.

Design properties enforced here (see ``srp/server/ANTI_ENUMERATION.md``):

* One public parameter set (SHA-256 / 2048-bit group) is used for every
  record, real or decoy, so the wire message shapes cannot diverge.
* Real salts are random.  Decoy salt and verifier are derived deterministically
  from a per-deployment server secret and the queried identity, giving a stable
  record without any account database row.  The verifier is a valid group
  element ``g^x mod N`` produced with the same primitive as a real verifier.
* The decoy verifier is never attached to an identity that can authenticate:
  the session carries an ``is_decoy`` flag that forces rejection regardless of
  the cryptographic comparison.
* Rejection logging uses a single fixed message.  Record existence, the salt
  and proof material never reach the log.
"""

import hmac
import logging
import threading

from srp import _pysrp as srp


logger = logging.getLogger("srp.server")

# Single, public policy shared by real and decoy records.
POLICY_HASH_ALG = srp.SHA256
POLICY_NG_TYPE = srp.NG_2048
SALT_BYTES = 16

# Fixed message used for every failed verification. It deliberately carries no
# identity, salt, record type or branch information.
_REJECTION_MESSAGE = "SRP verification rejected"


class AuthenticationFailed(Exception):
    """Raised on any failed SRP login, for any identity, with one message."""


def _as_bytes(value):
    if isinstance(value, str):
        return value.encode("utf-8")
    return value


class SrpUserStore:
    """In-memory store of real SRP registration records.

    A record is the ``(salt, verifier)`` pair produced by
    :func:`srp.create_salted_verification_key` under the shared public policy.
    Lookup uses constant-time hashed comparison so a store hit and miss do not
    leak through dictionary identity comparison timing.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._records = {}
        self._lookup_key = {}

    def put(self, username, salt, verifier):
        identity = _as_bytes(username)
        with self._lock:
            self._records[identity] = (salt, verifier)
            self._lookup_key[identity] = hmac.new(b"store-key", identity,
                                                  "sha256").digest()

    def register(self, username, password):
        identity = _as_bytes(username)
        salt, verifier = srp.create_salted_verification_key(
            identity,
            _as_bytes(password),
            hash_alg=POLICY_HASH_ALG,
            ng_type=POLICY_NG_TYPE,
            salt_len=SALT_BYTES,
        )
        self.put(identity, salt, verifier)
        return salt, verifier

    def constant_time_get(self, username):
        """Fetch a real record, timing-independent of which identity matched."""
        identity = _as_bytes(username)
        target = hmac.new(b"store-key", identity, "sha256").digest()
        with self._lock:
            snapshot = list(self._lookup_key.items())
        match = None
        for candidate_identity, candidate_key in snapshot:
            if hmac.compare_digest(target, candidate_key):
                match = candidate_identity
        if match is None:
            return None
        with self._lock:
            return self._records.get(match)


class SrpServer:
    """SRP verifier service that answers unknown identities with a decoy.

    ``server_secret`` is deployment-private entropy.  It only seeds decoy
    material; it is never transmitted and never mixed into real records.
    """

    def __init__(self, server_secret, user_store=None):
        secret = _as_bytes(server_secret)
        if len(secret) < 32:
            raise ValueError("server_secret must be at least 32 bytes")
        self._secret = secret
        self._store = user_store if user_store is not None else SrpUserStore()
        self._decoy_cache = {}
        self._decoy_lock = threading.Lock()

    @property
    def user_store(self):
        return self._store

    def _decoy_record(self, identity):
        """Deterministic, secret- and identity-bound decoy (salt, verifier).

        The derivation is memoized per identity.  ``HMAC`` keyed on the server
        secret binds both the salt and the private key ``x`` to this
        deployment and to the identity, so the same identity always yields the
        same record, two identities cannot collide without an HMAC forgery,
        and an attacker without the secret cannot predict or precompute one.
        """
        cached = self._decoy_cache.get(identity)
        if cached is not None:
            return cached
        with self._decoy_lock:
            cached = self._decoy_cache.get(identity)
            if cached is not None:
                return cached

            salt = hmac.new(self._secret, b"srp-decoy-salt" + identity,
                            "sha256").digest()[:SALT_BYTES]
            decoy_x = srp.bytes_to_long(
                hmac.new(self._secret, b"srp-decoy-x" + salt + identity,
                         "sha256").digest()
            )
            n_value, g_value = srp.get_ng(POLICY_NG_TYPE, None, None)
            verifier = srp.long_to_bytes(pow(g_value, decoy_x, n_value))
            cached = (salt, verifier)
            self._decoy_cache[identity] = cached
            return cached

    def prewarm_decoy(self, identities):
        """Pre-derive decoy records to remove first-contact derivation cost."""
        for identity in identities:
            self._decoy_record(_as_bytes(identity))

    def begin_handshake(self, username, client_A):
        """Issue ``(salt, B)`` for any identity, real or unknown.

        The returned :class:`HandshakeSession` exposes identical wire message
        shapes in both branches.  The server ephemeral ``b`` is generated by
        the backend per handshake, exactly as in a stock pysrp verifier.
        """
        identity = _as_bytes(username)
        record = self._store.constant_time_get(identity)
        if record is None:
            salt, verifier = self._decoy_record(identity)
            is_decoy = True
        else:
            salt, verifier = record
            is_decoy = False

        verifier_obj = srp.Verifier(
            identity,
            salt,
            verifier,
            client_A,
            hash_alg=POLICY_HASH_ALG,
            ng_type=POLICY_NG_TYPE,
        )
        return HandshakeSession(verifier_obj, is_decoy)


class HandshakeSession:
    """A single SRP handshake, indistinguishable on the wire for both branches."""

    def __init__(self, verifier, is_decoy):
        self._verifier = verifier
        self._is_decoy = is_decoy
        self._finished = False

    @property
    def is_decoy(self):
        return self._is_decoy

    def get_challenge(self):
        """Return ``(salt, B)``; ``(None, None)`` only on an SRP safety check."""
        return self._verifier.get_challenge()

    def verify_proof(self, client_M):
        """Verify the client proof and return HAMK, or ``None`` on rejection.

        Decoy sessions always fail business authentication even if a client
        proof happens to match, because there is no password that legitimately
        corresponds to the server-side decoy verifier.  Every rejection logs
        the same fixed message.
        """
        if self._finished:
            logger.warning(_REJECTION_MESSAGE)
            return None
        self._finished = True

        if self._verifier.safety_failed:
            logger.warning(_REJECTION_MESSAGE)
            return None

        hamk = self._verifier.verify_session(client_M)
        if hamk is None or self._is_decoy:
            logger.warning(_REJECTION_MESSAGE)
            return None

        if not self._verifier.authenticated():
            logger.warning(_REJECTION_MESSAGE)
            return None
        return hamk

    def authenticate(self, client_M):
        """Convenience wrapper raising :class:`AuthenticationFailed` uniformly."""
        hamk = self.verify_proof(client_M)
        if hamk is None:
            raise AuthenticationFailed(_REJECTION_MESSAGE)
        return hamk

    def authenticated(self):
        return (not self._is_decoy) and self._verifier.authenticated()
