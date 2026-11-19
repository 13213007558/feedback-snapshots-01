"""SRP login sessions and the authenticated post-login upgrade channel.

Both sides build their pysrp objects from the *record's* parameter set and
never replace hash/group/x-rule mid-handshake.  After a successful SRP login
the shared session key K authenticates an upgrade envelope carrying fresh
SHA-256 salt+verifier material that the *client* derived from the password.

The server never sees the plaintext password and has no function that turns a
SHA-1 verifier into a SHA-256 verifier -- that is mathematically unavailable;
the new verifier must come from a client that holds the password.
"""

import hashlib
import hmac
import json
import uuid

import srp

from .params import (UPGRADE_PATHS, assert_consistent,
                     assert_globals_pinned, get_param_set)
from .store import ConflictError, SimulatedCrash, from_hex, to_hex


class AuthenticationFailed(Exception):
    pass


def create_fixed_length_material(username, password, param_set):
    """Salt+verifier generation with a guaranteed fixed-length salt.

    pysrp.create_salted_verification_key() routes the random salt through an
    integer, so leading zero bytes are occasionally stripped (the returned
    salt can be shorter than salt_len).  Records here promise a fixed length,
    so we retry until pysrp returns a full-length salt.
    """
    ps = get_param_set(param_set)
    for _ in range(100):
        salt, verifier = srp.create_salted_verification_key(
            username, password, ps["hash_alg"], ps["ng_type"],
            salt_len=ps["salt_len"])
        if len(salt) == ps["salt_len"]:
            return salt, verifier
    raise RuntimeError("could not generate a fixed-length salt")


class UpgradeRejected(Exception):
    pass


def _canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _hmac(session_key, payload):
    return hmac.new(session_key, _canonical(payload), hashlib.sha256).hexdigest()


# --------------------------------------------------------------------- client
class Client:
    """In-process stand-in for the user's device, which holds the password."""

    def __init__(self, username, password, param_set):
        assert_globals_pinned()
        self.username = username
        self.password = password
        self.param_set = param_set
        ps = get_param_set(param_set)
        self._ps = ps
        self._user = srp.User(username, password, ps["hash_alg"],
                              ps["ng_type"])
        self._name, self._A = self._user.start_authentication()

    def start(self):
        return self._name, self._A

    def process_challenge(self, salt, B, served_param_set):
        # The client pins its interpretation to the record's parameter set.
        assert_consistent(self.param_set, served_param_set)
        M = self._user.process_challenge(salt, B)
        if M is None:
            raise AuthenticationFailed("SRP-6a safety check failed on client")
        return M

    def verify_server(self, HAMK):
        self._user.verify_session(HAMK)
        if not self._user.authenticated():
            raise AuthenticationFailed("server proof rejected by client")

    @property
    def session_key(self):
        if not self._user.authenticated():
            raise AuthenticationFailed("no authenticated session key")
        return self._user.get_session_key()

    def derive_new_verifier(self, to_param_set):
        """Fresh registration material for the new parameter set.

        Requires the password: a new random salt and
        v' = g^H(s', H(I:p)) mod N under the SHA-256 parameter set.  Nothing
        here derives from or reuses the old verifier.
        """
        assert_globals_pinned()
        return create_fixed_length_material(
            self.username, self.password, to_param_set)

    def build_upgrade_envelope(self, to_param_set):
        salt, verifier = self.derive_new_verifier(to_param_set)
        payload = {
            "username": self.username,
            "from_param_set": self.param_set,
            "to_param_set": to_param_set,
            "salt": to_hex(salt),
            "verifier": to_hex(verifier),
        }
        return {
            "payload": payload,
            "hmac_sha256": _hmac(self.session_key, payload),
        }, salt, verifier


# --------------------------------------------------------------------- server
class AuthService:
    """Server side: one record per user, one interpretation per handshake."""

    def __init__(self, store):
        assert_globals_pinned()
        self.store = store
        self._sessions = {}

    def challenge(self, username, A, requested_param_set):
        record = self.store.get_record(username)
        # Parameters are taken from the record; a different request is refused
        # rather than silently renegotiated.
        assert_consistent(record["param_set"], requested_param_set)
        ps = get_param_set(record["param_set"])
        verifier = srp.Verifier(
            username, from_hex(record["salt"]),
            from_hex(record["verifier"]), A,
            ps["hash_alg"], ps["ng_type"])
        salt, B = verifier.get_challenge()
        if salt is None or B is None:
            raise AuthenticationFailed("SRP-6a safety check failed on server")
        session_id = uuid.uuid4().hex
        self._sessions[session_id] = {
            "username": username,
            "verifier": verifier,
            "record_revision": record["revision"],
            "param_set": record["param_set"],
            "authenticated": False,
        }
        return session_id, salt, B, record["param_set"]

    def verify(self, session_id, M):
        session = self._sessions[session_id]
        HAMK = session["verifier"].verify_session(M)
        if HAMK is None:
            raise AuthenticationFailed("bad password or invalid client proof")
        session["authenticated"] = True
        return HAMK

    def _require_authenticated(self, session_id):
        session = self._sessions.get(session_id)
        if session is None:
            raise UpgradeRejected("unknown session")
        if not session["authenticated"]:
            raise UpgradeRejected("session is not authenticated")
        return session

    def begin_upgrade(self, session_id, envelope,
                      crash_after_replace=False):
        session = self._require_authenticated(session_id)
        record = self.store.get_record(session["username"])
        payload = envelope["payload"]
        expected = UPGRADE_PATHS.get(session["param_set"])

        if payload["username"] != session["username"]:
            raise UpgradeRejected("envelope username mismatch")
        if session["param_set"] != payload["from_param_set"]:
            raise UpgradeRejected("envelope from_param_set does not match "
                                  "the authenticated session")
        if expected is None or payload["to_param_set"] != expected:
            raise UpgradeRejected(
                "unsupported upgrade path %r -> %r"
                % (payload["from_param_set"], payload["to_param_set"]))
        if record["param_set"] != session["param_set"]:
            raise UpgradeRejected("record parameter set moved under session")
        # Authenticate the envelope with the SRP session key.
        if not hmac.compare_digest(
                envelope["hmac_sha256"],
                _hmac(session["verifier"].get_session_key(), payload)):
            raise UpgradeRejected("envelope HMAC does not verify")
        # Validate material shape under the target parameter set; the old
        # record stays untouched while this journal is staged.
        target = get_param_set(payload["to_param_set"])
        new_salt = from_hex(payload["salt"])
        new_verifier = from_hex(payload["verifier"])
        if len(new_salt) != target["salt_len"]:
            raise UpgradeRejected("new salt has the wrong length")
        if len(new_verifier) == 0:
            raise UpgradeRejected("empty new verifier")

        return self.store.begin_upgrade(
            session["username"], session["record_revision"], session_id,
            payload["to_param_set"], new_salt, new_verifier)

    def commit_upgrade(self, session_id, crash_after_replace=False):
        session = self._require_authenticated(session_id)
        try:
            return self.store.commit_upgrade(
                session["username"], session_id,
                crash_after_replace=crash_after_replace)
        except (ConflictError, SimulatedCrash):
            raise
        except Exception as exc:  # any failure keeps the old record live
            self.store.abort_upgrade(
                session["username"], session_id,
                reason="commit failed: %s" % exc)
            raise UpgradeRejected(str(exc))

    def abort_upgrade(self, session_id, reason):
        self._require_authenticated(session_id)
        return self.store.abort_upgrade(
            self._sessions[session_id]["username"], session_id, reason)

    def end_session(self, session_id):
        self._sessions.pop(session_id, None)


# Convenience: run a complete honest handshake and return (service, session).
def full_login(store, username, password, param_set):
    assert_globals_pinned()
    client = Client(username, password, param_set)
    service = AuthService(store)
    name, A = client.start()
    session_id, salt, B, served = service.challenge(name, A, param_set)
    M = client.process_challenge(salt, B, served)
    HAMK = service.verify(session_id, M)
    client.verify_server(HAMK)
    return service, session_id, client
