"""On-disk SRP record store with upgrade journals and optimistic locking.

Record layout (one JSON document per user, written atomically)::

    users/<username>.json
    pending/<username>__<session_id>.json   # staged, never authoritative
    quarantine/                             # interrupted journals, kept for audit

Invariants enforced on every write and at startup:

* A record names exactly one ``param_set`` and carries exactly one
  (salt, verifier) pair for it.  There is no place where a SHA-1 verifier
  could be relabelled as SHA-256.
* The embedded ``params`` block must match the central registry in
  :mod:`srp_migration_demo.params`, so a record is self-describing and the
  handshake interpretation cannot drift.
* Every mutation bumps ``revision`` and appends to ``history``; commits use
  compare-and-swap on the revision so a stale parallel upgrade cannot
  overwrite a record that moved on underneath it.
"""

import binascii
import copy
import json
import os
import threading
from datetime import datetime, timezone

from .params import UPGRADE_PATHS, describe, get_param_set

RECORD_VERSION = 1
MAX_HISTORY = 20


class NotFoundError(LookupError):
    pass


class ConflictError(RuntimeError):
    pass


class SimulatedCrash(RuntimeError):
    """Raised after the on-disk write actually happened, to mimic a crash."""


def _now():
    return datetime.now(timezone.utc).isoformat()


def to_hex(raw):
    return binascii.hexlify(raw).decode("ascii")


def from_hex(text):
    return binascii.unhexlify(text.encode("ascii"))


def _atomic_write(path, document):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def validate_record(record):
    """Assert the record belongs to one, and only one, parameter set."""
    if record.get("version") != RECORD_VERSION:
        raise ValueError("unsupported record version")
    name = record.get("param_set")
    ps = get_param_set(name)
    if record.get("params") != describe(name):
        raise ValueError("embedded params block does not match registry")
    if describe(name)["salt_encoding"] != "hex":
        raise ValueError("only hex salt encoding is supported by the demo")
    # Single, unambiguous material: exactly one salt + one verifier.
    for field in ("salt", "verifier"):
        value = record.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError("missing or malformed %s" % field)
        from_hex(value)  # raises if it is not clean hex
    if not isinstance(record.get("revision"), int) or record["revision"] < 1:
        raise ValueError("revision must be a positive integer")
    # Defence in depth: no dual-material fields that could be interpreted two
    # ways (e.g. a stale verifier kept next to a new one).
    forbidden = {"salt_sha1", "verifier_sha1", "salt_sha256",
                 "verifier_sha256", "legacy_verifier", "new_verifier"}
    if forbidden.intersection(record):
        raise ValueError("record must contain a single salt/verifier pair")
    return True


class RecordStore:
    def __init__(self, root):
        self.root = root
        self.users_dir = os.path.join(root, "users")
        self.pending_dir = os.path.join(root, "pending")
        self.quarantine_dir = os.path.join(root, "quarantine")
        for directory in (self.root, self.users_dir, self.pending_dir,
                          self.quarantine_dir):
            os.makedirs(directory, exist_ok=True)
        self._lock = threading.RLock()
        self.startup_recovery = self.recover()

    # ---------------------------------------------------------------- paths
    def _user_path(self, username):
        return os.path.join(self.users_dir, username + ".json")

    def _journal_path(self, username, session_id):
        return os.path.join(self.pending_dir,
                            "%s__%s.json" % (username, session_id))

    def _read_json(self, path):
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    # -------------------------------------------------------------- records
    def create_user(self, username, param_set, salt, verifier, note="registered"):
        with self._lock:
            path = self._user_path(username)
            if os.path.exists(path):
                raise ConflictError("user already exists: %s" % username)
            record = {
                "version": RECORD_VERSION,
                "username": username,
                "param_set": param_set,
                "params": describe(param_set),
                "salt": to_hex(salt),
                "verifier": to_hex(verifier),
                "revision": 1,
                "created_at": _now(),
                "updated_at": _now(),
                "history": [{"event": note, "param_set": param_set,
                             "at": _now()}],
            }
            validate_record(record)
            _atomic_write(path, record)
            return self.get_record(username)

    def get_record(self, username):
        with self._lock:
            path = self._user_path(username)
            if not os.path.exists(path):
                raise NotFoundError(username)
            record = self._read_json(path)
            validate_record(record)
            return copy.deepcopy(record)

    def _append_history(self, record, event, **extra):
        entry = {"event": event, "at": _now()}
        entry.update(extra)
        record["history"].append(entry)
        del record["history"][:-MAX_HISTORY]

    # ------------------------------------------------------ upgrade journals
    def begin_upgrade(self, username, base_revision, session_id,
                      to_param_set, new_salt, new_verifier):
        """Stage new material.  The live record is not touched yet."""
        with self._lock:
            record = self.get_record(username)
            from_param_set = record["param_set"]
            if UPGRADE_PATHS.get(from_param_set) != to_param_set:
                raise ValueError(
                    "no allowed upgrade path %r -> %r"
                    % (from_param_set, to_param_set))
            journal = {
                "username": username,
                "session_id": session_id,
                "base_revision": base_revision,
                "new_revision": base_revision + 1,
                "from_param_set": from_param_set,
                "to_param_set": to_param_set,
                "to_params": describe(to_param_set),
                "new_salt": to_hex(new_salt),
                "new_verifier": to_hex(new_verifier),
                "created_at": _now(),
            }
            _atomic_write(self._journal_path(username, session_id), journal)
            return copy.deepcopy(journal)

    def commit_upgrade(self, username, session_id, crash_after_replace=False):
        """Swap in the staged material via revision CAS, atomically.

        On any precondition failure the journal is discarded and the existing
        (still usable) record is left byte-for-byte untouched.
        """
        with self._lock:
            journal_path = self._journal_path(username, session_id)
            if not os.path.exists(journal_path):
                raise NotFoundError("upgrade journal: %s" % session_id)
            journal = self._read_json(journal_path)
            record = self.get_record(username)

            # Idempotent path: a previous attempt already swapped the record
            # but crashed before removing the journal.
            if (record["revision"] == journal["new_revision"]
                    and record["param_set"] == journal["to_param_set"]
                    and record["salt"] == journal["new_salt"]
                    and record["verifier"] == journal["new_verifier"]):
                if not crash_after_replace:
                    os.remove(journal_path)
                return self.get_record(username)

            # CAS: another session changed the record since the journal was
            # staged.  Refuse and keep the winning record intact.
            if record["revision"] != journal["base_revision"]:
                os.remove(journal_path)
                raise ConflictError(
                    "record revision moved from %d to %d; stale upgrade "
                    "discarded" % (journal["base_revision"],
                                   record["revision"]))

            if record["param_set"] != journal["from_param_set"]:
                os.remove(journal_path)
                raise ConflictError("record parameter set changed underneath")

            new_record = copy.deepcopy(record)
            new_record["param_set"] = journal["to_param_set"]
            new_record["params"] = journal["to_params"]
            new_record["salt"] = journal["new_salt"]
            new_record["verifier"] = journal["new_verifier"]
            new_record["revision"] = journal["new_revision"]
            new_record["updated_at"] = _now()
            self._append_history(
                new_record, "upgrade_committed",
                from_param_set=journal["from_param_set"],
                to_param_set=journal["to_param_set"],
                session_id=session_id)
            validate_record(new_record)
            _atomic_write(self._user_path(username), new_record)

            if crash_after_replace:
                # The replace already landed; only the journal cleanup is
                # skipped, exactly like a crash at this instant.
                raise SimulatedCrash("crash after record replace, before "
                                     "journal removal")
            os.remove(journal_path)
            return self.get_record(username)

    def abort_upgrade(self, username, session_id, reason):
        with self._lock:
            journal_path = self._journal_path(username, session_id)
            if os.path.exists(journal_path):
                os.remove(journal_path)
            record = self.get_record(username)
            new_record = copy.deepcopy(record)
            self._append_history(new_record, "upgrade_aborted", reason=reason,
                                 session_id=session_id)
            _atomic_write(self._user_path(username), new_record)
            return self.get_record(username)

    def list_journals(self, username=None):
        with self._lock:
            out = []
            for name in sorted(os.listdir(self.pending_dir)):
                if not name.endswith(".json"):
                    continue
                if username and not name.startswith(username + "__"):
                    continue
                out.append(self._read_json(os.path.join(self.pending_dir, name)))
            return out

    def recover(self):
        """Reconcile journals left behind by an interrupted process.

        Already-applied journals are cleaned up.  Journals whose swap never
        happened are quarantined for audit and *not* auto-committed: their
        fresh material was only ever validated inside the dead authenticated
        session, so a safe retry is a brand-new login-driven upgrade.  The
        live record stays untouched and usable throughout.
        """
        with self._lock:
            summary = {"completed_cleanup": [], "quarantined": []}
            for name in sorted(os.listdir(self.pending_dir)):
                if not name.endswith(".json"):
                    continue
                journal_path = os.path.join(self.pending_dir, name)
                journal = self._read_json(journal_path)
                username = journal["username"]
                record_path = self._user_path(username)
                if os.path.exists(record_path):
                    record = self._read_json(record_path)
                    validate_record(record)
                    applied = (
                        record["revision"] == journal["new_revision"]
                        and record["param_set"] == journal["to_param_set"]
                        and record["salt"] == journal["new_salt"]
                        and record["verifier"] == journal["new_verifier"])
                    if applied:
                        os.remove(journal_path)
                        summary["completed_cleanup"].append(name)
                        continue
                target = os.path.join(
                    self.quarantine_dir,
                    "%s.%s" % (name, _now().replace(":", "")))
                os.replace(journal_path, target)
                summary["quarantined"].append(name)
            return summary
