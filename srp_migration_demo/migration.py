"""Migration orchestration: what needs the password and what does not.

Two strictly separated kinds of work:

* Metadata work (no password): loading the store, reconciling interrupted
  journals, validating record invariants, and reporting which users are still
  on the legacy parameter set.  None of this can produce a SHA-256 verifier.
* Password work: a fully authenticated SRP login under the *existing* record,
  after which the client (which alone holds the password) generates fresh
  salt+verifier material for the target parameter set and the server swaps it
  in atomically.

There is deliberately no function that rewrites ``param_set`` while keeping
the old verifier: a SHA-1 verifier re-labelled SHA-256 is not a valid
SHA-256 verifier and would only lock the user out.
"""

import os

from .params import (LEGACY_PARAM_SET, TARGET_PARAM_SET,
                     assert_globals_pinned)
from .protocol import create_fixed_length_material, full_login
from .store import RecordStore, SimulatedCrash


# ----------------------------------------------------------- no-password work
def open_store(root):
    """Load the store and reconcile crashed journals. No password involved."""
    assert_globals_pinned()
    store = RecordStore(root)
    return store, store.startup_recovery


def review(store):
    """Report per-user migration status without touching any material."""
    report = {"legacy": [], "upgraded": [], "other": []}
    for username in sorted(
            name[:-5] for name in os.listdir(store.users_dir)
            if name.endswith(".json")):
        record = store.get_record(username)
        entry = {
            "username": username,
            "param_set": record["param_set"],
            "digest": record["params"]["digest"],
            "revision": record["revision"],
            "needs_password": record["param_set"] == LEGACY_PARAM_SET,
        }
        if record["param_set"] == LEGACY_PARAM_SET:
            report["legacy"].append(entry)
        elif record["param_set"] == TARGET_PARAM_SET:
            report["upgraded"].append(entry)
        else:
            report["other"].append(entry)
    report["open_journals"] = [
        (j["username"], j["session_id"]) for j in store.list_journals()]
    return report


def seed_legacy_user(store, username, password, note="legacy registration"):
    """Register a user exactly as the old SHA-1 service would have done."""
    salt, verifier = create_fixed_length_material(
        username, password, LEGACY_PARAM_SET)
    return store.create_user(username, LEGACY_PARAM_SET, salt, verifier,
                             note=note)


def register_new_user(store, username, password):
    """Brand-new users are written directly in the target parameter set."""
    salt, verifier = create_fixed_length_material(
        username, password, TARGET_PARAM_SET)
    return store.create_user(username, TARGET_PARAM_SET, salt, verifier,
                             note="registered on target parameter set")


# ------------------------------------------------------------- password work
def upgrade_after_login(store, username, password, crash_after_replace=False):
    """Full path that requires the password.

    1. SRP login against the record as it currently exists (legacy SHA-1).
    2. Client derives brand-new SHA-256 salt+verifier from the password.
    3. Authenticated upgrade envelope is staged, then committed atomically.

    Any failure raises and leaves the old record fully usable.
    """
    before = store.get_record(username)
    service, session_id, client = full_login(
        store, username, password, before["param_set"])
    try:
        envelope, new_salt, new_verifier = client.build_upgrade_envelope(
            TARGET_PARAM_SET)
        service.begin_upgrade(session_id, envelope)
        after = service.commit_upgrade(
            session_id, crash_after_replace=crash_after_replace)
    except SimulatedCrash:
        # Deliberately leave journal + record exactly as the crash left them
        # so recovery logic can be demonstrated; no cleanup, no session close.
        raise
    except Exception:
        # Best-effort cleanup; never overwrite the still-usable old record.
        service.abort_upgrade(session_id, reason="upgrade flow failed")
        service.end_session(session_id)
        raise
    else:
        service.end_session(session_id)
    return before, after, new_salt, new_verifier


def attempt_login(store, username, password, param_set):
    """Standalone login attempt; raises AuthenticationFailed on bad password."""
    service, session_id, client = full_login(
        store, username, password, param_set)
    service.end_session(session_id)
    return True
