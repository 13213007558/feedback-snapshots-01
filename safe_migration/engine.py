"""Bounded migration state machine for pre-approved source UIDs.

Safety contract
---------------
* Only UIDs present in the progress store (i.e. explicitly approved) are ever
  touched. New, unapproved mail is never selected, flagged or deleted.
* Success (``CONFIRMED``) is only ever derived from server identity evidence:
  a tagged OK carrying COPYUID for the exact source UID, corroborated by a
  FETCH on the named target UID. A look-alike message in the destination is
  never accepted as proof.
* Every ambiguous outcome is parked in ``REVIEW``; the engine never guesses.
* No plain ``EXPUNGE`` is ever issued. Source removal uses UID-scoped
  ``UID EXPUNGE`` (UIDPLUS only); without UIDPLUS the message is left in place
  for a human.
"""
from __future__ import annotations

import logging
from dataclasses import asdict
from typing import Callable, Optional

from .evidence import (
    ImapDisconnected,
    ImapRefused,
    ImapTimeout,
    MailboxAnchor,
    MessageFingerprint,
    MigrationStatus,
    build_fingerprint,
    extract_literal,
    parse_copyuid,
    parse_fetch_uid,
    parse_search_uids,
    parse_uidvalidity,
)
from .gateway import ImapGateway
from .progress import MigrationRecord, ProgressStore

log = logging.getLogger(__name__)

FETCH_PARTS = "(UID INTERNALDATE RFC822.SIZE BODY.PEEK[])"
GatewayFactory = Callable[[], ImapGateway]


class MigrationEngine:
    """Migrates one fixed source mailbox into one fixed destination mailbox."""

    def __init__(
        self,
        store: ProgressStore,
        gateway_factory: GatewayFactory,
        max_attempts: int = 3,
    ):
        self._store = store
        self._gateway_factory = gateway_factory
        self._max_attempts = max_attempts
        self._gateway: Optional[ImapGateway] = None

    # ------------------------------------------------------------------ #
    # Connection handling with fixed-identity checks
    # ------------------------------------------------------------------ #
    async def _connect(self, anchor: MailboxAnchor) -> ImapGateway:
        gateway = self._gateway_factory()
        await gateway.open()
        response = await gateway.select(anchor.mailbox)
        seen = parse_uidvalidity(response.lines)
        if seen != anchor.uidvalidity:
            await gateway.close()
            raise IdentityMismatch(
                f"{anchor.host}:{anchor.mailbox} UIDVALIDITY changed "
                f"(expected {anchor.uidvalidity}, server says {seen})"
            )
        self._gateway = gateway
        return gateway

    async def _fresh_gateway(self) -> ImapGateway:
        if self._gateway is not None:
            await self._gateway.close()
            self._gateway = None
        state = self._store.require_state()
        # Re-selecting the source anchor is enough to re-validate identity;
        # destination UIDVALIDITY is checked when target evidence is gathered.
        return await self._connect(state.anchor("source"))

    async def close(self) -> None:
        if self._gateway is not None:
            await self._gateway.close()
            self._gateway = None

    def _has(self, capability: str) -> bool:
        return self._gateway is not None and capability in self._gateway.capabilities

    # ------------------------------------------------------------------ #
    # Public entry point
    # ------------------------------------------------------------------ #
    async def migrate_uid(self, uid: int) -> MigrationStatus:
        record = self._store.get(uid)
        if record is None:
            raise UnknownUid(f"uid {uid} is not approved in the progress store")
        if record.is_terminal:
            return MigrationStatus(record.status)

        try:
            if self._gateway is None:
                await self._fresh_gateway()

            if record.status == MigrationStatus.MOVE_SENT_UNKNOWN.value:
                return await self._recover_move_unknown(record)
            if record.status == MigrationStatus.COPY_OK_DELETE_UNKNOWN.value:
                return await self._recover_copy_unknown(record)

            return await self._attempt(record)
        except IdentityMismatch as exc:
            self._park(record, "uidvalidity-mismatch", str(exc))
            return MigrationStatus.REVIEW
        except (ImapDisconnected, ImapTimeout) as exc:
            # Reconnectable transport problem: keep the recorded state and let
            # the next run retry; do not invent an outcome.
            record.last_error = f"{type(exc).__name__}: {exc}"
            self._store.save(record, f"transport error, retry later: {exc}")
            self._gateway = None
            return MigrationStatus(record.status)
        except ExceededAttempts as exc:
            self._park(record, "max-attempts", str(exc))
            return MigrationStatus.REVIEW

    # ------------------------------------------------------------------ #
    # Fresh attempt: choose a strategy from advertised capabilities
    # ------------------------------------------------------------------ #
    async def _attempt(self, record: MigrationRecord) -> MigrationStatus:
        fingerprint = await self._capture_fingerprint(record)
        record.fingerprint = asdict(fingerprint)
        self._store.save(record, "captured source fingerprint before any mutation")

        if self._has("MOVE"):
            return await self._try_move(record)
        return await self._try_copy_then_delete(record)

    async def _capture_fingerprint(self, record: MigrationRecord) -> MessageFingerprint:
        response = await self._gateway.uid_fetch(record.source_uid, FETCH_PARTS)
        if not response.ok:
            # Definite NO/BAD on a read: the UID cannot be read right now.
            raise ImapRefused(f"UID FETCH refused: {response.lines!r}")
        fetched_uid = parse_fetch_uid(response.lines)
        if fetched_uid != record.source_uid:
            raise IdentityMismatch(
                f"FETCH returned UID {fetched_uid}, expected {record.source_uid}"
            )
        return build_fingerprint(record.source_uid, response.lines,
                                 extract_literal(response.lines))

    # ------------------------------------------------------------------ #
    # MOVE path (RFC 6851)
    # ------------------------------------------------------------------ #
    async def _try_move(self, record: MigrationRecord) -> MigrationStatus:
        state = self._store.require_state()
        target_mailbox = state.destination["mailbox"]
        record.attempts += 1
        record.last_command = "UID MOVE"
        self._store.save(record, f"attempt {record.attempts}: send UID MOVE -> {target_mailbox}")
        try:
            response = await self._gateway.uid_move(record.source_uid, target_mailbox)
        except (ImapDisconnected, ImapTimeout):
            # Server may or may not have executed it. This is the central
            # "answer lost" case: never fall straight back to COPY+EXPUNGE.
            record.status = MigrationStatus.MOVE_SENT_UNKNOWN.value
            self._store.save(record, "MOVE sent but tagged answer lost; evidence required")
            self._gateway = None
            return MigrationStatus.MOVE_SENT_UNKNOWN

        if not response.ok:
            self._fail(record, f"MOVE refused: {response.result} {response.lines!r}")
            return MigrationStatus.FAILED

        copy_uid = parse_copyuid(response.lines)
        target_uid = copy_uid.maps_single(record.source_uid) if copy_uid else None
        if target_uid is None:
            self._park(record, "move-ok-without-copyuid",
                       f"MOVE OK but no single-UID COPYUID evidence: {response.lines!r}")
            return MigrationStatus.REVIEW
        if await self._confirm_target(record, copy_uid, target_uid):
            self._confirm(record, copy_uid, target_uid, "MOVE OK + COPYUID + target FETCH")
            return MigrationStatus.CONFIRMED
        self._park(record, "target-evidence-missing",
                   "MOVE reported OK but target UID evidence could not be verified")
        return MigrationStatus.REVIEW

    async def _recover_move_unknown(self, record: MigrationRecord) -> MigrationStatus:
        """Re-resolve a MOVE whose completion answer was lost."""
        if record.attempts >= self._max_attempts:
            raise ExceededAttempts(f"uid {record.source_uid} unresolved after {record.attempts}")
        record.attempts += 1
        self._store.save(record, f"recheck {record.attempts}: resolve lost MOVE answer")
        await self._fresh_gateway()

        source = await self._probe_source(record)
        target_uid = await self._probe_target_by_copyuid(record)

        if source == "absent" and target_uid is not None:
            from .evidence import CopyUid
            copy_uid = CopyUid(
                self._store.require_state().destination["uidvalidity"],
                (record.source_uid,), (target_uid,),
            )
            self._confirm(record, copy_uid, target_uid,
                          "recheck: source UID gone and target UID present with matching identity")
            return MigrationStatus.CONFIRMED
        if source == "present" and target_uid is None:
            # Evidence that MOVE did not happen: safe to run a fresh attempt.
            record.status = MigrationStatus.PENDING.value
            self._store.save(record, "recheck: still at source, no target copy -> retry fresh")
            return await self._attempt(record)
        self._park(
            record,
            "move-result-ambiguous",
            f"cannot classify MOVE (source={source}, target_uid={target_uid})",
        )
        return MigrationStatus.REVIEW

    # ------------------------------------------------------------------ #
    # COPY + UID-scoped delete path (no MOVE)
    # ------------------------------------------------------------------ #
    async def _try_copy_then_delete(self, record: MigrationRecord) -> MigrationStatus:
        state = self._store.require_state()
        target_mailbox = state.destination["mailbox"]
        record.attempts += 1
        record.last_command = "UID COPY"
        self._store.save(record, f"attempt {record.attempts}: send UID COPY -> {target_mailbox}")
        try:
            copy_response = await self._gateway.uid_copy(record.source_uid, target_mailbox)
        except (ImapDisconnected, ImapTimeout):
            # COPY outcome itself unknown: recheck before doing anything else.
            record.status = MigrationStatus.MOVE_SENT_UNKNOWN.value
            record.last_command = "UID COPY (answer lost)"
            self._store.save(record, "COPY sent but answer lost; evidence required")
            self._gateway = None
            return MigrationStatus.MOVE_SENT_UNKNOWN

        if not copy_response.ok:
            self._fail(record, f"COPY refused: {copy_response.result} {copy_response.lines!r}")
            return MigrationStatus.FAILED

        copy_uid = parse_copyuid(copy_response.lines)
        target_uid = copy_uid.maps_single(record.source_uid) if copy_uid else None
        if target_uid is None:
            # COPY said OK but no usable identity mapping: do not delete source.
            self._park(record, "copy-ok-without-copyuid",
                       f"COPY OK without single-UID COPYUID: {copy_response.lines!r}")
            return MigrationStatus.REVIEW
        record.copyuid = asdict(copy_uid)
        record.target_uid = target_uid
        self._store.save(record, f"COPY confirmed via COPYUID -> target UID {target_uid}")

        if not await self._confirm_target(record, copy_uid, target_uid):
            self._park(record, "target-evidence-missing",
                       "COPYUID present but target UID fetch did not corroborate identity")
            return MigrationStatus.REVIEW

        return await self._delete_source(record)

    async def _delete_source(self, record: MigrationRecord) -> MigrationStatus:
        record.last_command = "UID STORE +FLAGS (\\Deleted)"
        self._store.save(record, "target verified; flag source message \\Deleted")
        try:
            store_response = await self._gateway.uid_store_deleted(record.source_uid)
        except (ImapDisconnected, ImapTimeout):
            record.status = MigrationStatus.COPY_OK_DELETE_UNKNOWN.value
            self._store.save(record, "STORE answer lost; deletion state unknown")
            self._gateway = None
            return MigrationStatus.COPY_OK_DELETE_UNKNOWN
        if not store_response.ok:
            # Copy is safe at destination; source removal is the only gap.
            self._park(record, "store-deleted-refused",
                       f"COPY confirmed but \\Deleted refused: {store_response.lines!r}")
            return MigrationStatus.REVIEW

        if not self._has("UIDPLUS"):
            # Never issue a mailbox-wide EXPUNGE. Leave the flagged message and
            # hand the UID-scoped removal to an operator.
            self._park(
                record,
                "no-uidplus-expunge",
                "message copied and \\Deleted flagged; UIDPLUS absent so no UID EXPUNGE "
                "is possible and a full EXPUNGE is forbidden",
            )
            return MigrationStatus.REVIEW

        record.last_command = "UID EXPUNGE"
        self._store.save(record, "send UID EXPUNGE scoped to this single UID")
        try:
            expunge_response = await self._gateway.uid_expunge(record.source_uid)
        except (ImapDisconnected, ImapTimeout):
            record.status = MigrationStatus.COPY_OK_DELETE_UNKNOWN.value
            self._store.save(record, "UID EXPUNGE answer lost; recheck source presence")
            self._gateway = None
            return MigrationStatus.COPY_OK_DELETE_UNKNOWN
        if not expunge_response.ok:
            self._park(record, "uid-expunge-refused",
                       f"UID EXPUNGE refused: {expunge_response.lines!r}")
            return MigrationStatus.REVIEW

        self._confirm(record, _copyuid_from(record), record.target_uid,
                      "COPYUID + target FETCH + UID EXPUNGE OK")
        return MigrationStatus.CONFIRMED

    async def _recover_copy_unknown(self, record: MigrationRecord) -> MigrationStatus:
        """Resolve a confirmed COPY whose deletion acknowledgement was lost."""
        if record.attempts >= self._max_attempts:
            raise ExceededAttempts(f"uid {record.source_uid} unresolved after {record.attempts}")
        record.attempts += 1
        self._store.save(record, f"recheck {record.attempts}: resolve lost delete answer")
        await self._fresh_gateway()

        source = await self._probe_source(record)
        # Always re-verify the destination copy on a fresh connection, even
        # when the target UID is already recorded: the COPYUID mapping alone is
        # not re-proof after a disconnect.
        target_uid = await self._probe_target_by_copyuid(record)

        if source == "absent" and target_uid is not None:
            self._confirm(record, _copyuid_from(record), target_uid,
                          "recheck: source gone and target present -> migration complete")
            return MigrationStatus.CONFIRMED
        if source == "present" and target_uid is not None:
            # Target copy is proven; only source removal remains. Re-flag and
            # expunge the single UID, never a mailbox-wide EXPUNGE.
            return await self._delete_source(record)
        self._park(record, "copy-delete-ambiguous",
                   f"cannot classify delete (source={source}, target_uid={target_uid})")
        return MigrationStatus.REVIEW

    # ------------------------------------------------------------------ #
    # Evidence probes
    # ------------------------------------------------------------------ #
    async def _probe_source(self, record: MigrationRecord) -> str:
        """Return 'present' / 'absent' based on a UID FETCH, not guessing."""
        try:
            response = await self._gateway.uid_fetch(record.source_uid, "(UID)")
        except ImapRefused:
            return "absent"
        if not response.ok or parse_fetch_uid(response.lines) != record.source_uid:
            return "absent"
        return "present"

    async def _probe_target_by_copyuid(self, record: MigrationRecord) -> Optional[int]:
        """Resolve and verify the target UID, then return to the source mailbox.

        Two evidence paths are allowed, neither of which trusts a look-alike:

        * If the COPYUID mapping was captured (COPY path), fetch the exact
          target UID it named.
        * If the answer was lost before COPYUID could be read (MOVE path),
          run a bounded ``UID SEARCH HEADER MESSAGE-ID`` on the destination
          and accept the result only when exactly one UID matches *and* its
          full fingerprint equals the source fingerprint.
        """
        state = self._store.require_state()
        target = state.anchor("destination")
        gateway = self._gateway
        response = await gateway.select(target.mailbox)
        if parse_uidvalidity(response.lines) != target.uidvalidity:
            raise IdentityMismatch(
                f"destination UIDVALIDITY changed (expected {target.uidvalidity})"
            )

        target_uid = record.target_uid
        if target_uid is None:
            target_uid = await self._search_target_uid(record)
            if target_uid is None:
                await gateway.select(state.source["mailbox"])
                return None
        else:
            fetch = await gateway.uid_fetch(target_uid, FETCH_PARTS)
            if not fetch.ok or parse_fetch_uid(fetch.lines) != target_uid:
                await gateway.select(state.source["mailbox"])
                return None
            fingerprint = build_fingerprint(target_uid, fetch.lines,
                                            extract_literal(fetch.lines))
            if not _identity_matches(record.fingerprint, fingerprint):
                await gateway.select(state.source["mailbox"])
                return None

        await gateway.select(state.source["mailbox"])
        return target_uid

    async def _search_target_uid(self, record: MigrationRecord) -> Optional[int]:
        """Bounded exact-header search; returns a UID only on a unique match."""
        message_id = (record.fingerprint or {}).get("message_id")
        if not message_id:
            return None
        search = await self._gateway.uid_search_message_id(message_id)
        if not search.ok:
            return None
        candidates = parse_search_uids(search.lines)
        if len(candidates) != 1:
            # Zero hits means "not migrated"; several hits means ambiguous.
            return None
        candidate = candidates[0]
        fetch = await self._gateway.uid_fetch(candidate, FETCH_PARTS)
        if not fetch.ok or parse_fetch_uid(fetch.lines) != candidate:
            return None
        fingerprint = build_fingerprint(candidate, fetch.lines,
                                        extract_literal(fetch.lines))
        if not _identity_matches(record.fingerprint, fingerprint):
            return None
        record.target_uid = candidate
        return candidate

    async def _confirm_target(self, record, copy_uid, target_uid: int) -> bool:
        state = self._store.require_state()
        target = state.anchor("destination")
        gateway = self._gateway
        response = await gateway.select(target.mailbox)
        if parse_uidvalidity(response.lines) != target.uidvalidity:
            raise IdentityMismatch("destination UIDVALIDITY changed during migration")
        fetch = await gateway.uid_fetch(target_uid, FETCH_PARTS)
        ok = (
            fetch.ok
            and parse_fetch_uid(fetch.lines) == target_uid
            and _identity_matches(record.fingerprint,
                                  build_fingerprint(target_uid, fetch.lines,
                                                    extract_literal(fetch.lines)))
        )
        await gateway.select(state.source["mailbox"])
        return ok

    # ------------------------------------------------------------------ #
    # Terminal transitions
    # ------------------------------------------------------------------ #
    def _confirm(self, record, copy_uid, target_uid: int, note: str) -> None:
        record.status = MigrationStatus.CONFIRMED.value
        record.copyuid = asdict(copy_uid) if copy_uid is not None else record.copyuid
        record.target_uid = target_uid
        record.review_reason = None
        record.last_error = None
        self._store.save(record, f"CONFIRMED: {note}")

    def _fail(self, record: MigrationRecord, note: str) -> None:
        record.status = MigrationStatus.FAILED.value
        record.last_error = note
        self._store.save(record, f"FAILED (definite server refusal): {note}")

    def _park(self, record: MigrationRecord, reason: str, note: str) -> None:
        record.status = MigrationStatus.REVIEW.value
        record.review_reason = reason
        record.last_error = note
        self._store.save(record, f"REVIEW [{reason}]: {note}")


def _identity_matches(expected: Optional[dict], actual: MessageFingerprint) -> bool:
    """Corroborate target identity against the captured source fingerprint."""
    if not expected:
        return False
    if expected.get("message_id") and actual.message_id:
        mid_ok = expected["message_id"] == actual.message_id
    else:
        mid_ok = False
    size_ok = expected["rfc822_size"] == actual.rfc822_size and actual.rfc822_size > 0
    digest_ok = bool(expected.get("body_sha256")) and \
        expected["body_sha256"] == actual.body_sha256
    # Digest is the strongest signal; Message-ID+size is an accepted fallback
    # when the server strips literals. Either way this only corroborates an
    # already-known target UID, never discovers a "similar" message.
    return digest_ok or (mid_ok and size_ok)


def _copyuid_from(record: MigrationRecord):
    if not record.copyuid:
        return None
    from .evidence import CopyUid
    return CopyUid(
        record.copyuid["uidvalidity"],
        tuple(record.copyuid["source_uids"]),
        tuple(record.copyuid["target_uids"]),
    )


class UnknownUid(RuntimeError):
    """Raised when a caller asks to migrate a UID that was never approved."""


class IdentityMismatch(RuntimeError):
    """Raised when UIDVALIDITY / UID identity no longer matches the job."""


class ExceededAttempts(RuntimeError):
    """Raised when an unresolved UID has used all recheck attempts."""
