"""Approved backend (provider) renames with evidence-safe binding migration.

A backend rename changes the ``provider`` string stored on each
``UserSocialAuth`` association while leaving the provider-scoped account
identifier (``uid``/``id_key``) untouched. Ownership of an account is therefore
still established by the stable provider identifier, never by an email address,
username, or display name.

The application supplies an explicit, approved mapping of old to new backend
names through the ``BACKENDS_RENAME`` setting. The mapping is the only
authorization a rename consults: an association is moved solely from its
approved old provider to its approved new provider, and every ambiguous or
conflicting case is reported with a verifiable status instead of being merged
silently.

The migration is idempotent and per-row atomic, so an interrupted run leaves the
storage in a consistent state and a retry finishes the remaining rows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .exceptions import AuthAssociationError, AuthConfigurationError

if TYPE_CHECKING:
    from .backends.base import BaseAuth
    from .storage import UserMixin

#: Migration completed and the association is now stored under the new name.
RENAMED = "renamed"
#: The association already carried the new provider name; nothing to change.
ALREADY_RENAMED = "already_renamed"
#: A different association already owns the target (new provider, uid) slot.
TARGET_CONFLICT = "target_conflict"

#: Local account collision evidence recorded alongside a successful move.
USERNAME_IN_USE = "username_in_use"
EMAIL_IN_USE = "email_in_use"

# Statuses that mean the association was not moved and a retry is meaningful.
PENDING_STATUSES = frozenset({TARGET_CONFLICT})

_SETTING_NAME = "BACKENDS_RENAME"


@dataclass(frozen=True)
class BackendRename:
    """One approved old-to-new backend name transition."""

    old_name: str
    new_name: str


@dataclass
class RenameStatus:
    """Verifiable outcome for a single association during a rename."""

    social: UserMixin
    status: str
    provider: str
    uid: str
    id_key: str
    conflicts: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def migrated(self) -> bool:
        return self.status in (RENAMED, ALREADY_RENAMED)

    @property
    def pending(self) -> bool:
        return self.status in PENDING_STATUSES


@dataclass
class RenameReport:
    """Aggregate, evidence-based result of migrating one provider rename."""

    rename: BackendRename
    statuses: list[RenameStatus] = field(default_factory=list)

    @property
    def migrated(self) -> list[RenameStatus]:
        return [status for status in self.statuses if status.migrated]

    @property
    def pending(self) -> list[RenameStatus]:
        return [status for status in self.statuses if status.pending]

    @property
    def complete(self) -> bool:
        return not self.pending

    @property
    def evidence(self) -> list[RenameStatus]:
        """Moved rows that also share a username or email with another account."""
        return [status for status in self.migrated if status.evidence]


def approved_backend_renames(backend: BaseAuth[object]) -> dict[str, str]:
    """Return the validated, application-approved old-to-new backend mapping.

    The setting must be a mapping of non-empty, distinct old and new provider
    names. Self renames, non-string entries, and chains (a name that is both a
    source and a target) are rejected as configuration errors so an approval
    can never be applied ambiguously.
    """
    raw = backend.setting(_SETTING_NAME, {})
    if not raw:
        return {}
    if not isinstance(raw, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in raw.items()
    ):
        raise AuthConfigurationError(
            backend,
            code="invalid_setting",
            parameter=_SETTING_NAME,
            stage="pipeline",
        )
    mapping = {str(key): str(value) for key, value in raw.items()}
    if any(not old or not new for old, new in mapping.items()):
        raise AuthConfigurationError(
            backend,
            code="invalid_setting",
            parameter=_SETTING_NAME,
            stage="pipeline",
        )
    if any(old == new for old, new in mapping.items()) or set(mapping) & set(
        mapping.values()
    ):
        raise AuthConfigurationError(
            backend,
            "Backend rename mappings must not rename a name to itself or chain names",
            code="invalid_setting",
            parameter=_SETTING_NAME,
            stage="pipeline",
        )
    return mapping


def resolve_backend_name(backend: BaseAuth[object], name: str) -> str:
    """Resolve a possibly-renamed provider name to its current published name."""
    return approved_backend_renames(backend).get(name, name)


def legacy_provider_names(backend: BaseAuth[object]) -> tuple[str, ...]:
    """Return the approved old names that may still hold migrated associations."""
    return tuple(approved_backend_renames(backend))


def get_renamed_social_auth(
    backend: BaseAuth[object], storage: Any, uid: str, id_key: str | None = None
):
    """Find an association by the current name, then any approved old name.

    Lookups stay provider scoped: the stable ``uid``/``id_key`` must match under
    one exact provider name. An approval only adds the binding's own old name as
    a fallback, so a mapping for a different provider can never redirect the
    search onto an unrelated account.
    """
    current = backend.name
    social = storage.user.get_social_auth(current, uid, id_key=id_key)
    if social is not None:
        return social
    mapping = approved_backend_renames(backend)
    for old_name, new_name in mapping.items():
        if new_name != current:
            continue
        social = storage.user.get_social_auth(old_name, uid, id_key=id_key)
        if social is not None:
            return social
    return None


def pending_rename_providers(
    backend: BaseAuth[object], storage: Any
) -> dict[str, int]:
    """Report approved old providers that still store unmigrated associations.

    The mapping gives an evidence-based answer to "is the storage migration
    finished?": each old name maps to the number of rows still carrying it. An
    empty result means no approved binding remains on a legacy provider name.
    """
    pending: dict[str, int] = {}
    for old_name in approved_backend_renames(backend):
        remaining = storage.user.get_social_auth_for_provider(old_name)
        if remaining:
            pending[old_name] = len(remaining)
    return pending


def _local_identity_evidence(storage: Any, social: UserMixin) -> dict[str, Any]:
    """Collect same-username and same-email local account evidence.

    These mutable claims never decide the migration or merge accounts; they are
    surfaced only so an operator can verify whether the renamed provider's owner
    also collides with an existing local account. Email matching is reported
    rather than trusted as proof of ownership.
    """
    evidence: dict[str, Any] = {}
    owner = social.user
    username = storage.user.get_username(owner)
    if username and storage.user.user_exists(username):
        same_name = storage.user.user_model().get(username)
        if same_name is not None and same_name != owner:
            evidence["username"] = username
            evidence["username_user_id"] = same_name.id
    email = getattr(owner, "email", None)
    if email:
        matches = [
            account
            for account in storage.user.get_users_by_email(email)
            if account != owner
        ]
        if matches:
            evidence["email"] = email
            evidence["matching_user_ids"] = sorted(account.id for account in matches)
    return evidence


def _migrate_one(
    backend: BaseAuth[object], storage: Any, social: UserMixin, new_provider: str
) -> RenameStatus:
    if social.provider == new_provider:
        return RenameStatus(
            social,
            ALREADY_RENAMED,
            social.provider,
            social.uid,
            social.id_key,
        )

    # A pre-existing association on the target provider owns that identifier
    # slot. The provenance differs, so the rows must never be merged.
    occupant = storage.user.get_social_auth(
        new_provider, social.uid, id_key=social.id_key
    )
    if occupant is None:
        # Also detect an unkeyed/keyed row occupying the same uid regardless of
        # id_key, mirroring how lookups resolve the identifier at login time.
        occupant = storage.user.get_social_auth(new_provider, social.uid)
    if occupant is not None and occupant is not social:
        return RenameStatus(
            social,
            TARGET_CONFLICT,
            social.provider,
            social.uid,
            social.id_key,
            conflicts={
                "existing_provider": occupant.provider,
                "existing_user_id": occupant.user.id,
            },
        )

    evidence = _local_identity_evidence(storage, social)
    try:
        storage.user.rename_social_auth_provider(social, new_provider)
    except Exception as err:
        if not isinstance(err, ValueError) and not storage.is_integrity_error(err):
            raise
        raise AuthAssociationError(
            backend,
            "Backend rename could not move the stored association",
            code="identifier_migration_conflict",
            stage="pipeline",
        ) from err
    return RenameStatus(
        social,
        RENAMED,
        social.provider,
        social.uid,
        social.id_key,
        evidence=evidence,
    )


def migrate_backend_renames(
    backend: BaseAuth[object],
    storage: Any,
    old_name: str,
    new_name: str,
) -> RenameReport:
    """Move every association of an approved old backend to its new name.

    Only rows stored under exactly the approved ``old_name`` are considered, and
    each is moved only to the approved ``new_name``. The call is safe to re-run:
    already-migrated rows are reported as such and rows that still conflict are
    left untouched so the underlying accounts remain recoverable.
    """
    mapping = approved_backend_renames(backend)
    if mapping.get(old_name) != new_name:
        detail = (
            f"Rename {old_name!r} -> {new_name!r} is not in the approved mapping"
        )
        raise AuthConfigurationError(
            backend,
            detail,
            code="invalid_setting",
            parameter=_SETTING_NAME,
            stage="pipeline",
        )

    report = RenameReport(BackendRename(old_name, new_name))
    for social in storage.user.get_social_auth_for_provider(old_name):
        report.statuses.append(_migrate_one(backend, storage, social, new_name))
    return report
