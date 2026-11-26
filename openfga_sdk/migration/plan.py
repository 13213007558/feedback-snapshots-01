"""
Migration plan describing the target relationship state of a role migration.

A plan is the single source of truth for what the final store must look like:

* ``approved`` relationships are the only ones the migration is allowed to
  ensure exist.
* ``revoked`` relationships must be removed and must never be re-created by
  the migration, even when retrying an uncertain batch.

The plan rejects any tuple that appears in both sets up front so that a later
reconciliation step can never implicitly revive a withdrawn relationship.
"""

from collections.abc import Mapping

from openfga_sdk.client.models.tuple import ClientTuple
from openfga_sdk.migration.tuple_key import to_client_tuple, tuple_identity


class MigrationPlanError(ValueError):
    """Raised when a migration plan is inconsistent or unsafe to execute."""


class MigrationPlan:
    """
    Immutable description of the relationships to add and remove.

    :param approved: Tuples that must exist once the migration completes.
    :param revoked: Tuples that must not exist once the migration completes.
    """

    def __init__(
        self,
        approved: list[ClientTuple | Mapping[str, str]] | None = None,
        revoked: list[ClientTuple | Mapping[str, str]] | None = None,
    ) -> None:
        approved_tuples = [to_client_tuple(item) for item in (approved or [])]
        revoked_tuples = [to_client_tuple(item) for item in (revoked or [])]

        self._approved = self._deduplicate(approved_tuples)
        self._revoked = self._deduplicate(revoked_tuples)

        self._approved_ids = {tuple_identity(item) for item in self._approved}
        self._revoked_ids = {tuple_identity(item) for item in self._revoked}

        overlap = self._approved_ids & self._revoked_ids
        if overlap:
            raise MigrationPlanError(
                "tuples cannot be both approved and revoked: "
                + ", ".join(sorted(overlap))
            )

    @staticmethod
    def _deduplicate(tuples: list[ClientTuple]) -> list[ClientTuple]:
        unique: dict[str, ClientTuple] = {}
        for item in tuples:
            unique.setdefault(tuple_identity(item), item)
        return list(unique.values())

    @property
    def approved(self) -> list[ClientTuple]:
        return list(self._approved)

    @property
    def revoked(self) -> list[ClientTuple]:
        return list(self._revoked)

    @property
    def approved_ids(self) -> set[str]:
        return set(self._approved_ids)

    @property
    def revoked_ids(self) -> set[str]:
        return set(self._revoked_ids)

    def is_approved(self, identity: str) -> bool:
        return identity in self._approved_ids

    def is_revoked(self, identity: str) -> bool:
        return identity in self._revoked_ids

    def assert_safe_to_write(self, tuples: list[ClientTuple]) -> None:
        """
        Guard that every tuple in a write batch is part of the approved set.

        This is the safety boundary preventing a retry from re-creating a
        relationship that was explicitly withdrawn.
        """
        offending = [
            tuple_identity(item)
            for item in tuples
            if tuple_identity(item) not in self._approved_ids
        ]
        if offending:
            raise MigrationPlanError(
                "refusing to write tuples outside the approved migration set: "
                + ", ".join(sorted(offending))
            )
