from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from dissect.database.ese.exception import KeyNotFoundError
from dissect.database.ese.ntds.identity.model import ObjectIdentity, ObjectState

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.database import Database
    from dissect.database.ese.ntds.objects import Object


class NTDSObjectSource:
    """Adapt a live :class:`~dissect.database.ese.ntds.database.Database` to ObjectSource.

    The adapter reads each row's logical attributes independently and never fills in missing
    information: a row that cannot be resolved stays missing, and phantom/deleted records keep
    their state instead of being presented as normal live objects.

    Args:
        database: The NTDS database whose ``datatable`` should be exposed.
    """

    def __init__(self, database: Database):
        self.database = database

    @staticmethod
    def _state(obj: Object) -> ObjectState:
        state = ObjectState.LIVE
        if obj.is_deleted:
            state |= ObjectState.DELETED
        if obj.is_phantom:
            state |= ObjectState.PHANTOM
        return state

    def get_identity(self, dnt: int) -> ObjectIdentity | None:
        try:
            obj = self.database.data.get(dnt)
        except KeyNotFoundError:
            return None
        return self.from_object(obj)

    def identities(self) -> Iterator[ObjectIdentity]:
        for obj in self.database.data.iter():
            yield self.from_object(obj)

    def from_object(self, obj: Object) -> ObjectIdentity:
        """Convert an NTDS :class:`Object` to an :class:`ObjectIdentity`.

        RDN values beyond the primary ``name`` are not stored as separate rows in the
        datatable; the multi-valued path is therefore represented through the generic builder
        and remains available for fixture-based sources.
        """
        guid = obj.guid
        if isinstance(guid, str):
            guid = UUID(guid)

        return ObjectIdentity(
            dnt=obj.dnt,
            pdnt=obj.pdnt,
            guid=guid,
            name=obj.name,
            rdn_type=obj.get("RdnType"),
            state=self._state(obj),
            ncdnt=obj.ncdnt,
            raw=obj.record,
        )
