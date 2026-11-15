from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from dissect.database.ese.ntds.identity.model import ObjectIdentity

if TYPE_CHECKING:
    from collections.abc import Iterator


@runtime_checkable
class ObjectSource(Protocol):
    """Provider of identity records for a single snapshot.

    Implementations must never synthesize missing rows or upgrade phantom/deleted records into
    live ones. A missing parent is reported as absent so the path builder can diagnose it
    instead of inventing a placeholder object.
    """

    def get_identity(self, dnt: int) -> ObjectIdentity | None:
        """Return the identity stored at ``dnt``, or :class:`None` if no such row exists."""

    def identities(self) -> Iterator[ObjectIdentity]:
        """Yield every identity record in the snapshot, including deleted and phantom rows."""
