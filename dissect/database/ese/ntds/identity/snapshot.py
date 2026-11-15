from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.ese.ntds.identity.builder import DisplayPathBuilder
from dissect.database.ese.ntds.identity.model import DisplayPath, ObjectIdentity, identity_from_mapping

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Mapping
    from typing import Any


class InMemoryObjectSource:
    """An :class:`ObjectSource` backed by a simple DNT-keyed dictionary.

    This keeps the identity/path logic testable without a full ESE database and makes the
    small offline snapshots used for comparisons explicit data structures rather than
    reconstructed live objects.

    Args:
        identities: The identity records belonging to the snapshot.
    """

    def __init__(self, identities: Iterable[ObjectIdentity]):
        self._by_dnt: dict[int, ObjectIdentity] = {}
        for identity in identities:
            if identity.dnt in self._by_dnt:
                raise ValueError(f"Duplicate DNT in snapshot: {identity.dnt}")
            self._by_dnt[identity.dnt] = identity

    @classmethod
    def from_mappings(cls, records: Iterable[Mapping[str, Any]]) -> InMemoryObjectSource:
        """Build a source from plain mapping fixtures using :func:`identity_from_mapping`."""
        return cls(identity_from_mapping(record) for record in records)

    def get_identity(self, dnt: int) -> ObjectIdentity | None:
        return self._by_dnt.get(dnt)

    def identities(self) -> Iterator[ObjectIdentity]:
        yield from self._by_dnt.values()


class Snapshot:
    """A single point-in-time view over an object source with path construction support.

    A snapshot never mutates or "repairs" its records. Deleted and phantom identities are
    stored and retrievable exactly like live ones, but their :class:`ObjectState` makes their
    nature explicit to every caller.

    Args:
        source: The identity provider backing the snapshot.
        label: A human-readable label used in comparison reports.
        strict_paths: Whether path construction should raise on incomplete chains.
    """

    def __init__(self, source: Any, *, label: str, strict_paths: bool = False):
        self.source = source
        self.label = label
        self._builder = DisplayPathBuilder(source, strict=strict_paths)

    @classmethod
    def from_mappings(
        cls,
        records: Iterable[Mapping[str, Any]],
        *,
        label: str,
        strict_paths: bool = False,
    ) -> Snapshot:
        """Create a snapshot directly from plain mapping fixtures."""
        return cls(InMemoryObjectSource.from_mappings(records), label=label, strict_paths=strict_paths)

    def get(self, dnt: int) -> ObjectIdentity | None:
        """Return the identity at ``dnt`` without any state-based filtering."""
        return self.source.get_identity(dnt)

    def path(self, dnt: int) -> DisplayPath:
        """Build the display path for ``dnt`` (partial path plus diagnostics if incomplete)."""
        return self._builder.build(dnt)

    def identities(self) -> Iterator[ObjectIdentity]:
        """Yield all records in the snapshot, deleted and phantom included."""
        yield from self.source.identities()

    def by_guid(self) -> dict[Any, list[ObjectIdentity]]:
        """Index records by GUID, keeping every record even if a GUID repeats."""
        result: dict[Any, list[ObjectIdentity]] = {}
        for identity in self.source.identities():
            if identity.guid is not None:
                result.setdefault(identity.guid, []).append(identity)
        return result
