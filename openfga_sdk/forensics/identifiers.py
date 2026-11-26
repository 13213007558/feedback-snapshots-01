"""
Stable public identifiers used inside shareable authorization forensics
reports.

A report may be forwarded outside the organization, so internal account ids
must never appear in it. At the same time, the same real subject can show up
at several positions in an Expand tree, and two different subjects may share a
display name. Display names are therefore never used to merge subjects.

Merging is always performed on the full OpenFGA object reference
(``"<type>:<id>"``). Every distinct reference receives one stable public id
that is reused everywhere that reference occurs within a report. The id is
derived deterministically, so two exports of the same data produce the same
public ids even when the server returns tree children in a different order.
"""

import hashlib


DEFAULT_PUBLIC_ID_PREFIX = "subj"
PUBLIC_ID_LENGTH = 10


def _normalize_object_ref(object_ref: str) -> str:
    if not isinstance(object_ref, str) or ":" not in object_ref:
        raise ValueError(
            f"Expected an OpenFGA object reference of the form '<type>:<id>', "
            f"got: {object_ref!r}"
        )
    return object_ref.strip()


def public_identifier(
    object_ref: str,
    *,
    salt: str = "",
    prefix: str = DEFAULT_PUBLIC_ID_PREFIX,
) -> str:
    """
    Return the stable public id for an OpenFGA object reference.

    The same reference + salt always maps to the same id while the raw id is
    never recoverable from the output. The salt optionally scopes a report so
    identifiers cannot be joined across unrelated reports.
    """
    normalized = _normalize_object_ref(object_ref)
    digest = hashlib.sha256(f"{salt}\x1f{normalized}".encode()).hexdigest()
    return f"{prefix}_{digest[:PUBLIC_ID_LENGTH]}"


def object_type(object_ref: str) -> str:
    """Return the type portion of an OpenFGA object reference."""
    return _normalize_object_ref(object_ref).split(":", 1)[0]


def evidence_identifier(tuple_key: dict, *, salt: str = "") -> str:
    """
    Return a deterministic id for a stored relationship tuple.

    Tuples have no wire-level primary key, so the id is derived from the full
    (user, relation, object) triple, which uniquely identifies a tuple.
    """
    canonical = "\x1f".join(
        str(tuple_key.get(field, "") or "") for field in ("user", "relation", "object")
    )
    digest = hashlib.sha256(f"{salt}\x1f{canonical}".encode()).hexdigest()
    return f"ev_{digest[:PUBLIC_ID_LENGTH]}"


class SubjectRegistry:
    """
    Tracks the mapping between real OpenFGA object references and public ids
    for a single report.

    Only public data is exposed through :meth:`public_records`. The raw
    mapping is retained on the instance for internal re-identification only
    and is never serialized into a shareable report.
    """

    def __init__(
        self,
        *,
        salt: str = "",
        prefix: str = DEFAULT_PUBLIC_ID_PREFIX,
        display_name_resolver=None,
    ) -> None:
        self.salt = salt
        self.prefix = prefix
        self.display_name_resolver = display_name_resolver
        self._public_id_by_ref: dict[str, str] = {}
        self._display_names: dict[str, list[str]] = {}

    def public_id(self, object_ref: str) -> str:
        normalized = _normalize_object_ref(object_ref)
        existing = self._public_id_by_ref.get(normalized)
        if existing is not None:
            return existing

        public_id = public_identifier(normalized, salt=self.salt, prefix=self.prefix)
        self._public_id_by_ref[normalized] = public_id
        if self.display_name_resolver is not None:
            display_name = self.display_name_resolver(normalized)
            if display_name:
                self._display_names.setdefault(normalized, [display_name])
        return public_id

    def record_display_name(self, object_ref: str, display_name: str) -> None:
        """
        Record a display name observed for a reference. Multiple names for the
        same reference are kept rather than overwritten.
        """
        if not display_name:
            return
        normalized = _normalize_object_ref(object_ref)
        names = self._display_names.setdefault(normalized, [])
        if display_name not in names:
            names.append(display_name)

    def display_name_collisions(self) -> list[dict]:
        """
        Return display names shared by two or more distinct object references.

        Collisions are surfaced as warnings in the report so consumers do not
        infer that equal display names denote the same subject.
        """
        refs_by_name: dict[str, set[str]] = {}
        for object_ref, names in self._display_names.items():
            for name in names:
                refs_by_name.setdefault(name, set()).add(object_ref)

        collisions = []
        for name, refs in sorted(refs_by_name.items()):
            if len(refs) > 1:
                collisions.append(
                    {
                        "display_name": name,
                        "public_subject_ids": sorted(
                            self._public_id_by_ref[ref] for ref in refs
                        ),
                    }
                )
        return collisions

    def public_records(self) -> list[dict]:
        """Build the shareable subject directory, ordered by public id."""
        records = []
        for object_ref, public_id in sorted(
            self._public_id_by_ref.items(), key=lambda item: item[1]
        ):
            record = {
                "public_subject_id": public_id,
                "object_type": object_type(object_ref),
                "display_names": sorted(self._display_names.get(object_ref, [])),
            }
            records.append(record)
        return records

    def raw_mapping(self) -> dict[str, str]:
        """Internal-only reverse map. Must never be added to a public report."""
        return dict(self._public_id_by_ref)
