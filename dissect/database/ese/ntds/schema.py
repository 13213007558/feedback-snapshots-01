from __future__ import annotations

import re
from io import BytesIO
from typing import TYPE_CHECKING, NamedTuple

from dissect.database.ese.ntds.c_ds import c_ds
from dissect.database.ese.ntds.util import SYNTAX_ENCODE_DECODE_MAP

if TYPE_CHECKING:
    from dissect.database.ese.ntds.database import Database
    from dissect.database.ese.ntds.util import SearchFlag

# These are fixed columns in the NTDS database
# They do not exist in the schema, but are required for basic operation
BOOTSTRAP_COLUMNS = [
    # (lDAPDisplayName, column_name, attributeSyntax)
    ("DNT", "DNT_col", 0x00080009),
    ("Pdnt", "PDNT_col", 0x00080009),
    ("Obj", "OBJ_col", 0x00080008),
    ("RdnType", "RDNtyp_col", 0x00080002),
    ("CNT", "cnt_col", 0x00080009),
    ("AB_cnt", "ab_cnt_col", 0x00080009),
    ("Time", "time_col", 0x0008000B),
    ("Ncdnt", "NCDNT_col", 0x00080009),
    ("RecycleTime", "recycle_time_col", 0x0008000B),
    ("Ancestors", "Ancestors_col", 0x0008000A),
    ("IsVisibleInAB", "IsVisibleInAB", 0x00080009),  # TODO: Confirm syntax + what is this?
]

# These are required for bootstrapping the schema
# Most of these will be overwritten when the schema is loaded from the database
BOOTSTRAP_ATTRIBUTES = [
    # (lDAPDisplayName, attributeID, attributeSyntax, isSingleValued)
    # Essential attributes
    ("objectClass", 0, 0x00080002, False),  # ATTc0
    ("cn", 3, 0x0008000C, True),  # ATTm3
    ("isDeleted", 131120, 0x00080008, True),  # ATTi131120
    ("instanceType", 131073, 0x00080009, True),  # ATTj131073
    ("name", 589825, 0x0008000C, True),  # ATTm589825
    # Common schema
    ("lDAPDisplayName", 131532, 0x0008000C, True),  # ATTm131532
    # Attribute schema
    ("attributeID", 131102, 0x00080002, True),  # ATTc131102
    ("attributeSyntax", 131104, 0x00080002, True),  # ATTc131104
    ("oMSyntax", 131303, 0x00080009, True),  # ATTj131303
    ("oMObjectClass", 131290, 0x0008000A, True),  # ATTk131290
    ("isSingleValued", 131105, 0x00080008, True),  # ATTi131105
    ("linkId", 131122, 0x00080009, True),  # ATTj131122
    ("searchFlags", 131406, 0x00080009, True),  # ATTj131406
    # Class schema
    ("governsID", 131094, 0x00080002, True),  # ATTc131094
    # DSA attributes
    ("dMDLocation", 131108, 0x00080001, True),  # ATTb131108
]

# For convenience, bootstrap some common object classes
# These will also be overwritten when the schema is loaded from the database
BOOTSTRAP_OBJECT_CLASSES = {
    "top": 0x00010000,
    "classSchema": 0x0003000D,
    "attributeSchema": 0x0003000E,
}

# These are fixed OID prefixes used in the schema
# Reference: MSPrefixTable
BOOTSTRAP_OID_PREFIXES = {
    0: b"\x55\x04",
    1: b"\x55\x06",
    2: b"\x2a\x86\x48\x86\xf7\x14\x01\x02",
    3: b"\x2a\x86\x48\x86\xf7\x14\x01\x03",
    4: b"\x60\x86\x48\x01\x65\x02\x02\x01",
    5: b"\x60\x86\x48\x01\x65\x02\x02\x03",
    6: b"\x60\x86\x48\x01\x65\x02\x01\x05",
    7: b"\x60\x86\x48\x01\x65\x02\x01\x04",
    8: b"\x55\x05",
    9: b"\x2a\x86\x48\x86\xf7\x14\x01\x04",
    10: b"\x2a\x86\x48\x86\xf7\x14\x01\x05",
    11: b"\x2a\x86\x48\x86\xf7\x14\x01\x04\x82\x04",
    12: b"\x2a\x86\x48\x86\xf7\x14\x01\x05\x38",
    13: b"\x2a\x86\x48\x86\xf7\x14\x01\x04\x82\x06",
    14: b"\x2a\x86\x48\x86\xf7\x14\x01\x05\x39",
    15: b"\x2a\x86\x48\x86\xf7\x14\x01\x04\x82\x07",
    16: b"\x2a\x86\x48\x86\xf7\x14\x01\x05\x3a",
    17: b"\x2a\x86\x48\x86\xf7\x14\x01\x05\x49",
    18: b"\x2a\x86\x48\x86\xf7\x14\x01\x04\x82\x31",
    19: b"\x09\x92\x26\x89\x93\xf2\x2c\x64",
    20: b"\x60\x86\x48\x01\x86\xf8\x42\x03",
    21: b"\x09\x92\x26\x89\x93\xf2\x2c\x64\x01",
    22: b"\x60\x86\x48\x01\x86\xf8\x42\x03\x01",
    23: b"\x2a\x86\x48\x86\xf7\x14\x01\x05\xb6\x58",
    24: b"\x55\x15",
    25: b"\x55\x12",
    26: b"\x55\x14",
    27: b"\x2b\x06\x01\x04\x01\x8b\x3a\x65\x77",
    28: b"\x60\x86\x48\x01\x86\xf8\x42\x03\x02",
    29: b"\x2b\x06\x01\x04\x01\x81\x7a\x01",
    30: b"\x2a\x86\x48\x86\xf7\x0d\x01\x09",
    31: b"\x09\x92\x26\x89\x93\xf2\x2c\x64\x04",
    32: b"\x2a\x86\x48\x86\xf7\x14\x01\x06\x17",
    33: b"\x2a\x86\x48\x86\xf7\x14\x01\x06\x12\x01",
    34: b"\x2a\x86\x48\x86\xf7\x14\x01\x06\x12\x02",
    35: b"\x2a\x86\x48\x86\xf7\x14\x01\x06\x0d\x03",
    36: b"\x2a\x86\x48\x86\xf7\x14\x01\x06\x0d\x04",
    37: b"\x2b\x06\x01\x01\x01\x01",
    38: b"\x2b\x06\x01\x01\x01\x02",
}


class SchemaSource:
    """Where a schema entry originated from."""

    BOOTSTRAP_COLUMN = "bootstrap_column"
    BOOTSTRAP_ATTRIBUTE = "bootstrap_attribute"
    BOOTSTRAP_CLASS = "bootstrap_class"
    DATABASE = "database"
    SYNTHETIC = "synthetic"


class DeficiencyReason:
    """Machine-readable reasons describing why a schema entry cannot fully explain a value."""

    NAME_COLLISION = "name_collision"
    ATTRTYP_COLLISION = "attrtyp_collision"
    COLUMN_COLLISION = "column_collision"
    DNT_COLLISION = "dnt_collision"
    UNKNOWN_SYNTAX = "unknown_syntax"
    NO_SYNTAX_DECODER = "no_syntax_decoder"
    UNKNOWN_ATTRIBUTE = "unknown_attribute"
    UNKNOWN_CLASS = "unknown_class"
    UNRESOLVED_REFERENCE = "unresolved_reference"
    MALFORMED_VALUE = "malformed_value"


class SchemaConflict(NamedTuple):
    """A record of one schema entry replacing or failing to replace another."""

    index: str
    key: object
    previous: NamedTuple
    current: NamedTuple
    reason: str


class ClassEntry(NamedTuple):
    dnt: int
    id: int
    name: str
    source: str = SchemaSource.BOOTSTRAP_CLASS


class AttributeEntry(NamedTuple):
    dnt: int
    id: int
    name: str
    column: str
    syntax: int
    om_syntax: int | None
    om_object_class: bytes | None
    is_single_valued: bool
    link_id: int | None
    search_flags: SearchFlag | None
    source: str = SchemaSource.BOOTSTRAP_ATTRIBUTE


class Schema:
    """An index for schema entries providing fast lookups by various keys.

    Provides efficient lookups for schema entries by DNT, OID, ATTRTYP, LDAP display name, and column name.
    """

    def __init__(self):
        # Combined indices
        self._dnt_index: dict[int, ClassEntry | AttributeEntry] = {}
        self._attrtyp_index: dict[int, ClassEntry | AttributeEntry] = {}

        # Attribute specific indices
        self._attribute_id_index: dict[int, AttributeEntry] = {}
        self._attribute_name_index: dict[str, AttributeEntry] = {}
        self._attribute_link_index: dict[int, AttributeEntry] = {}
        self._attribute_column_index: dict[str, AttributeEntry] = {}

        # Class specific indices
        self._class_id_index: dict[int, ClassEntry] = {}
        self._class_name_index: dict[str, ClassEntry] = {}

        # Entries that could not be indexed under their preferred key because another entry already claimed it.
        # The displaced entry is retained here so no schema information is silently lost.
        self.conflicts: list[SchemaConflict] = []

        # Records of database entries superseding the built-in bootstrap definitions. This is expected behavior,
        # but kept explicit so callers can see exactly when a bootstrap definition stops being authoritative.
        self.overrides: list[SchemaConflict] = []

        # Attribute entries indexed by the physical ESE column name, including columns that are not described by
        # any schema entry. These are synthesized on demand so their raw values remain inspectable.
        self._unknown_column_index: dict[str, AttributeEntry] = {}

        # Class ATTRTYP values encountered on objects without a classSchema definition. Populated lazily while
        # resolving objectClass values so unregistered custom classes remain visible in the deficiency report.
        self._unknown_class_ids: set[int] = set()

        # OID prefixes
        self._oid_idx_to_prefix_index: dict[int, str] = {
            idx: decode_oid(prefix) for idx, prefix in BOOTSTRAP_OID_PREFIXES.items()
        }
        self._oid_prefix_to_idx_index: dict[str, int] = {
            prefix: idx for idx, prefix in self._oid_idx_to_prefix_index.items()
        }

        # Bootstrap fixed database columns (these do not exist in the schema)
        for ldap_name, column_name, attrtyp in BOOTSTRAP_COLUMNS:
            self._add(
                AttributeEntry(
                    dnt=-1,
                    id=-1,
                    name=ldap_name,
                    column=column_name,
                    syntax=attrtyp & 0xFF,
                    om_syntax=None,
                    om_object_class=None,
                    is_single_valued=True,
                    link_id=None,
                    search_flags=None,
                    source=SchemaSource.BOOTSTRAP_COLUMN,
                )
            )

        # Bootstrap initial attributes
        for name, id, attrtyp, is_single_valued in BOOTSTRAP_ATTRIBUTES:
            self._add_attribute(
                dnt=-1,
                id=id,
                name=name,
                syntax=attrtyp,
                om_syntax=None,
                om_object_class=None,
                is_single_valued=is_single_valued,
                link_id=None,
                search_flags=None,
                source=SchemaSource.BOOTSTRAP_ATTRIBUTE,
            )

        # Bootstrap initial object classes
        for name, id in BOOTSTRAP_OBJECT_CLASSES.items():
            self._add_class(
                dnt=-1,
                id=id,
                name=name,
                source=SchemaSource.BOOTSTRAP_CLASS,
            )

    def load(self, db: Database) -> None:
        """Load the classes and attributes from the database into the schema index.

        Args:
            db: The database instance to load the schema from.
        """
        # Load the schema entries from the DMD object
        # This _should_ have all the attribute and class schema entries
        # We used to perform an index search on objectClass (ATTc0, INDEX_00000000), but apparently
        # not all databases have this index
        dmd = db.dmd()

        # We bootstrapped these earlier
        attribute_schema = self.lookup_class(name="attributeSchema")
        class_schema = self.lookup_class(name="classSchema")

        for obj in dmd.children():
            # Get as raw to avoid decoding the attribute and class schema entries before we know which is which
            classes = obj.get("objectClass", raw=True)
            if attribute_schema.id in classes:
                self._add_attribute(
                    dnt=obj.dnt,
                    id=obj.get("attributeID", raw=True),
                    name=obj.get("lDAPDisplayName"),
                    syntax=obj.get("attributeSyntax", raw=True),
                    om_syntax=obj.get("oMSyntax"),
                    om_object_class=obj.get("oMObjectClass"),
                    is_single_valued=obj.get("isSingleValued"),
                    link_id=obj.get("linkId"),
                    search_flags=obj.get("searchFlags"),
                    source=SchemaSource.DATABASE,
                )

            elif class_schema.id in classes:
                self._add_class(
                    dnt=obj.dnt,
                    id=obj.get("governsID", raw=True),
                    name=obj.get("lDAPDisplayName"),
                    source=SchemaSource.DATABASE,
                )

        # Load user-defined OID prefixes
        if (prefix_map := dmd.get("prefixMap")) is not None:
            self._oid_idx_to_prefix_index.update(parse_prefix_map(prefix_map))
            # Rebuild the reverse index
            self._oid_prefix_to_idx_index = {prefix: idx for idx, prefix in self._oid_idx_to_prefix_index.items()}

    def _add_class(self, dnt: int, id: int, name: str, source: str) -> None:
        entry = ClassEntry(
            dnt=dnt,
            id=id,
            name=name,
            source=source,
        )
        self._add(entry)

    def _add_attribute(
        self,
        dnt: int,
        id: int,
        name: str,
        syntax: int,
        om_syntax: int | None,
        om_object_class: bytes | None,
        is_single_valued: bool,
        link_id: int | None,
        search_flags: SearchFlag | None,
        source: str,
    ) -> None:
        entry = AttributeEntry(
            dnt=dnt,
            id=id,
            name=name,
            column=f"ATT{chr(ord('a') + (syntax & 0xFFFF))}{id}",
            syntax=syntax & 0xFF,
            om_syntax=om_syntax,
            om_object_class=om_object_class,
            is_single_valued=is_single_valued,
            link_id=link_id,
            search_flags=search_flags,
            source=source,
        )
        self._add(entry)

    def _replace_index(
        self,
        index: dict,
        key: object,
        entry: ClassEntry | AttributeEntry,
        reason: str,
        index_name: str,
    ) -> None:
        """Place ``entry`` in ``index`` under ``key``, recording genuine schema collisions.

        A bootstrap entry being superseded by a database entry is the normal, expected flow (the database is
        the authoritative source) and is not recorded as a conflict. A database entry replacing another
        database entry under the same key means the extended schema is ambiguous and is retained for
        inspection instead of being silently overwritten without a trace.
        """
        previous = index.get(key)
        if previous is not None and previous != entry:
            is_bootstrap_replacement = (
                previous.source != SchemaSource.DATABASE and entry.source == SchemaSource.DATABASE
            )
            if is_bootstrap_replacement:
                self.overrides.append(
                    SchemaConflict(index=index_name, key=key, previous=previous, current=entry, reason=reason)
                )
            else:
                self.conflicts.append(
                    SchemaConflict(index=index_name, key=key, previous=previous, current=entry, reason=reason)
                )
        index[key] = entry

    def _add(self, entry: ClassEntry | AttributeEntry) -> None:
        if entry.dnt != -1:
            self._replace_index(self._dnt_index, entry.dnt, entry, DeficiencyReason.DNT_COLLISION, index_name="dnt")
        if entry.id != -1:
            self._replace_index(
                self._attrtyp_index, entry.id, entry, DeficiencyReason.ATTRTYP_COLLISION, index_name="attrtyp"
            )

        if isinstance(entry, ClassEntry):
            self._replace_index(
                self._class_name_index,
                entry.name.lower(),
                entry,
                DeficiencyReason.NAME_COLLISION,
                index_name="class_name",
            )

            if entry.id != -1:
                self._replace_index(
                    self._class_id_index,
                    entry.id,
                    entry,
                    DeficiencyReason.ATTRTYP_COLLISION,
                    index_name="class_id",
                )

        if isinstance(entry, AttributeEntry):
            self._replace_index(
                self._attribute_name_index,
                entry.name.lower(),
                entry,
                DeficiencyReason.NAME_COLLISION,
                index_name="attribute_name",
            )
            self._replace_index(
                self._attribute_column_index,
                entry.column,
                entry,
                DeficiencyReason.COLUMN_COLLISION,
                index_name="attribute_column",
            )

            if entry.id != -1:
                self._replace_index(
                    self._attribute_id_index,
                    entry.id,
                    entry,
                    DeficiencyReason.ATTRTYP_COLLISION,
                    index_name="attribute_id",
                )
            if entry.link_id is not None:
                self._attribute_link_index[entry.link_id] = entry

    def lookup_attribute(
        self,
        *,
        id: int | None = None,
        name: str | None = None,
        link_id: int | None = None,
        column: str | None = None,
    ) -> AttributeEntry | None:
        """Lookup an attribute schema entry by an indexed field.

        Args:
            id: The attribute ID to look up.
            name: The LDAP display name to look up.
            link_id: The link ID to look up.
            column: The column name to look up.

        Returns:
            The matching attribute schema entry or ``None`` if not found.
        """
        if sum(key is not None for key in [id, name, link_id, column]) != 1:
            raise ValueError("Exactly one lookup key must be provided")

        if id is not None:
            return self._attribute_id_index.get(id)

        if name is not None:
            return self._attribute_name_index.get(name.lower())

        if link_id is not None:
            return self._attribute_link_index.get(link_id)

        if column is not None:
            return self._attribute_column_index.get(column)

        return None

    def lookup_class(
        self,
        *,
        id: int | None = None,
        name: str | None = None,
    ) -> ClassEntry | None:
        """Lookup a class schema entry by an indexed field.

        Args:
            id: The class ID to look up.
            name: The LDAP display name to look up.

        Returns:
            The matching class schema entry or ``None`` if not found.
        """
        if sum(key is not None for key in [id, name]) != 1:
            raise ValueError("Exactly one lookup key must be provided")

        if id is not None:
            return self._class_id_index.get(id)

        if name is not None:
            return self._class_name_index.get(name.lower())

        return None

    # Physical NTDS columns are named "ATT<syntax-letter><ATTRTYP>", e.g. ATTm590012 or ATTq999.
    # Fixed internal columns (DNT_col, ...) do not match this pattern and are always bootstrapped.
    _ATT_COLUMN_PATTERN = re.compile(r"^ATT([a-z])(\d+)$")

    def entry_for_column(self, column: str) -> AttributeEntry | None:
        """Resolve a physical ESE column name to a schema entry, synthesizing one for unknown columns.

        Extended schemas can introduce attributes that have no corresponding ``attributeSchema`` object in a
        stripped-down offline database. Instead of discarding such a column, a synthetic :class:`AttributeEntry`
        is reconstructed from the column name itself (the syntax letter encodes the syntax, the number is the
        ATTRTYP), so the raw value remains inspectable and the gap in the schema is reported explicitly.

        Args:
            column: The physical ESE column name (e.g. ``ATTm590012``).

        Returns:
            The registered or synthesized attribute entry, or ``None`` if the column name does not encode an
            ATTRTYP and is not otherwise known.
        """
        entry = self._attribute_column_index.get(column) or self._unknown_column_index.get(column)
        if entry is not None:
            return entry

        match = self._ATT_COLUMN_PATTERN.match(column)
        if match is None:
            return None

        letter, attrtyp_text = match.groups()
        syntax = ord(letter) - ord("a")
        attrtyp = int(attrtyp_text)

        entry = AttributeEntry(
            dnt=-1,
            id=attrtyp,
            # There is no lDAPDisplayName for this attribute; keep the physical column name as a stable label
            # rather than inventing a misleading display name.
            name=column,
            column=column,
            syntax=syntax,
            om_syntax=None,
            om_object_class=None,
            # We cannot tell single- from multi-valued without the schema entry; treat it as multi-valued so a
            # list value is never truncated and the raw value is preserved losslessly.
            is_single_valued=False,
            link_id=None,
            search_flags=None,
            source=SchemaSource.SYNTHETIC,
        )
        self._unknown_column_index[column] = entry
        return entry

    def unknown_attributes(self) -> list[AttributeEntry]:
        """Return the attribute entries synthesized from columns without a schema definition."""
        return list(self._unknown_column_index.values())

    def is_known_syntax(self, syntax: int) -> bool:
        """Return whether the syntax has a registered value decoder.

        A syntax may be a valid AD syntax but still lack a decoder (e.g. presentation-address), which is a
        different deficiency from encountering a syntax number that is not part of AD at all.
        """
        return syntax in SYNTAX_ENCODE_DECODE_MAP

    def syntax_deficiency_reason(self, syntax: int) -> str | None:
        """Return the specific reason a syntax cannot be decoded, or ``None`` if it can."""
        if syntax not in SYNTAX_ENCODE_DECODE_MAP:
            return DeficiencyReason.UNKNOWN_SYNTAX

        if SYNTAX_ENCODE_DECODE_MAP[syntax][1] is None:
            return DeficiencyReason.NO_SYNTAX_DECODER

        return None

    def explain_attribute(self, name: str) -> dict | None:
        """Explain which definition backs an attribute name and how values are (or cannot be) decoded.

        Args:
            name: The LDAP display name to explain.

        Returns:
            A dictionary describing the ATTRTYP/OID, physical column, syntax, provenance (bootstrap versus
            database) and any decoding deficiency, or ``None`` if the name is not known.
        """
        entry = self.lookup_attribute(name=name)
        if entry is None:
            return None

        return self._explain(entry)

    def explain_column(self, column: str) -> dict | None:
        """Explain the definition behind a physical ESE column name, synthesizing one if necessary."""
        entry = self.entry_for_column(column)
        if entry is None:
            return None

        return self._explain(entry)

    def _explain(self, entry: AttributeEntry) -> dict:
        reason = None
        if entry.source == SchemaSource.SYNTHETIC:
            reason = DeficiencyReason.UNKNOWN_ATTRIBUTE
        else:
            reason = self.syntax_deficiency_reason(entry.syntax)

        return {
            "name": entry.name,
            "attrtyp": entry.id if entry.id != -1 else None,
            "oid": self.attrtyp_to_oid(entry.id) if entry.id != -1 else None,
            "column": entry.column,
            "syntax": entry.syntax,
            "om_syntax": entry.om_syntax,
            "om_object_class": entry.om_object_class,
            "is_single_valued": entry.is_single_valued,
            "link_id": entry.link_id,
            "search_flags": entry.search_flags,
            "source": entry.source,
            "dnt": entry.dnt if entry.dnt != -1 else None,
            "deficiency_reason": reason,
        }

    def name_conflicts(self) -> list[SchemaConflict]:
        """Return conflicts where two attribute or class definitions claimed the same display name."""
        return [conflict for conflict in self.conflicts if conflict.reason == DeficiencyReason.NAME_COLLISION]

    def deficiencies(self) -> list[dict]:
        """Return every schema deficiency that prevents a fully explained read.

        Each item names the exact definition that is insufficient (the conflicting entries, the unknown
        attribute or the unsupported syntax), so callers never have to guess behind a generic error string.
        """
        result = []
        for conflict in self.conflicts:
            result.append(
                {
                    "reason": conflict.reason,
                    "index": conflict.index,
                    "key": conflict.key,
                    "previous": _entry_reference(conflict.previous),
                    "current": _entry_reference(conflict.current),
                }
            )

        for entry in self._unknown_column_index.values():
            result.append(
                {
                    "reason": DeficiencyReason.UNKNOWN_ATTRIBUTE,
                    "column": entry.column,
                    "attrtyp": entry.id,
                    "oid": self.attrtyp_to_oid(entry.id),
                    "syntax": entry.syntax,
                }
            )

        result.extend(self.unknown_classes())

        for entry in self._attribute_id_index.values():
            # Synthetic entries are already reported as unknown attributes above
            if entry.source == SchemaSource.SYNTHETIC:
                continue
            if (reason := self.syntax_deficiency_reason(entry.syntax)) is not None:
                result.append(
                    {
                        "reason": reason,
                        "name": entry.name,
                        "attrtyp": entry.id,
                        "column": entry.column,
                        "syntax": entry.syntax,
                        "source": entry.source,
                    }
                )

        return result

    def lookup_oid(self, oid: str) -> ClassEntry | AttributeEntry | None:
        """Lookup a schema entry by OID.

        Args:
            oid: The OID to look up.

        Returns:
            The matching schema entry or ``None`` if not found.
        """
        parts = oid.split(".")
        if len(parts) < 2:
            return None

        long_id = 0
        prefix_length = 0
        if len(parts) > 2 and int(parts[-2]) & 0x80:
            prefix_length = len(parts) - 2
            long_id = int(parts[-3]) >> 7
        else:
            prefix_length = len(parts) - 1

        prefix = ".".join(parts[:prefix_length])
        if (idx := self._oid_prefix_to_idx_index.get(prefix)) is None:
            return None

        attrtyp = idx << 16
        if len(parts) == prefix_length + 2:
            attrtyp += (int(parts[-2]) & 0x7F) << 7
            if long_id:
                attrtyp |= 0x8000

        attrtyp += int(parts[-1])
        return self._attrtyp_index.get(attrtyp)

    def attrtyp_to_oid(self, attrtyp: int) -> str | None:
        """Convert an ATTRTYP integer value to an OID string.

        Args:
            attrtyp: The ATTRTYP integer value to convert.

        Returns:
            The corresponding OID string or ``None`` if the ATTRTYP does not correspond to a valid OID.
        """
        if (prefix := self._oid_idx_to_prefix_index.get(attrtyp >> 16)) is None:
            return None

        parts = [prefix]

        if attrtyp & 0xFFFF < 0x80:
            parts.append(str(attrtyp & 0xFF))
        else:
            parts.append(str(((attrtyp & 0xFF80) >> 7) | 0x80))
            parts.append(str(attrtyp & 0x7F))

        return ".".join(parts)

    def lookup(
        self,
        *,
        dnt: int | None = None,
        oid: str | None = None,
        attrtyp: int | None = None,
        name: str | None = None,
    ) -> ClassEntry | AttributeEntry | None:
        """Lookup a schema entry by an indexed field.

        Args:
            dnt: The DNT (Distinguished Name Tag) of the schema entry to look up.
            oid: The OID (Object Identifier) of the schema entry to look up.
            attrtyp: The ATTRTYP (attribute type) of the schema entry to look up.
            name: The LDAP display name of the schema entry to look up.

        Returns:
            The matching schema entry or ``None`` if not found.
        """
        # Ensure exactly one lookup key is provided
        if sum(key is not None for key in [dnt, oid, attrtyp, name]) != 1:
            raise ValueError("Exactly one lookup key must be provided")

        if dnt is not None:
            return self._dnt_index.get(dnt)

        if oid is not None:
            return self.lookup_oid(oid)

        if attrtyp is not None:
            return self._attrtyp_index.get(attrtyp)

        if name is not None:
            name = name.lower()
            return self._class_name_index.get(name) or self._attribute_name_index.get(name)

        return None

    def resolve_class_ids(self, class_ids: list[int]) -> tuple[list[str | int], list[int]]:
        """Resolve objectClass ATTRTYP values to display names, retaining any unregistered class IDs.

        Custom schema extensions may add structural or auxiliary classes that are not present in an offline
        database's class schema. The known classes are returned by name while the unknown IDs are kept verbatim
        (never dropped or guessed), together with the list of unresolved IDs.

        Args:
            class_ids: The raw objectClass ATTRTYP values stored on an object.

        Returns:
            A tuple of (resolved names-or-ids in original order, the subset of unregistered IDs).
        """
        resolved: list[str | int] = []
        unresolved: list[int] = []

        for class_id in class_ids:
            entry = self.lookup_class(id=class_id)
            if entry is None:
                resolved.append(class_id)
                unresolved.append(class_id)
                self._unknown_class_ids.add(class_id)
            else:
                resolved.append(entry.name)

        return resolved, unresolved

    def unknown_classes(self) -> list[dict]:
        """Return the class ATTRTYPs seen on objects without a registered classSchema definition."""
        return [
            {
                "reason": DeficiencyReason.UNKNOWN_CLASS,
                "attrtyp": class_id,
                "oid": self.attrtyp_to_oid(class_id),
            }
            for class_id in sorted(self._unknown_class_ids)
        ]


def _entry_reference(entry: ClassEntry | AttributeEntry) -> dict:
    """Return a compact, comparable description of a schema entry for deficiency reporting."""
    reference = {
        "source": entry.source,
        "dnt": entry.dnt if entry.dnt != -1 else None,
        "id": entry.id if entry.id != -1 else None,
        "name": entry.name,
    }
    if isinstance(entry, AttributeEntry):
        reference["column"] = entry.column
        reference["syntax"] = entry.syntax
    return reference


def parse_prefix_map(buf: bytes) -> dict[int, str]:
    """Parse a prefix map.

    Args:
        buf: The buffer containing the prefix map data.
    """
    result = {}

    fh = BytesIO(buf)
    c_ds.uint32(fh)  # Number of prefixes
    total_size = c_ds.uint32(fh)  # Total size

    while fh.tell() < total_size:
        index = c_ds.uint16(fh)
        prefix_length = c_ds.uint16(fh)
        prefix = fh.read(prefix_length)

        result[index] = decode_oid(prefix)

    return result


def decode_oid(buf: bytes) -> str:
    """Decode a BER encoded OID.

    Args:
        buf: The buffer containing the BER encoded OID.
    """
    values = [*divmod(buf[0], 40)]

    idx = 1
    while idx < len(buf):
        value = buf[idx] & 0x7F
        while buf[idx] & 0x80:
            value <<= 7
            idx += 1

            if idx >= len(buf):
                break

            value |= buf[idx] & 0x7F

        values.append(value)
        idx += 1

    return ".".join(map(str, values))
