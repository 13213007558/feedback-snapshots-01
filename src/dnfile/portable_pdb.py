# -*- coding: utf-8 -*-
"""
Limited, offline Portable PDB reader.

This module implements a deliberately narrow slice of the Portable PDB
format:

* the metadata root and its stream table,
* the ``#Pdb`` standalone-PDB header (PDB id, entry point token, and the
  row counts of the external type-system tables),
* the ``Document`` and ``MethodDebugInformation`` tables,
* the ``StateMachineMethod`` table, only because it is a compact way to
  expose the width of MethodDef references.

It does not open source files named by Document rows and it does not access
the network.  Document names are returned as evidence, never used to look up
or read a file.

Association with an assembly is conservative: the Portable PDB is associated
only when the 20-byte ``#Pdb`` id matches the assembly's CodeView RSDS record
and the external MethodDef row count matches the assembly's MethodDef table.
A successful association says nothing about whether the debug information is
trustworthy.

REFERENCES

    Portable PDB v1.0 specification (dotnet/runtime PortablePdb-Metadata.md)
    ECMA-335, 6th Edition, Partition II Section 24.2.4

Copyright (c) 2020-2024 MalwareFrank
"""

import os
import struct
import logging
from typing import Any, Dict, List, Tuple, Union, Optional

from . import enums, utils, errors

logger = logging.getLogger(__name__)


METADATA_SIGNATURE = b"BSJB"
PDB_STREAM_NAME = b"#Pdb"
TABLES_STREAM_NAMES = (b"#~", b"#-")
STRINGS_STREAM_NAME = b"#Strings"
GUID_STREAM_NAME = b"#GUID"
BLOB_STREAM_NAME = b"#Blob"

TYPE_SYSTEM_TABLE_COUNT = 48
TABLE_COUNT = 64

# Portable PDB table numbers.
TABLE_DOCUMENT = 48
TABLE_METHOD_DEBUG_INFORMATION = 49
TABLE_LOCAL_SCOPE = 50
TABLE_LOCAL_VARIABLE = 51
TABLE_LOCAL_CONSTANT = 52
TABLE_IMPORT_SCOPE = 53
TABLE_STATE_MACHINE_METHOD = 54
TABLE_CUSTOM_DEBUG_INFORMATION = 55

PDB_TABLE_NAMES = {
    TABLE_DOCUMENT: "Document",
    TABLE_METHOD_DEBUG_INFORMATION: "MethodDebugInformation",
    TABLE_LOCAL_SCOPE: "LocalScope",
    TABLE_LOCAL_VARIABLE: "LocalVariable",
    TABLE_LOCAL_CONSTANT: "LocalConstant",
    TABLE_IMPORT_SCOPE: "ImportScope",
    TABLE_STATE_MACHINE_METHOD: "StateMachineMethod",
    TABLE_CUSTOM_DEBUG_INFORMATION: "CustomDebugInformation",
}

PDB_TABLE_NUMBERS = dict((v, k) for k, v in PDB_TABLE_NAMES.items())

# Type-system tables that may appear in the #Pdb external mask.  This is the
# same set used by System.Reflection.Metadata's ValidateTypeSystemRowCounts.
ALLOWED_EXTERNAL_TABLES = frozenset(
    (0, 1, 2, 4, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 20, 21, 23, 24, 25, 26, 27, 28, 29, 32, 35, 38, 39, 40, 41, 42, 43, 44)
)
FORBIDDEN_EXTERNAL_MASK = 0xFFFFE036C04800A8

# Coded index used by CustomDebugInformation.  The tuple index is the tag.
HAS_CUSTOM_DEBUG_INFORMATION_TABLES = (
    6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43,
    48, 50, 51, 52, 53,
)

HIDDEN_LINE = 0xFEEFEE
MAX_LINE = 0xFEEFED
MAX_COLUMN = 0xFFFF
MAX_ROW_COUNT = 0xFFFFFF

METHODDEF_TOKEN_PREFIX = 0x06000000
NATIVE_ENTRYPOINT_FLAG = 0x10


class PortablePdbError(errors.dnFormatError):
    """Raised when a Portable PDB cannot be read."""


class _BlobReader:
    """Small bounds-checked reader for Portable PDB blobs."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def read_byte(self) -> int:
        if self.pos >= len(self.data):
            raise PortablePdbError("unexpected end of blob")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def read_compressed_uint(self) -> int:
        result = utils.read_compressed_int(self.data[self.pos:])
        if result is None:
            raise PortablePdbError("invalid compressed integer at blob offset %d" % self.pos)
        value, size = result
        self.pos += size
        return value

    def read_compressed_signed(self) -> int:
        if self.pos >= len(self.data):
            raise PortablePdbError("unexpected end of blob")

        first = self.data[self.pos]
        if first & 0x80 == 0:
            encoded = first
            size = 1
        elif first & 0x40 == 0:
            if self.remaining() < 2:
                raise PortablePdbError("truncated two-byte compressed integer")
            encoded = ((first & 0x3F) << 8) | self.data[self.pos + 1]
            size = 2
        elif first & 0x20 == 0:
            if self.remaining() < 4:
                raise PortablePdbError("truncated four-byte compressed integer")
            encoded = (
                ((first & 0x1F) << 24)
                | (self.data[self.pos + 1] << 16)
                | (self.data[self.pos + 2] << 8)
                | self.data[self.pos + 3]
            )
            size = 4
        else:
            raise PortablePdbError("invalid compressed signed integer at blob offset %d" % self.pos)

        self.pos += size
        value = encoded >> 1
        if encoded & 1:
            if size == 1:
                value |= 0xFFFFFFC0
            elif size == 2:
                value |= 0xFFFFE000
            else:
                value |= 0xF0000000
        if value & 0x80000000:
            value -= 0x100000000
        return value


def _read_uint(data: bytes, offset: int, size: int) -> Optional[int]:
    if offset < 0 or offset + size > len(data):
        return None
    return int.from_bytes(data[offset:offset + size], "little")


def _format_guid(data: bytes) -> Optional[str]:
    if data is None or len(data) < 16:
        return None
    d1, d2, d3 = struct.unpack_from("<IHH", data)
    return "%08x-%04x-%04x-%s-%s" % (d1, d2, d3, data[8:10].hex(), data[10:16].hex())


class MetadataStream:
    """One stream entry in a Portable PDB metadata root."""

    def __init__(self, name: bytes, offset: int, size: int, data: bytes):
        self.name = name
        self.offset = offset
        self.size = size
        self.data = data

    def to_dict(self) -> dict:
        return {
            "name": self.name.decode("utf-8", errors="replace"),
            "offset": self.offset,
            "declared_size": self.size,
            "available_size": len(self.data),
        }


class SequencePoint:
    """One decoded sequence point.

    ``document_row_id`` is the Document table row id used by this point, not a
    path.  Paths are represented separately by ``DocumentRow`` and are evidence
    only.
    """

    def __init__(
        self,
        il_offset: int,
        start_line: int,
        start_column: int,
        end_line: int,
        end_column: int,
        document_row_id: int,
        is_hidden: bool,
    ):
        self.il_offset = il_offset
        self.start_line = start_line
        self.start_column = start_column
        self.end_line = end_line
        self.end_column = end_column
        self.document_row_id = document_row_id
        self.is_hidden = is_hidden

    @property
    def ILOffset(self) -> int:
        return self.il_offset

    @property
    def StartLine(self) -> int:
        return self.start_line

    @property
    def StartColumn(self) -> int:
        return self.start_column

    @property
    def EndLine(self) -> int:
        return self.end_line

    @property
    def EndColumn(self) -> int:
        return self.end_column

    @property
    def DocumentRowId(self) -> int:
        return self.document_row_id

    @property
    def IsHidden(self) -> bool:
        return self.is_hidden

    def to_dict(self) -> dict:
        return {
            "il_offset": self.il_offset,
            "start_line": self.start_line,
            "start_column": self.start_column,
            "end_line": self.end_line,
            "end_column": self.end_column,
            "document_row_id": self.document_row_id,
            "is_hidden": self.is_hidden,
        }


class DocumentRow:
    """A decoded Document table row.  The name is evidence only."""

    def __init__(
        self,
        pdb: "PortablePdb",
        row_id: int,
        raw: bytes,
        name_blob_offset: int,
        name_blob: Optional[bytes],
        separator: Optional[int],
        name_parts: List[str],
        name: str,
        hash_algorithm_index: int,
        hash_algorithm: Optional[str],
        hash_bytes: Optional[bytes],
        language_index: int,
        language: Optional[str],
        decode_error: Optional[str],
    ):
        self.row_id = row_id
        self.raw = raw
        self.name_blob_offset = name_blob_offset
        self.name_blob = name_blob
        self.separator = separator
        self.name_parts = name_parts
        self.name = name
        self.hash_algorithm_index = hash_algorithm_index
        self.hash_algorithm = hash_algorithm
        self.hash_bytes = hash_bytes
        self.language_index = language_index
        self.language = language
        self.decode_error = decode_error

    @property
    def Name(self) -> str:
        return self.name

    @property
    def NameParts(self) -> List[str]:
        return self.name_parts

    @property
    def Separator(self) -> Optional[int]:
        return self.separator

    @property
    def HashAlgorithm(self) -> Optional[str]:
        return self.hash_algorithm

    @property
    def Hash(self) -> Optional[bytes]:
        return self.hash_bytes

    @property
    def Language(self) -> Optional[str]:
        return self.language

    def to_dict(self) -> dict:
        return {
            "table": "Document",
            "row_id": self.row_id,
            "raw": self.raw.hex(),
            "name_blob_offset": self.name_blob_offset,
            "name_blob": self.name_blob.hex() if self.name_blob is not None else None,
            "separator": self.separator,
            "name_parts": list(self.name_parts),
            "name": self.name,
            "name_is_evidence_only": True,
            "hash_algorithm_index": self.hash_algorithm_index,
            "hash_algorithm": self.hash_algorithm,
            "hash": self.hash_bytes.hex() if self.hash_bytes is not None else None,
            "language_index": self.language_index,
            "language": self.language,
            "decode_error": self.decode_error,
        }


class MethodDebugInformationRow:
    """A decoded MethodDebugInformation table row.

    The row id is the MethodDef rid it belongs to.  Sequence points are decoded
    lazily so that reading a large PDB does not decode every blob eagerly.
    """

    def __init__(
        self,
        pdb: "PortablePdb",
        row_id: int,
        raw: bytes,
        document_row_id: int,
        sequence_points_blob_offset: int,
        sequence_points_blob: Optional[bytes],
    ):
        self._pdb = pdb
        self.row_id = row_id
        self.raw = raw
        self.document_row_id = document_row_id
        self.sequence_points_blob_offset = sequence_points_blob_offset
        self.sequence_points_blob = sequence_points_blob
        self._sequence_points: Optional[List[SequencePoint]] = None
        self.decode_error: Optional[str] = None

    @property
    def sequence_points(self) -> List[SequencePoint]:
        if self._sequence_points is None:
            self._sequence_points, self.decode_error = _decode_sequence_points(
                self.sequence_points_blob,
                self.document_row_id,
            )
        return self._sequence_points

    @property
    def document(self) -> Optional[DocumentRow]:
        return self._pdb.get_document(self.document_row_id)

    @property
    def Document(self) -> Optional[DocumentRow]:
        return self.document

    @property
    def DocumentRowId(self) -> int:
        return self.document_row_id

    @property
    def SequencePoints(self) -> List[SequencePoint]:
        return self.sequence_points

    def to_dict(self) -> dict:
        document = self.document
        return {
            "table": "MethodDebugInformation",
            "row_id": self.row_id,
            "raw": self.raw.hex(),
            "document_row_id": self.document_row_id,
            "sequence_points_blob_offset": self.sequence_points_blob_offset,
            "sequence_points_blob": self.sequence_points_blob.hex() if self.sequence_points_blob is not None else None,
            "sequence_points": [p.to_dict() for p in self.sequence_points],
            "decode_error": self.decode_error,
            "document": document.to_dict() if document is not None else None,
        }


class StateMachineMethodRow:
    """A decoded StateMachineMethod row.

    These rows are not used for source-line association; they are decoded so
    callers can see the actual width selected for external MethodDef references.
    """

    def __init__(
        self,
        row_id: int,
        raw: bytes,
        move_next_method_row_id: int,
        kickoff_method_row_id: int,
    ):
        self.row_id = row_id
        self.raw = raw
        self.move_next_method_row_id = move_next_method_row_id
        self.kickoff_method_row_id = kickoff_method_row_id

    @property
    def MoveNextMethod(self) -> int:
        return self.move_next_method_row_id

    @property
    def KickoffMethod(self) -> int:
        return self.kickoff_method_row_id

    def to_dict(self) -> dict:
        return {
            "table": "StateMachineMethod",
            "row_id": self.row_id,
            "raw": self.raw.hex(),
            "move_next_method_row_id": self.move_next_method_row_id,
            "kickoff_method_row_id": self.kickoff_method_row_id,
        }


class _Column:
    def __init__(self, name: str, kind: str, argument: Any = None):
        self.name = name
        self.kind = kind
        self.argument = argument


def _table_schema(table_number: int) -> Tuple[str, Tuple[_Column, ...]]:
    if table_number == TABLE_DOCUMENT:
        return "Document", (
            _Column("Name", "blob"),
            _Column("HashAlgorithm", "guid"),
            _Column("Hash", "blob"),
            _Column("Language", "guid"),
        )
    if table_number == TABLE_METHOD_DEBUG_INFORMATION:
        return "MethodDebugInformation", (
            _Column("Document", "table", TABLE_DOCUMENT),
            _Column("SequencePoints", "blob"),
        )
    if table_number == TABLE_LOCAL_SCOPE:
        return "LocalScope", (
            _Column("Method", "table", 6),
            _Column("ImportScope", "table", TABLE_IMPORT_SCOPE),
            _Column("VariableList", "table", TABLE_LOCAL_VARIABLE),
            _Column("ConstantList", "table", TABLE_LOCAL_CONSTANT),
            _Column("StartOffset", "u32"),
            _Column("Length", "u32"),
        )
    if table_number == TABLE_LOCAL_VARIABLE:
        return "LocalVariable", (
            _Column("Attributes", "u16"),
            _Column("Index", "u16"),
            _Column("Name", "strings"),
        )
    if table_number == TABLE_LOCAL_CONSTANT:
        return "LocalConstant", (
            _Column("Name", "strings"),
            _Column("Signature", "blob"),
        )
    if table_number == TABLE_IMPORT_SCOPE:
        return "ImportScope", (
            _Column("Parent", "table", TABLE_IMPORT_SCOPE),
            _Column("Imports", "blob"),
        )
    if table_number == TABLE_STATE_MACHINE_METHOD:
        return "StateMachineMethod", (
            _Column("MoveNextMethod", "table", 6),
            _Column("KickoffMethod", "table", 6),
        )
    if table_number == TABLE_CUSTOM_DEBUG_INFORMATION:
        return "CustomDebugInformation", (
            _Column("Parent", "coded", (5, HAS_CUSTOM_DEBUG_INFORMATION_TABLES)),
            _Column("Kind", "guid"),
            _Column("Value", "blob"),
        )
    raise PortablePdbError("unsupported Portable PDB table number: %d" % table_number)


def _table_index_size(row_count: int) -> int:
    # Roslyn and System.Reflection.Metadata use < 0x10000, not <=.
    return 2 if row_count < 0x10000 else 4


def _coded_index_size(tag_bits: int, row_count: int) -> int:
    return 2 if row_count < (1 << (16 - tag_bits)) else 4


def _decode_document_name(blob: Optional[bytes], blob_reader: "PortablePdb") -> Tuple[Optional[int], List[str], str, Optional[str]]:
    """Decode a Document.Name blob into a separator, parts, and joined name."""
    if not blob:
        return None, [], "", None

    separator = blob[0]
    if separator > 0x7F:
        return separator, [], "", "document name separator is not ASCII"

    reader = _BlobReader(blob)
    reader.read_byte()
    parts: List[str] = []
    error: Optional[str] = None
    while reader.remaining() > 0:
        try:
            handle = reader.read_compressed_uint()
        except PortablePdbError as e:
            error = "document name blob: %s" % e
            break
        part = blob_reader.get_blob(handle)
        if part is None:
            error = "document name part references invalid blob handle %d" % handle
            break
        parts.append(part.decode("utf-8", errors="replace"))

    # The separator byte is not part of the first part; parts are joined by
    # the separator.  A zero separator means no separator at all.
    if separator == 0:
        name = "".join(parts)
    else:
        name = chr(separator).join(parts)
    return separator, parts, name, error


def _decode_sequence_points(
    blob: Optional[bytes],
    initial_document_row_id: int,
) -> Tuple[List[SequencePoint], Optional[str]]:
    """Decode a MethodDebugInformation.SequencePoints blob.

    Malformed input yields whatever points could be decoded plus an error
    string.  A Document row id of zero means "nil document" and is preserved so
    the association layer can report a missing document instead of inventing a
    path.
    """
    if not blob:
        return [], None

    reader = _BlobReader(blob)
    points: List[SequencePoint] = []
    errors: List[str] = []
    try:
        local_signature = reader.read_compressed_uint()
        del local_signature
    except PortablePdbError as e:
        return [], "invalid local signature: %s" % e

    document_row_id = initial_document_row_id
    il_offset = 0
    previous_line: Optional[int] = None
    previous_column: Optional[int] = None
    first = True
    guard = 0

    while reader.remaining() > 0:
        guard += 1
        if guard > len(blob) * 2 + 2:
            errors.append("sequence point count exceeds a safe bound")
            break

        try:
            if first:
                if document_row_id == 0:
                    document_row_id = reader.read_compressed_uint()
                il_offset = reader.read_compressed_uint()
                first = False
            else:
                delta_il = reader.read_compressed_uint()
                if delta_il == 0:
                    document_row_id = reader.read_compressed_uint()
                else:
                    il_offset += delta_il

            delta_lines = reader.read_compressed_uint()
            if delta_lines != 0:
                delta_columns = reader.read_compressed_signed()
            else:
                delta_columns = reader.read_compressed_uint()

            if delta_lines == 0 and delta_columns == 0:
                point = SequencePoint(il_offset, HIDDEN_LINE, 0, HIDDEN_LINE, 0, document_row_id, True)
                points.append(point)
                continue

            if previous_line is None or previous_column is None:
                start_line = reader.read_compressed_uint()
                start_column = reader.read_compressed_uint()
            else:
                start_line = previous_line + reader.read_compressed_signed()
                start_column = previous_column + reader.read_compressed_signed()

            end_line = start_line + delta_lines
            end_column = start_column + delta_columns
            previous_line = start_line
            previous_column = start_column

            points.append(SequencePoint(il_offset, start_line, start_column, end_line, end_column, document_row_id, False))
        except PortablePdbError as e:
            errors.append(str(e))
            break

    return points, ("; ".join(errors) if errors else None)


class _IdentityCheck:
    def __init__(self, name: str):
        self.name = name
        self.status = "unavailable"
        self.detail: Optional[str] = None
        self.evidence: Dict[str, Any] = {}

    def to_dict(self) -> dict:
        return {
            "check": self.name,
            "status": self.status,
            "detail": self.detail,
            "evidence": dict(self.evidence),
        }


class DebugIdentity:
    """The result of the file-identity checks."""

    def __init__(self) -> None:
        self.status = "unavailable"
        self.checks: List[_IdentityCheck] = []
        self.pdb_id: Optional[bytes] = None
        self.codeview_ids: List[bytes] = []
        self.codeview_names: List[bytes] = []
        self.codeview_raw: List[bytes] = []
        self.reasons: List[dict] = []

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "pdb_id": self.pdb_id.hex() if self.pdb_id is not None else None,
            "checks": [check.to_dict() for check in self.checks],
            "codeview_ids": [value.hex() for value in self.codeview_ids],
            "codeview_names": [value.decode("utf-8", errors="replace") for value in self.codeview_names],
            "codeview_raw": [value.hex() for value in self.codeview_raw],
            "reasons": list(self.reasons),
        }


class MethodAssociation:
    """One MethodDef-to-debug-record association or non-association."""

    def __init__(
        self,
        methoddef_row_id: int,
        method_name: Optional[str],
        method_rva: Optional[int],
        pdb_row: Optional[MethodDebugInformationRow],
        identity: DebugIdentity,
    ):
        self.methoddef_row_id = methoddef_row_id
        self.method_name = method_name
        self.method_rva = method_rva
        self.pdb_row = pdb_row
        self.pdb_row_id = pdb_row.row_id if pdb_row is not None else None
        self.method_row_present = True
        self.identity = identity
        self.status = "unresolved"
        self.reasons: List[dict] = []
        self.line_check: Dict[str, Any] = {}
        self.method_row_check: Dict[str, Any] = {}
        self._document: Optional[DocumentRow] = pdb_row.document if pdb_row is not None else None
        self._sequence_points: Optional[List[SequencePoint]] = None

    @property
    def methoddef_token(self) -> int:
        return METHODDEF_TOKEN_PREFIX | self.methoddef_row_id

    @property
    def document(self) -> Optional[DocumentRow]:
        """The document evidence, only after the file identity checks pass."""
        if self.identity.status != "match":
            return None
        return self._document

    @document.setter
    def document(self, value: Optional[DocumentRow]) -> None:
        self._document = value

    @property
    def sequence_points(self) -> List[SequencePoint]:
        """Decoded points, only after the file identity checks pass."""
        if self.identity.status != "match":
            return []
        if self._sequence_points is None and self.pdb_row is not None:
            self._sequence_points = self.pdb_row.sequence_points
        return self._sequence_points or []

    @sequence_points.setter
    def sequence_points(self, value: List[SequencePoint]) -> None:
        self._sequence_points = value

    def add_reason(self, code: str, detail: Optional[str] = None) -> None:
        reason: Dict[str, Any] = {"code": code}
        if detail:
            reason["detail"] = detail
        self.reasons.append(reason)

    def to_dict(self) -> dict:
        identity_established = self.identity.status == "match"
        # Raw PDB records stay available as rejected evidence, but a source
        # path and decoded line locations are attached to a method only after
        # the file identity checks pass.
        document_for_evidence = self._document
        document = self.document
        sequence_points = self.sequence_points
        raw_records: Dict[str, Any] = {
            "method_debug_information": self.pdb_row.raw.hex() if self.pdb_row is not None else None,
            "sequence_points_blob": (
                self.pdb_row.sequence_points_blob.hex()
                if self.pdb_row is not None and self.pdb_row.sequence_points_blob is not None
                else None
            ),
            "document": (
                document_for_evidence.raw.hex() if document_for_evidence is not None else None
            ),
            "document_name_blob": (
                document_for_evidence.name_blob.hex()
                if identity_established
                and document_for_evidence is not None
                and document_for_evidence.name_blob is not None
                else None
            ),
        }
        return {
            "identifier": {
                "methoddef_token": self.methoddef_token,
                "methoddef_token_hex": "0x%08x" % self.methoddef_token,
                "methoddef_row_id": self.methoddef_row_id,
                "pdb_table": "MethodDebugInformation",
                "pdb_row_id": self.pdb_row.row_id if self.pdb_row is not None else None,
                "identity_kind": "codeview-rsds-20-byte-pdb-id",
                "identity_value": self.identity.pdb_id.hex() if self.identity.pdb_id is not None else None,
            },
            "method": {
                "name": self.method_name,
                "rva": self.method_rva,
            },
            "raw_records": raw_records,
            "document": document.to_dict() if document is not None else None,
            "document_row_ids": sorted(set(point.document_row_id for point in sequence_points)),
            "sequence_points": [point.to_dict() for point in sequence_points],
            "pdb_side_evidence_withheld": not identity_established,
            "checks": {
                "file_identity": self.identity.to_dict(),
                "method_row": dict(self.method_row_check),
                "line_numbers": dict(self.line_check),
                "missing_debug_record": {
                    "missing": any(
                        reason["code"] in ("missing-debug-record", "empty-debug-record") for reason in self.reasons
                    ),
                    "reason": next(
                        (
                            reason["code"]
                            for reason in self.reasons
                            if reason["code"] in ("missing-debug-record", "empty-debug-record")
                        ),
                        None,
                    ),
                },
            },
            "status": self.status,
            "unresolved_reasons": list(self.reasons),
            "trusted": False,
        }


class AssociationResult:
    """Result of associating one Portable PDB with one explicitly supplied assembly."""

    def __init__(self, pdb: "PortablePdb", assembly: Any):
        self.pdb = pdb
        self.assembly = assembly
        self.identity = DebugIdentity()
        self.assembly_methoddef_count: Optional[int] = None
        self.methods: List[MethodAssociation] = []
        self.notes: List[str] = [
            "Document names are evidence only; no document file was opened, searched, or fetched.",
            "A successful association only means the PDB id and MethodDef row layout matched; it does not assert that the debug information is trustworthy.",
            "Only the explicitly supplied assembly and this PDB were read.",
        ]

    def to_dict(self) -> dict:
        associated = sum(1 for method in self.methods if method.status == "associated")
        missing_records = sum(
            1
            for method in self.methods
            if any(reason["code"] in ("missing-debug-record", "empty-debug-record") for reason in method.reasons)
        )
        missing_documents = sum(
            1 for method in self.methods if any(reason["code"] == "missing-document" for reason in method.reasons)
        )
        enumerated_method_count = len(self.methods)
        comparison_method_count = (
            self.assembly_methoddef_count
            if self.assembly_methoddef_count is not None
            else enumerated_method_count
        )
        pdb_rows_without_methoddef = max(0, self.pdb.method_debug_information_row_count - comparison_method_count)
        identity_mismatch = self.identity.status == "mismatch"
        return {
            "pdb": {
                "name": self.pdb.name,
                "pdb_id": self.pdb.pdb_id.hex(),
                "entry_point_token": "0x%08x" % self.pdb.entry_point_token,
                "external_tables_mask": "0x%016x" % self.pdb.external_tables_mask,
                "external_row_counts": dict((str(key), value) for key, value in self.pdb.external_row_counts.items()),
                "table_row_counts": dict(
                    (PDB_TABLE_NAMES[key], self.pdb.table_row_counts[key]) for key in sorted(PDB_TABLE_NAMES)
                ),
                "table_row_sizes": dict(
                    (PDB_TABLE_NAMES[key], self.pdb.table_row_sizes[key]) for key in sorted(PDB_TABLE_NAMES)
                ),
                "document_row_count": self.pdb.document_row_count,
                "method_debug_information_row_count": self.pdb.method_debug_information_row_count,
                "pdb_stream_header": self.pdb.pdb_stream_header,
                "streams": [stream.to_dict() for stream in self.pdb.streams],
                "warnings": list(self.pdb.warnings),
            },
            "identity": self.identity.to_dict(),
            "documents": [document.to_dict() for document in self.pdb.documents],
            "methods": [method.to_dict() for method in self.methods],
            "summary": {
                "methods_total": enumerated_method_count,
                "associated": associated,
                "unresolved": enumerated_method_count - associated,
                "missing_debug_records": missing_records,
                "methods_with_missing_document": missing_documents,
                "pdb_rows_without_methoddef": pdb_rows_without_methoddef,
                "file_identity": self.identity.status,
                "identity_failed": identity_mismatch,
                "method_enumeration_truncated": (
                    self.assembly_methoddef_count is not None
                    and enumerated_method_count < self.assembly_methoddef_count
                ),
                "assembly_methoddef_rows": self.assembly_methoddef_count,
            },
            "notes": list(self.notes),
            "trusted": False,
        }


class PdbTable:
    """A read-only view of one decoded Portable PDB table.

    Rows are 1-indexed through :meth:`get_with_row_index` and 0-indexed through
    ``[]``, matching the rest of dnfile's metadata table API.
    """

    def __init__(self, pdb: "PortablePdb", number: int, name: str, rows: List[Any], row_size: int):
        self._pdb = pdb
        self.number = number
        self.name = name
        self.rows = rows
        self.num_rows = len(rows)
        self.row_size = row_size

    def __getitem__(self, index: int) -> Any:
        return self.rows[index]

    def __len__(self) -> int:
        return len(self.rows)

    def __iter__(self):
        return iter(self.rows)

    def get_with_row_index(self, row_index: int) -> Optional[Any]:
        if row_index < 1 or row_index > len(self.rows):
            return None
        return self.rows[row_index - 1]


class PortablePdb:
    """A limited, offline Portable PDB reader.

    Use :meth:`from_path` or :meth:`from_bytes` to construct an instance.  The
    reader never follows Document names and never performs network access.
    """

    def __init__(self, data: bytes, name: Optional[str] = None):
        self.data = data
        self.name = name
        self.streams: List[MetadataStream] = []
        self.streams_by_name: Dict[bytes, MetadataStream] = {}
        self.version: bytes = b""
        self.flags = 0
        self.warnings: List[str] = []

        self.pdb_id: bytes = b""
        self.pdb_stream_header: Dict[str, Any] = {}
        self.entry_point_token = 0
        self.external_tables_mask = 0
        self.external_row_counts: Dict[int, int] = {}
        self.internal_tables_mask = 0
        self.internal_sorted_mask = 0
        self.internal_row_counts: List[int] = [0] * TABLE_COUNT
        self.table_row_counts: List[int] = [0] * TABLE_COUNT
        self.table_row_sizes: Dict[int, int] = dict((number, 0) for number in PDB_TABLE_NAMES)
        self.heap_sizes = 0
        self.strings_index_size = 2
        self.guid_index_size = 2
        self.blob_index_size = 2

        self._strings_data = b""
        self._guid_data = b""
        self._blob_data = b""
        self._table_data: Dict[int, bytes] = {}
        self.documents: List[DocumentRow] = []
        self.method_debug_information: List[MethodDebugInformationRow] = []
        self.state_machine_methods: List[StateMachineMethodRow] = []
        self.Document: PdbTable
        self.MethodDebugInformation: PdbTable
        self.StateMachineMethod: PdbTable
        self.tables: Dict[int, PdbTable] = {}

        self._parse()
        self._build_table_views()

    @classmethod
    def from_path(cls, path: Union[str, "os.PathLike[str]"]) -> "PortablePdb":
        with open(path, "rb") as handle:
            data = handle.read()
        return cls(data, name=os.fspath(path))

    @classmethod
    def from_bytes(cls, data: bytes, name: Optional[str] = None) -> "PortablePdb":
        return cls(bytes(data), name=name)

    @property
    def document_row_count(self) -> int:
        return self.internal_row_counts[TABLE_DOCUMENT]

    @property
    def method_debug_information_row_count(self) -> int:
        return self.internal_row_counts[TABLE_METHOD_DEBUG_INFORMATION]

    @property
    def external_methoddef_row_count(self) -> Optional[int]:
        return self.external_row_counts.get(6)

    @property
    def external_row_counts_by_name(self) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for table_number, row_count in sorted(self.external_row_counts.items()):
            try:
                name = enums.MetadataTables(table_number).name
            except ValueError:
                name = "Table%d" % table_number
            result[name] = row_count
        return result

    @property
    def table_row_counts_by_name(self) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for table_number in range(TABLE_COUNT):
            if table_number in PDB_TABLE_NAMES:
                name = PDB_TABLE_NAMES[table_number]
            else:
                try:
                    name = enums.MetadataTables(table_number).name
                except ValueError:
                    name = "Table%d" % table_number
            result[name] = self.table_row_counts[table_number]
        return result

    @property
    def table_row_sizes_by_name(self) -> Dict[str, int]:
        return dict((PDB_TABLE_NAMES[number], size) for number, size in self.table_row_sizes.items())

    def row_count(self, table: Union[int, str]) -> int:
        return self.table_row_counts[self._table_number(table)]

    def row_size(self, table: Union[int, str]) -> int:
        return self.table_row_sizes.get(self._table_number(table), 0)

    def stream(self, name: Union[bytes, str]) -> Optional[MetadataStream]:
        if isinstance(name, str):
            name = name.encode("utf-8")
        return self.streams_by_name.get(name)

    def table_index_size(self, table: Union[int, str]) -> int:
        """Return the on-disk width (2 or 4 bytes) of a table row reference.

        The value is derived from the combined row counts: external counts from
        the ``#Pdb`` stream for type-system tables, and internal counts from the
        metadata tables stream for Portable PDB tables.
        """
        number = self._table_number(table)
        if number < 0 or number >= TABLE_COUNT:
            raise PortablePdbError("invalid table number: %r" % (table,))
        return _table_index_size(self.table_row_counts[number])

    def get_table_index_size(self, table: Union[int, str]) -> int:
        return self.table_index_size(table)

    def get_document(self, row_id: int) -> Optional[DocumentRow]:
        if row_id < 1 or row_id > len(self.documents):
            return None
        return self.documents[row_id - 1]

    def get_method_debug_information(self, row_id: int) -> Optional[MethodDebugInformationRow]:
        if row_id < 1 or row_id > len(self.method_debug_information):
            return None
        return self.method_debug_information[row_id - 1]

    def get_string(self, index: int) -> Optional[str]:
        if index == 0:
            return ""
        if index is None or index < 0 or index >= len(self._strings_data):
            return None
        end = self._strings_data.find(b"\x00", index)
        if end < 0:
            end = len(self._strings_data)
        return self._strings_data[index:end].decode("utf-8", errors="replace")

    def get_blob(self, index: int) -> Optional[bytes]:
        if index == 0:
            return b""
        if index is None or index < 0 or index >= len(self._blob_data):
            return None
        result = utils.read_compressed_int(self._blob_data[index:])
        if result is None:
            return None
        length, size = result
        start = index + size
        end = start + length
        if end > len(self._blob_data):
            return None
        return self._blob_data[start:end]

    def get_guid(self, index: int) -> Optional[bytes]:
        if index == 0:
            return None
        if index is None or index < 0:
            return None
        start = (index - 1) * 16
        end = start + 16
        if start < 0 or end > len(self._guid_data):
            return None
        return self._guid_data[start:end]

    def _build_table_views(self) -> None:
        self.Document = PdbTable(
            self, TABLE_DOCUMENT, "Document", self.documents, self.table_row_sizes.get(TABLE_DOCUMENT, 0)
        )
        self.MethodDebugInformation = PdbTable(
            self,
            TABLE_METHOD_DEBUG_INFORMATION,
            "MethodDebugInformation",
            self.method_debug_information,
            self.table_row_sizes.get(TABLE_METHOD_DEBUG_INFORMATION, 0),
        )
        self.StateMachineMethod = PdbTable(
            self,
            TABLE_STATE_MACHINE_METHOD,
            "StateMachineMethod",
            self.state_machine_methods,
            self.table_row_sizes.get(TABLE_STATE_MACHINE_METHOD, 0),
        )
        self.tables = {
            TABLE_DOCUMENT: self.Document,
            TABLE_METHOD_DEBUG_INFORMATION: self.MethodDebugInformation,
            TABLE_STATE_MACHINE_METHOD: self.StateMachineMethod,
        }

    def associate(self, assembly: Any, max_methods: Optional[int] = None) -> AssociationResult:
        """Associate this PDB with one explicitly supplied assembly.

        ``assembly`` may be a path, PE bytes, or an existing ``dnfile.dnPE``
        instance.  No sibling file is searched, no Document name is opened, and
        no network request is made.
        """
        pe = _coerce_assembly(assembly)
        result = AssociationResult(self, pe)
        result.identity = self._check_identity(pe)

        method_table = None
        if getattr(pe, "net", None) is not None and getattr(pe.net, "mdtables", None) is not None:
            method_table = getattr(pe.net.mdtables, "MethodDef", None)

        method_count = method_table.num_rows if method_table is not None else 0
        result.assembly_methoddef_count = method_count
        if max_methods is not None:
            method_count = min(method_count, max_methods)

        identity_ok = result.identity.status == "match"
        for row_id in range(1, method_count + 1):
            method_row = method_table.get_with_row_index(row_id) if method_table is not None else None
            method_name_value = getattr(method_row, "Name", None)
            method_name = str(method_name_value) if method_name_value is not None else None
            method_rva = getattr(method_row, "Rva", None)
            pdb_row = self.get_method_debug_information(row_id)
            association = MethodAssociation(row_id, method_name, method_rva, pdb_row, result.identity)
            association.method_row_present = method_row is not None
            self._classify_association(association, identity_ok)
            result.methods.append(association)

        return result

    def _classify_association(self, association: MethodAssociation, identity_ok: bool) -> None:
        # Check the method row mapping independently of the file identity.
        method_row_check: Dict[str, Any] = {
            "methoddef_row_id": association.methoddef_row_id,
            "methoddef_row_present": association.method_row_present,
            "pdb_row_id": association.pdb_row_id,
        }
        if not association.method_row_present:
            method_row_check["status"] = "methoddef-row-missing"
            method_row_check["matched"] = False
        elif association.pdb_row is None:
            method_row_check["status"] = "missing-debug-record"
            method_row_check["matched"] = False
        elif association.pdb_row_id == association.methoddef_row_id:
            method_row_check["status"] = "match"
            method_row_check["matched"] = True
        else:
            method_row_check["status"] = "mismatch"
            method_row_check["matched"] = False
        association.method_row_check = method_row_check

        row = association.pdb_row
        if row is not None:
            points = row.sequence_points
            association.sequence_points = points
            association.document = row.document
            if association.document is None:
                for point in points:
                    if point.document_row_id != 0:
                        association.document = self.get_document(point.document_row_id)
                        break

        if not identity_ok:
            association.add_reason("identity-not-established", "file identity checks did not all pass")
            association.line_check = {"status": "not-checked", "detail": "identity not established"}
            association.status = "unresolved"
            return

        if not association.method_row_present:
            association.add_reason("methoddef-row-missing", "MethodDef row could not be read from the assembly")
            association.line_check = {"status": "unavailable", "detail": "MethodDef row missing"}
            association.status = "unresolved"
            return

        if row is None:
            association.add_reason("missing-debug-record", "no MethodDebugInformation row for this MethodDef rid")
            association.line_check = {"status": "unavailable", "detail": "no MethodDebugInformation row"}
            association.status = "unresolved"
            return

        points = row.sequence_points

        if row.document_row_id == 0 and (row.sequence_points_blob is None or len(row.sequence_points_blob) == 0):
            association.add_reason("empty-debug-record", "row has neither an initial Document nor sequence points")
            association.line_check = {"status": "empty", "detail": "row has no debug payload", "reasons": ["empty-debug-record"]}
            association.status = "unresolved"
            return

        visible = [point for point in points if not point.is_hidden]
        line_check: Dict[str, Any] = {
            "status": "ok",
            "visible_point_count": len(visible),
            "hidden_point_count": len(points) - len(visible),
            "min_line": min([point.start_line for point in visible], default=None),
            "max_line": max([point.end_line for point in visible], default=None),
            "min_il_offset": min([point.il_offset for point in points], default=None),
            "max_il_offset": max([point.il_offset for point in points], default=None),
            "reasons": [],
        }

        # Check 1: the MethodDebugInformation row exists but carries no useful
        # sequence-point payload.  This is separate from a missing Document.
        if row.sequence_points_blob is None or len(row.sequence_points_blob) == 0:
            association.add_reason("missing-sequence-points", "MethodDebugInformation row has no sequence points blob")
            line_check["status"] = "empty"
            line_check["reasons"].append("missing-sequence-points")
        elif not points:
            association.add_reason("missing-sequence-points", "sequence points blob decoded to no points")
            line_check["status"] = "empty"
            line_check["reasons"].append("missing-sequence-points")

        if row.decode_error is not None:
            association.add_reason("sequence-points-malformed", row.decode_error)
            line_check["status"] = "invalid"
            line_check["reasons"].append("sequence-points-malformed")

        # Check 2: document evidence.  A nil or out-of-range Document handle is
        # reported without substituting a filename or opening any file.
        missing_document_ids = set()
        if row.document_row_id != 0 and row.document is None:
            missing_document_ids.add(row.document_row_id)
        for point in points:
            if point.document_row_id == 0:
                missing_document_ids.add(0)
            elif self.get_document(point.document_row_id) is None:
                missing_document_ids.add(point.document_row_id)
        if missing_document_ids:
            if 0 in missing_document_ids:
                association.add_reason("missing-document", "sequence points use a nil Document handle")
            ids = sorted(value for value in missing_document_ids if value != 0)
            if ids:
                association.add_reason("missing-document", "Document row(s) not present: %s" % ", ".join(str(value) for value in ids))
            line_check["status"] = "invalid"
            line_check["reasons"].append("missing-document")

        if points and not visible:
            association.add_reason("no-visible-sequence-points", "all sequence points are hidden")
            if line_check["status"] == "ok":
                line_check["status"] = "hidden-only"
            line_check["reasons"].append("no-visible-sequence-points")

        # Check 3: method line-number evidence.  These are structural checks on
        # the decoded values, not a claim that a source file contains the line.
        bad_lines = [
            point
            for point in visible
            if not (0 <= point.start_line < HIDDEN_LINE)
            or not (0 <= point.end_line < HIDDEN_LINE)
            or point.end_line < point.start_line
        ]
        if bad_lines:
            association.add_reason("line-number-out-of-range", "one or more visible sequence points have invalid line numbers")
            line_check["status"] = "invalid"
            line_check["reasons"].append("line-number-out-of-range")

        bad_columns = [
            point
            for point in visible
            if not (0 <= point.start_column <= MAX_COLUMN) or not (0 <= point.end_column <= MAX_COLUMN)
        ]
        if bad_columns:
            association.add_reason("line-column-out-of-range", "one or more visible sequence points have invalid columns")
            line_check["status"] = "invalid"
            line_check["reasons"].append("line-column-out-of-range")

        last_il = -1
        for index, point in enumerate(points):
            if point.il_offset < last_il:
                association.add_reason(
                    "sequence-point-il-order",
                    "sequence point %d has non-monotonic IL offset %d" % (index, point.il_offset),
                )
                line_check["status"] = "invalid"
                line_check["reasons"].append("sequence-point-il-order")
                break
            last_il = point.il_offset

        association.line_check = line_check
        association.status = "associated" if not association.reasons else "unresolved"

    def _check_identity(self, pe: Any) -> DebugIdentity:
        identity = DebugIdentity()
        identity.pdb_id = self.pdb_id

        codeview_records = _read_codeview_records(pe)
        rsds_records = [record for record in codeview_records if record.signature == b"RSDS"]
        identity.codeview_ids = [record.identity for record in rsds_records if record.identity is not None]
        identity.codeview_names = [record.pdb_name for record in rsds_records if record.pdb_name]
        identity.codeview_raw = [record.data for record in codeview_records]

        # Inspect the PDB id independently from the MethodDef row count.
        pdb_id_check = _IdentityCheck("pdb-id")
        pdb_id_check.evidence = {
            "pdb_id": self.pdb_id.hex(),
            "codeview_rsds_ids": [value.hex() for value in identity.codeview_ids],
            "codeview_pdb_names": [value.decode("utf-8", errors="replace") for value in identity.codeview_names],
        }
        if not rsds_records:
            pdb_id_check.status = "unavailable"
            pdb_id_check.detail = "assembly has no CodeView RSDS record"
            identity.reasons.append({"code": "assembly-no-codeview-rsds", "detail": pdb_id_check.detail})
        elif any(record.identity == self.pdb_id for record in rsds_records):
            pdb_id_check.status = "match"
            if sum(1 for record in rsds_records if record.identity == self.pdb_id) > 1:
                pdb_id_check.detail = "multiple CodeView RSDS records match; the first one is evidence"
        else:
            pdb_id_check.status = "mismatch"
            pdb_id_check.detail = "no CodeView RSDS record matches the #Pdb id"
            identity.reasons.append(
                {
                    "code": "pdb-id-mismatch",
                    "detail": "pdb=%s codeview=%s"
                    % (self.pdb_id.hex(), ", ".join(value.hex() for value in identity.codeview_ids) or "none"),
                }
            )
        identity.checks.append(pdb_id_check)

        assembly_methoddef_count: Optional[int] = None
        if getattr(pe, "net", None) is not None and getattr(pe.net, "mdtables", None) is not None:
            method_table = getattr(pe.net.mdtables, "MethodDef", None)
            if method_table is not None:
                assembly_methoddef_count = method_table.num_rows

        pdb_methoddef_count = self.external_methoddef_row_count
        rowcount_check = _IdentityCheck("methoddef-row-count")
        rowcount_check.evidence = {
            "pdb_external_methoddef_rows": pdb_methoddef_count,
            "assembly_methoddef_rows": assembly_methoddef_count,
        }
        if pdb_methoddef_count is None:
            rowcount_check.status = "unavailable"
            rowcount_check.detail = "the #Pdb stream does not declare an external MethodDef row count"
            identity.reasons.append({"code": "methoddef-rowcount-missing", "detail": rowcount_check.detail})
        elif assembly_methoddef_count is None:
            rowcount_check.status = "unavailable"
            rowcount_check.detail = "the assembly has no readable MethodDef table"
            identity.reasons.append({"code": "assembly-methoddef-unavailable", "detail": rowcount_check.detail})
        elif pdb_methoddef_count == assembly_methoddef_count:
            rowcount_check.status = "match"
        else:
            rowcount_check.status = "mismatch"
            rowcount_check.detail = "PDB declares %d MethodDef rows, assembly has %d" % (
                pdb_methoddef_count,
                assembly_methoddef_count,
            )
            identity.reasons.append(
                {"code": "methoddef-rowcount-mismatch", "detail": rowcount_check.detail}
            )
        identity.checks.append(rowcount_check)

        entrypoint_check = _IdentityCheck("entry-point")
        assembly_entrypoint: Optional[int] = None
        assembly_flags = 0
        if getattr(pe, "net", None) is not None:
            assembly_entrypoint = getattr(pe.net.struct, "EntryPointTokenOrRva", None)
            assembly_flags = getattr(pe.net.struct, "Flags", 0) or 0
        entrypoint_check.evidence = {
            "pdb_entry_point_token": "0x%08x" % self.entry_point_token,
            "assembly_entry_point": "0x%08x" % assembly_entrypoint if assembly_entrypoint is not None else None,
            "assembly_native_entrypoint": bool(assembly_flags & NATIVE_ENTRYPOINT_FLAG),
        }
        if self.entry_point_token == 0 and (assembly_entrypoint in (None, 0)):
            entrypoint_check.status = "match"
        elif self.entry_point_token == 0 or assembly_entrypoint in (None, 0):
            entrypoint_check.status = "not-applicable"
            entrypoint_check.detail = "entry point is not available on both sides"
        elif assembly_flags & NATIVE_ENTRYPOINT_FLAG:
            entrypoint_check.status = "not-applicable"
            entrypoint_check.detail = "assembly entry point is a native RVA, not a MethodDef token"
        elif self.entry_point_token == assembly_entrypoint:
            entrypoint_check.status = "match"
        else:
            entrypoint_check.status = "mismatch"
            entrypoint_check.detail = "PDB entry point token differs from assembly entry point"
            identity.reasons.append({"code": "entrypoint-mismatch", "detail": entrypoint_check.detail})
        identity.checks.append(entrypoint_check)

        required = [pdb_id_check, rowcount_check]
        if any(check.status == "mismatch" for check in required) or entrypoint_check.status == "mismatch":
            identity.status = "mismatch"
        elif all(check.status == "match" for check in required):
            identity.status = "match"
        else:
            identity.status = "unavailable"
        return identity

    def _table_number(self, table: Union[int, str]) -> int:
        if isinstance(table, str):
            if table in PDB_TABLE_NUMBERS:
                return PDB_TABLE_NUMBERS[table]
            try:
                return enums.MetadataTables[table].value
            except KeyError:
                pass
            try:
                return int(table, 0)
            except ValueError:
                raise PortablePdbError("unknown table name: %r" % (table,))
        return int(table)

    def _add_warning(self, message: str) -> None:
        self.warnings.append(message)
        logger.warning(message)

    def _parse(self) -> None:
        self._parse_metadata_root()
        self._parse_pdb_stream()
        self._parse_tables_stream()
        self._parse_heaps()
        self._parse_table_rows()

    def _parse_metadata_root(self) -> None:
        data = self.data
        if len(data) < 16 or data[:4] != METADATA_SIGNATURE:
            raise PortablePdbError("not a Portable PDB: missing BSJB metadata signature")

        major, minor, reserved, version_length = struct.unpack_from("<HHII", data, 4)
        del major, minor, reserved
        pos = 16
        if version_length > len(data) - pos:
            raise PortablePdbError("Portable PDB version string is truncated")
        self.version = data[pos:pos + version_length]
        pos += version_length
        if pos + 4 > len(data):
            raise PortablePdbError("Portable PDB metadata root is truncated")
        self.flags, stream_count = struct.unpack_from("<HH", data, pos)
        pos += 4

        for index in range(stream_count):
            if pos + 8 > len(data):
                raise PortablePdbError("Portable PDB stream table is truncated")
            offset, size = struct.unpack_from("<II", data, pos)
            pos += 8
            try:
                end = data.index(b"\x00", pos)
            except ValueError:
                raise PortablePdbError("Portable PDB stream name is not terminated")
            name = data[pos:end]
            name_length = end - pos + 1
            pos += (name_length + 3) & ~3

            if offset > len(data):
                self._add_warning("stream %r starts beyond the end of the PDB" % name)
                stream_data = b""
            else:
                available = min(size, len(data) - offset)
                if available != size:
                    self._add_warning("stream %r is truncated: declared %d, available %d" % (name, size, available))
                stream_data = data[offset:offset + available]
            stream = MetadataStream(name, offset, size, stream_data)
            self.streams.append(stream)
            self.streams_by_name[name] = stream

    def _parse_pdb_stream(self) -> None:
        stream = self.streams_by_name.get(PDB_STREAM_NAME)
        if stream is None:
            raise PortablePdbError("Portable PDB is missing the #Pdb stream")
        data = stream.data
        if len(data) < 32:
            raise PortablePdbError("#Pdb stream is truncated (need at least 32 bytes)")

        self.pdb_id = data[0:20]
        self.entry_point_token = struct.unpack_from("<I", data, 20)[0]
        self.external_tables_mask = struct.unpack_from("<Q", data, 24)[0]
        pos = 32

        if self.entry_point_token != 0:
            if (self.entry_point_token & 0x7F000000) != METHODDEF_TOKEN_PREFIX:
                self._add_warning(
                    "#Pdb entry point token 0x%08x is not a MethodDef token" % self.entry_point_token
                )
            if (self.entry_point_token & 0xFFFFFF) == 0:
                self._add_warning("#Pdb entry point token has row id zero")

        if self.external_tables_mask & FORBIDDEN_EXTERNAL_MASK:
            self._add_warning(
                "#Pdb external table mask has forbidden bits: 0x%016x"
                % (self.external_tables_mask & FORBIDDEN_EXTERNAL_MASK)
            )
        if self.external_tables_mask & ~((1 << TYPE_SYSTEM_TABLE_COUNT) - 1):
            self._add_warning("#Pdb external table mask references non-type-system tables")

        for table_number in range(TABLE_COUNT):
            if not (self.external_tables_mask & (1 << table_number)):
                continue
            if pos + 4 > len(data):
                self._add_warning(
                    "#Pdb stream is truncated before the row count for table %d" % table_number
                )
                break
            row_count = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            if row_count > MAX_ROW_COUNT:
                self._add_warning(
                    "#Pdb external row count %d for table %d exceeds the format limit" % (row_count, table_number)
                )
            if table_number not in ALLOWED_EXTERNAL_TABLES:
                self._add_warning(
                    "#Pdb external table %d is not an allowed type-system table" % table_number
                )
            self.external_row_counts[table_number] = row_count

        trailing = data[pos:]
        if any(byte != 0 for byte in trailing):
            self._add_warning("#Pdb stream has %d non-zero trailing byte(s)" % len(trailing))
        self.pdb_stream_header = {
            "raw": data[:pos].hex(),
            "pdb_id": self.pdb_id.hex(),
            "entry_point_token": "0x%08x" % self.entry_point_token,
            "external_tables_mask": "0x%016x" % self.external_tables_mask,
            "external_row_counts": dict((str(key), value) for key, value in sorted(self.external_row_counts.items())),
        }

    def _parse_tables_stream(self) -> None:
        stream = None
        for name in TABLES_STREAM_NAMES:
            stream = self.streams_by_name.get(name)
            if stream is not None:
                break
        if stream is None:
            self._add_warning("Portable PDB has no #~ or #- metadata tables stream")
            self._recompute_row_counts()
            return

        data = stream.data
        if len(data) < 24:
            raise PortablePdbError("metadata tables stream is truncated")

        reserved_1, major, minor, heap_sizes, reserved_2 = struct.unpack_from("<IBBBB", data, 0)
        del major, minor
        if reserved_1 != 0 or reserved_2 != 0:
            self._add_warning("metadata tables stream has non-zero reserved values")
        self.heap_sizes = heap_sizes
        self.strings_index_size = 4 if heap_sizes & 0x01 else 2
        self.guid_index_size = 4 if heap_sizes & 0x02 else 2
        self.blob_index_size = 4 if heap_sizes & 0x04 else 2

        self.internal_tables_mask, self.internal_sorted_mask = struct.unpack_from("<QQ", data, 8)
        pos = 24

        for table_number in range(TABLE_COUNT):
            if not (self.internal_tables_mask & (1 << table_number)):
                continue
            if pos + 4 > len(data):
                self._add_warning(
                    "metadata tables stream is truncated before the row count for table %d" % table_number
                )
                break
            row_count = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            if row_count > MAX_ROW_COUNT:
                self._add_warning(
                    "internal row count %d for table %d exceeds the format limit" % (row_count, table_number)
                )
            self.internal_row_counts[table_number] = row_count
            if table_number < TYPE_SYSTEM_TABLE_COUNT:
                self._add_warning(
                    "metadata tables stream declares type-system table %d; a standalone Portable PDB should not"
                    % table_number
                )

        if heap_sizes & 0x40:
            # Extra data dword used by some metadata table stream variants.
            pos += 4

        self._recompute_row_counts()
        external_methoddef_count = self.external_row_counts.get(6)
        internal_mdi_count = self.internal_row_counts[TABLE_METHOD_DEBUG_INFORMATION]
        if external_methoddef_count is not None and internal_mdi_count > external_methoddef_count:
            self._add_warning(
                "MethodDebugInformation has %d rows but the external MethodDef count is %d"
                % (internal_mdi_count, external_methoddef_count)
            )
        for table_number in sorted(PDB_TABLE_NAMES):
            self.table_row_sizes[table_number] = self._schema_row_size(table_number)

        # Rows are stored in ascending table-number order.
        for table_number in range(TABLE_COUNT):
            if not (self.internal_tables_mask & (1 << table_number)):
                continue
            if table_number < TYPE_SYSTEM_TABLE_COUNT:
                # A well-formed standalone PDB should not carry type-system
                # rows.  If one is present we cannot size it, so stop rather
                # than misalign every later table.
                if self.internal_row_counts[table_number]:
                    self._add_warning(
                        "cannot size internal type-system table %d; later table data is not read"
                        % table_number
                    )
                    break
                continue
            if table_number not in PDB_TABLE_NAMES:
                if self.internal_row_counts[table_number]:
                    self._add_warning(
                        "cannot size unsupported internal table %d; later table data is not read" % table_number
                    )
                break
            row_size = self.table_row_sizes.get(table_number, 0)
            row_count = self.internal_row_counts[table_number]
            total = row_size * row_count
            if total == 0:
                self._table_data[table_number] = b""
                continue
            available = max(0, len(data) - pos)
            if available < total:
                self._add_warning(
                    "table %s is truncated: need %d bytes, have %d"
                    % (PDB_TABLE_NAMES.get(table_number, table_number), total, available)
                )
            chunk = data[pos:pos + min(total, available)]
            self._table_data[table_number] = chunk
            pos += len(chunk)
            if len(chunk) < total:
                # Do not attempt to locate later tables after a truncated one.
                break

        if pos < len(data) and any(byte != 0 for byte in data[pos:]):
            self._add_warning("metadata tables stream has %d non-zero trailing byte(s) after the last table" % (len(data) - pos))

    def _recompute_row_counts(self) -> None:
        for table_number in range(TABLE_COUNT):
            if table_number < TYPE_SYSTEM_TABLE_COUNT:
                self.table_row_counts[table_number] = self.external_row_counts.get(table_number, 0)
            else:
                self.table_row_counts[table_number] = self.internal_row_counts[table_number]

    def _schema_row_size(self, table_number: int) -> int:
        name, columns = _table_schema(table_number)
        del name
        size = 0
        for column in columns:
            if column.kind == "u16":
                size += 2
            elif column.kind == "u32":
                size += 4
            elif column.kind == "strings":
                size += self.strings_index_size
            elif column.kind == "guid":
                size += self.guid_index_size
            elif column.kind == "blob":
                size += self.blob_index_size
            elif column.kind == "table":
                size += _table_index_size(self.table_row_counts[column.argument])
            elif column.kind == "coded":
                tag_bits, tables = column.argument
                max_rows = max([self.table_row_counts[value] for value in tables], default=0)
                size += _coded_index_size(tag_bits, max_rows)
            else:
                raise PortablePdbError("unknown column kind: %r" % (column.kind,))
        return size

    def _parse_heaps(self) -> None:
        strings = self.streams_by_name.get(STRINGS_STREAM_NAME)
        guids = self.streams_by_name.get(GUID_STREAM_NAME)
        blobs = self.streams_by_name.get(BLOB_STREAM_NAME)
        self._strings_data = strings.data if strings is not None else b""
        self._guid_data = guids.data if guids is not None else b""
        self._blob_data = blobs.data if blobs is not None else b""

    def _parse_table_rows(self) -> None:
        self._parse_document_rows()
        self._parse_method_debug_information_rows()
        self._parse_state_machine_method_rows()

    def _parse_document_rows(self) -> None:
        data = self._table_data.get(TABLE_DOCUMENT, b"")
        row_size = self.table_row_sizes.get(TABLE_DOCUMENT, 0)
        row_count = self.internal_row_counts[TABLE_DOCUMENT]
        if row_size == 0:
            return

        for index in range(row_count):
            offset = index * row_size
            if offset + row_size > len(data):
                self._add_warning("Document table row %d is truncated" % (index + 1))
                break
            raw = data[offset:offset + row_size]
            pos = 0
            name_offset = _read_uint(raw, pos, self.blob_index_size)
            pos += self.blob_index_size
            hash_algorithm_index = _read_uint(raw, pos, self.guid_index_size)
            pos += self.guid_index_size
            hash_offset = _read_uint(raw, pos, self.blob_index_size)
            pos += self.blob_index_size
            language_index = _read_uint(raw, pos, self.guid_index_size)

            name_blob = self.get_blob(name_offset) if name_offset else None
            separator, parts, name, decode_error = _decode_document_name(name_blob, self)
            hash_bytes = self.get_blob(hash_offset) if hash_offset else None
            hash_guid = self.get_guid(hash_algorithm_index) if hash_algorithm_index is not None else None
            language_guid = self.get_guid(language_index) if language_index is not None else None

            self.documents.append(
                DocumentRow(
                    self,
                    index + 1,
                    raw,
                    name_offset if name_offset is not None else 0,
                    name_blob,
                    separator,
                    parts,
                    name,
                    hash_algorithm_index if hash_algorithm_index is not None else 0,
                    _format_guid(hash_guid) if hash_guid is not None else None,
                    hash_bytes,
                    language_index if language_index is not None else 0,
                    _format_guid(language_guid) if language_guid is not None else None,
                    decode_error,
                )
            )

    def _parse_method_debug_information_rows(self) -> None:
        data = self._table_data.get(TABLE_METHOD_DEBUG_INFORMATION, b"")
        row_size = self.table_row_sizes.get(TABLE_METHOD_DEBUG_INFORMATION, 0)
        row_count = self.internal_row_counts[TABLE_METHOD_DEBUG_INFORMATION]
        document_index_size = _table_index_size(self.table_row_counts[TABLE_DOCUMENT])
        if row_size == 0:
            return

        for index in range(row_count):
            offset = index * row_size
            if offset + row_size > len(data):
                self._add_warning("MethodDebugInformation table row %d is truncated" % (index + 1))
                break
            raw = data[offset:offset + row_size]
            pos = 0
            document_row_id = _read_uint(raw, pos, document_index_size)
            pos += document_index_size
            sequence_points_offset = _read_uint(raw, pos, self.blob_index_size)

            blob = self.get_blob(sequence_points_offset) if sequence_points_offset else None
            self.method_debug_information.append(
                MethodDebugInformationRow(
                    self,
                    index + 1,
                    raw,
                    document_row_id if document_row_id is not None else 0,
                    sequence_points_offset if sequence_points_offset is not None else 0,
                    blob,
                )
            )

    def _parse_state_machine_method_rows(self) -> None:
        data = self._table_data.get(TABLE_STATE_MACHINE_METHOD, b"")
        row_size = self.table_row_sizes.get(TABLE_STATE_MACHINE_METHOD, 0)
        row_count = self.internal_row_counts[TABLE_STATE_MACHINE_METHOD]
        method_index_size = _table_index_size(self.table_row_counts[6])
        if row_size == 0:
            return

        for index in range(row_count):
            offset = index * row_size
            if offset + row_size > len(data):
                self._add_warning("StateMachineMethod table row %d is truncated" % (index + 1))
                break
            raw = data[offset:offset + row_size]
            move_next = _read_uint(raw, 0, method_index_size)
            kickoff = _read_uint(raw, method_index_size, method_index_size)
            self.state_machine_methods.append(
                StateMachineMethodRow(
                    index + 1,
                    raw,
                    move_next if move_next is not None else 0,
                    kickoff if kickoff is not None else 0,
                )
            )


class _CodeViewRecord:
    def __init__(self, signature: bytes, data: bytes):
        self.signature = signature
        self.data = data
        self.identity: Optional[bytes] = None
        self.pdb_name: bytes = b""
        if signature == b"RSDS" and len(data) >= 24:
            self.identity = data[4:24]
            self.pdb_name = data[24:].split(b"\x00", 1)[0]
        elif signature == b"NB10" and len(data) >= 16:
            self.pdb_name = data[8:].split(b"\x00", 1)[0]


def _read_codeview_records(pe: Any) -> List[_CodeViewRecord]:
    """Read CodeView records from the explicitly supplied assembly.

    This uses only the PE bytes already loaded in the dnPE/pefile object.  The
    embedded-PDB and PDB-file-name fields are recorded as evidence but are not
    used to locate or open any file.
    """
    records: List[_CodeViewRecord] = []
    optional_header = getattr(pe, "OPTIONAL_HEADER", None)
    if optional_header is None:
        return records
    data_directories = getattr(optional_header, "DATA_DIRECTORY", None)
    if not data_directories or len(data_directories) <= 6:
        return records
    directory = data_directories[6]
    rva = getattr(directory, "VirtualAddress", 0)
    size = getattr(directory, "Size", 0)
    if not rva or not size:
        return records

    raw_data = getattr(pe, "__data__", None)
    if raw_data is None:
        return records

    entry_size = 28
    for index in range(size // entry_size):
        entry_offset = rva + index * entry_size
        entry = None
        try:
            entry = pe.get_data(entry_offset, entry_size)
        except Exception:  # pragma: no cover - defensive around pefile
            entry = None
        if entry is None or len(entry) < entry_size:
            # Some PEs have a debug directory whose RVA is not mapped; fall
            # back to the file offset when possible.
            try:
                file_offset = pe.get_offset_from_rva(entry_offset)
            except Exception:  # pragma: no cover - defensive around pefile
                break
            if file_offset + entry_size > len(raw_data):
                break
            entry = raw_data[file_offset:file_offset + entry_size]
        if len(entry) < entry_size:
            break

        _, _, _, _, debug_type, data_size, address, pointer = struct.unpack("<IIHHIIII", entry)
        if debug_type != 2 or data_size == 0:
            continue
        payload = None
        if pointer and pointer + data_size <= len(raw_data):
            payload = raw_data[pointer:pointer + data_size]
        elif address:
            try:
                payload = pe.get_data(address, data_size)
            except Exception:  # pragma: no cover - defensive around pefile
                payload = None
        if payload is None or len(payload) < 4:
            continue
        records.append(_CodeViewRecord(payload[:4], payload))
    return records


def _coerce_assembly(assembly: Any) -> Any:
    if isinstance(assembly, (str, os.PathLike)):
        from . import dnPE

        return dnPE(os.fspath(assembly))
    if isinstance(assembly, (bytes, bytearray, memoryview)):
        from . import dnPE

        return dnPE(data=bytes(assembly))
    if getattr(assembly, "OPTIONAL_HEADER", None) is None:
        raise PortablePdbError("assembly must be a dnfile.dnPE, a path, or PE bytes")
    return assembly


def read_portable_pdb(source: Union[str, "os.PathLike[str]", bytes, bytearray]) -> PortablePdb:
    """Read a Portable PDB from an explicit path or byte string.

    This is the only entry point that opens a file.  It opens exactly the given
    PDB; it does not search for sibling files, open any Document name, or use
    the network.
    """
    if isinstance(source, (bytes, bytearray)):
        return PortablePdb.from_bytes(bytes(source))
    return PortablePdb.from_path(source)


def associate_debug_records(
    pdb: Union[PortablePdb, str, "os.PathLike[str]", bytes, bytearray],
    assembly: Any,
    max_methods: Optional[int] = None,
) -> AssociationResult:
    """Associate a Portable PDB with one explicitly supplied assembly."""
    if not isinstance(pdb, PortablePdb):
        pdb = read_portable_pdb(pdb)
    return pdb.associate(assembly, max_methods=max_methods)
