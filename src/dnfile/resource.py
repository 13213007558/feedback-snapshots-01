import enum
import struct
from typing import Any, Dict, List, Tuple, Optional

from . import base, enums, utils
from .enums import ResourceEntryStatus, ResourceOrigin, ResourceStatus

# References:
#   https://ntcore.com/files/manifestres.htm
#   https://github.com/0xd4d/dnlib/tree/master/src/DotNet/Resources
#   https://referencesource.microsoft.com/mscorlib/system/resources/resourcetypecode.cs.html


class ResourceTypeCode(enum.IntEnum):
    Null        = 0
    String      = 1
    Boolean     = 2
    Char        = 3
    Byte        = 4
    SByte       = 5
    Int16       = 6
    UInt16      = 7
    Int32       = 8
    UInt32      = 9
    Int64       = 0xa
    UInt64      = 0xb
    Single      = 0xc
    Double      = 0xd
    Decimal     = 0xe
    DateTime    = 0xf
    TimeSpan    = 0x10

    # Types with a special representation, like byte[] and Stream
    ByteArray   = 0x20
    Stream      = 0x21

    # User types - serialized using the binary formatter.
    StartOfUserTypes = 0x40


ResourceTypeStrings: Dict[int, str] = {
    ResourceTypeCode.Null:      "Null",
    ResourceTypeCode.String:    "System.String",
    ResourceTypeCode.Boolean:   "System.Boolean",
    ResourceTypeCode.Char:      "System.Char",
    ResourceTypeCode.Byte:      "System.Byte",
    ResourceTypeCode.SByte:     "System.SByte",
    ResourceTypeCode.Int16:     "System.Int16",
    ResourceTypeCode.UInt16:    "System.UInt16",
    ResourceTypeCode.Int32:     "System.Int32",
    ResourceTypeCode.UInt32:    "System.UInt32",
    ResourceTypeCode.Int64:     "System.Int64",
    ResourceTypeCode.UInt64:    "System.UInt64",
    ResourceTypeCode.Single:    "System.Single",
    ResourceTypeCode.Double:    "System.Double",
    ResourceTypeCode.Decimal:   "System.Decimal",
    ResourceTypeCode.DateTime:  "System.DateTime",
    ResourceTypeCode.TimeSpan:  "System.TimeSpan",
    ResourceTypeCode.ByteArray: "System.ByteArray",
    ResourceTypeCode.Stream:    "System.Stream",
}


class ResourceTypeFactory(object):

    def read_serialized_data(self, data: bytes, offset: int) -> Tuple[bytes, int]:
        """
        Read a serialized data (compressed int size, followed by data of that many bytes).

        Return the data (bytes) and number of bytes read (size + data).
        """
        x = utils.read_compressed_int(data[offset:offset + 4])
        if x is None:
            raise ValueError("CLR resource error: not enough data at offset")
        size = x[0]
        nbytes = x[1]
        offset += nbytes
        if offset + size > len(data):
            raise ValueError("CLR resource error: not enough data at offset")
        value = data[offset:offset + size]
        nbytes += size
        return value, nbytes

    def read_serialized_string(self, data: bytes, offset: int, encoding="utf-8") -> Tuple[str, int]:
        val, n = self.read_serialized_data(data, offset)
        return val.decode(encoding), n

    def _unsupported_payload(self, data: bytes, offset: int, entry: "ResourceEntry", type_name: Optional[str]) -> None:
        """
        A user type uses the binary formatter, which this parser does not
        decode.  Its payload is not length-prefixed, so no payload bytes are
        claimed; the entry keeps its type and offset and reports that no
        decoder was applied.
        """
        entry.status = ResourceEntryStatus.Unsupported

    def read_rsrc_data_v1(self, data: bytes, offset: int, userTypes: List[bytes], entry: "ResourceEntry"):
        if offset < 0 or offset + 1 > len(data):
            entry.status = ResourceEntryStatus.Failed
            entry.error = "expected type code at resource-set offset 0x{:x}".format(offset)
            return
        t = int.from_bytes(data[offset:offset + 1], byteorder="little", signed=False)
        entry.struct.Type = t
        offset += 4
        # https://github.com/0xd4d/dnlib/blob/master/src/DotNet/Resources/ResourceReader.cs
        if t == -1:
            # Null
            entry.type_name = "Null"
            entry.data = b""
            entry.status = ResourceEntryStatus.Empty
            # entry.value is already None
            return
        elif t < 0 or t >= len(userTypes):
            # invalid resource type
            entry.status = ResourceEntryStatus.Invalid
            entry.error = "invalid resource type code {}".format(t)
            return
        # get type string
        ts = userTypes[t]
        # remove comma postfix
        comma_loc = ts.find(b",")
        if comma_loc > 0:
            ts = ts[:comma_loc]
        try:
            tn = ts.decode("utf-8")
        except UnicodeDecodeError:
            entry.type_name = None
            entry.status = ResourceEntryStatus.Raw
            entry.problems.append("unable to decode resource type name at index {}".format(t))
            return
        entry.type_name = tn
        if tn in ResourceTypeStrings.values():
            self._decode_value(tn, data, offset, entry)
        else:
            # user-defined type; the payload uses the binary formatter
            self._unsupported_payload(data, offset, entry, tn)

    def read_rsrc_data_v2(self, data: bytes, offset: int, userTypes: List[bytes], entry: "ResourceEntry"):
        if offset < 0 or offset + 1 > len(data):
            entry.status = ResourceEntryStatus.Failed
            entry.error = "expected type code at resource-set offset 0x{:x}".format(offset)
            return
        # dnlib reads four bytes, but it looks like one byte in the files I have
        t = int.from_bytes(data[offset:offset + 1], byteorder="little", signed=True)
        entry.struct.Type = t
        offset += 1
        # check for invalid type code
        if t < 0 or t >= ResourceTypeCode.StartOfUserTypes + len(userTypes):
            # invalid resource type
            entry.status = ResourceEntryStatus.Invalid
            entry.error = "invalid resource type code {}".format(t)
            return
        # https://github.com/0xd4d/dnlib/blob/master/src/IO/DataReader.cs
        if t in ResourceTypeStrings:
            entry.type_name = ResourceTypeStrings[t]
            self._decode_value(entry.type_name, data, offset, entry)
        elif t >= ResourceTypeCode.StartOfUserTypes:
            # get type string
            ts = userTypes[t - ResourceTypeCode.StartOfUserTypes]
            # remove comma postfix
            comma_loc = ts.find(b",")
            if comma_loc > 0:
                ts = ts[:comma_loc]
            try:
                entry.type_name = ts.decode("utf-8")
            except UnicodeDecodeError:
                entry.type_name = None
                entry.problems.append("unable to decode resource type name at index {}".format(t - ResourceTypeCode.StartOfUserTypes))
            # user types are serialized using the binary formatter; keep the
            # remaining payload rather than pretending it was decoded.
            self._unsupported_payload(data, offset, entry, entry.type_name)
        else:
            entry.status = ResourceEntryStatus.Invalid
            entry.error = "invalid resource type code {}".format(t)

    def _decode_value(self, type_name: str, data: bytes, offset: int, entry: "ResourceEntry") -> None:
        if type_name == "Null":
            entry.data = b""
            entry.status = ResourceEntryStatus.Empty
            return
        try:
            d, v = self.type_str_to_type(type_name, data, offset)
        except (ValueError, struct.error, IndexError, OverflowError) as e:
            entry.status = ResourceEntryStatus.Failed
            entry.error = "unable to decode '{}' at resource-set offset 0x{:x}: {}".format(type_name, offset, e)
            return
        if d is not None:
            entry.data = d
        if v is not None:
            entry.value = v
            entry.status = ResourceEntryStatus.Decoded
        elif entry.data is not None:
            # the bytes were obtained, but no typed value was decoded
            entry.status = ResourceEntryStatus.Raw
        elif type_name not in ResourceTypeStrings.values():
            # a recognized type code for which this parser has no decoder
            entry.status = ResourceEntryStatus.Unsupported
        else:
            entry.status = ResourceEntryStatus.Raw

    def type_str_to_type(self, type_name: str, data: bytes, offset: int) -> Tuple[Optional[bytes], Optional[Any]]:
        """
        Given a type string, data buffer, and offset into that buffer.
        Return a tuple of the raw data and the deserialized value.

        Raises ValueError when the payload is too short for the declared type.
        """
        def need(size: int):
            if offset < 0 or offset + size > len(data):
                raise ValueError("not enough data for {}".format(type_name))

        # switch on type
        # https://github.com/0xd4d/dnlib/blob/master/src/IO/DataReader.cs
        final_bytes: Optional[bytes] = None
        final_value: Optional[Any] = None
        if type_name == "Null":
            final_bytes = b""
        elif type_name == "System.String":
            final_bytes, n = self.read_serialized_data(data, offset)
            try:
                final_value = final_bytes.decode("utf-8")
            except UnicodeDecodeError:
                # TODO warn/error
                pass
        elif type_name == "System.Int32":
            tsize = 4
            need(tsize)
            final_bytes = data[offset:offset + tsize]
            final_value = int.from_bytes(final_bytes, byteorder="little", signed=False)
        elif type_name == "System.Byte":
            tsize = 1
            need(tsize)
            final_bytes = data[offset:offset + tsize]
            final_value = final_bytes
        elif type_name == "System.SByte":
            tsize = 1
            need(tsize)
            final_bytes = data[offset:offset + tsize]
            final_value = final_bytes
        elif type_name == "System.Boolean":
            tsize = 1
            need(tsize)
            final_bytes = data[offset:offset + tsize]
            final_value = final_bytes[0] != 0
        elif type_name == "System.Char":
            tsize = 2
            need(tsize)
            final_bytes = data[offset:offset + tsize]
            try:
                final_value = final_bytes.decode("utf-16")
            except UnicodeDecodeError:
                # TODO warn/error
                pass
        elif type_name == "System.Int16":
            tsize = 2
            need(tsize)
            final_bytes = data[offset:offset + tsize]
            final_value = int.from_bytes(final_bytes, byteorder="little", signed=False)
        elif type_name == "System.Int64":
            tsize = 8
            need(tsize)
            final_bytes = data[offset:offset + tsize]
            final_value = int.from_bytes(final_bytes, byteorder="little", signed=False)
        elif type_name == "System.UInt16":
            tsize = 2
            need(tsize)
            final_bytes = data[offset:offset + tsize]
            final_value = int.from_bytes(final_bytes, byteorder="little", signed=False)
        elif type_name == "System.UInt32":
            tsize = 4
            need(tsize)
            final_bytes = data[offset:offset + tsize]
            final_value = int.from_bytes(final_bytes, byteorder="little", signed=False)
        elif type_name == "System.UInt64":
            tsize = 8
            need(tsize)
            final_bytes = data[offset:offset + tsize]
            final_value = int.from_bytes(final_bytes, byteorder="little", signed=False)
        elif type_name == "System.Single":
            tsize = 4
            need(tsize)
            final_bytes = data[offset:offset + tsize]
            final_value = struct.unpack("<f", final_bytes)[0]
        elif type_name == "System.Double":
            tsize = 8
            need(tsize)
            final_bytes = data[offset:offset + tsize]
            final_value = struct.unpack("<d", final_bytes)[0]
        elif type_name == "System.DateTime":
            tsize = 8
            need(tsize)
            final_bytes = data[offset:offset + tsize]
            dt = base.DateTime(final_bytes)
            dt.parse()
            final_value = dt
        elif type_name == "System.TimeSpan":
            # TODO return resourceDataFactory.Create(new TimeSpan(reader.ReadInt64()));
            tsize = 8
            need(tsize)
            final_bytes = data[offset:offset + tsize]
        elif type_name == "System.Decimal":
            # https://referencesource.microsoft.com/mscorlib/system/decimal.cs.html
            sign_mask = 0x80000000
            scale_mask = 0x00FF0000
            tsize = 16
            need(tsize)
            final_bytes = data[offset:offset + tsize]
            low, med, high, flags = struct.unpack("<IIII", final_bytes)
            final_value = low | med << 8 | high << 16
            scale = scale_mask & flags
            if scale > 0:
                final_value = final_value / 10**scale
            if sign_mask & flags:
                final_value = -final_value
        elif type_name in ("System.ByteArray", "System.Stream"):
            tsize = 4
            need(tsize)
            dsize = int.from_bytes(data[offset:offset + tsize], byteorder="little", signed=False)
            if offset + tsize + dsize > len(data):
                raise ValueError("not enough data for {} payload".format(type_name))
            final_bytes = data[offset:offset + tsize + dsize]
            final_value = data[offset + tsize:offset + tsize + dsize]
        else:
            # TODO
            pass
        return final_bytes, final_value


def _manifest_row_name(row) -> str:
    return str(row.Name) if getattr(row, "Name", None) is not None else ""


def _referenced_row(implementation):
    try:
        return implementation.row
    except (IndexError, TypeError, ValueError):
        return None


def create_resource(row) -> base.ClrResource:
    """
    Build the resource object for a ManifestResource row.

    Internal resources still need their bytes loaded by the caller.  External
    resources are created without content: the declaration only names another
    file or assembly, so there is nothing in this file to return.
    """
    name = _manifest_row_name(row)
    public = bool(getattr(getattr(row, "Flags", None), "mrPublic", False))
    private = bool(getattr(getattr(row, "Flags", None), "mrPrivate", False))

    implementation = getattr(row, "Implementation", None)
    if implementation is None:
        return InternalResource(name, public, private)

    table = getattr(implementation, "table", None)
    table_name = getattr(table, "name", None)
    referenced_row = _referenced_row(implementation)

    if table_name == "File":
        source = _manifest_row_name(referenced_row) if referenced_row is not None else None
        return FileResource(name, public, private, metadata=referenced_row, source=source)
    if table_name == "AssemblyRef":
        source = _manifest_row_name(referenced_row) if referenced_row is not None else None
        return AssemblyResource(name, public, private, metadata=referenced_row, source=source)

    # Other Implementation targets (e.g. ExportedType) also point outside this
    # file's resource data.  Keep the declaration visible without guessing.
    source = "{}[{}]".format(table_name, getattr(implementation, "row_index", "?")) if table_name else None
    return ExternalResource(name, public, private, metadata=referenced_row, source=source)


class ExternalResource(base.ClrResource):
    """
    A resource declared in another file or assembly.

    The bytes are not part of this file.  `data` is None and `status` is
    ExternalMissing until a caller explicitly supplies content via
    `set_data()`, which records that the bytes came from outside the parser.
    """

    origin = ResourceOrigin.External
    metadata: Optional[base.MDTableRow]
    source: Optional[str]

    def __init__(self, name: str, public: bool = False, private: bool = False,
                 metadata: Optional[base.MDTableRow] = None, source: Optional[str] = None):
        super().__init__(name, public, private)
        self.metadata = metadata
        self.source = source
        self.data = None
        self.status = ResourceStatus.ExternalMissing
        self.error = self._external_missing_message()

    def _external_missing_message(self) -> str:
        if self.source:
            return "external resource '{}' is declared in '{}'; no content was supplied".format(self.name, self.source)
        return "external resource '{}'; no content was supplied".format(self.name)

    def set_data(self, data: bytes):
        super().set_data(data)
        self.status = ResourceStatus.Extracted
        self.error = None

    def parse(self):
        if self.data is None:
            # Nothing was supplied, so there is nothing to parse.  Do not
            # fabricate empty content.
            self.status = ResourceStatus.ExternalMissing
            self.error = self._external_missing_message()
            return
        if isinstance(self.data, ResourceSet):
            return
        rs = ResourceSet(self.data, self)
        if rs.valid():
            self.data = rs
            rs.parse()
            self.problems.extend(rs.problems)
            if not rs.complete:
                self.status = ResourceStatus.Partial
            else:
                self.status = ResourceStatus.Extracted


class FileResource(ExternalResource):
    origin = ResourceOrigin.File

    @property
    def file_name(self) -> Optional[str]:
        return self.source


class AssemblyResource(ExternalResource):
    origin = ResourceOrigin.Assembly

    @property
    def assembly_name(self) -> Optional[str]:
        return self.source


class InternalResource(base.ClrResource):
    origin = ResourceOrigin.Internal
    rva: Optional[int]
    size: Optional[int]
    file_offset: Optional[int]

    def __init__(self, name: str, public: bool = False, private: bool = False,
                 rva: Optional[int] = None, size: Optional[int] = None,
                 file_offset: Optional[int] = None):
        super().__init__(name, public, private)
        self.rva = rva
        self.size = size
        self.file_offset = file_offset
        self.status = ResourceStatus.Unreadable
        self.error = "embedded resource content was not read"

    def set_data(self, data: bytes):
        super().set_data(data)
        self.status = ResourceStatus.Extracted
        self.error = None

    def parse(self):
        if self.data is None:
            self.status = ResourceStatus.Unreadable
            if not self.error:
                self.error = "embedded resource content was not read"
            return
        if isinstance(self.data, ResourceSet):
            return
        # attempt to parse as a ResourceSet
        rs = ResourceSet(self.data, self)
        if rs.valid():
            self.data = rs
            rs.parse()
            # surface per-entry diagnostics on the resource too, while keeping
            # the entry's own source/offset information intact
            self.problems.extend(rs.problems)
            if rs.complete:
                self.status = ResourceStatus.Extracted
            else:
                self.status = ResourceStatus.Partial
        # otherwise treat as raw resource


class ResourceEntryStruct(object):
    Type: Optional[int]
    Hash: Optional[int]
    NamePtr: Optional[int]
    DataOffset: Optional[int]
    Name: Optional[bytes]

    def __init__(self):
        self.Type: Optional[int] = None
        self.Hash: Optional[int] = None
        self.NamePtr: Optional[int] = None
        self.DataOffset: Optional[int] = None
        self.Name: Optional[bytes] = None


class ResourceEntry(object):
    """
    One entry within an embedded ResourceSet.

    `struct` retains the on-disk metadata (type code, hash, name pointer,
    data offset) even when decoding fails, so a failure can still be traced
    back to its declaring entry.  `data` holds the raw payload when bytes were
    obtained; `value` holds a decoded value when decoding succeeded.
    """

    struct: ResourceEntryStruct
    type_name: Optional[str]
    value: Optional[Any]
    data: Optional[bytes]
    name: Optional[str]
    status: ResourceEntryStatus
    error: Optional[str]
    problems: List[str]
    # offset of the payload within the resource set buffer, when known
    data_offset: Optional[int]
    # the resource that contains this entry, when parsed as part of one
    resource: Optional[base.ClrResource]

    def __init__(self):
        self.struct = ResourceEntryStruct()
        self.type_name: Optional[str] = None
        self.value: Optional[Any] = None
        self.data: Optional[bytes] = None
        self.name: Optional[str] = None
        self.status: ResourceEntryStatus = ResourceEntryStatus.Failed
        self.error: Optional[str] = None
        self.problems: List[str] = list()
        self.data_offset: Optional[int] = None
        self.resource: Optional[base.ClrResource] = None

    @property
    def type_code(self) -> Optional[int]:
        """The raw type code from the entry's serialized header."""
        return self.struct.Type

    @property
    def offset(self) -> Optional[int]:
        """The payload offset relative to the set's data section."""
        return self.struct.DataOffset

    @property
    def source(self) -> str:
        """A description of the containing resource, for diagnostics."""
        rsrc = self.resource
        if rsrc is None:
            return "unknown resource"
        origin = getattr(getattr(rsrc, "origin", None), "value", "unknown")
        return "{} '{}' (origin: {})".format(type(rsrc).__name__, rsrc.name, origin)

    @property
    def extracted(self) -> bool:
        return self.data is not None

    @property
    def decoded(self) -> bool:
        return self.status == ResourceEntryStatus.Decoded

    @property
    def complete(self) -> bool:
        """
        True when this entry's bytes/payload were obtained without a failure.

        Raw payloads (bytes without a typed value) count as extracted.
        Unsupported user types and invalid/failed entries do not.
        """
        return self.status in (
            ResourceEntryStatus.Decoded,
            ResourceEntryStatus.Empty,
            ResourceEntryStatus.Raw,
        ) and not self.problems

    def __repr__(self) -> str:
        return "<ResourceEntry name={!r} type={!r} status={}>".format(
            self.name, self.type_name, self.status.value
        )


class ResourceSetStruct(object):
    Magic: int
    NumberOfReaders: int
    SizeOfReaderTypes: int
    ReaderTypes: bytes
    Version: int
    NumberOfResources: int
    NumberOfResourceTypes: int
    DataSectionOffset: int
    TableOfNames: int


class ResourceSet(object):
    """
    An embedded .NET resource set.

    Parsing is best-effort: a problem in one entry does not prevent later
    entries from being read.  Each problem is recorded in `problems` and in
    the affected entry's `error`.  `complete` is False whenever any declared
    entry failed, so callers do not mistake a partially decoded set for a
    fully extracted one.
    """

    parent: Optional[base.ClrResource]
    struct: Optional[ResourceSetStruct]
    entries: List[ResourceEntry]
    problems: List[str]
    MAGIC: int = 0xbeefcace
    MAGIC_BYTES: bytes = b"\xCE\xCA\xEF\xBE"

    def __init__(self, data: bytes, parent: Optional[base.ClrResource]):
        self._data = data
        self._min_valid_size = 7 * 4
        self.entries: List[ResourceEntry] = list()
        self.resource_types: List[bytes] = list()
        self.problems: List[str] = list()
        self.struct: Optional[ResourceSetStruct] = None
        self.parent: Optional[base.ClrResource] = parent

    @property
    def source(self) -> str:
        """Identify the resource this set came from in diagnostics."""
        if self.parent is None:
            return "unknown resource"
        origin = getattr(getattr(self.parent, "origin", None), "value", "unknown")
        return "{} '{}' (origin: {})".format(type(self.parent).__name__, self.parent.name, origin)

    def valid(self):
        if len(self._data) < self._min_valid_size:
            # not enough data
            return False
        # test magic
        if not self._data.startswith(self.MAGIC_BYTES):
            return False
        # we have enough data, and it starts with the right signature
        return True

    @property
    def complete(self) -> bool:
        return not self.problems and all(entry.complete for entry in self.entries)

    def _problem(self, message: str) -> None:
        # `source` is available on the set and on each entry; the message
        # itself carries the entry/offset evidence.
        self.problems.append(message)

    def _fail_pending_entries(self, reason: str) -> None:
        """Give every not-yet-parsed entry a traceable failure reason."""
        for entry in self.entries:
            if entry.status == ResourceEntryStatus.Failed and entry.error is None:
                entry.error = reason

    def parse(self):
        # parse initial structure
        self.struct = ResourceSetStruct()
        offset = 0
        try:
            self.struct.Magic = struct.unpack_from("<I", self._data, offset)[0]
            offset += 4
            self.struct.NumberOfReaders = struct.unpack_from("<I", self._data, offset)[0]
            offset += 4
            self.struct.SizeOfReaderTypes = struct.unpack_from("<I", self._data, offset)[0]
            offset += 4
            # reader types string
            self.struct.ReaderTypes = self._data[offset:offset + self.struct.SizeOfReaderTypes]
            offset += self.struct.SizeOfReaderTypes
            # version
            self.struct.Version = struct.unpack_from("<I", self._data, offset)[0]
            offset += 4
            # NumberOfResources
            self.struct.NumberOfResources = struct.unpack_from("<I", self._data, offset)[0]
            offset += 4
            # NumberofResourceTypes
            self.struct.NumberOfResourceTypes = struct.unpack_from("<I", self._data, offset)[0]
            offset += 4
        except struct.error:
            self._problem("resource-set header is truncated")
            return

        # parse type strings
        for i in range(self.struct.NumberOfResourceTypes):
            try:
                type_string, size = self.read_serialized_data(offset)
            except ValueError:
                self._problem("expected more data for types at rsrc offset 0x{:x}".format(offset))
                return
            # add to list
            self.resource_types.append(type_string)
            # next
            offset += size

        # align to 8-byte boundary
        over = offset % 8
        if over != 0:
            offset += 8 - over

        # read hashes
        for i in range(self.struct.NumberOfResources):
            if offset + 4 > len(self._data):
                reason = "expected more data for entry hashes at rsrc offset 0x{:x}".format(offset)
                self._problem(reason)
                self._fail_pending_entries(reason)
                return
            e = ResourceEntry()
            e.struct.Hash = int.from_bytes(self._data[offset:offset + 4], byteorder="little")
            self.entries.append(e)
            # next
            offset += 4

        # read name pointers
        for e in self.entries:
            if offset + 4 > len(self._data):
                reason = "expected more data for entry name pointers at rsrc offset 0x{:x}".format(offset)
                self._problem(reason)
                self._fail_pending_entries(reason)
                return
            e.struct.NamePtr = int.from_bytes(self._data[offset:offset + 4], byteorder="little")
            # next
            offset += 4

        if offset + 4 > len(self._data):
            reason = "expected data section offset at rsrc offset 0x{:x}".format(offset)
            self._problem(reason)
            self._fail_pending_entries(reason)
            return
        # dword (data section offset)
        self.struct.DataSectionOffset = int.from_bytes(self._data[offset:offset + 4], byteorder="little")
        offset += 4
        # table_of_names = current offset
        self.struct.TableOfNames = offset

        if self.struct.DataSectionOffset > len(self._data):
            reason = "data section offset 0x{:x} is beyond resource-set size 0x{:x}".format(
                self.struct.DataSectionOffset, len(self._data))
            self._problem(reason)
            self._fail_pending_entries(reason)
            return

        rsrc_factory = ResourceTypeFactory()
        for e in self.entries:
            self._parse_entry(e, rsrc_factory)

    def _parse_entry(self, entry: ResourceEntry, rsrc_factory: ResourceTypeFactory) -> None:
        """Parse one entry, recording failures without affecting the others."""
        entry.resource = self.parent
        name_offset = self.struct.TableOfNames + entry.struct.NamePtr
        try:
            entry.struct.Name, name_size = self.read_serialized_data(name_offset)
        except ValueError:
            entry.status = ResourceEntryStatus.Failed
            entry.error = "expected more data for entry name at rsrc offset 0x{:x}".format(name_offset)
            self._problem("entry at name-pointer 0x{:x}: {}".format(entry.struct.NamePtr, entry.error))
            return
        try:
            entry.name = entry.struct.Name.decode("utf-16")
        except UnicodeDecodeError:
            # keep the raw name bytes in struct.Name; the entry is still traceable
            entry.problems.append("entry name is not valid UTF-16")
            self._problem("entry name at rsrc offset 0x{:x} is not valid UTF-16".format(name_offset))

        data_offset_pos = name_offset + name_size
        if data_offset_pos + 4 > len(self._data):
            entry.status = ResourceEntryStatus.Failed
            entry.error = "expected data offset for entry at rsrc offset 0x{:x}".format(data_offset_pos)
            self._problem(entry.error)
            return
        entry.struct.DataOffset = int.from_bytes(self._data[data_offset_pos:data_offset_pos + 4], byteorder="little")

        e_data_offset = self.struct.DataSectionOffset + entry.struct.DataOffset
        entry.data_offset = e_data_offset
        try:
            if self.struct.Version == 1:
                rsrc_factory.read_rsrc_data_v1(self._data, e_data_offset, self.resource_types, entry)
            else:
                rsrc_factory.read_rsrc_data_v2(self._data, e_data_offset, self.resource_types, entry)
        except (ValueError, struct.error, IndexError, OverflowError) as e:
            entry.status = ResourceEntryStatus.Failed
            entry.error = "expected more data for serialized data at rsrc offset 0x{:x}: {}".format(e_data_offset, e)

        if entry.status in (ResourceEntryStatus.Failed, ResourceEntryStatus.Invalid):
            if entry.error:
                self._problem("entry '{}': {}".format(entry.name or "<unnamed>", entry.error))
        elif entry.status == ResourceEntryStatus.Decoded and entry.value is None and entry.data is None:
            entry.status = ResourceEntryStatus.Failed
            entry.error = "no data for entry '{}'".format(entry.name or "<unnamed>")
            self._problem(entry.error)

    def read_serialized_data(self, offset: int) -> Tuple[bytes, int]:
        """
        Read a serialized data (compressed int size, followed by data of that many bytes).

        Return the data (bytes) and number of bytes read (size + data).
        """
        if offset < 0:
            raise ValueError("CLR resource error: not enough data at offset")
        x = utils.read_compressed_int(self._data[offset:offset + 4])
        if x is None:
            raise ValueError("CLR resource error: not enough data at offset")
        size = x[0]
        nbytes = x[1]
        offset += nbytes
        if offset + size > len(self._data):
            raise ValueError("CLR resource error: not enough data at offset")
        value = self._data[offset:offset + size]
        nbytes += size
        return value, nbytes

    def read_serialized_string(self, offset: int, encoding="utf-8") -> Tuple[str, int]:
        val, n = self.read_serialized_data(offset)
        return val.decode(encoding), n
