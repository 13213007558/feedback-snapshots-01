# -*- coding: utf-8 -*-
"""
dnfile, .NET Executable file parser


REFERENCES

    https://www.ntcore.com/files/dotnetformat.htm
    https://referencesource.microsoft.com/System.AddIn/System/Addin/MiniReflection/MetadataReader/Metadata.cs.html
    https://asmresolver.readthedocs.io/en/latest/peimage/dotnet.html#metadata-streams


Copyright (c) 2020-2022 MalwareFrank
"""

__author__ = """MalwareFrank"""
__version__ = "0.18.0"

import copy as _copymod
import codecs
import struct as _struct
import logging
from typing import Dict, List, Optional

from pefile import PE as _PE
from pefile import DIRECTORY_ENTRY, MAX_SYMBOL_EXPORT_COUNT, Dump, Structure, DataContainer, PEFormatError

from . import base, enums, errors, stream, resource, streamtable
from .streamtable import StreamPolicy, StreamStatus, StreamTableEntry, StreamTableReport

logger = logging.getLogger(__name__)
CLR_METADATA_SIGNATURE = 0x424A5342


# These come from the great article[1] which contains great insights on
# working with unicode in both Python 2 and 3.
# [1]: http://python3porting.com/problems.html
def handler(err):
    start = err.start
    end = err.end
    values = [
        ("\\u{0:04x}" if ord(err.object[i]) > 255 else "\\x{0:02x}", ord(err.object[i]))
        for i in range(start, end)
    ]
    return (u"".join([elm[0].format(elm[1]) for elm in values]), end)


codecs.register_error("backslashreplace_", handler)


class dnPE(_PE):
    def add_warning(self, msg):
        self._warnings.append(msg)

    def __init__(
        self,
        name=None,
        data=None,
        fast_load=None,
        max_symbol_exports=MAX_SYMBOL_EXPORT_COUNT,
        clr_lazy_load=False,
        stream_policy=None,
    ):
        self._warnings = list()
        self.clr_lazy_load = clr_lazy_load
        self.stream_policy = streamtable.normalize_policy(stream_policy)
        super().__init__(name, data, fast_load)

    def dump_info(self, dump=None, encoding="utf-8"):
        """
        Dump all the PE and CLR header information into human readable string.
        """
        if dump is None:
            dump = Dump()

        super().dump_info(dump, encoding)

        if not hasattr(self, "net") or not self.net:
            return dump.get_text()

        #### CLR
        # directory entry
        dump.add_header("CLR (.NET)")
        dump.add_lines(self.net.struct.dump())
        dump.add_newline()

        # metadata
        if hasattr(self.net, "metadata") and self.net.metadata:
            dump.add_lines(self.net.metadata.struct.dump(), indent=2)
            dump.add_newline()
            # Streams
            if (
                hasattr(self.net.metadata, "streams_list")
                and self.net.metadata.streams_list
            ):
                for stream_ in self.net.metadata.streams_list:
                    dump.add_lines(stream_.struct.dump(), indent=4)
                    dump.add_newline()

        # Metadata Tables
        if hasattr(self.net, "mdtables") and self.net.mdtables:
            dump.add_header("CLR (.NET) Metadata Tables")
            for s in self.net.metadata.streams_list:
                if isinstance(s, stream.MetaDataTables):
                    s: stream.MetaDataTables
                    dump.add_lines(s.struct.dump())
                    dump.add_newline()
                    if hasattr(s, "tables_list") and s.tables_list:
                        for t in s.tables_list:
                            for label, value in (
                                ("RVA", hex(t.rva)),
                                ("TableName", t.name),
                                ("TableNumber", t.number),
                                ("IsSorted", t.is_sorted),
                                ("NumRows", t.num_rows),
                                ("RowSize", t.row_size),
                            ):
                                dump.add_line(
                                    "{0:<20}{1}".format(label  + ":", str(value)),
                                    indent=2,
                                )
                            dump.add_newline()

        return dump.get_text()

    def get_warnings(self):
        """
        Returns a copy of the list of warning messages.
        """
        result = _copymod.deepcopy(super().get_warnings())
        result.extend(self._warnings)
        return result

    def __parse__(self, fname, data, fast_load):
        super().__parse__(fname, data, fast_load)

        # NOTE: .NET loaders ignores NumberOfRvaAndSizes
        #   We check this elsewhere, but note it here.
        #   example: 1d41308bf4148b4c138f9307abc696a6e4c05a5a89ddeb8926317685abb1c241

    def parse_data_directories(
        self, directories=None, forwarded_exports_only=False, import_dllnames_only=False
    ):
        super().parse_data_directories(
            directories, forwarded_exports_only, import_dllnames_only
        )

        directory_parsing = (
            ("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", self.parse_clr_structure),
        )

        # Indicate no .NET object parsed
        self.net = None

        if self.__data__ is None:
            logger.warning("not a .NET module: failed to read data")
            return

        opt_header = getattr(self, "OPTIONAL_HEADER", None)
        if opt_header is None:
            logger.warning("not a .NET module: no optional header")
            return

        if directories is not None:
            if not isinstance(directories, (tuple, list)):
                directories = [directories]

        for entry in directory_parsing:
            try:
                directory_index = DIRECTORY_ENTRY[entry[0]]
                dir_entry = opt_header.DATA_DIRECTORY[directory_index]
            except IndexError:
                break

            # Only process all the directories if no individual ones have
            # been chosen
            #
            if directories is None or directory_index in directories:

                if dir_entry.VirtualAddress:
                    value = entry[1](dir_entry.VirtualAddress, dir_entry.Size)
                    if value:
                        setattr(self, entry[0][6:], value)
                        if entry[0] == "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR":
                            # create shortcut for .NET/CLR data
                            self.net = value

            if (
                (directories is not None)
                and isinstance(directories, list)
                and (entry[0] in directories)
            ):
                directories.remove(directory_index)

        # NOTE: .NET loaders ignores NumberOfRvaAndSizes, so attempt to parse anyways
        #   example: 1d41308bf4148b4c138f9307abc696a6e4c05a5a89ddeb8926317685abb1c241
        attr_name = "DIRECTORY_ENTRY_COM_DESCRIPTOR"
        if not hasattr(self, attr_name):
            dir_entry_size = Structure(self.__IMAGE_DATA_DIRECTORY_format__).sizeof()
            dd_offset = (
                opt_header.get_file_offset() + opt_header.sizeof()
            )
            clr_entry_offset = dd_offset + (
                DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"] * dir_entry_size
            )
            data = self.__data__[clr_entry_offset:clr_entry_offset + dir_entry_size]
            dir_entry = self.__unpack_data__(
                self.__IMAGE_DATA_DIRECTORY_format__, data, file_offset=clr_entry_offset
            )

            # if COM entry appears valid
            if dir_entry is not None and dir_entry.VirtualAddress:
                # try to parse the .NET CLR directory
                value = self.parse_clr_structure(
                    dir_entry.VirtualAddress, dir_entry.Size
                )
                if value:
                    setattr(self, attr_name, value)
                    # create shortcut for .NET/CLR data
                    self.net = value

    def parse_clr_structure(self, rva, size) -> Optional["ClrData"]:
        try:
            return ClrData(self, rva, size, self.clr_lazy_load, self.stream_policy)
        except errors.dnFormatError as e:
            logger.warning("failed to parse CLR data: %s",  e)
            return None


class ClrMetaDataStruct(Structure):
    Signature: int
    MajorVersion: int
    MinorVersion: int
    Reserved: int
    VersionLength: int
    Version: bytes
    Flags: int
    NumberOfStreams: int


class ClrMetaData(DataContainer):
    """Holds CLR (.NET) MetaData.

    struct:         IMAGE_CLR_METADATA structure
    streams:        Dictionary to access the selected stream for each name (bytes)
    streams_list:   List of streams in order of entry in header
    stream_report:  StreamTableReport that records every header, range, and verdict
    """

    rva: int
    struct: ClrMetaDataStruct
    streams: Dict[bytes, base.ClrStream]
    streams_list: List[base.ClrStream]
    stream_report: streamtable.StreamTableReport

    _format = (
        "IMAGE_CLR_METADATA",
        [
            "I,Signature",
            "H,MajorVersion",
            "H,MinorVersion",
            "I,Reserved",
            "I,VersionLength",
            # '?,Version',
            # 'H,Flags',
            # 'H,NumberOfStreams',
        ],
    )
    #### MetaData section
    #
    # dd    Signature
    # dw    MajorVersion
    # dw    MinorVersion
    # dd    Reserved
    # dd    Length
    # var   Version
    # dw    Flags
    # dw    NumberOfStreams
    # var   StreamHeaders

    def __init__(
        self,
        pe: dnPE,
        rva: int,
        size: int,
        lazy_load=False,
        stream_policy=None,
    ):
        """
        Given a dnPE object, MetaData RVA and MetaData Size.
        Raises dnFormatError if encounter problems parsing.
        """
        metadata_rva = rva
        policy = streamtable.normalize_policy(stream_policy)

        # The metadata RVA, used for stream offsets
        self.rva = rva
        self.stream_policy = policy

        # dynamically create metadata header structure
        struct_format = _copymod.deepcopy(self.__class__._format)
        struct_data = pe.get_data(rva, size)
        self.size = len(struct_data)
        min_header_size = Structure(self.__class__._format).sizeof()
        if len(struct_data) < min_header_size:
            raise errors.dnFormatError(
                "Invalid CLR MetaData Structure size. Can't read %d "
                "bytes at RVA: 0x%x" % (size, rva)
            )
        # check signature
        sig = _struct.unpack_from("<I", struct_data)[0]
        if sig != CLR_METADATA_SIGNATURE:
            raise errors.dnFormatError(
                "Invalid CLR MetaData Signature at 0x%x. Expected 0x%x but "
                "got 0x%x" % (rva, CLR_METADATA_SIGNATURE, sig)
            )
        # parse struct so that we can get the version length
        metadata_struct = ClrMetaDataStruct(
            format=struct_format,
            file_offset=pe.get_offset_from_rva(metadata_rva)
        )
        metadata_struct.__unpack__(struct_data)
        # add variable-length version field
        if metadata_struct.VersionLength > 0:
            struct_format[1].append(
                "{0}s,Version".format(metadata_struct.VersionLength)
            )
        # add Flags
        struct_format[1].append("H,Flags")
        # add NumberOfStreams
        struct_format[1].append("H,NumberOfStreams")

        # re-parse metadata header structure
        metadata_struct = ClrMetaDataStruct(
            format=struct_format,
            file_offset=pe.get_offset_from_rva(metadata_rva)
        )
        struct_size = metadata_struct.sizeof()
        struct_data = pe.get_data(metadata_rva, struct_size)
        if len(struct_data) < struct_size:
            raise errors.dnFormatError(
                "unable to read full CLR metadata structure, expected {} got {}".format(
                    struct_size, len(struct_data)
                )
            )
        metadata_struct.__unpack__(struct_data)

        self.struct = metadata_struct

        # Keep the bytes that are really available.  Stream headers and stream
        # bodies are both bounded by this buffer so a bad header cannot pull
        # adjacent sections (or overlay) into a stream.
        self._metadata_data = pe.get_data(metadata_rva, self.size)
        self._body_end_rva = metadata_rva + self.size
        self._declared_end_rva = metadata_rva + size

        report = streamtable.StreamTableReport(
            policy=policy,
            metadata_rva=metadata_rva,
            metadata_declared_size=size,
            metadata_read_size=self.size,
            expected_entries=metadata_struct.NumberOfStreams,
        )
        if self.size < size:
            report.add_warning(
                "CLR metadata directory is truncated: declared 0x{:x} bytes, "
                "read 0x{:x} bytes at rva 0x{:x}".format(size, self.size, metadata_rva)
            )

        if metadata_struct.NumberOfStreams > 0:
            # parse the streams table
            streams_table_rva = metadata_rva + struct_size
            self.parse_stream_table(pe, streams_table_rva, report)
        else:
            self.streams_list = []
            self.streams = {}

        if policy is streamtable.StreamPolicy.STRICT and report.has_conflicts:
            report.rejected = True
            report.rejection_reason = report.strict_rejection_message()
            for warning in report.drain_new_warnings():
                pe.add_warning(warning)
            pe.add_warning(report.rejection_reason)
            logger.warning(report.rejection_reason)
            self.stream_report = report
            self.streams = {}
            self.streams_list = []
            raise errors.dnStreamTableError(report.rejection_reason, report)

        for warning in report.drain_new_warnings():
            pe.add_warning(warning)

        # Only selected, structurally valid streams are parsed.  A malformed
        # stream cannot shadow another valid stream with the same name.
        selected_streams = report.selected_streams()
        for entry in report.parseable_entries():
            s = entry.stream
            assert s is not None
            try:
                s.parse(selected_streams, lazy_load=lazy_load)
            except (errors.dnFormatError, PEFormatError) as e:
                entry.statuses.add(streamtable.StreamStatus.PARSE_ERROR)
                # other streams may parse, so add to warnings and continue
                pe.add_warning("Unable to parse stream {!r}".format(s.struct.Name))
                pe.add_warning(str(e))
                logger.warning("unable to parse stream: %s: %s", s.struct.Name, e)

        streamtable.apply_evidence_to_streams(report)
        streamtable.finalize_evidence(report)
        for warning in report.drain_new_warnings():
            pe.add_warning(warning)
        self.stream_report = report
        self.streams = report.selected_stream_map()
        self.streams_list = [e.stream for e in report.entries if e.stream is not None]

    def parse_stream_table(self, pe: dnPE, streams_table_rva, report=None):
        if report is None:
            report = streamtable.StreamTableReport(
                policy=streamtable.StreamPolicy.FORENSIC,
                metadata_rva=self.rva,
                metadata_declared_size=self.size,
                metadata_read_size=self.size,
                expected_entries=self.struct.NumberOfStreams,
            )
        elif report.entries:
            raise ValueError("stream table report is already populated")

        metadata_end_rva = self._body_end_rva
        stream_entry_rva = streams_table_rva
        entry_index = 0

        for slot in range(self.struct.NumberOfStreams):
            entry, failure = ClrStreamFactory.readStreamEntry(
                pe,
                stream_entry_rva,
                self.rva,
                metadata_end_rva,
                self._declared_end_rva,
                index=entry_index,
                slot=slot,
            )
            if entry is None:
                report.invalid_slots.append(stream_entry_rva)
                logger.warning("Invalid .NET stream header at rva 0x%x: %s", stream_entry_rva, failure)
                report.add_warning(
                    "Invalid .NET stream header {} at rva 0x{:x}: {}".format(
                        slot + 1, stream_entry_rva, failure or "unreadable"
                    )
                )
                recovered_rva = streamtable.find_recovered_header(
                    self._metadata_data,
                    self.rva,
                    stream_entry_rva + 4,
                    metadata_end_rva,
                )
                if recovered_rva is None:
                    report.table_truncated = True
                    report.add_warning(
                        "Stopped reading .NET stream table after {} of {} declared entries".format(
                            slot, self.struct.NumberOfStreams
                        )
                    )
                    break
                # Do not consume the recovered header for this slot.  Treat the
                # bad slot as missing and resume scanning at the recovered
                # header, so the following real headers still map to their own
                # table slots.
                report.add_warning(
                    "Skipped unreadable .NET stream slot {} at rva 0x{:x}; "
                    "resumed at header 0x{:x}".format(slot + 1, report.invalid_slots[-1], recovered_rva)
                )
                stream_entry_rva = recovered_rva
                continue

            report.entries.append(entry)
            entry_index += 1
            stream_entry_rva += entry.header_size

        streamtable.annotate_conflicts(report)
        streamtable.resolve_entries(report)
        streamtable.finalize_structure(report)
        return report


class ClrStruct(Structure):
    cb: int
    MajorRuntimeVersion: int
    MinorRuntimeVersion: int
    MetaDataRva: int
    MetaDataSize: int
    Flags: int
    EntryPointTokenOrRva: int
    ResourcesRva: int
    ResourcesSize: int
    StrongNameSignatureRva: int
    StrongNameSignatureSize: int
    CodeManagerTableRva: int
    CodeManagerTableSize: int
    VTableFixupsRva: int
    VTableFixupsSize: int
    ExportAddressTableJumpsRva: int
    ExportAddressTableJumpsSize: int
    ManagedNativeHeaderRva: int
    ManagedNativeHeaderSize: int


class ClrData(DataContainer):
    """Holds CLR (.NET) header data.

    struct:         IMAGE_NET_DIRECTORY structure
    metadata:       ClrMetaData or None
    strings:        stream.StringsHeap or None
    user_strings:   stream.UserStringsHeap or None
    guids:          stream.GuidHeap or None
    blobs:          stream.BlobHeap or None
    mdtables:       stream.MetaDataTables or None
    Flags:          enums.ClrHeaderFlags or None
    """

    struct: ClrStruct
    metadata: Optional[ClrMetaData]
    strings: Optional[stream.StringsHeap]
    user_strings: Optional[stream.UserStringHeap]
    guids: Optional[stream.GuidHeap]
    blobs: Optional[stream.BlobHeap]
    mdtables: Optional[stream.MetaDataTables]
    Flags: Optional[enums.ClrHeaderFlags]

    _resources: Optional[List[base.ClrResource]]

    @property
    def resources(self) -> List[base.ClrResource]:
        if self._resources is None:
            self._init_resources(getattr(self, "_pe"))
            assert self._resources is not None
        return self._resources

    # Structure description from:
    # http://www.ntcore.com/files/dotnetformat.htm
    _format = (
        "IMAGE_NET_DIRECTORY",
        (
            "I,cb",
            "H,MajorRuntimeVersion",
            "H,MinorRuntimeVersion",
            "I,MetaDataRva",
            "I,MetaDataSize",
            "I,Flags",
            "I,EntryPointTokenOrRva",
            "I,ResourcesRva",
            "I,ResourcesSize",
            "I,StrongNameSignatureRva",
            "I,StrongNameSignatureSize",
            "I,CodeManagerTableRva",
            "I,CodeManagerTableSize",
            "I,VTableFixupsRva",
            "I,VTableFixupsSize",
            "I,ExportAddressTableJumpsRva",
            "I,ExportAddressTableJumpsSize",
            "I,ManagedNativeHeaderRva",
            "I,ManagedNativeHeaderSize",
        ),
    )

    def __init__(self, pe: dnPE, rva: int, size: int, lazy_load: bool, stream_policy=None):
        """
        Given dnPE object, .NET header RVA and header size.
        Raises dnFormatError if problems parsing.
        """
        self.stream_policy = streamtable.normalize_policy(
            stream_policy if stream_policy is not None else getattr(pe, "stream_policy", None)
        )
        data = pe.get_data(rva, size)

        try:
            clr_struct = ClrStruct(
                self._format, file_offset=pe.get_offset_from_rva(rva)
            )
            clr_struct.__unpack__(data)
        except PEFormatError:
            # raise exception because we can't do anything halfway here.
            raise errors.dnFormatError(
                "Invalid CLR Structure information. Can't read "
                "data at RVA: 0x%x" % rva
            )

        # set structure member
        self.struct = clr_struct
        # parse metadata
        metadata_rva = clr_struct.MetaDataRva
        metadata_size = clr_struct.MetaDataSize

        # shortcuts are always defined, even if None, for easier code completion in IDEs
        self.metadata = None
        self.strings = None
        self.user_strings = None
        self.guids = None
        self.blobs = None
        self.mdtables = None
        self._resources = None
        self.Flags = None
        self.stream_report = None
        self.type_evidence = "missing"
        self.resource_evidence = "candidate"

        # Set the flags according to the Flags member
        flags_object = enums.ClrHeaderFlags(clr_struct.Flags)
        self.Flags = flags_object

        try:
            self.metadata = ClrMetaData(
                pe, metadata_rva, metadata_size, lazy_load, self.stream_policy
            )
        except errors.dnStreamTableError as e:
            pe.add_warning("failed to parse .NET metadata: {}".format(e))
            logger.warning("failed to parse .NET metadata: %s", e)
            self.stream_report = getattr(e, "report", None)
            return
        except (errors.dnFormatError, PEFormatError) as e:
            pe.add_warning("failed to parse .NET metadata: {}".format(e))
            logger.warning("failed to parse .NET metadata: %s", e)
            return

        self.stream_report = self.metadata.stream_report
        self.type_evidence = self.stream_report.table_evidence
        self.resource_evidence = self.stream_report.resource_evidence

        # create shortcuts for the selected stream of each type.  Selection is
        # done by the stream table report: a structurally valid entry wins over
        # a damaged one, so a broken duplicate cannot replace a usable stream.
        for selected_stream in self.metadata.streams.values():
            if isinstance(selected_stream, stream.StringsHeap):
                self.strings = selected_stream
            elif isinstance(selected_stream, stream.UserStringHeap):
                self.user_strings = selected_stream
            elif isinstance(selected_stream, stream.GuidHeap):
                self.guids = selected_stream
            elif isinstance(selected_stream, stream.BlobHeap):
                self.blobs = selected_stream
            elif isinstance(selected_stream, stream.MetaDataTables):
                self.mdtables: stream.MetaDataTables = selected_stream

        if self.mdtables is not None:
            for table in self.mdtables.tables_list:
                table.evidence = self.type_evidence

        if not lazy_load:
            self._init_resources(pe)
        else:
            # store the dnPE reference for lazy-loading
            setattr(self, "_pe", pe)

    def _init_resources(self, pe):
        """Parse and initialize assembly resources.

        This is separate from `ClrData.__init__` to allow for mdtable lazy-loading since
        parsing `ManifestResourceRow.Implementation` requires all tables to be loaded.
        """
        self._resources = []
        # parse the resources
        if self.struct.ResourcesRva > 0 and self.mdtables and self.mdtables.ManifestResource and self.mdtables.ManifestResource.num_rows > 0:
            # for each row
            for row in self.mdtables.ManifestResource.rows:
                # TODO: handle external resources
                if row.Implementation is None:
                    # internal resource, embedded in this file
                    rva = self.struct.ResourcesRva + row.Offset
                    try:
                        buf = pe.get_data(rva, 4)
                    except PEFormatError as e:
                        # warn
                        pe.add_warning("CLR resource parse error, expected more data at rva 0x{:02x}".format(rva))
                        continue
                    if not buf or len(buf) < 4:
                        # warn
                        pe.add_warning("CLR resource parse error, expected at least 4 bytes at rva 0x{:02x}".format(rva))
                        continue
                    size = int.from_bytes(buf, byteorder="little")
                    rsrc_rva = rva + 4
                    try:
                        rdata = pe.get_data(rsrc_rva, size)
                    except PEFormatError as e:
                        # warn
                        pe.add_warning("CLR resource parse error, expected more data at rva 0x{:02x}".format(rsrc_rva))
                        continue
                    if not rdata or len(rdata) < size:
                        pe.add_warning("CLR resource parse error, expected more data at rva 0x{:02x}".format(rsrc_rva))
                        continue
                    res = resource.InternalResource(row.Name, row.Flags.mrPublic, row.Flags.mrPrivate)
                    res.rva = rsrc_rva
                    res.size = size
                    res.data = rdata
                    res.evidence = self.resource_evidence
                    self._resources.append(res)
            for rsrc in self._resources:
                try:
                    rsrc.parse()
                except errors.dnFormatError as e:
                    if isinstance(rsrc, resource.InternalResource):
                        pe.add_warning("CLR resource parse error for '{}' at 0x{:02x}: {}".format(rsrc.name, rsrc.rva, str(e)))
                    else:
                        pe.add_warning("CLR resource parse error for '{}': {}".format(rsrc.name, str(e)))


class ClrStreamFactory(object):
    _name_type_map = {
        b"#~": stream.MetaDataTables,
        b"#-": stream.MetaDataTables,
        b"#Schema": stream.MetaDataTables,
        b"#Strings": stream.StringsHeap,
        b"#GUID": stream.GuidHeap,
        b"#Blob": stream.BlobHeap,
        b"#US": stream.UserStringHeap,
    }
    _template_format = (
        "IMAGE_CLR_STREAM",
        [
            "I,Offset",
            "I,Size",
            # '?,Name',
        ],
    )

    @classmethod
    def readStreamEntry(
        cls,
        pe: dnPE,
        stream_entry_rva: int,
        metadata_rva: int,
        metadata_read_end_rva: int,
        metadata_declared_end_rva: int,
        index: int = 0,
        slot: Optional[int] = None,
    ):
        """Read one stream header and its declared bytes, without reading past metadata.

        Returns ``(StreamTableEntry, None)`` on success and ``(None, reason)``
        when the header is unreadable.  The entry records the header order,
        header location, declared range, and the bytes actually available.
        """

        entry = streamtable.StreamTableEntry(
            index=index,
            slot=index if slot is None else slot,
            header_rva=stream_entry_rva,
            header_offset=None,
        )
        try:
            entry.header_offset = pe.get_offset_from_rva(stream_entry_rva)
        except PEFormatError as e:
            return None, "header rva cannot be mapped to a file offset: {}".format(e)

        try:
            header_format = _copymod.deepcopy(cls._template_format)
            if stream_entry_rva < metadata_rva or stream_entry_rva + 8 > metadata_read_end_rva:
                return None, "stream header outside readable metadata"
            raw = pe.get_data(stream_entry_rva, 8)
            if raw is None or len(raw) < 8:
                return None, "truncated stream header"
            name_limit = min(256, metadata_read_end_rva - (stream_entry_rva + 8))
            if name_limit <= 0:
                return None, "truncated stream name"
            name_bytes = pe.get_data(stream_entry_rva + 8, name_limit)
            if not name_bytes:
                return None, "truncated stream name"
            end = name_bytes.find(b"\x00")
            if end < 0:
                return None, "unterminated stream name"
            name = name_bytes[:end]
            if not name:
                return None, "empty stream name"
            # Every CLR metadata stream name is "#"-prefixed in practice.
            # Reject garbage names early so header recovery can find the
            # following real header instead of turning random bytes into a
            # candidate stream.
            if not name.startswith(b"#"):
                return None, "unexpected stream name {!r}".format(name)
            # Round the field length up to the next 4-byte boundary; the NUL
            # terminator must fit inside the field.
            name_len = len(name) + (4 - (len(name) % 4))
            header_format[1].append("{0}s,Name".format(name_len))
            stream_struct = base.StreamStruct(
                header_format,
                file_offset=entry.header_offset,
            )
            struct_size = stream_struct.sizeof()
            struct_data = pe.get_data(stream_entry_rva, struct_size)
            if struct_data is None or len(struct_data) < struct_size:
                return None, "truncated stream header"
            stream_struct.__unpack__(struct_data)
            stream_struct.Name = stream_struct.Name.rstrip(b"\x00")
        except (errors.dnFormatError, PEFormatError, ValueError, _struct.error) as e:
            return None, "unreadable stream header: {}".format(e)

        entry.header_size = stream_struct.sizeof()
        entry.name = stream_struct.Name
        entry.offset = stream_struct.Offset
        entry.size = stream_struct.Size
        entry.declared_rva = metadata_rva + entry.offset
        entry.declared_end_rva = entry.declared_rva + entry.size

        stream_class = cls._name_type_map.get(entry.name, stream.GenericStream)
        try:
            entry.stream = cls._read_stream_body(
                pe,
                stream_class,
                metadata_rva,
                stream_struct,
                entry,
                metadata_read_end_rva,
                metadata_declared_end_rva,
            )
        except (errors.dnFormatError, PEFormatError) as e:
            return None, "unreadable stream body: {}".format(e)
        return entry, None

    @classmethod
    def _read_stream_body(
        cls,
        pe: dnPE,
        stream_class,
        metadata_rva: int,
        stream_struct,
        entry: streamtable.StreamTableEntry,
        metadata_read_end_rva: int,
        metadata_declared_end_rva: int,
    ):
        if entry.size is None or entry.declared_rva is None or entry.declared_end_rva is None:
            raise errors.dnFormatError("missing stream range")
        if entry.size == 0:
            entry.statuses.add(streamtable.StreamStatus.ZERO_LENGTH)
            data = b""
        else:
            # The declared metadata directory is the authority for whether a
            # header escaped it.  A truncated file may make fewer bytes
            # readable, which is TRUNCATED, not OUTSIDE_METADATA.
            if (
                entry.declared_rva < metadata_rva
                or entry.declared_rva >= metadata_declared_end_rva
                or entry.declared_end_rva > metadata_declared_end_rva
            ):
                entry.statuses.add(streamtable.StreamStatus.OUTSIDE_METADATA)
            available = max(0, metadata_read_end_rva - entry.declared_rva)
            read_size = min(entry.size, available)
            data = pe.get_data(entry.declared_rva, read_size)
            if data is None:
                data = b""
            if len(data) < entry.size:
                entry.statuses.add(streamtable.StreamStatus.TRUNCATED)
            entry.read_size = len(data)

        if entry.read_size == 0 and entry.size:
            entry.statuses.add(streamtable.StreamStatus.TRUNCATED)
        if entry.size:
            entry.read_end_rva = entry.declared_rva + entry.read_size
        else:
            entry.read_end_rva = entry.declared_rva

        s = stream_class(metadata_rva, stream_struct, data)
        try:
            s.file_offset = pe.get_offset_from_rva(entry.declared_rva)
        except PEFormatError:
            s.file_offset = None
        entry.data_file_offset = s.file_offset
        # Size reported by the object is the bytes actually loaded, not the
        # declared size, so table sizing checks cannot read outside the buffer.
        return s

    @classmethod
    def createStream(
        cls, pe: dnPE, stream_entry_rva: int, metadata_rva: int
    ) -> Optional[base.ClrStream]:
        """Backwards-compatible single-header reader.

        New code should call :meth:`readStreamEntry`, which also returns the
        header/range bookkeeping used by the stream policy.
        """

        metadata = getattr(getattr(pe, "net", None), "metadata", None)
        metadata_size = getattr(metadata, "size", None) or 0
        entry, failure = cls.readStreamEntry(
            pe,
            stream_entry_rva,
            metadata_rva,
            metadata_rva + metadata_size,
            metadata_rva + metadata_size,
            0,
        )
        if entry is None:
            logger.warning("failed to parse stream: %s", failure)
            return None
        return entry.stream
