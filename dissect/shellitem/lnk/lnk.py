from __future__ import annotations

import logging
import typing
from dataclasses import dataclass
from io import BytesIO
from struct import unpack
from typing import Any, BinaryIO
from uuid import UUID

from dissect.util.stream import RangeStream

from dissect.shellitem.lnk.c_lnk import (
    EXTRA_DATA_BLOCK_SIGNATURES,
    LINK_EXTRA_DATA_HEADER_SIZE,
    LINK_HEADER_SIZE,
    LINK_INFO_BODY_SIZE,
    LINK_INFO_HEADER_SIZE,
    c_lnk,
)
from dissect.shellitem.lnk.encoding import (
    AnsiCodec,
    EncodedText,
    EncodingSource,
    coerce_ansi_codec,
    decode_ansi,
    decode_utf16le,
)

if typing.TYPE_CHECKING:
    from io import BufferedReader

log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False


@dataclass
class StringDataEntry:
    """One STRING_DATA section field plus its decoding decision.

    Replaces the raw cstruct typedef so the field can carry provenance. The
    cstruct-compatible ``character_count`` keeps the byte length semantics the
    previous implementation exposed (doubled for UTF-16LE), while ``string`` is
    an :class:`EncodedText` instead of a bare ``str``/``bytes``.
    """

    character_count: int
    string: EncodedText

    def __str__(self) -> str:
        return str(self.string)


def _read_cstring(buffer: bytes, offset: int, encoding: str) -> bytes:
    """Read a NUL-terminated string from ``buffer`` starting at ``offset``.

    Returns the raw bytes without the terminator for both single and double
    byte encodings. Reads up to the end of the buffer when no terminator exists.
    """
    if encoding == "utf-16-le":
        terminator = b"\x00\x00"
        step = 2
    else:
        terminator = b"\x00"
        step = 1

    end = offset
    while end + step <= len(buffer):
        if buffer[end : end + step] == terminator:
            break
        end += step
    return bytes(buffer[offset:end])


class LnkExtraData:
    """Class that represents the a LNK file's EXTRA_DATA structure.

    This optional structure hold additional optional structures that convey additional information about a link target

    Args:
        fh: A file-like object to an EXTRA_DATA structure
        ansi_codec: Optional, caller-sourced codec for the ANSI fields in
            ENVIRONMENT, ICON_ENVIRONMENT, DARWIN and TRACKER blocks.
    """

    # EXTRA_DATA = *EXTRA_DATA_BLOCK TERMINAL_BLOCK

    # EXTRA_DATA_BLOCK = CONSOLE_PROPS / CONSOLE_FE_PROPS / DARWIN_PROPS /
    #                    ENVIRONMENT_PROPS / ICON_ENVIRONMENT_PROPS /
    #                    KNOWN_FOLDER_PROPS / PROPERTY_STORE_PROPS /
    #                    SHIM_PROPS / SPECIAL_FOLDER_PROPS /
    #                    TRACKER_PROPS / VISTA_AND_ABOVE_IDLIST_PROPS
    # This is kinda the same as LnkStringData only that the defined extra structures can wildly vary
    def __init__(self, fh: BinaryIO | None = None, ansi_codec: AnsiCodec | None = None):
        self.extradata = {}
        self.ansi_codec = ansi_codec
        # Every textual field encountered in EXTRA_DATA, keyed by dotted path.
        self.text_fields: dict[str, EncodedText] = {}
        # Raw CodePage values of every ConsoleFEDataBlock, in file order. The
        # ConsoleFE page documents console output only and is never auto-applied.
        self.console_fe_code_pages: list[int] = []

        if fh:
            self._parse(fh)

    @property
    def console_fe_conflict(self) -> bool:
        """Whether the file declares more than one distinct ConsoleFE code page."""
        return len(set(self.console_fe_code_pages)) > 1

    def _record(self, field: EncodedText) -> EncodedText:
        self.text_fields[field.name] = field
        return field

    def _parse(self, fh: BinaryIO) -> None:
        self.size = c_lnk.uint32(fh)

        if self.size == 0x00000000:
            # terminal block encountered. end of lnk file
            self.extradata.update({"TERMINAL_BLOCK": c_lnk.EXTRA_DATA(extra_data_block=None, terminal_block=self.size)})
            return

        signature = c_lnk.uint32(fh)
        block_name = EXTRA_DATA_BLOCK_SIGNATURES.get_name(signature)

        if block_name:
            read_size = self.size - LINK_EXTRA_DATA_HEADER_SIZE
            block_data = memoryview(fh.read(read_size))

            if len(block_data) != read_size:
                # Some malicious lnk files have a mismatch in the size indicated in the data block and actual bytes red.
                # This causes cstruct to have an EOFError when trying to parse the actual size. Which is not reflected.
                log.warning(
                    "Mismatch in read size (%i) and actual EXTRA_DATA_BLOCK length (%i) for data block (%s)",
                    read_size,
                    len(block_data),
                    block_name,
                )
                return

            if block_name == "VISTA_AND_ABOVE_IDLIST_PROPS":
                struct = LnkTargetIdList(BytesIO(block_data), read_size)
            else:
                struct = c_lnk.typedefs[block_name](block_data)

            if block_name == "PROPERTY_STORE_PROPS":
                # TODO implement actual serialized property parsing
                guid = self._parse_guid(struct.format_id)
                struct.format_id = guid

            elif block_name == "TRACKER_PROPS":
                for name in struct.fields:
                    if "droid" in name:
                        guid = self._parse_guid(getattr(struct, name))
                        setattr(struct, name, guid)
                # machine_id is a fixed 16-byte ANSI field, NUL-padded. The raw
                # bytes stay available on the cstruct; the interpreted view is
                # recorded separately so existing byte comparisons keep working.
                self._record(decode_ansi("extradata.TRACKER_PROPS.machine_id", struct.machine_id, self.ansi_codec))

            elif block_name == "KNOWN_FOLDER_PROPS":
                guid = self._parse_guid(struct.known_folder_id)
                struct.known_folder_id = guid

            elif block_name == "CONSOLE_FE_PROPS":
                self.console_fe_code_pages.append(struct.code_page)
                if self.console_fe_conflict:
                    log.warning(
                        "Conflicting ConsoleFE code page declarations encountered: %s", self.console_fe_code_pages
                    )

            elif block_name == "CONSOLE_PROPS":
                # FaceName is a fixed 64-byte UTF-16LE buffer, NUL-terminated.
                self._record(
                    decode_utf16le(
                        "extradata.CONSOLE_PROPS.face_name",
                        _read_cstring(struct.face_name, 0, "utf-16-le"),
                    )
                )

            elif block_name in ("ENVIRONMENT_PROPS", "ICON_ENVIRONMENT_PROPS", "DARWIN_PROPS"):
                if block_name == "DARWIN_PROPS":
                    ansi_raw = _read_cstring(struct.darwin_data_ansi, 0, "ansi")
                    unicode_raw = _read_cstring(struct.darwin_data_unicode, 0, "utf-16-le")
                    ansi_name = "darwin_data_ansi"
                    unicode_name = "darwin_data_unicode"
                else:
                    ansi_raw = _read_cstring(struct.target_ansi, 0, "ansi")
                    unicode_raw = _read_cstring(struct.target_unicode, 0, "utf-16-le")
                    ansi_name = "target_ansi"
                    unicode_name = "target_unicode"

                ansi_text = self._record(decode_ansi(f"extradata.{block_name}.{ansi_name}", ansi_raw, self.ansi_codec))
                unicode_text = self._record(decode_utf16le(f"extradata.{block_name}.{unicode_name}", unicode_raw))
                # Keep the raw ANSI bytes on the struct, but expose the
                # locale-independent interpretation alongside them.
                setattr(struct, ansi_name, ansi_text)
                setattr(struct, unicode_name, unicode_text)

            self.extradata.update({block_name: struct})

        else:
            log.warning("Unknown extra data block encountered with signature %x", signature)

        # keep calling parse until the TERMINAL_BLOCK is hit.
        self._parse(fh)

    def _parse_guid(self, guid: bytes, endianness: str = "<") -> UUID:
        if endianness == "<":
            return UUID(bytes_le=guid)

        return UUID(bytes=guid)

    def __getattr__(self, attr: str) -> Any:
        try:
            return self.extradata[attr]
        except KeyError:
            return object.__getattribute__(self, attr)

    def __repr__(self) -> str:
        return " ".join(f"{value}" for value in self.extradata.values())


class LnkStringData:
    """This class represents the LNK file's STING_DATA structure. The STRING_DATA structure refers to a set of
    structures that convey user interface and path identification information.

    STRING_DATA = [NAME_STRING] [RELATIVE_PATH] [WORKING_DIR] [COMMAND_LINE_ARGUMENTS] [ICON_LOCATION]

    Args:
        fh: A file-lke object to a STRING_DATA structure
        lnk_flags: Parsed LINK_HEADER flags
        ansi_codec: Optional, caller-sourced codec used when is_unicode is unset.
    """

    def __init__(
        self,
        fh: BinaryIO | None = None,
        lnk_flags: c_lnk.LINK_FLAGS | None = None,
        ansi_codec: AnsiCodec | None = None,
    ):
        self.flags = None
        self.string_data = None
        self.ansi_codec = ansi_codec
        # Every textual field encountered in STRING_DATA, keyed by dotted path.
        self.text_fields: dict[str, EncodedText] = {}
        if fh:
            self.flags = lnk_flags
            self.string_data = {}
            self._parse(fh)

    def _parse(self, fh: BinaryIO) -> None:
        flag_names = (
            ("has_name", "name_string"),
            ("has_relative_path", "relative_path"),
            ("has_working_dir", "working_dir"),
            ("has_arguments", "command_line_arguments"),
            ("has_icon_location", "icon_location"),
        )

        for flag, string_data_name in flag_names:
            if self.flags & c_lnk.LINK_FLAGS[flag]:
                string_data = self._get_stringdata(fh, string_data_name)
                self.string_data.update({string_data_name: string_data})
                self.text_fields[f"stringdata.{string_data_name}"] = string_data.string

    def _get_stringdata(self, fh: BinaryIO, field_name: str) -> StringDataEntry:
        # STRING_DATA structs have a size called character_count. For UTF-16LE
        # fields the character count is doubled to obtain the byte length; for
        # ANSI fields the count already equals the byte length.
        character_count = unpack("H", fh.read(2))[0]
        is_unicode = bool(self.flags & c_lnk.LINK_FLAGS.is_unicode)
        byte_size = character_count * 2 if is_unicode else character_count
        raw = fh.read(byte_size)

        if is_unicode:
            text = decode_utf16le(
                f"stringdata.{field_name}",
                raw,
                source=EncodingSource.LINK_FLAG_IS_UNICODE,
                note="LinkFlags.is_unicode set",
            )
        else:
            text = decode_ansi(f"stringdata.{field_name}", raw, self.ansi_codec)

        # character_count keeps the historical byte-length semantics.
        return StringDataEntry(character_count=byte_size, string=text)

    def __getattr__(self, attr: str) -> Any:
        try:
            return self.string_data[attr]
        except KeyError:
            return object.__getattribute__(self, attr)

    def __repr__(self) -> str:
        return " ".join(f"{value}" for value in self.string_data.values())


class LnkInfo:
    """This class represents a LNK file's LINK_INFO structure. The optional LINK_INFO structure specifies information
    necessary to resolve a link target if it is not found in its original location. This includes information about
    the volume that the target was stored on, the mapped drive letter, and a UNC path if existed when the link was
    created.

    Args:
        fh: A file-like objet to a LINK_INFO structure
        ansi_codec: Optional, caller-sourced codec for the ANSI LinkInfo strings.
    """

    def __init__(self, fh: BinaryIO | None = None, ansi_codec: AnsiCodec | None = None):
        self.fh = fh
        self.flags = None
        self.size = None
        self.ansi_codec = ansi_codec
        # Every textual field encountered in LINK_INFO, keyed by dotted path.
        self.text_fields: dict[str, EncodedText] = {}

        self.link_info = None
        self.linkinfo_header = None
        self.linkinfo_body = None

        if fh:
            self.linkinfo_header = c_lnk.LINK_INFO_HEADER(fh.read(LINK_INFO_HEADER_SIZE))
            self.flags = self.linkinfo_header.link_info_flags

            # A header size of at least 0x24 adds the optional LocalBasePath and
            # CommonPathSuffix Unicode offsets, which are parsed below.
            if self.linkinfo_header.link_info_header_size >= 0x00000024:
                log.debug(
                    "Extended link_info_header encountered (size %x): Unicode path offsets present.",
                    self.linkinfo_header.link_info_header_size,
                )

            self.linkinfo_body = c_lnk.LINK_INFO_BODY(fh.read(LINK_INFO_BODY_SIZE))

            offset = fh.seek(fh.tell() - LINK_INFO_HEADER_SIZE - LINK_INFO_BODY_SIZE)
            buff = RangeStream(fh, offset, self.linkinfo_header.link_info_size)
            self._raw_buffer = buff.read()
            self._parse(BytesIO(self._raw_buffer))

    def _record(self, field: EncodedText) -> EncodedText:
        self.text_fields[field.name] = field
        return field

    def _read_offset_string(self, offset: int, encoding: str) -> bytes:
        if offset <= 0 or offset >= len(self._raw_buffer):
            return b""
        return _read_cstring(self._raw_buffer, offset, encoding)

    def _read_volume_label(self, volumeid: c_lnk.VOLUME_ID) -> tuple[bytes, str]:
        """Read the volume label using offsets relative to the VolumeID start.

        The label offsets in MS-SHLLINK are relative to the beginning of the
        VolumeID structure, not absolute LinkInfo offsets. A 16-byte fixed
        header precedes the ``data`` buffer that holds the label bytes.
        """
        label_offset = volumeid.volume_label_offset
        unicode_offset = getattr(volumeid, "volume_label_offset_unicode", None)
        # VOLUME_ID_UNICODE has a 20-byte fixed header (extra Unicode offset
        # field); the plain VOLUME_ID header is 16 bytes.
        fixed_header = 20 if unicode_offset is not None else 16

        if label_offset == 0x14 and unicode_offset:
            relative = unicode_offset - fixed_header
            return _read_cstring(volumeid.data, relative, "utf-16-le"), "utf-16-le"

        relative = label_offset - fixed_header
        if relative < 0:
            return b"", "ansi"
        return _read_cstring(volumeid.data, relative, "ansi"), "ansi"

    def _parse(self, buff: BinaryIO) -> None:
        buff.seek(LINK_INFO_HEADER_SIZE + LINK_INFO_BODY_SIZE)

        common_network_relative_link = None
        local_base_path = None
        net_name = None
        device_name = None
        volumeid = None

        # Optional Unicode header extensions (header size >= 0x24). These two
        # offsets sit immediately after the fixed LINK_INFO_BODY.
        local_basepath_offset_unicode = 0
        common_pathsuffix_offset_unicode = 0
        if self.linkinfo_header.link_info_header_size >= 0x00000024:
            local_basepath_offset_unicode = unpack("I", buff.read(4))[0]
            common_pathsuffix_offset_unicode = unpack("I", buff.read(4))[0]

        if self.flag("volumeid_and_local_basepath"):
            # Seek to the declared VolumeID offset explicitly: reading the
            # optional Unicode header offsets above advances the stream past the
            # start of the VolumeID structure.
            buff.seek(self.linkinfo_body.volumeid_offset)
            volumeid_size = unpack("I", buff.read(4))[0]
            # The ANSI volume label offset is the fourth 32-bit field (offset 12).
            # A value of 0x14 means a Unicode label is present and the VolumeID
            # carries the extra 32-bit Unicode offset field (a 20-byte fixed
            # header instead of 16).
            buff.seek(self.linkinfo_body.volumeid_offset + 12)
            volume_label_offset = unpack("I", buff.read(4))[0]
            buff.seek(self.linkinfo_body.volumeid_offset)
            if volume_label_offset == 0x14:
                volumeid = c_lnk.VOLUME_ID_UNICODE(buff.read(volumeid_size))
            else:
                volumeid = c_lnk.VOLUME_ID(buff.read(volumeid_size))

            # A VolumeID can be present without a following LocalBasePath (its
            # offset is zero or the VolumeID already fills the structure).
            if self.linkinfo_body.local_basepath_offset:
                local_base_path = c_lnk.LOCAL_BASE_PATH(buff.read())
                local_base_path = local_base_path.local_base_path
            # put pointer back before common_path_suffix
            buff.seek(self.linkinfo_body.common_network_relative_link_offset)

        if self.flag("common_network_relative_link_and_pathsuffix"):
            start_common_network_relative_link = buff.tell()
            # read the size of the common_network_relative_link_size. This is 20 bytes
            header = c_lnk.COMMON_NETWORK_RELATIVE_LINK_HEADER(buff.read(20))
            flags = header.common_network_relative_link_flags

            if flags & c_lnk.COMMON_NETWORK_RELATIVE_LINK_FLAGS.valid_device:
                offset = buff.seek(start_common_network_relative_link + header.device_name_offset)
                device_name = c_lnk.DEVICE_NAME(buff.read())
                read_size = len(device_name.dumps())
                device_name = device_name.device_name
                buff.seek(offset + read_size)

            if flags & c_lnk.COMMON_NETWORK_RELATIVE_LINK_FLAGS.valid_net_type:
                offset = buff.seek(start_common_network_relative_link + header.net_name_offset)
                net_name = c_lnk.NET_NAME(buff.read())
                read_size = len(net_name.dumps())
                net_name = net_name.net_name
                buff.seek(offset + read_size)

            common_network_relative_link = c_lnk.COMMON_NETWORK_RELATIVE_LINK(
                common_network_relative_link_size=header.common_network_relative_link_size,
                common_network_relative_link_flags=header.common_network_relative_link_flags,
                net_name_offset=header.net_name_offset,
                device_name_offset=header.device_name_offset,
                net_provider_type=header.net_provider_type,
                net_name=net_name,
                device_name=device_name,
            )

        # common_path_suffix is always present, even when its value is just 0x00
        # or when the flag common_network_relative_link_and_pathsuffix indicates otherwise
        suffix_offset = self.linkinfo_body.common_pathsuffix_offset
        if suffix_offset and suffix_offset < len(self._raw_buffer):
            buff.seek(suffix_offset)
            common_path_suffix = c_lnk.COMMON_PATH_SUFFIX(buff.read()).common_path_suffix
        else:
            common_path_suffix = b""

        self.link_info = c_lnk.LINK_INFO(
            link_info_size=self.linkinfo_header.link_info_size,
            link_info_header_size=self.linkinfo_header.link_info_header_size,
            link_info_flags=self.flags,
            volumeid_offset=self.linkinfo_body.volumeid_offset,
            local_basepath_offset=self.linkinfo_body.local_basepath_offset,
            common_network_relative_link_offset=self.linkinfo_body.common_network_relative_link_offset,
            common_pathsuffix_offset=self.linkinfo_body.common_pathsuffix_offset,
            volumeid=volumeid,
            local_base_path=local_base_path,
            common_network_relative_link=common_network_relative_link,
            common_path_suffix=common_path_suffix,
        )

        self._interpret_strings(
            local_base_path,
            common_path_suffix,
            net_name,
            device_name,
            volumeid,
            local_basepath_offset_unicode,
            common_pathsuffix_offset_unicode,
        )

    def _interpret_strings(
        self,
        local_base_path: bytes | None,
        common_path_suffix: bytes,
        net_name: bytes | None,
        device_name: bytes | None,
        volumeid: c_lnk.VOLUME_ID | None,
        local_basepath_offset_unicode: int,
        common_pathsuffix_offset_unicode: int,
    ) -> None:
        """Build per-field, provenance-aware interpretations of every string.

        The cstruct objects keep exposing the original ANSI bytes. The
        :class:`EncodedText` records live in :attr:`text_fields` and never depend
        on the host locale.
        """
        if local_base_path is not None:
            self._record(decode_ansi("linkinfo.local_base_path", local_base_path, self.ansi_codec))
        self._record(decode_ansi("linkinfo.common_path_suffix", common_path_suffix, self.ansi_codec))

        if net_name is not None:
            self._record(decode_ansi("linkinfo.common_network_relative_link.net_name", net_name, self.ansi_codec))
        if device_name is not None:
            self._record(decode_ansi("linkinfo.common_network_relative_link.device_name", device_name, self.ansi_codec))

        if volumeid is not None:
            # VolumeID holds either an ANSI label (offset 0x10) or, when the ANSI
            # offset is 0x14, an explicit UTF-16LE label located via the Unicode
            # offset. Offsets are relative to the VolumeID structure itself.
            label_raw, label_encoding = self._read_volume_label(volumeid)
            if label_encoding == "utf-16-le":
                self._record(decode_utf16le("linkinfo.volumeid.volume_label", label_raw))
            else:
                self._record(decode_ansi("linkinfo.volumeid.volume_label", label_raw, self.ansi_codec))

        # Optional, explicitly UTF-16LE variants from the extended header.
        if local_basepath_offset_unicode:
            raw = self._read_offset_string(local_basepath_offset_unicode, "utf-16-le")
            self._record(decode_utf16le("linkinfo.local_base_path_unicode", raw))
        if common_pathsuffix_offset_unicode:
            raw = self._read_offset_string(common_pathsuffix_offset_unicode, "utf-16-le")
            self._record(decode_utf16le("linkinfo.common_path_suffix_unicode", raw))

    def flag(self, name: str) -> int:
        """Returns whether supplied flag is set.

        Args:
            name: Name of the flag

        Returns:
            int: >0 if flag is set
        """
        return self.flags & c_lnk.LINK_INFO_FLAGS[name]

    def __getattr__(self, attr: str) -> Any:
        try:
            return self.link_info[attr]
        except KeyError:
            return object.__getattribute__(self, attr)

    def __repr__(self) -> str:
        if self.link_info:
            return self.link_info
        return "<LINK_INFO>"


class LnkTargetIdList:
    """This class represents a LNK file's TARGET_IDLIST structure. The TARGET_IDLIST structure specifies the target of
    the link. The ITEM_ID structures inside are opaque shell data source blobs and carry no declared text encoding, so
    they are intentionally not decoded here.

    Args:
        fh: A file-like object to a TARGET_IDLIST structure.
        size: Size of the TARGET_IDLIST structure
    """

    def __init__(self, fh: BinaryIO | None = None, size: int | None = None):
        self.target_idlist = None
        self.idlist = None
        self.size = None

        if fh:
            self.size = unpack("H", fh.read(2))[0] if size is None else size
            self._parse(fh.read(self.size))

    def _parse(self, buff: BinaryIO) -> None:
        idlists = []
        buff = BytesIO(buff)

        # the size of the target_idlist struct includes itself. Thus we minus 2 here.
        while buff.tell() < self.size - 2:
            size = unpack("H", buff.read(2))[0]
            data = buff.read(size - 2)  # size of the struct includes the 16-bit size value. Thus we minus 2 here again.
            itemid = c_lnk.ITEMID(itemid_size=size, data=data)
            idlists.append(itemid)

        self.idlist = c_lnk.IDLIST(itemid_list=idlists, terminalid=buff.read())
        self.target_idlist = c_lnk.LINK_TARGET_IDLIST(idlist_size=self.size, idlist=self.idlist)

    def __repr__(self) -> str:
        return repr(self.target_idlist)


class Lnk:
    """This class represents a LNK file's SHELL_LINK_HEADER, and the remainder of the parsed LNK file structures.
    This SHELL_LINK_HEADER structure contains identification information, timestamps, and flags that specify the
    presence of optional structures.

    Parses a .lnk file (aka Microsoft Shell Item) according to the MS-SHLLINK specification
    reference: https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/%5bMS-SHLLINK%5d.pdf

    Args:
        path: (string) Path to a link file.
        target_idlist: A LnkTargetIdList object.
        linkinfo: A LnkInfo object.
        stringdata: A LnkStringData object.
        extradata: A LnkExtraData object.
        ansi_codec: Optional codec (name or :class:`AnsiCodec`) for the file's
            ANSI fields. The LNK format never records this code page, so it must
            come from the caller with provenance. When omitted, ANSI fields stay
            undecoded and pending instead of being mapped through the host locale.
    """

    def __init__(
        self,
        fh: BufferedReader,
        target_idlist: LnkTargetIdList | None = None,
        linkinfo: LnkInfo | None = None,
        stringdata: LnkStringData | None = None,
        extradata: LnkExtraData | None = None,
        ansi_codec: AnsiCodec | str | None = None,
    ):
        self.fh = fh
        self.ansi_codec = coerce_ansi_codec(ansi_codec)

        self.flags = None
        self.link_header = self._parse_header(self.fh)
        self.target_idlist = LnkTargetIdList()
        self.linkinfo = LnkInfo()
        self.stringdata = LnkStringData()
        self.extradata = LnkExtraData()

        if self.link_header:
            self.flags = self.link_header.link_flags

            if self.flag("has_link_target_idlist"):
                self.target_idlist = LnkTargetIdList(self.fh)

            if self.flag("has_link_info"):
                self.linkinfo = LnkInfo(self.fh, ansi_codec=self.ansi_codec)

            if (
                self.flag("has_name")
                or self.flag("has_relative_path")
                or self.flag("has_working_dir")
                or self.flag("has_arguments")
                or self.flag("has_icon_location")
            ):
                self.stringdata = LnkStringData(self.fh, self.flags, ansi_codec=self.ansi_codec)

            self.extradata = LnkExtraData(self.fh, ansi_codec=self.ansi_codec)

    @property
    def text_fields(self) -> dict[str, EncodedText]:
        """All textual fields of the file, keyed by dotted path, each with provenance."""
        fields = {}
        fields.update(self.stringdata.text_fields)
        fields.update(self.linkinfo.text_fields)
        fields.update(self.extradata.text_fields)
        return fields

    @property
    def console_fe_code_pages(self) -> list[int]:
        """Raw ConsoleFEDataBlock CodePage values; never applied automatically."""
        return self.extradata.console_fe_code_pages

    @property
    def console_fe_conflict(self) -> bool:
        """Whether conflicting ConsoleFE code pages were declared."""
        return self.extradata.console_fe_conflict

    def explain_text(self) -> str:
        """Human-readable, per-field explanation of every decoding decision."""
        return "\n".join(field.explain() for field in self.text_fields.values())

    def flag(self, name: str) -> int:
        """Returns whether supplied flag is set.

        Args:
            name: Name of the flag

        Returns:
            int: >0 if flag is set
        """
        return self.flags & c_lnk.LINK_FLAGS[name]

    def _parse_header(self, fh: BinaryIO | None) -> c_lnk.SHELL_LINK_HEADER | None:
        """Returns LINK header.

        Parse the header in a buffer that does not start at offset 0

        Args:
            fh: File object

        Returns:
            LINK header if size is 0x4C, else none
        """
        offset = fh.tell()
        header_size = unpack("I", fh.read(4))[0]
        fh.seek(offset)

        if header_size == LINK_HEADER_SIZE:
            link_header = c_lnk.SHELL_LINK_HEADER(fh.read(LINK_HEADER_SIZE))
            link_clsid = str(UUID(bytes_le=link_header.link_clsid))

            if link_clsid == "00021401-0000-0000-c000-000000000046":
                return link_header

            log.info("Encountered invalid link file header: %s. Skipping.", link_header)
            return None

        log.info(
            "Encountered invalid link file with magic header size 0x%x. \
            Magic header size should be 0x%x. Skipping.",
            header_size,
            LINK_HEADER_SIZE,
        )
        return None

    @property
    def clsid(self) -> UUID:
        """Returns the class id (clsid) of the LNK file."""
        return UUID(bytes_le=self.link_header.link_clsid)

    def __repr__(self) -> str:
        return f"{self.link_header} {self.target_idlist} {self.linkinfo.link_info} {self.stringdata} {self.extradata}"
