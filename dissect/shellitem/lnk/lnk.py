from __future__ import annotations

import logging
import typing
from dataclasses import dataclass
from enum import Enum
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

if typing.TYPE_CHECKING:
    from collections.abc import Mapping
    from io import BufferedReader

log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False


class FolderReferenceStatus(str, Enum):
    """Status of correlating a SPECIAL_FOLDER_PROPS or KNOWN_FOLDER_PROPS offset with the target IDList."""

    RESOLVED = "resolved"
    NO_IDLIST = "no_target_idlist"
    MID_ITEM = "offset_mid_item"
    AT_TERMINAL = "offset_at_terminal"
    OUT_OF_RANGE = "offset_out_of_range"


@dataclass
class LnkFolderReference:
    """Correlation result of a SPECIAL_FOLDER_PROPS or KNOWN_FOLDER_PROPS block with the target IDList.

    The folder identifiers in these blocks are not full disk paths. A path is only derived when the caller
    supplies an offline folder mapping; the analysis machine's own user folders are never consulted.

    When ``tracking_disabled`` is set, the DisableKnownFolderTracking link flag instructed the shell to
    ignore these blocks when loading the link, so the reference must not be interpreted as the actual
    launch target and no path is derived from it.
    """

    block_name: str
    folder_id: UUID | int
    offset: int
    status: FolderReferenceStatus
    first_child_index: int | None = None
    itemid_range: tuple[int, int] | None = None
    tracking_disabled: bool = False
    resolved_path: str | None = None
    mapping_key: str | int | None = None


class LnkExtraData:
    """Class that represents the a LNK file's EXTRA_DATA structure.

    This optional structure hold additional optional structures that convey additional information about a link target

    Args:
        fh: A file-like object to an EXTRA_DATA structure
    """

    # EXTRA_DATA = *EXTRA_DATA_BLOCK TERMINAL_BLOCK

    # EXTRA_DATA_BLOCK = CONSOLE_PROPS / CONSOLE_FE_PROPS / DARWIN_PROPS /
    #                    ENVIRONMENT_PROPS / ICON_ENVIRONMENT_PROPS /
    #                    KNOWN_FOLDER_PROPS / PROPERTY_STORE_PROPS /
    #                    SHIM_PROPS / SPECIAL_FOLDER_PROPS /
    #                    TRACKER_PROPS / VISTA_AND_ABOVE_IDLIST_PROPS
    # This is kinda the same as LnkStringData only that the defined extra structures can wildly vary
    def __init__(self, fh: BinaryIO | None = None):
        self.extradata = {}

        if fh:
            self._parse(fh)

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

            elif block_name == "KNOWN_FOLDER_PROPS":
                guid = self._parse_guid(struct.known_folder_id)
                struct.known_folder_id = guid

            elif (
                block_name == "ENVIRONMENT_PROPS"
                or block_name == "ICON_ENVIRONMENT_PROPS"
                or block_name == "DARWIN_PROPS"
            ):
                if block_name == "DARWIN_PROPS":
                    struct.darwin_data_ansi = struct.darwin_data_ansi
                    struct.darwin_data_unicode = struct.darwin_data_unicode.decode().rstrip("\x00")
                else:
                    struct.target_ansi = struct.target_ansi
                    struct.target_unicode = struct.target_unicode.decode("utf-16").rstrip("\x00")

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
    """

    def __init__(self, fh: BinaryIO | None = None, lnk_flags: c_lnk.LINK_FLAGS | None = None):
        self.flags = None
        self.string_data = None
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
                string_data = self._get_stringdata(fh)
                self.string_data.update({string_data_name: string_data})

    def _get_stringdata(self, fh: BinaryIO) -> c_lnk.STRING_DATA:
        # STRING_DATA structs have a size called character_count
        # this size (character_count) should be doubled when unicode is used
        size = unpack("H", fh.read(2))[0]
        if self.flags & c_lnk.LINK_FLAGS.is_unicode:
            size = size * 2
            data = fh.read(size).decode("utf-16")
        else:
            data = fh.read(size)

        return c_lnk.STRING_DATA(character_count=size, string=data)

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
    """

    def __init__(self, fh: BinaryIO | None = None):
        self.fh = fh
        self.flags = None
        self.size = None

        self.link_info = None
        self.linkinfo_header = None
        self.linkinfo_body = None

        if fh:
            self.linkinfo_header = c_lnk.LINK_INFO_HEADER(fh.read(LINK_INFO_HEADER_SIZE))
            self.flags = self.linkinfo_header.link_info_flags

            # values higher than 0x24 indicate the presence of optional fields in the link info structure
            # if so the LocalBasePathOffsetUnicode and CommonPathSuffixOffsetUnicode fields are present
            if self.linkinfo_header.link_info_header_size >= 0x00000024:
                log.error(
                    "Unicode link_info_header encountered. Size bigger than 0x00000024. Size encountered: %x",
                    self.linkinfo_header.link_info_header_size,
                )
                # TODO parse unicode headers. none encountered yet.

            self.linkinfo_body = c_lnk.LINK_INFO_BODY(fh.read(LINK_INFO_BODY_SIZE))

            offset = fh.seek(fh.tell() - LINK_INFO_HEADER_SIZE - LINK_INFO_BODY_SIZE)
            buff = RangeStream(fh, offset, self.linkinfo_header.link_info_size)
            self._parse(buff)

    def _parse(self, buff: BinaryIO) -> None:
        buff.seek(LINK_INFO_HEADER_SIZE + LINK_INFO_BODY_SIZE)
        offset = buff.tell()

        common_network_relative_link = None
        local_base_path = None
        net_name = None
        device_name = None
        volumeid = None

        if self.flag("volumeid_and_local_basepath"):
            volumeid_size = unpack("I", buff.read(4))[0]
            buff.seek(offset)
            volumeid = c_lnk.VOLUME_ID(buff.read(volumeid_size))

            offset = buff.tell()
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
        buff.seek(self.linkinfo_body.common_pathsuffix_offset)
        common_path_suffix = c_lnk.COMMON_PATH_SUFFIX(buff.read()).common_path_suffix

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
    the link. This information is stored in individual ITEM_ID structures.

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

    def item_offsets(self) -> list[int]:
        """Return the byte offset of each ItemID relative to the start of the IDList.

        The offsets stored in the SPECIAL_FOLDER_PROPS and KNOWN_FOLDER_PROPS extra data blocks are
        relative to the start of the IDList, i.e. directly after the IDListSize field.
        """
        offsets = []
        offset = 0
        for itemid in self.idlist.itemid_list if self.idlist else []:
            offsets.append(offset)
            offset += itemid.itemid_size
        return offsets

    def find_itemid(self, offset: int) -> tuple[FolderReferenceStatus, int | None]:
        """Locate the ItemID at a byte offset into the IDList.

        Args:
            offset: Offset in bytes, relative to the start of the IDList.

        Returns:
            Tuple of the correlation status and, when the offset points exactly at the start of an
            ItemID, the index of that ItemID in the IDList. The index is None for every other status.
        """
        if not self.idlist:
            return FolderReferenceStatus.NO_IDLIST, None

        item_offset = 0
        for index, itemid in enumerate(self.idlist.itemid_list):
            if offset == item_offset:
                return FolderReferenceStatus.RESOLVED, index
            if item_offset < offset < item_offset + itemid.itemid_size:
                return FolderReferenceStatus.MID_ITEM, None
            item_offset += itemid.itemid_size

        if offset == item_offset:
            return FolderReferenceStatus.AT_TERMINAL, None
        return FolderReferenceStatus.OUT_OF_RANGE, None

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
    """

    def __init__(
        self,
        fh: BufferedReader,
        target_idlist: LnkTargetIdList | None = None,
        linkinfo: LnkInfo | None = None,
        stringdata: LnkStringData | None = None,
        extradata: LnkExtraData | None = None,
    ):
        self.fh = fh

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
                self.linkinfo = LnkInfo(self.fh)

            if (
                self.flag("has_name")
                or self.flag("has_relative_path")
                or self.flag("has_working_dir")
                or self.flag("has_arguments")
                or self.flag("has_icon_location")
            ):
                self.stringdata = LnkStringData(self.fh, self.flags)

            self.extradata = LnkExtraData(self.fh)

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

    def folder_references(self, folder_mapping: Mapping[str | int, str] | None = None) -> list[LnkFolderReference]:
        """Correlate SPECIAL_FOLDER_PROPS and KNOWN_FOLDER_PROPS blocks with the target IDList.

        Both blocks declare a folder (by special folder ID or known folder GUID) and an offset into the
        link target IDList of the first child ItemID of that folder. Neither is a full disk path by
        itself. For each block present, the offset is resolved against the IDList and, when both blocks
        are present, a reference is returned for each of them in the order they appear in the file.

        A path is only derived when the caller supplies an offline folder mapping; the analysis
        machine's own user folders are never consulted. When the DisableKnownFolderTracking link flag
        is set, these blocks are ignored when the shell loads the link, so the returned references are
        marked as tracking disabled and no path is derived from them.

        Args:
            folder_mapping: Optional offline mapping of folder identifiers to paths. Keys are the
                string representation of the known folder GUID for KNOWN_FOLDER_PROPS blocks, or the
                integer special folder ID for SPECIAL_FOLDER_PROPS blocks.

        Returns:
            A list of LnkFolderReference objects, one per folder block encountered.
        """
        references = []
        tracking_disabled = bool(self.flags) and bool(self.flag("disable_known_folder_tracking"))

        for block_name, block in self.extradata.extradata.items():
            if block_name == "KNOWN_FOLDER_PROPS":
                folder_id = block.known_folder_id
                mapping_key: str | int = str(folder_id)
            elif block_name == "SPECIAL_FOLDER_PROPS":
                folder_id = block.special_folder_id
                mapping_key = folder_id
            else:
                continue

            status, first_child_index = self.target_idlist.find_itemid(block.offset)
            itemid_range = None
            if first_child_index is not None:
                itemid_range = (first_child_index, len(self.target_idlist.idlist.itemid_list))

            resolved_path = None
            used_mapping_key = None
            if not tracking_disabled and folder_mapping is not None and mapping_key in folder_mapping:
                resolved_path = folder_mapping[mapping_key]
                used_mapping_key = mapping_key

            references.append(
                LnkFolderReference(
                    block_name=block_name,
                    folder_id=folder_id,
                    offset=block.offset,
                    status=status,
                    first_child_index=first_child_index,
                    itemid_range=itemid_range,
                    tracking_disabled=tracking_disabled,
                    resolved_path=resolved_path,
                    mapping_key=used_mapping_key,
                )
            )

        return references

    def __repr__(self) -> str:
        return f"{self.link_header} {self.target_idlist} {self.linkinfo.link_info} {self.stringdata} {self.extradata}"
