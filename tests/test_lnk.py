from __future__ import annotations

import struct
from io import BytesIO
from typing import TYPE_CHECKING
from uuid import UUID

import pytest
from dissect.util.ts import uuid1timestamp

from dissect.shellitem.lnk import FolderReferenceStatus, Lnk, c_lnk

if TYPE_CHECKING:
    from pathlib import Path


def test_xp_custom_destination_remote_lnk_file(xp_modified_remote_lnk_file: Path) -> None:
    # The first 16 bytes contain the LNK GUID a to simulate a Jumplist CustomDestination file
    fh = xp_modified_remote_lnk_file.open("rb")
    fh.seek(16)

    lnk_file = Lnk(fh)

    assert lnk_file.link_header.header_size == 0x4C
    assert str(lnk_file.clsid) == "00021401-0000-0000-c000-000000000046"


def test_xp_remote_lnk_file(xp_remote_lnk_file: Path) -> None:
    fh = xp_remote_lnk_file.open("rb")
    lnk_file = Lnk(fh)

    assert lnk_file.link_header.header_size == 0x4C
    assert str(lnk_file.clsid) == "00021401-0000-0000-c000-000000000046"

    flags = lnk_file.flags

    assert flags & c_lnk.LINK_FLAGS.has_link_target_idlist
    idlist = lnk_file.target_idlist.idlist
    assert len(idlist.itemid_list) == 9
    assert idlist.terminalid == b"\x00\x00"
    assert all(entry.itemid_size == len(entry.dumps()) for entry in idlist.itemid_list)

    assert flags & c_lnk.LINK_FLAGS.has_link_info
    link_info = lnk_file.linkinfo.link_info
    link_info_flags = link_info.link_info_flags
    assert link_info_flags & c_lnk.LINK_INFO_FLAGS.volumeid_and_local_basepath == 0
    assert link_info_flags & c_lnk.LINK_INFO_FLAGS.common_network_relative_link_and_pathsuffix

    common_network_relative_link = lnk_file.linkinfo.common_network_relative_link
    assert (
        common_network_relative_link.common_network_relative_link_flags
        & c_lnk.COMMON_NETWORK_RELATIVE_LINK_FLAGS.valid_device
        == 0
    )
    assert (
        common_network_relative_link.common_network_relative_link_flags
        & c_lnk.COMMON_NETWORK_RELATIVE_LINK_FLAGS.valid_net_type
    )
    assert common_network_relative_link.net_name_offset == 0x14
    assert common_network_relative_link.device_name_offset == 0x0
    assert common_network_relative_link.device_name.device_name == b""
    assert common_network_relative_link.net_provider_type == 0x20000
    assert common_network_relative_link.net_name == b"\\\\ALS-FICHIERS3\\QUALIT\xc9"
    assert link_info.common_path_suffix == b"Archives\\M\xe9thodologie WAS\\Norme de d\xe9veloppement JAVA.doc"

    assert flags & c_lnk.LINK_FLAGS.has_working_dir
    assert len(lnk_file.stringdata.string_data) == 1
    working_dir = lnk_file.stringdata.string_data["working_dir"]
    assert working_dir.character_count == 0x62
    assert working_dir.string == "\\\\als-fichiers3\\Qualité\\Archives\\Méthodologie WAS"
    assert len(working_dir.string) == working_dir.character_count / 2  # extra 0x00 bytes are decoded away.

    tracker_props = lnk_file.extradata.extradata["TRACKER_PROPS"]
    assert tracker_props.length == 0x58
    assert tracker_props.version == 0
    assert tracker_props.machine_id == b"als-fichiers3\x00\x00\x00"
    assert str(tracker_props.file_droid) == "ea461b34-9877-11da-80bd-000f1ff7c0dc"
    assert str(tracker_props.file_droid_birth) == "ea461b34-9877-11da-80bd-000f1ff7c0dc"
    assert uuid1timestamp(tracker_props.file_droid.time).ctime() == "Wed Feb  8 07:52:55 2006"


def test_xp_remote_lnk_dir(xp_remote_lnk_dir: Path) -> None:
    fh = xp_remote_lnk_dir.open("rb")
    lnk_file = Lnk(fh)

    assert lnk_file.link_header.header_size == 0x4C
    assert str(lnk_file.clsid) == "00021401-0000-0000-c000-000000000046"

    flags = lnk_file.flags

    assert flags & c_lnk.LINK_FLAGS.has_link_target_idlist
    idlist = lnk_file.target_idlist.idlist
    assert len(idlist.itemid_list) == 7
    assert idlist.terminalid == b"\x00\x00"
    assert all(entry.itemid_size == len(entry.dumps()) for entry in idlist.itemid_list)

    assert flags & c_lnk.LINK_FLAGS.has_link_info
    link_info = lnk_file.linkinfo.link_info
    link_info_flags = link_info.link_info_flags
    assert link_info_flags & c_lnk.LINK_INFO_FLAGS.volumeid_and_local_basepath == 0
    assert link_info_flags & c_lnk.LINK_INFO_FLAGS.common_network_relative_link_and_pathsuffix

    common_network_relative_link = lnk_file.linkinfo.common_network_relative_link
    assert (
        common_network_relative_link.common_network_relative_link_flags
        & c_lnk.COMMON_NETWORK_RELATIVE_LINK_FLAGS.valid_device
        == 0
    )
    assert (
        common_network_relative_link.common_network_relative_link_flags
        & c_lnk.COMMON_NETWORK_RELATIVE_LINK_FLAGS.valid_net_type
    )

    assert common_network_relative_link.net_name_offset == 0x14
    assert common_network_relative_link.device_name_offset == 0x0
    assert common_network_relative_link.device_name.device_name == b""
    assert common_network_relative_link.net_provider_type == 0x20000
    assert common_network_relative_link.net_name == b"\\\\ALS-FICHIERS3\\QUALIT\xc9"
    assert link_info.common_path_suffix == b"GMAldheris"

    tracker_props = lnk_file.extradata.extradata["TRACKER_PROPS"]
    assert tracker_props.length == 0x58
    assert tracker_props.version == 0
    assert tracker_props.machine_id == b"als-fichiers3\x00\x00\x00"
    assert str(tracker_props.file_droid) == "8ab7e0c5-75c8-11de-b8c9-000f1ff7c0dd"
    assert str(tracker_props.file_droid_birth) == "8ab7e0c5-75c8-11de-b8c9-000f1ff7c0dd"
    assert uuid1timestamp(tracker_props.file_droid.time).ctime() == "Tue Jul 21 07:31:44 2009"


def test_win7_local_lnk_dir(win7_local_lnk_dir: Path) -> None:
    fh = win7_local_lnk_dir.open("rb")
    lnk_file = Lnk(fh)

    assert lnk_file.link_header.header_size == 0x4C
    assert str(lnk_file.clsid) == "00021401-0000-0000-c000-000000000046"

    flags = lnk_file.flags

    assert flags & c_lnk.LINK_FLAGS.has_link_target_idlist
    idlist = lnk_file.target_idlist.idlist
    assert len(idlist.itemid_list) == 4
    assert idlist.terminalid == b"\x00\x00"
    assert all(entry.itemid_size == len(entry.dumps()) for entry in idlist.itemid_list)

    assert flags & c_lnk.LINK_FLAGS.has_link_info
    link_info = lnk_file.linkinfo.link_info
    link_info_flags = link_info.link_info_flags
    assert link_info_flags & c_lnk.LINK_INFO_FLAGS.volumeid_and_local_basepath
    assert link_info_flags & c_lnk.LINK_INFO_FLAGS.common_network_relative_link_and_pathsuffix
    assert link_info.local_base_path == b"C:\\Users\\"

    volumeid = lnk_file.linkinfo.volumeid
    assert volumeid.drive_type == 0x3
    assert volumeid.drive_serial_number == 0x502E1A8A
    assert volumeid.volume_label_offset == 0x10
    assert volumeid.data == b"SSD-WIN7\x00"

    common_network_relative_link = lnk_file.linkinfo.common_network_relative_link
    assert (
        common_network_relative_link.common_network_relative_link_flags
        & c_lnk.COMMON_NETWORK_RELATIVE_LINK_FLAGS.valid_device
        == 0
    )
    assert (
        common_network_relative_link.common_network_relative_link_flags
        & c_lnk.COMMON_NETWORK_RELATIVE_LINK_FLAGS.valid_net_type
    )

    assert common_network_relative_link.net_name_offset == 0x14
    assert common_network_relative_link.device_name_offset == 0x0
    assert common_network_relative_link.device_name.device_name == b""
    assert common_network_relative_link.net_provider_type == 0x20000
    assert common_network_relative_link.net_name == b"\\\\NETBOOK\\Users"

    assert flags & c_lnk.LINK_FLAGS.has_relative_path
    assert lnk_file.stringdata.relative_path.character_count == 0x26
    assert lnk_file.stringdata.relative_path.string == "..\\..\\Administrator"

    tracker_props = lnk_file.extradata.extradata["TRACKER_PROPS"]
    assert tracker_props.length == 0x58
    assert tracker_props.version == 0
    assert tracker_props.machine_id == b"netbook\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    assert str(tracker_props.file_droid) == "136502ff-8c66-11df-b6eb-001377d34a59"
    assert str(tracker_props.file_droid_birth) == "136502ff-8c66-11df-b6eb-001377d34a59"
    assert uuid1timestamp(tracker_props.file_droid.time).ctime() == "Sat Jul 10 20:59:48 2010"

    property_store_props = lnk_file.extradata.extradata["PROPERTY_STORE_PROPS"]
    assert property_store_props.storage_size == 0xAC
    assert property_store_props.version == 0x53505331
    assert str(property_store_props.format_id) == "b725f130-47ef-101a-a5f1-02608c9eebac"


def test_common_path_suffix(win81_downloads_lnk_dir: Path) -> None:
    fh = win81_downloads_lnk_dir.open("rb")
    downloads = Lnk(fh)

    link_info = downloads.linkinfo.link_info
    link_info_flags = link_info.link_info_flags
    # edge-case were common_network_relative_link_and_pathsuffix indicates no common_path_suffix
    # but when reality says otherwise.
    assert link_info_flags & c_lnk.LINK_INFO_FLAGS.common_network_relative_link_and_pathsuffix == 0
    assert link_info.common_path_suffix == b""
    assert link_info.common_path_suffix.decode() == ""


def test_vista_and_above_idlist_lnk_props(vista_idlist_lnk_file: Path) -> None:
    fh = vista_idlist_lnk_file.open("rb")
    lnk_file = Lnk(fh)
    vista_props = lnk_file.extradata.extradata["VISTA_AND_ABOVE_IDLIST_PROPS"]

    assert vista_props.size == 0x62  # 98
    assert vista_props.idlist.itemid_list[0].itemid_size == 0x60  # 96
    assert len(vista_props.idlist.itemid_list[0].data) == 0x5E  # 94


KNOWN_FOLDER_GUID = UUID("374de290-123f-4565-9164-39c4925e467b")  # FOLDERID_Downloads
SPECIAL_FOLDER_ID = 0x27  # CSIDL_MYPICTURES

# ItemID sizes of the synthetic target IDList. Item boundaries land at offsets 0, 12 and 26,
# the TerminalID at offset 42.
ITEMID_SIZES = (0x0C, 0x0E, 0x10)
KNOWN_FOLDER_OFFSET = 0x0C
SPECIAL_FOLDER_OFFSET = 0x1A

ALICE_FOLDER_MAPPING = {
    str(KNOWN_FOLDER_GUID): "C:\\Users\\alice\\Downloads",
    SPECIAL_FOLDER_ID: "C:\\Users\\alice\\Pictures",
}
BOB_FOLDER_MAPPING = {
    str(KNOWN_FOLDER_GUID): "D:\\Profiles\\bob\\Downloads",
    SPECIAL_FOLDER_ID: "D:\\Profiles\\bob\\Pictures",
}


def _lnk_header(link_flags: int) -> bytes:
    clsid = UUID("00021401-0000-0000-c000-000000000046").bytes_le
    header = struct.pack("<I", 0x4C) + clsid + struct.pack("<II", link_flags, 0x20)
    return header + b"\x00" * (0x4C - len(header))


def _target_idlist() -> bytes:
    items = b"".join(
        struct.pack("<H", size) + bytes([0x41 + index]) * (size - 2) for index, size in enumerate(ITEMID_SIZES)
    )
    idlist = items + b"\x00\x00"
    return struct.pack("<H", len(idlist)) + idlist


def _known_folder_block(offset: int) -> bytes:
    return struct.pack("<II", 0x1C, 0xA000000B) + KNOWN_FOLDER_GUID.bytes_le + struct.pack("<I", offset)


def _special_folder_block(offset: int) -> bytes:
    return struct.pack("<II", 0x10, 0xA0000005) + struct.pack("<II", SPECIAL_FOLDER_ID, offset)


def _build_folder_lnk(
    link_flags: int = 0x81,
    known_folder_offset: int | None = KNOWN_FOLDER_OFFSET,
    special_folder_offset: int | None = SPECIAL_FOLDER_OFFSET,
) -> BytesIO:
    data = _lnk_header(link_flags) + _target_idlist()
    if special_folder_offset is not None:
        data += _special_folder_block(special_folder_offset)
    if known_folder_offset is not None:
        data += _known_folder_block(known_folder_offset)
    return BytesIO(data + b"\x00\x00\x00\x00")


@pytest.mark.parametrize(
    ("folder_mapping", "downloads_path", "pictures_path"),
    [
        (ALICE_FOLDER_MAPPING, "C:\\Users\\alice\\Downloads", "C:\\Users\\alice\\Pictures"),
        (BOB_FOLDER_MAPPING, "D:\\Profiles\\bob\\Downloads", "D:\\Profiles\\bob\\Pictures"),
    ],
)
def test_folder_references_offline_user_mappings(
    folder_mapping: dict, downloads_path: str, pictures_path: str
) -> None:
    lnk_file = Lnk(_build_folder_lnk())
    references = {reference.block_name: reference for reference in lnk_file.folder_references(folder_mapping)}

    assert set(references) == {"KNOWN_FOLDER_PROPS", "SPECIAL_FOLDER_PROPS"}

    known_folder = references["KNOWN_FOLDER_PROPS"]
    assert known_folder.folder_id == KNOWN_FOLDER_GUID
    assert known_folder.offset == KNOWN_FOLDER_OFFSET
    assert known_folder.status == FolderReferenceStatus.RESOLVED
    assert known_folder.first_child_index == 1
    assert known_folder.itemid_range == (1, len(ITEMID_SIZES))
    assert known_folder.resolved_path == downloads_path
    assert known_folder.mapping_key == str(KNOWN_FOLDER_GUID)
    assert not known_folder.tracking_disabled

    special_folder = references["SPECIAL_FOLDER_PROPS"]
    assert special_folder.folder_id == SPECIAL_FOLDER_ID
    assert special_folder.offset == SPECIAL_FOLDER_OFFSET
    assert special_folder.status == FolderReferenceStatus.RESOLVED
    assert special_folder.first_child_index == 2
    assert special_folder.itemid_range == (2, len(ITEMID_SIZES))
    assert special_folder.resolved_path == pictures_path
    assert special_folder.mapping_key == SPECIAL_FOLDER_ID
    assert not special_folder.tracking_disabled


def test_folder_references_without_mapping() -> None:
    lnk_file = Lnk(_build_folder_lnk())
    references = lnk_file.folder_references()

    assert len(references) == 2
    for reference in references:
        assert reference.status == FolderReferenceStatus.RESOLVED
        assert reference.resolved_path is None
        assert reference.mapping_key is None


@pytest.mark.parametrize(
    ("known_folder_offset", "status"),
    [
        (0x0D, FolderReferenceStatus.MID_ITEM),  # in range, but not on an ItemID boundary
        (0x2A, FolderReferenceStatus.AT_TERMINAL),  # points at the TerminalID
        (0x30, FolderReferenceStatus.OUT_OF_RANGE),  # beyond the IDList
    ],
)
def test_folder_reference_offset_status(known_folder_offset: int, status: FolderReferenceStatus) -> None:
    lnk_file = Lnk(_build_folder_lnk(known_folder_offset=known_folder_offset, special_folder_offset=None))
    (reference,) = lnk_file.folder_references(ALICE_FOLDER_MAPPING)

    assert reference.folder_id == KNOWN_FOLDER_GUID
    assert reference.offset == known_folder_offset
    assert reference.status == status
    assert reference.first_child_index is None
    assert reference.itemid_range is None
    # the folder identifier itself is still decoded against the offline mapping
    assert reference.resolved_path == ALICE_FOLDER_MAPPING[str(KNOWN_FOLDER_GUID)]
    assert reference.mapping_key == str(KNOWN_FOLDER_GUID)


def test_folder_references_disable_known_folder_tracking() -> None:
    link_flags = 0x81 | int(c_lnk.LINK_FLAGS.disable_known_folder_tracking)
    lnk_file = Lnk(_build_folder_lnk(link_flags=link_flags))
    references = lnk_file.folder_references(ALICE_FOLDER_MAPPING)

    assert len(references) == 2
    for reference in references:
        # the blocks are ignored when the shell loads the link, so they are not the actual launch target
        assert reference.tracking_disabled
        assert reference.resolved_path is None
        assert reference.mapping_key is None
        assert reference.status == FolderReferenceStatus.RESOLVED
