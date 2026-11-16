from __future__ import annotations

import io
import struct
from typing import TYPE_CHECKING

import pytest

from dissect.shellitem.lnk import Lnk
from dissect.shellitem.lnk.lnk import LnkTargetIdList

if TYPE_CHECKING:
    from collections.abc import Callable

LINK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
LINK_HEADER_SIZE = 0x4C
LINK_INFO_HEADER_SIZE = 0x1C
LINK_INFO_SUFFIX = b"AFTER-IDLIST\x00"
TERMINAL = b"\x00\x00"
VISTA_IDLIST_SIGNATURE = 0xA000000C
SPECIAL_FOLDER_SIGNATURE = 0xA0000005
SPECIAL_FOLDER_ID = 0x0000002A
SPECIAL_FOLDER_OFFSET = 0x00000010
LINK_FLAGS = 0x00000001 | 0x00000002  # has_link_target_idlist | has_link_info

# Parsing one complete shortcut touches a fixed set of structures. Anything above this bound means the
# IDList reader is doing work proportional to the (attacker controlled) declared size or item count.
MAX_READS = 32

# Minimal IDList byte samples that used to be misparsed. They are kept verbatim so a regression is
# visible without reconstructing the whole shortcut by hand.
#
# A terminal element is not the same as an ordinary empty item: a zero ItemIDSize terminates the list.
# The old reader interpreted the two zero bytes as an item of size zero and then read ``size - 2 == -2``
# bytes, which consumes every remaining byte of the IDList.
MINIMAL_TERMINAL_THEN_TAIL = bytes.fromhex("00005041")
# An ItemIDSize smaller than the two byte size field itself cannot make progress.
MINIMAL_ITEM_SIZE_BELOW_HEADER = bytes.fromhex("01000000")
# The item claims six bytes but only two payload bytes are present, so it is truncated at the IDList
# boundary instead of borrowing bytes from the following structure.
MINIMAL_TRUNCATED_BEFORE_TERMINAL = bytes.fromhex("06004141")


class CountingReader(io.BytesIO):
    """Count read calls so tests can enforce an upper bound on parser I/O."""

    def __init__(self, data: bytes):
        super().__init__(data)
        self.reads = 0

    def read(self, size: int = -1) -> bytes:
        self.reads += 1
        return super().read(size)


def item(payload: bytes) -> bytes:
    """Build an ITEMID whose size field includes itself."""
    return struct.pack("<H", len(payload) + 2) + payload


def make_header() -> bytes:
    header = bytearray(LINK_HEADER_SIZE)
    struct.pack_into("<I", header, 0, LINK_HEADER_SIZE)
    header[4:20] = LINK_CLSID
    struct.pack_into("<I", header, 0x14, LINK_FLAGS)
    return bytes(header)


def make_link_info() -> bytes:
    size = LINK_INFO_HEADER_SIZE + len(LINK_INFO_SUFFIX)
    return (
        struct.pack("<III", size, LINK_INFO_HEADER_SIZE, 0)
        + struct.pack("<IIII", 0, 0, 0, LINK_INFO_HEADER_SIZE)
        + LINK_INFO_SUFFIX
    )


def make_extra_block(signature: int, body: bytes) -> bytes:
    return struct.pack("<II", 8 + len(body), signature) + body


def make_target_lnk(idlist: bytes) -> bytes:
    # TARGET_IDLIST carries its own two byte size field, which is not part of the counted extent.
    return make_header() + struct.pack("<H", len(idlist)) + idlist + make_link_info() + struct.pack("<I", 0)


def make_vista_lnk(idlist: bytes) -> bytes:
    # VISTA_AND_ABOVE_IDLIST_PROPS is an EXTRA_DATA_BLOCK: its four byte size includes the eight byte
    # EXTRA_DATA_BLOCK header, and the IDList itself has no size prefix. The block is followed by a
    # second extra data block so an over-read into the next block is observable.
    extra = make_extra_block(VISTA_IDLIST_SIGNATURE, idlist)
    extra += make_extra_block(SPECIAL_FOLDER_SIGNATURE, struct.pack("<II", SPECIAL_FOLDER_ID, SPECIAL_FOLDER_OFFSET))
    extra += struct.pack("<I", 0)
    return (
        make_header()
        + struct.pack("<H", 2)
        + TERMINAL  # empty LinkTargetIDList for the shortcut itself
        + make_link_info()
        + extra
    )


ENTRIES: dict[str, Callable[[bytes], bytes]] = {
    "target_idlist": make_target_lnk,
    "vista_idlist": make_vista_lnk,
}


def parse_entry(entry: str, idlist: bytes) -> tuple[Lnk, LnkTargetIdList, CountingReader]:
    reader = CountingReader(ENTRIES[entry](idlist))
    lnk = Lnk(reader)
    parsed = lnk.target_idlist if entry == "target_idlist" else lnk.extradata.extradata["VISTA_AND_ABOVE_IDLIST_PROPS"]
    return lnk, parsed, reader


def assert_successors_intact(entry: str, lnk: Lnk) -> None:
    # LINK_INFO follows the main TargetIdList, and is located before the Vista block in EXTRA_DATA.
    assert lnk.linkinfo.link_info.link_info_size == LINK_INFO_HEADER_SIZE + len(LINK_INFO_SUFFIX)
    assert lnk.linkinfo.common_path_suffix == b"AFTER-IDLIST"

    if entry == "target_idlist":
        assert list(lnk.extradata.extradata) == ["TERMINAL_BLOCK"]
        assert lnk.extradata.TERMINAL_BLOCK.terminal_block == 0
    else:
        # The block after the Vista IDList must still be parsed, which fails when the IDList reader
        # consumes beyond its own block.
        assert list(lnk.extradata.extradata) == [
            "VISTA_AND_ABOVE_IDLIST_PROPS",
            "SPECIAL_FOLDER_PROPS",
            "TERMINAL_BLOCK",
        ]
        special_folder = lnk.extradata.SPECIAL_FOLDER_PROPS
        assert special_folder.special_folder_id == SPECIAL_FOLDER_ID
        assert special_folder.offset == SPECIAL_FOLDER_OFFSET


UNKNOWN_ITEM = b"\x99\x00SECRET~1.EXE\x00"
OTHER_ITEM = b"\x98\x00not-a-real-name.txt\x00"
ZERO_TAIL_ITEM = b"\x97\x00tail\x00\x00"

ITEM_CASES = [
    pytest.param(
        item(UNKNOWN_ITEM) + item(OTHER_ITEM) + TERMINAL,
        [(len(UNKNOWN_ITEM) + 2, UNKNOWN_ITEM), (len(OTHER_ITEM) + 2, OTHER_ITEM)],
        TERMINAL,
        id="two-unknown-items",
    ),
    pytest.param(
        TERMINAL,
        [],
        TERMINAL,
        id="legal-empty-list",
    ),
    pytest.param(
        TERMINAL + b"PADDING!",
        [],
        TERMINAL + b"PADDING!",
        id="empty-list-with-tail-padding",
    ),
    pytest.param(
        item(UNKNOWN_ITEM) + TERMINAL + item(OTHER_ITEM) + TERMINAL,
        [(len(UNKNOWN_ITEM) + 2, UNKNOWN_ITEM)],
        TERMINAL + item(OTHER_ITEM) + TERMINAL,
        id="terminal-before-second-item",
    ),
    pytest.param(
        item(UNKNOWN_ITEM) + TERMINAL + b"PADDING!",
        [(len(UNKNOWN_ITEM) + 2, UNKNOWN_ITEM)],
        TERMINAL + b"PADDING!",
        id="tail-padding-after-terminal",
    ),
    pytest.param(
        item(UNKNOWN_ITEM) + MINIMAL_ITEM_SIZE_BELOW_HEADER + TERMINAL,
        [(len(UNKNOWN_ITEM) + 2, UNKNOWN_ITEM)],
        MINIMAL_ITEM_SIZE_BELOW_HEADER + TERMINAL,
        id="item-size-below-header",
    ),
    pytest.param(
        item(UNKNOWN_ITEM) + struct.pack("<H", 6) + b"A",
        [(len(UNKNOWN_ITEM) + 2, UNKNOWN_ITEM), (6, b"A")],
        b"",
        id="truncated-item-before-terminal",
    ),
    pytest.param(
        item(UNKNOWN_ITEM) + b"Z",
        [(len(UNKNOWN_ITEM) + 2, UNKNOWN_ITEM)],
        b"Z",
        id="truncated-size-field-before-terminal",
    ),
    pytest.param(
        item(UNKNOWN_ITEM) + struct.pack("<H", 0x20) + b"XY",
        [(len(UNKNOWN_ITEM) + 2, UNKNOWN_ITEM), (0x20, b"XY")],
        b"",
        id="item-size-beyond-declared-extent",
    ),
    pytest.param(
        item(UNKNOWN_ITEM) + item(ZERO_TAIL_ITEM),
        [(len(UNKNOWN_ITEM) + 2, UNKNOWN_ITEM), (len(ZERO_TAIL_ITEM) + 2, ZERO_TAIL_ITEM)],
        b"",
        id="last-item-ends-with-zero-bytes",
    ),
]


@pytest.mark.parametrize("entry", ENTRIES)
@pytest.mark.parametrize(("idlist", "expected_items", "expected_terminal"), ITEM_CASES)
def test_idlist_structural_mutations(
    entry: str,
    idlist: bytes,
    expected_items: list[tuple[int, bytes]],
    expected_terminal: bytes,
) -> None:
    lnk, parsed, reader = parse_entry(entry, idlist)

    # Unknown shell items are kept verbatim. Their payload must not be merged with the next item,
    # and a terminal element must never be interpreted as a zero sized item.
    assert [
        (shell_item.itemid_size, bytes(shell_item.data)) for shell_item in parsed.idlist.itemid_list
    ] == expected_items
    assert parsed.idlist.terminalid == expected_terminal
    # The parsed extent is the IDList itself. For the Vista block this excludes the eight byte
    # EXTRA_DATA_BLOCK header that is part of the on-disk block size.
    assert parsed.size == len(idlist)

    assert_successors_intact(entry, lnk)
    assert reader.reads <= MAX_READS


@pytest.mark.parametrize("entry", ENTRIES)
@pytest.mark.parametrize(
    ("idlist", "expected_items", "expected_terminal"),
    [
        pytest.param(MINIMAL_TERMINAL_THEN_TAIL, [], TERMINAL + b"PA", id="terminal-then-tail"),
        pytest.param(MINIMAL_ITEM_SIZE_BELOW_HEADER, [], MINIMAL_ITEM_SIZE_BELOW_HEADER, id="item-size-one"),
        pytest.param(
            MINIMAL_TRUNCATED_BEFORE_TERMINAL,
            [(6, b"AA")],
            b"",
            id="truncated-before-terminal",
        ),
    ],
)
def test_idlist_minimal_reproducers(
    entry: str,
    idlist: bytes,
    expected_items: list[tuple[int, bytes]],
    expected_terminal: bytes,
) -> None:
    # Before the fix the first sample produced a zero sized item containing the tail bytes, and the
    # second sample produced an item of size one swallowing the terminal element.
    lnk, parsed, reader = parse_entry(entry, idlist)

    assert [
        (shell_item.itemid_size, bytes(shell_item.data)) for shell_item in parsed.idlist.itemid_list
    ] == expected_items
    assert parsed.idlist.terminalid == expected_terminal
    assert_successors_intact(entry, lnk)
    assert reader.reads <= MAX_READS


def test_idlist_wrapper_length_semantics_boundary() -> None:
    # This is the case that only differs between the two encapsulations: the same IDList bytes are
    # counted by a bare two byte size for TARGET_IDLIST, but by a four byte block size that includes
    # the eight byte EXTRA_DATA_BLOCK header for the Vista block. Feeding either on-disk size straight
    # into the IDList reader drops the terminal element, or reads into the following LinkInfo.
    idlist = item(UNKNOWN_ITEM) + TERMINAL

    target_blob = make_target_lnk(idlist)
    target, target_idlist, target_reader = parse_entry("target_idlist", idlist)
    assert struct.unpack_from("<H", target_blob, LINK_HEADER_SIZE)[0] == len(idlist)
    assert target_idlist.size == len(idlist)

    vista_blob = make_vista_lnk(idlist)
    vista, vista_idlist, vista_reader = parse_entry("vista_idlist", idlist)
    vista_signature_offset = vista_blob.index(struct.pack("<I", VISTA_IDLIST_SIGNATURE))
    vista_block_size = struct.unpack_from("<I", vista_blob, vista_signature_offset - 4)[0]
    assert vista_block_size == len(idlist) + 8
    # The block header is stripped, so the parsed extent is the bare IDList and matches the main entry.
    assert vista_idlist.size == len(idlist)
    assert vista_idlist.size == target_idlist.size

    for lnk, parsed, reader, entry in (
        (target, target_idlist, target_reader, "target_idlist"),
        (vista, vista_idlist, vista_reader, "vista_idlist"),
    ):
        assert [(shell_item.itemid_size, bytes(shell_item.data)) for shell_item in parsed.idlist.itemid_list] == [
            (len(UNKNOWN_ITEM) + 2, UNKNOWN_ITEM)
        ]
        assert parsed.idlist.terminalid == TERMINAL
        assert_successors_intact(entry, lnk)
        assert reader.reads <= MAX_READS


@pytest.mark.parametrize("entry", ENTRIES)
def test_idlist_read_count_does_not_scale_with_item_count(entry: str) -> None:
    idlist = b"".join(item(bytes([0x90 + index % 0x10]) + b"payload") for index in range(200)) + TERMINAL

    lnk, parsed, reader = parse_entry(entry, idlist)

    assert len(parsed.idlist.itemid_list) == 200
    assert parsed.idlist.terminalid == TERMINAL
    assert_successors_intact(entry, lnk)
    assert reader.reads <= MAX_READS
