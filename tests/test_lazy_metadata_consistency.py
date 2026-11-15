"""
Regression tests for lazy decoding and mutable metadata.

The capture bytes are the evidence.  A block's raw view must describe the
values that were decoded from those bytes together with the interface/section
metadata that was effective at that moment.  Editing an interface afterwards
may change the edit view, but it must never change what the raw view reports,
and the order of "access first, edit later" vs "edit first, access later" must
not matter for the raw view.
"""

import copy
import io

import pytest

import pcapng.blocks as blocks
from pcapng import FileScanner, FileWriter
from pcapng.utils import pack_timestamp_resolution

TSRESOL_US = pack_timestamp_resolution(10, 6)
TSRESOL_MS = pack_timestamp_resolution(10, 3)


def _build_capture(snaplen=8, tsresol=TSRESOL_US):
    """Build a small in-memory capture and parse it back."""
    shb = blocks.SectionHeader()
    shb.new_member(
        blocks.InterfaceDescription,
        link_type=1,
        snaplen=snaplen,
        options={"if_tsresol": tsresol, "if_name": "eth0"},
    )
    epb = shb.new_member(
        blocks.EnhancedPacket,
        interface_id=0,
        timestamp_high=0,
        timestamp_low=123456,
    )
    epb.packet_data = b"A" * 10
    epb.packet_len = 12
    spb = shb.new_member(blocks.SimplePacket, packet_data=b"B" * 10)

    stream = io.BytesIO()
    writer = FileWriter(stream, shb)
    writer.write_block(epb)
    writer.write_block(spb)
    stream.seek(0)
    return list(FileScanner(stream))


def _observe(blocks_, access_first):
    """Read raw/edit values, optionally touching them before the edits."""
    shb, idb, epb, spb = blocks_
    if access_first:
        # Force the lazy properties to be resolved before metadata changes.
        assert epb.timestamp > 0
        assert spb.captured_len > 0
    idb.options["if_tsresol"] = TSRESOL_MS
    idb.snaplen = 4
    return {
        "raw": (
            epb.raw_view.timestamp,
            epb.raw_view.timestamp_resolution,
            spb.raw_view.captured_len,
            spb.raw_view.packet_len,
        ),
        "edit": (
            epb.edit_view.timestamp,
            epb.edit_view.timestamp_resolution,
            spb.edit_view.captured_len,
            spb.edit_view.packet_len,
        ),
    }


def test_raw_view_independent_of_access_edit_order():
    first_edit = _observe(_build_capture(), access_first=False)
    first_access = _observe(_build_capture(), access_first=True)

    assert first_edit["raw"] == first_access["raw"]
    assert first_edit["edit"] == first_access["edit"]

    # The raw evidence is the originally decoded interpretation.
    assert first_edit["raw"] == (0.123456, 1e-6, 8, 10)
    # The edit view follows the edited interface metadata.
    assert first_edit["edit"] == (123.456, 1e-3, 4, 10)


def test_epb_raw_packet_length_stable_after_edit():
    _, _, epb, _ = _build_capture()
    before = (epb.raw_view.packet_len, epb.raw_view.captured_len)

    epb.packet_len = 99
    epb.packet_data = b"C" * 3

    assert (epb.raw_view.packet_len, epb.raw_view.captured_len) == before == (12, 10)
    assert (epb.edit_view.packet_len, epb.edit_view.captured_len) == (99, 3)


def test_spb_raw_captured_len_uses_snaplen_at_read_time():
    _, idb, _, spb = _build_capture(snaplen=8)
    assert spb.raw_view.captured_len == 8

    idb.snaplen = 0  # unlimited, but only for the edit view
    assert spb.raw_view.captured_len == 8
    assert spb.edit_view.captured_len == 10

    idb.snaplen = 4
    assert spb.raw_view.captured_len == 8
    assert spb.edit_view.captured_len == 4


def test_interface_metadata_is_pinned_in_raw_view():
    _, idb, epb, _ = _build_capture(snaplen=8)
    assert epb.raw_view.interface.snaplen == 8
    assert epb.raw_view.interface.options["if_name"] == "eth0"

    idb.snaplen = 64
    idb.options["if_name"] = "changed"

    assert epb.edit_view.interface.snaplen == 64
    assert epb.edit_view.interface.options["if_name"] == "changed"
    assert epb.raw_view.interface.snaplen == 8
    assert epb.raw_view.interface.options["if_name"] == "eth0"


def test_raw_view_cannot_be_mutated_through_returned_objects():
    _, idb, epb, _ = _build_capture()
    snapshot_options = epb.raw_view.interface.options
    snapshot_options["if_tsresol"] = TSRESOL_MS

    assert epb.raw_view.interface.options["if_tsresol"] == TSRESOL_US
    assert epb.raw_view.timestamp_resolution == 1e-6
    # and the live block was not touched by mutating a raw snapshot
    assert idb.options["if_tsresol"] == TSRESOL_US
    assert not epb.edited


def test_edit_view_and_diff_are_traceable():
    _, idb, epb, _ = _build_capture()
    assert epb.raw_view.diff() == {}
    assert epb.raw_view.diff() == epb.edit_view.diff()

    idb.options["if_tsresol"] = TSRESOL_MS

    diff = epb.raw_view.diff()
    assert diff["timestamp"] == (0.123456, 123.456)
    assert diff["timestamp_resolution"] == (1e-6, 1e-3)
    # Unchanged metadata is not reported as a difference.
    assert "link_type_description" not in diff

    # The edit is attributed to the interface, not to the packet block.
    assert [r.name for r in idb.edit_log] == ["if_tsresol"]
    assert [r.source for r in idb.edit_log] == ["options"]
    assert idb.edit_log[0].before == [TSRESOL_US]
    assert idb.edit_log[0].after == [TSRESOL_MS]
    assert epb.edit_log == ()

    epb.packet_len = 20
    assert [r.name for r in epb.edit_log] == ["packet_len"]
    assert epb.edit_log[0].source == "field"


def test_copy_keeps_raw_view_and_isolated_edit_log():
    _, idb, epb, _ = _build_capture()
    idb.options["if_tsresol"] = TSRESOL_MS

    shallow = copy.copy(epb)
    deep = copy.deepcopy(epb)

    for clone in (shallow, deep):
        assert clone.raw_view.timestamp == 0.123456
        assert clone.edit_view.timestamp == 123.456
    assert shallow.section is epb.section
    assert deep.section is not epb.section
    assert deep.interface.snaplen == epb.interface.snaplen

    copied_idb = copy.deepcopy(idb)
    assert copied_idb.raw_view.timestamp_resolution == 1e-6
    assert copied_idb.edit_view.timestamp_resolution == 1e-3
    assert copied_idb.edit_log == idb.edit_log

    copied_idb.options["if_tsresol"] = TSRESOL_US
    assert [r.name for r in copied_idb.edit_log] == ["if_tsresol", "if_tsresol"]
    # ... while the original block and its log stay unchanged
    assert len(idb.edit_log) == 1
    assert idb.options["if_tsresol"] == TSRESOL_MS


def test_copying_a_section_keeps_its_members_consistent():
    shb, idb, _, _ = _build_capture()
    clone = copy.deepcopy(shb)

    assert clone is not shb
    assert clone.interfaces[0] is not idb
    assert clone.interfaces[0].section is clone
    assert clone.interfaces[0].raw_view.snaplen == 8

    # Adding to the copy must not leak back into the original numbering.
    clone.new_member(blocks.InterfaceDescription)
    assert sorted(clone.interfaces) == [0, 1]
    assert sorted(shb.interfaces) == [0]


def test_interface_stats_found_while_streaming_are_raw_metadata():
    """An ISB is read after the IDB it belongs to; that is read-time discovery."""
    shb = blocks.SectionHeader()
    shb.new_member(blocks.InterfaceDescription, link_type=1)
    isb = shb.new_member(
        blocks.InterfaceStatistics,
        interface_id=0,
        timestamp_high=0,
        timestamp_low=5,
    )

    stream = io.BytesIO()
    writer = FileWriter(stream, shb)
    writer.write_block(isb)
    stream.seek(0)
    _, idb, parsed_isb = list(FileScanner(stream))

    assert idb.raw_view.statistics is parsed_isb
    assert idb.edit_view.statistics is parsed_isb
    # No user edit happened, so nothing is logged.
    assert idb.edit_log == ()
    assert not idb.edited


@pytest.mark.parametrize("endianness", ["<", ">"])
def test_raw_view_does_not_depend_on_section_endianness_edits(endianness):
    """Changing section endianness must not rewrite captured values."""
    shb, _, epb, _ = _build_capture()
    assert shb.endianness == "<"
    assert epb.raw_view.endianness == "<"
    assert epb.raw_view.packet_data == b"A" * 10

    shb.endianness = ">"

    assert epb.edit_view.endianness == ">"
    assert epb.raw_view.endianness == "<"
    assert epb.raw_view.packet_len == 12
    assert epb.raw_view.packet_data == b"A" * 10
    assert epb.edit_view.packet_data == b"A" * 10

    # And the edited value is traceable to its source.
    assert epb.raw_view.diff()["endianness"] == ("<", ">")


def test_written_blocks_use_the_current_section_endianness_consistently():
    """Option headers cache endianness; writing must not mix byte orders."""
    shb, idb, epb, _ = _build_capture()
    shb.endianness = ">"

    stream = io.BytesIO()
    writer = FileWriter(stream, shb)
    writer.write_block(epb)
    stream.seek(0)
    _, parsed_idb, parsed_epb = list(FileScanner(stream))

    assert parsed_idb.options["if_name"] == "eth0"
    assert parsed_idb.options["if_tsresol"] == TSRESOL_US
    assert parsed_epb.packet_data == b"A" * 10
    assert parsed_epb.raw_view.packet_len == 12
    # The raw evidence still describes the capture as read.
    assert epb.raw_view.interface.options["if_tsresol"] == TSRESOL_US
    assert epb.raw_view.timestamp_resolution == 1e-6


def test_declared_raw_values_survive_metadata_edits_for_all_block_types():
    """A broad guard: every block type keeps its raw fields after edits."""
    shb, idb, epb, spb = _build_capture()
    obsp = shb.new_member(blocks.ObsoletePacket, packet_data=b"X" * 4)
    nrb = shb.new_member(blocks.NameResolution, records=[])
    isb = shb.new_member(blocks.InterfaceStatistics, interface_id=0)

    before = {
        "idb": (idb.raw_view.link_type, idb.raw_view.snaplen),
        "epb": (epb.raw_view.interface_id, epb.raw_view.packet_len),
        "spb": (spb.raw_view.packet_len, spb.raw_view.captured_len),
        "pb": (obsp.raw_view.interface_id, obsp.raw_view.packet_len),
        "nrb": tuple(obsp.raw_view.options),
        "isb": (isb.raw_view.interface_id, isb.raw_view.timestamp),
    }

    idb.link_type = 101
    idb.snaplen = 1
    shb.endianness = ">"
    isb.interface_id = 0

    assert (idb.raw_view.link_type, idb.raw_view.snaplen) == before["idb"]
    assert (epb.raw_view.interface_id, epb.raw_view.packet_len) == before["epb"]
    assert (spb.raw_view.packet_len, spb.raw_view.captured_len) == before["spb"]
    assert (obsp.raw_view.interface_id, obsp.raw_view.packet_len) == before["pb"]
    assert idb.edit_view.link_type == 101
    assert nrb.raw_view.records == []
