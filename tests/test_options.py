"""
Tests for the ordered, repeat-aware representation of block options.

The on-disk option list is an ordered sequence of TLVs. Options with the
same code may repeat and be interleaved with other options, and options
with codes unknown to the schema (typically vendor-specific data) must be
preserved byte-for-byte. These tests pin down that behavior together with
the backwards-compatible Mapping interface.
"""

import io
import struct

import pytest

import pcapng.blocks as blocks
from pcapng import FileScanner, FileWriter
from pcapng.structs import OptionEntry, Options, read_options
from pcapng.strictness import Strictness, set_strictness


IDB_SCHEMA = blocks.InterfaceDescription.schema[-1][1].options_schema


def tlv(code, payload, endianness=">"):
    """Build one on-wire option TLV, including 32-bit padding."""
    head = struct.pack(endianness + "HH", code, len(payload))
    pad = b"\x00" * ((-len(payload)) % 4)
    return head + payload + pad


def end_of_options(endianness=">"):
    return struct.pack(endianness + "I", 0)


def parse_raw_options(raw, endianness=">", schema=None):
    return Options(
        schema=IDB_SCHEMA if schema is None else schema,
        data=read_options(io.BytesIO(raw), endianness),
        endianness=endianness,
    )


def raw_tlv_list(blob, endianness=">"):
    """Parse an options area back into an ordered list of (code, payload)."""
    return read_options(io.BytesIO(blob), endianness)


def make_idb_with_raw_options(raw_options, endianness=">"):
    """
    Build a minimal section (SHB + IDB) where the IDB's options area is
    exactly the given raw TLV bytes, bypassing the high-level option API.

    The SHB is produced by the library itself so the comparison targets the
    library's own canonical (no empty opt_endofopt) encoding; the IDB is
    assembled by hand to be able to inject interleaved/unknown options.
    """
    shb = blocks.SectionHeader(endianness=endianness)
    idb = shb.new_member(blocks.InterfaceDescription, link_type=1, snaplen=0)

    link_type = struct.pack(endianness + "H", 1)
    reserved = b"\x00\x00"
    snaplen = struct.pack(endianness + "I", 0)
    payload = link_type + reserved + snaplen + raw_options
    block_length = 12 + len(payload)
    raw_idb = (
        struct.pack(endianness + "I", idb.magic_number)
        + struct.pack(endianness + "I", block_length)
        + payload
        + struct.pack(endianness + "I", block_length)
    )

    canonical_shb = io.BytesIO()
    shb._write(canonical_shb)
    section_blob = canonical_shb.getvalue() + raw_idb
    scanned = list(FileScanner(io.BytesIO(section_blob)))
    return scanned[0], scanned[1], section_blob


def rescan_section(shb):
    """Write the section (SHB + registered IDBs) back and scan it again."""
    out = io.BytesIO()
    FileWriter(out, shb)
    out.seek(0)
    return list(FileScanner(out)), out.getvalue()


# A deliberately messy option area: three repeated opt_comment (code 1)
# entries interleaved with two unknown vendor options and known numeric
# options. Lengths vary so padding differs between entries.
def sample_option_bytes(endianness):
    return b"".join(
        [
            tlv(1, b"comment one", endianness),
            tlv(0xBEEF, b"\xde\xad\xbe\xef", endianness),  # unknown vendor
            tlv(1, b"comment two", endianness),
            tlv(10, struct.pack(endianness + "I", 0x11223344), endianness),  # if_tzone
            tlv(0xCAFE, b"\x00\x01\x02\x03\x04", endianness),  # unknown, odd length
            tlv(1, b"comment three", endianness),
            tlv(13, struct.pack(endianness + "B", 7), endianness),  # if_fcslen u8
            end_of_options(endianness),
        ]
    )


EXPECTED_ORDER = [1, 0xBEEF, 1, 10, 0xCAFE, 1, 13]


@pytest.mark.parametrize("endianness", ["<", ">"])
def test_scan_preserves_order_repeats_and_unknown_bytes(endianness):
    raw = sample_option_bytes(endianness)
    options = parse_raw_options(raw, endianness)

    entries = options.entries()
    assert [entry.code for entry in entries] == EXPECTED_ORDER
    assert all(isinstance(entry, OptionEntry) for entry in entries)

    # Repeated comments are kept as three separate, ordered entries
    assert options.get_all("opt_comment") == [
        "comment one",
        "comment two",
        "comment three",
    ]
    # Unknown options keep their exact payload bytes, no decoding attempted
    assert options[0xBEEF] == b"\xde\xad\xbe\xef"
    assert options[0xCAFE] == b"\x00\x01\x02\x03\x04"
    # Known numeric options decode according to the section endianness
    assert options["if_tzone"] == 0x11223344
    assert options["if_fcslen"] == 7


@pytest.mark.parametrize("endianness", ["<", ">"])
def test_roundtrip_without_edits_is_byte_identical(endianness):
    shb, idb, original = make_idb_with_raw_options(
        sample_option_bytes(endianness), endianness
    )
    # Sanity: the scanner really decoded everything in order
    assert [entry.code for entry in idb.options.entries()] == EXPECTED_ORDER

    _, rewritten = rescan_section(shb)
    assert rewritten == original


@pytest.mark.parametrize("endianness", ["<", ">"])
def test_edit_middle_entry_changes_only_that_semantic_content(endianness):
    shb, idb, original = make_idb_with_raw_options(
        sample_option_bytes(endianness), endianness
    )
    original_items = raw_tlv_list(
        sample_option_bytes(endianness), endianness
    )

    # Entry 2 is the middle repeated comment: "comment two".
    assert idb.options.get_entry(2) == OptionEntry(1, "comment two")
    idb.options.set_value_at(2, "comment TWO, edited")

    rescanned, rewritten = rescan_section(shb)
    edited_idb = rescanned[1]
    new_items = raw_tlv_list(_idb_options_area(rewritten, endianness), endianness)

    # Order and codes are untouched
    assert [code for code, _ in new_items] == [code for code, _ in original_items]
    assert len(new_items) == len(original_items)

    for index, ((old_code, old_payload), (new_code, new_payload)) in enumerate(
        zip(original_items, new_items)
    ):
        if index == 2:
            assert new_code == old_code == 1
            assert new_payload == b"comment TWO, edited"
        else:
            # Everything else, including unknown vendor bytes, is identical
            assert new_code == old_code
            assert new_payload == old_payload

    # The other two comments and the unknown options survive unchanged
    assert edited_idb.options.get_all("opt_comment") == [
        "comment one",
        "comment TWO, edited",
        "comment three",
    ]
    assert edited_idb.options[0xBEEF] == b"\xde\xad\xbe\xef"
    assert edited_idb.options[0xCAFE] == b"\x00\x01\x02\x03\x04"
    assert edited_idb.options["if_tzone"] == 0x11223344


def _idb_options_area(section_blob, endianness):
    """Extract the options-area bytes of the IDB in a minimal section."""
    stream = io.BytesIO(section_blob)
    scanned = list(FileScanner(stream))
    idb = scanned[1]
    # Re-encode just the block payload and slice the fixed 8-byte IDB header
    encoded = io.BytesIO()
    idb._encode(encoded)
    payload = encoded.getvalue()
    return payload[8:]


@pytest.mark.parametrize("endianness", ["<", ">"])
def test_known_numeric_options_reencoded_in_section_endianness(endianness):
    # A value whose wire bytes differ between endiannesses
    raw = b"".join(
        [
            tlv(10, struct.pack(endianness + "I", 0x01020304), endianness),
            end_of_options(endianness),
        ]
    )
    shb, idb, _ = make_idb_with_raw_options(raw, endianness)
    assert idb.options["if_tzone"] == 0x01020304

    # Edit through the decoded integer; the block must be fully re-encoded
    # (the raw bytes are not just copied back), in the section endianness
    idb.options["if_tzone"] = 0x0A0B0C0D
    rescanned, rewritten = rescan_section(shb)

    expected_payload = struct.pack(endianness + "I", 0x0A0B0C0D)
    assert (10, expected_payload) in raw_tlv_list(
        _idb_options_area(rewritten, endianness), endianness
    )
    assert rescanned[1].options["if_tzone"] == 0x0A0B0C0D

    # The actual wire bytes must reflect the section endianness
    assert expected_payload == (
        b"\x0a\x0b\x0c\x0d" if endianness == ">" else b"\x0d\x0c\x0b\x0a"
    )


def test_sections_with_different_endianness_decode_independently():
    little = sample_option_bytes("<")
    big = sample_option_bytes(">")

    shb_le, idb_le, _ = make_idb_with_raw_options(little, "<")
    shb_be, idb_be, _ = make_idb_with_raw_options(big, ">")

    assert idb_le.options.endianness == "<"
    assert idb_be.options.endianness == ">"
    # Same logical value, decoded from opposite byte orders
    assert idb_le.options["if_tzone"] == idb_be.options["if_tzone"] == 0x11223344

    _, blob_le = rescan_section(shb_le)
    _, blob_be = rescan_section(shb_be)
    # Numeric TLV payloads must be encoded in each section's own endianness
    assert struct.pack("<I", 0x11223344) in blob_le
    assert struct.pack(">I", 0x11223344) in blob_be
    assert struct.pack(">I", 0x11223344) not in blob_le


def test_setitem_replaces_value_in_place_and_drops_extra_occurrences():
    options = parse_raw_options(sample_option_bytes(">"))
    assert [entry.code for entry in options.entries()] == EXPECTED_ORDER

    options["opt_comment"] = "only comment now"

    # The replacement keeps the position of the first occurrence; the two
    # later comments disappear, all other entries and their order survive
    assert [entry.code for entry in options.entries()] == [
        1,
        0xBEEF,
        10,
        0xCAFE,
        13,
    ]
    assert options["opt_comment"] == "only comment now"
    assert options.get_all("opt_comment") == ["only comment now"]
    assert options.entries()[0] == OptionEntry(1, "only comment now")

    # Setting a brand new code appends a single entry at the end
    options["if_os"] = "Linux"
    assert options.entries()[-1] == OptionEntry(12, "Linux")


def test_add_appends_same_code_entry_at_end():
    options = parse_raw_options(sample_option_bytes(">"))
    original_count = len(options.entries())

    options.add("opt_comment", "an extra comment")

    assert len(options.entries()) == original_count + 1
    assert options.entries()[-1] == OptionEntry(1, "an extra comment")
    assert options.get_all("opt_comment") == [
        "comment one",
        "comment two",
        "comment three",
        "an extra comment",
    ]


def test_delitem_removes_every_value_of_code():
    options = parse_raw_options(sample_option_bytes(">"))
    del options["opt_comment"]

    assert 1 not in options
    assert options.get_all("opt_comment") == []
    assert [entry.code for entry in options.entries()] == [
        0xBEEF,
        10,
        0xCAFE,
        13,
    ]
    with pytest.raises(KeyError):
        del options["opt_comment"]


def test_unknown_option_requires_raw_bytes_for_edits():
    options = parse_raw_options(sample_option_bytes(">"))
    beef_index = [
        index for index, entry in enumerate(options.entries()) if entry.code == 0xBEEF
    ][0]

    # Raw bytes are fine and are written back verbatim
    options.set_value_at(beef_index, b"\xff\xee")
    assert options[0xBEEF] == b"\xff\xee"

    # A decoded value cannot be assigned to an unknown code
    with pytest.raises(TypeError):
        options.set_value_at(beef_index, 12345)


def test_mapping_return_rules():
    options = parse_raw_options(sample_option_bytes(">"))

    # Distinct codes, in order of first appearance, names where available
    assert list(options.keys()) == [
        "opt_comment",
        0xBEEF,
        "if_tzone",
        0xCAFE,
        "if_fcslen",
    ]
    assert len(options) == 5  # distinct codes, even though 7 entries exist

    # Subscript and .get() expose the first value only
    assert options["opt_comment"] == "comment one"
    assert options.get("opt_comment") == "comment one"
    assert options.get("nope", "default") == "default"
    with pytest.raises(KeyError):
        options["nope"]

    # Membership looks at code presence, name or numeric code
    assert "opt_comment" in options
    assert 1 in options
    assert 0xBEEF in options
    assert "if_os" not in options
    assert 99 not in options

    # values()/items() use the first value of each code
    assert list(options.values())[0] == "comment one"
    assert dict(options.items())["if_tzone"] == 0x11223344

    # Multi-value accessors never raise on missing codes
    assert options.get_all("if_os") == []
    assert options.get_all_raw("if_os") == []
    with pytest.raises(KeyError):
        options.get_raw("if_os")

    # Raw accessors re-encode known values and pass unknown bytes through
    assert options.get_raw("if_tzone") == struct.pack(">I", 0x11223344)
    assert options.get_raw(0xBEEF) == b"\xde\xad\xbe\xef"
    assert options.get_all_raw("opt_comment") == [
        b"comment one",
        b"comment two",
        b"comment three",
    ]


def test_iter_all_items_groups_values_without_losing_order():
    options = parse_raw_options(sample_option_bytes(">"))
    grouped = dict(options.iter_all_items())

    assert grouped["opt_comment"] == [
        "comment one",
        "comment two",
        "comment three",
    ]
    assert grouped[0xBEEF] == [b"\xde\xad\xbe\xef"]
    assert list(grouped.keys()) == [
        "opt_comment",
        0xBEEF,
        "if_tzone",
        0xCAFE,
        "if_fcslen",
    ]


def test_constructor_accepts_legacy_mapping_input():
    # Historical callers could pass a mapping of code -> raw payload bytes
    options = Options(
        schema=IDB_SCHEMA,
        data={12: b"Linux", 99: b"\x01\x02"},
        endianness=">",
    )
    assert options["if_os"] == "Linux"
    assert options[99] == b"\x01\x02"
    assert [entry.code for entry in options.entries()] == [12, 99]


def test_scan_edit_rescan_full_pipeline_both_endiannesses():
    # One complete scan -> edit -> rescan chain per endianness, asserting
    # that only the edited semantic content changes.
    for endianness in ("<", ">"):
        shb, idb, original = make_idb_with_raw_options(
            sample_option_bytes(endianness), endianness
        )
        before = raw_tlv_list(sample_option_bytes(endianness), endianness)

        # Replace one comment, append a comment, delete a numeric option
        idb.options.set_value_at(2, "replaced middle comment")
        idb.options.add("opt_comment", "appended comment")
        del idb.options["if_fcslen"]

        rescanned, rewritten = rescan_section(shb)
        after = raw_tlv_list(_idb_options_area(rewritten, endianness), endianness)
        options_after = rescanned[1].options

        # Unknown vendor bytes are untouched throughout
        assert options_after[0xBEEF] == b"\xde\xad\xbe\xef"
        assert options_after[0xCAFE] == b"\x00\x01\x02\x03\x04"
        # Numeric option not deleted still decodes with the right endianness
        assert options_after["if_tzone"] == 0x11223344
        # Deleted code is gone for good
        assert "if_fcslen" not in options_after
        # Comment edits are reflected, order preserved
        assert options_after.get_all("opt_comment") == [
            "comment one",
            "replaced middle comment",
            "comment three",
            "appended comment",
        ]
        # Every non-deleted payload other than the replaced one is identical
        before_map = {}
        for code, payload in before:
            before_map.setdefault(code, []).append(payload)
        for code, payload in after:
            if code == 1:
                continue
            assert payload in before_map[code]
