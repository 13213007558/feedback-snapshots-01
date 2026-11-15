import hashlib
import io

import pytest

import pcapng
import pcapng.blocks as blocks
from pcapng import FileScanner, FileWriter
from pcapng.derive import derive_capture, verify_derived_capture
from pcapng.exceptions import DeriveError


PAYLOAD = b"\x00\x01\x02\x03identical-evidence-packet"


def test_scanner_reports_block_position_and_payload():
    source, packets = _build_two_sections()
    scanner = FileScanner(io.BytesIO(source))
    blocks_out = list(scanner)
    # The scanner reports the last block it returned; easier to inspect by
    # consuming one block at a time.
    scanner = FileScanner(io.BytesIO(source))
    positions = []
    for block in scanner:
        positions.append(
            (
                scanner.block_offset,
                scanner.block_length,
                scanner.block_index,
                scanner.block_type,
            )
        )
    assert positions[0][0] == 0
    assert positions[0][2] == 0
    assert positions[0][3] == 0x0A0D0D0A
    assert positions[1][0] == positions[0][1]  # contiguous blocks
    assert positions[1][3] == 0x00000001
    assert positions[-1][0] + positions[-1][1] == len(source)
    assert [p[2] for p in positions] == list(range(len(positions)))
    assert len(blocks_out) == len(positions)
    # The raw payload is available without re-reading the stream.
    scanner = FileScanner(io.BytesIO(source))
    next(iter(scanner))
    first_data = scanner.block_data
    assert isinstance(first_data, bytes)


def _build_two_sections():
    """
    Two sections, each with two interfaces, and three identical packets.

    Section 0: IDB ethA (id 0), IDB ethB (id 1)
        EPB on ethB  -> "occurrence 1"
        EPB on ethA  -> "occurrence 2" (identical bytes and timestamp)
    Section 1: IDB ethC (id 0), IDB ethD (id 1)
        EPB on ethD  -> "occurrence 3" (identical bytes and timestamp)
    """
    stream = io.BytesIO()

    shb0 = blocks.SectionHeader(
        endianness="<", options={"shb_userappl": "pytest-derive"}
    )
    eth_a = shb0.new_member(
        blocks.InterfaceDescription, link_type=1, options={"if_name": "ethA"}
    )  # noqa: F841
    eth_b = shb0.new_member(
        blocks.InterfaceDescription, link_type=1, options={"if_name": "ethB"}
    )  # noqa: F841

    p1 = shb0.new_member(
        blocks.EnhancedPacket,
        interface_id=1,
        timestamp_high=0,
        timestamp_low=1000,
        packet_data=PAYLOAD,
    )
    p2 = shb0.new_member(
        blocks.EnhancedPacket,
        interface_id=0,
        timestamp_high=0,
        timestamp_low=1000,
        packet_data=PAYLOAD,
    )

    writer = FileWriter(stream, shb0)
    writer.write_block(p1)
    writer.write_block(p2)

    shb1 = blocks.SectionHeader(endianness="<")
    shb1.new_member(
        blocks.InterfaceDescription, link_type=1, options={"if_name": "ethC"}
    )
    shb1.new_member(
        blocks.InterfaceDescription, link_type=1, options={"if_name": "ethD"}
    )
    p3 = shb1.new_member(
        blocks.EnhancedPacket,
        interface_id=1,
        timestamp_high=0,
        timestamp_low=1000,
        packet_data=PAYLOAD,
    )
    writer.write_block(shb1)
    writer.write_block(p3)

    return stream.getvalue(), (p1, p2, p3)


def test_identical_packets_are_distinct_evidence():
    source, packets = _build_two_sections()

    # All three packets are byte-for-byte identical, including timestamps.
    assert packets[0].packet_data == packets[1].packet_data == packets[2].packet_data
    assert (
        packets[0].timestamp_low
        == packets[1].timestamp_low
        == packets[2].timestamp_low
    )
    assert len({id(p) for p in packets}) == 3

    kept = []
    for packet in packets[1:]:
        kept.append(packet.packet_data)

    out = io.BytesIO()
    manifest = derive_capture(
        io.BytesIO(source), out, lambda block: block.packet_data in kept
    )

    # Three identical packets in the input, three selected: nothing is
    # deduplicated by content.
    assert manifest.selected_packets == 3
    assert len(manifest.entries_for_packets()) == 3
    source_offsets = [e.source_offset for e in manifest.entries_for_packets()]
    assert len(set(source_offsets)) == 3


def test_keep_specific_occurrences_across_two_sections():
    source, packets = _build_two_sections()

    # Keep the 1st and 3rd occurrence of the identical payload.
    seen = [0]

    def predicate(block):
        if block.packet_data != PAYLOAD:
            return False
        seen[0] += 1
        return seen[0] in (1, 3)

    out = io.BytesIO()
    manifest = derive_capture(io.BytesIO(source), out, predicate)
    derived = out.getvalue()

    # Manifest is bound to the input digest, not to a path.
    assert manifest.source_digest == hashlib.sha256(source).hexdigest()
    assert manifest.digest_algorithm == "sha256"
    assert all(e.source_digest == manifest.source_digest for e in manifest.entries)

    packet_entries = manifest.entries_for_packets()
    assert len(packet_entries) == 2
    # Two distinct source offsets, one per selected occurrence.
    assert packet_entries[0].source_offset != packet_entries[1].source_offset
    # Two different sections.
    assert packet_entries[0].source_section_index == 0
    assert packet_entries[1].source_section_index == 1
    # Output offsets are distinct too.
    assert packet_entries[0].output_offset != packet_entries[1].output_offset

    # Read the derived file back: correct interfaces survive renumbering.
    read_back = list(FileScanner(io.BytesIO(derived)))
    shbs = [b for b in read_back if isinstance(b, blocks.SectionHeader)]
    assert len(shbs) == 2

    idbs0 = [
        b
        for b in shbs[0].interfaces.values()
        if isinstance(b, blocks.InterfaceDescription)
    ]
    idbs1 = [
        b
        for b in shbs[1].interfaces.values()
        if isinstance(b, blocks.InterfaceDescription)
    ]
    # Only the interfaces needed by the selected packets are present, and
    # each is renumbered from zero.
    assert [i.interface_id for i in idbs0] == [0]
    assert idbs0[0].options["if_name"] == "ethB"
    assert [i.interface_id for i in idbs1] == [0]
    assert idbs1[0].options["if_name"] == "ethD"

    out_packets = [
        b for b in read_back if isinstance(b, blocks.EnhancedPacket)
    ]
    assert len(out_packets) == 2
    assert [p.packet_data for p in out_packets] == [PAYLOAD, PAYLOAD]
    assert [p.interface.options["if_name"] for p in out_packets] == ["ethB", "ethD"]
    assert [p.interface_id for p in out_packets] == [0, 0]

    # Manifest interface mapping matches what was read back.
    assert [e.source_interface_id for e in packet_entries] == [1, 1]
    assert [e.output_interface_id for e in packet_entries] == [0, 0]

    # Each output entry uniquely locates its original record.
    for entry in manifest.entries:
        assert entry.source_offset + entry.source_length <= len(source)
        assert entry.output_offset + entry.output_length <= len(derived)

    # The two source packets really are the 1st and 3rd original records
    # (SHB, IDB, IDB, p1, p2 for section 0; SHB, IDB, IDB, p3 for section 1).
    assert packet_entries[0].source_block_index == 3
    assert packet_entries[1].source_block_index == 8
    assert packet_entries[1].source_offset > packet_entries[0].source_offset


def test_verify_reads_back_and_locates_every_entry():
    source, _ = _build_two_sections()

    seen = [0]

    def predicate(block):
        if block.packet_data != PAYLOAD:
            return False
        seen[0] += 1
        return seen[0] in (2, 3)

    out = io.BytesIO()
    manifest = derive_capture(io.BytesIO(source), out, predicate)
    derived = out.getvalue()

    assert verify_derived_capture(io.BytesIO(source), io.BytesIO(derived), manifest)

    # The two selected packets came from two distinct source sections/offsets.
    entries = manifest.entries_for_packets()
    assert len(entries) == 2
    assert entries[0].source_offset != entries[1].source_offset

    # Tampering with the manifest is detected.
    entries[0].source_offset += 4
    with pytest.raises(DeriveError):
        verify_derived_capture(io.BytesIO(source), io.BytesIO(derived), manifest)


def test_digest_identity_survives_rename(tmp_path):
    source, _ = _build_two_sections()
    src = tmp_path / "capture-a.pcapng"
    src.write_bytes(source)

    out_path = tmp_path / "derived.pcapng"
    manifest = derive_capture(src, out_path, lambda block: True)
    first_digest = manifest.source_digest

    renamed = tmp_path / "moved-elsewhere.pcapng"
    src.rename(renamed)

    out2 = tmp_path / "derived2.pcapng"
    manifest2 = derive_capture(renamed, out2, lambda block: True)
    assert manifest2.source_digest == first_digest

    # The manifest itself carries no path identity.
    assert str(tmp_path) not in manifest.to_json()
    assert str(src) not in manifest.to_json()


def test_retained_global_blocks_do_not_claim_filtered_statistics():
    shb = blocks.SectionHeader()
    shb.new_member(blocks.InterfaceDescription, link_type=1, options={"if_name": "e0"})
    shb.new_member(blocks.InterfaceDescription, link_type=1, options={"if_name": "e1"})
    good = shb.new_member(
        blocks.EnhancedPacket, interface_id=0, packet_data=b"keep"
    )
    shb.new_member(blocks.EnhancedPacket, interface_id=1, packet_data=b"drop")
    nrb = shb.new_member(
        blocks.NameResolution,
        records=[{"type": 1, "address": "192.0.2.1", "names": ["example"]}],
    )
    isb = shb.new_member(
        blocks.InterfaceStatistics,
        interface_id=0,
        options={"isb_ifrecv": 2, "isb_filteraccept": 2},
    )

    stream = io.BytesIO()
    writer = FileWriter(stream, shb)
    writer.write_block(good)
    writer.write_block(nrb)
    writer.write_block(isb)
    source = stream.getvalue()

    out = io.BytesIO()
    manifest = derive_capture(
        io.BytesIO(source),
        out,
        lambda block: block.packet_data == b"keep",
        include_name_resolution=True,
        include_interface_statistics=True,
    )

    assert manifest.retained["name_resolution"]["blocks_copied"] == 1
    assert manifest.retained["name_resolution"]["represent_filtered_output"] is False
    assert manifest.retained["interface_statistics"]["blocks_copied"] == 1
    assert (
        manifest.retained["interface_statistics"]["represent_filtered_output"] is False
    )

    # Retained ISB keeps the original counters even though one packet was
    # filtered out: they describe the source capture, not the output.
    read_back = list(FileScanner(io.BytesIO(out.getvalue())))
    stats = [b for b in read_back if isinstance(b, blocks.InterfaceStatistics)]
    assert len(stats) == 1
    assert stats[0].options["isb_ifrecv"] == 2
    assert stats[0].interface_id == 0

    retained_entries = [e for e in manifest.entries if e.retained]
    assert all(
        e.kind in ("name_resolution", "interface_statistics")
        for e in retained_entries
    )
    assert len(retained_entries) == 2


def test_default_omits_global_blocks():
    shb = blocks.SectionHeader()
    shb.new_member(blocks.InterfaceDescription)
    pkt = shb.new_member(blocks.EnhancedPacket, packet_data=b"x")
    nrb = shb.new_member(
        blocks.NameResolution,
        records=[{"type": 1, "address": "192.0.2.1", "names": ["example"]}],
    )

    stream = io.BytesIO()
    writer = FileWriter(stream, shb)
    writer.write_block(pkt)
    writer.write_block(nrb)
    source = stream.getvalue()

    out = io.BytesIO()
    manifest = derive_capture(io.BytesIO(source), out, lambda block: True)
    assert manifest.retained["name_resolution"]["blocks_copied"] == 0
    assert not [e for e in manifest.entries if e.kind == "name_resolution"]


def test_zero_selection_still_yields_readable_capture():
    source, _ = _build_two_sections()
    out = io.BytesIO()
    manifest = derive_capture(io.BytesIO(source), out, lambda block: False)
    assert manifest.selected_packets == 0
    derived = out.getvalue()
    read_back = list(FileScanner(io.BytesIO(derived)))
    assert len(read_back) == 1
    assert isinstance(read_back[0], blocks.SectionHeader)
    assert verify_derived_capture(io.BytesIO(source), io.BytesIO(derived), manifest)


def test_sections_with_no_selected_packets_are_dropped():
    source, _ = _build_two_sections()

    def predicate(block):
        return block.section.version == (1, 0) and block.interface_id == 0

    out = io.BytesIO()
    manifest = derive_capture(io.BytesIO(source), out, predicate)
    derived = out.getvalue()
    read_back = list(FileScanner(io.BytesIO(derived)))
    shbs = [b for b in read_back if isinstance(b, blocks.SectionHeader)]
    assert len(shbs) == 1
    assert len(manifest.sections) == 1
    assert verify_derived_capture(io.BytesIO(source), io.BytesIO(derived), manifest)


def test_simple_packet_with_renumbered_interface_is_rejected():
    # An SPB in a multi-interface section is invalid pcap-ng, but such files
    # exist; the derived file must not silently reinterpret its interface.
    from pcapng.strictness import Strictness, set_strictness

    shb = blocks.SectionHeader()
    shb.new_member(blocks.InterfaceDescription, options={"if_name": "e0"})
    shb.new_member(blocks.InterfaceDescription, options={"if_name": "e1"})
    spb = shb.new_member(blocks.SimplePacket, packet_data=b"spb")
    epb = shb.new_member(
        blocks.EnhancedPacket, interface_id=1, packet_data=b"other"
    )

    stream = io.BytesIO()
    set_strictness(Strictness.WARN)
    try:
        with pytest.warns(Warning):
            writer = FileWriter(stream, shb)
            writer.write_block(spb)
            writer.write_block(epb)
    finally:
        set_strictness(Strictness.FORBID)
    source = stream.getvalue()

    out = io.BytesIO()
    with pytest.raises(DeriveError):
        derive_capture(io.BytesIO(source), out, lambda block: True)


def test_predicate_errors_are_propagated():
    shb = blocks.SectionHeader()
    shb.new_member(blocks.InterfaceDescription)
    pkt = shb.new_member(blocks.EnhancedPacket, packet_data=b"x")
    stream = io.BytesIO()
    writer = FileWriter(stream, shb)
    writer.write_block(pkt)
    source = stream.getvalue()

    def predicate(block):
        raise ZeroDivisionError("boom")

    with pytest.raises(ZeroDivisionError):
        derive_capture(io.BytesIO(source), io.BytesIO(), predicate)


def test_interfaces_follow_first_use_order_and_unused_isb_is_skipped():
    # Three source interfaces, but selections only use ids 2 then 1.
    stream = io.BytesIO()
    shb = blocks.SectionHeader()
    shb.new_member(blocks.InterfaceDescription, options={"if_name": "a"})
    shb.new_member(blocks.InterfaceDescription, options={"if_name": "b"})
    shb.new_member(blocks.InterfaceDescription, options={"if_name": "c"})
    isb_c = shb.new_member(
        blocks.InterfaceStatistics, interface_id=2, options={"isb_ifrecv": 9}
    )
    isb_a = shb.new_member(
        blocks.InterfaceStatistics, interface_id=0, options={"isb_ifrecv": 1}
    )
    p_c = shb.new_member(blocks.EnhancedPacket, interface_id=2, packet_data=b"from-c")
    p_b = shb.new_member(blocks.EnhancedPacket, interface_id=1, packet_data=b"from-b")

    writer = FileWriter(stream, shb)
    writer.write_block(isb_c)
    writer.write_block(isb_a)
    writer.write_block(p_c)
    writer.write_block(p_b)
    source = stream.getvalue()

    out = io.BytesIO()
    manifest = derive_capture(
        io.BytesIO(source),
        out,
        lambda block: True,
        include_interface_statistics=True,
    )

    read_back = list(FileScanner(io.BytesIO(out.getvalue())))
    names = [
        b.options["if_name"]
        for b in read_back
        if isinstance(b, blocks.InterfaceDescription)
    ]
    assert names == ["c", "b"]

    packets = [b for b in read_back if isinstance(b, blocks.EnhancedPacket)]
    assert [p.interface.options["if_name"] for p in packets] == ["c", "b"]
    assert [p.interface_id for p in packets] == [0, 1]

    stats = [b for b in read_back if isinstance(b, blocks.InterfaceStatistics)]
    assert len(stats) == 1
    assert stats[0].interface_id == 0
    assert stats[0].options["isb_ifrecv"] == 9

    assert manifest.retained["interface_statistics"]["blocks_copied"] == 1
    # The ISB for interface "a" has no selected packet to justify its IDB,
    # so it is skipped rather than silently pulling in an extra interface.
    assert manifest.retained["interface_statistics"]["blocks_skipped"] == 1

    assert verify_derived_capture(
        io.BytesIO(source), io.BytesIO(out.getvalue()), manifest
    )


def test_derived_digest_chains_when_deriving_again():
    shb = blocks.SectionHeader()
    shb.new_member(blocks.InterfaceDescription, link_type=1)
    packets = [
        shb.new_member(blocks.EnhancedPacket, packet_data=data, timestamp_low=i)
        for i, data in enumerate((b"a", b"b", b"c"))
    ]
    stream = io.BytesIO()
    writer = FileWriter(stream, shb)
    for packet in packets:
        writer.write_block(packet)
    source = stream.getvalue()

    first = io.BytesIO()
    manifest1 = derive_capture(
        io.BytesIO(source), first, lambda block: block.packet_data in (b"b", b"c")
    )
    derived1 = first.getvalue()
    assert manifest1.output_digest == hashlib.sha256(derived1).hexdigest()

    second = io.BytesIO()
    manifest2 = derive_capture(
        io.BytesIO(derived1), second, lambda block: block.packet_data == b"c"
    )
    # The second manifest identifies the intermediate file by digest.
    assert manifest2.source_digest == manifest1.output_digest

    assert verify_derived_capture(io.BytesIO(source), io.BytesIO(derived1), manifest1)
    assert verify_derived_capture(
        io.BytesIO(derived1), io.BytesIO(second.getvalue()), manifest2
    )


def test_manifest_json_round_trip():
    source, _ = _build_two_sections()
    out = io.BytesIO()
    manifest = derive_capture(io.BytesIO(source), out, lambda block: True)

    import json

    data = json.loads(manifest.to_json())
    assert data["source_digest"] == manifest.source_digest
    assert len(data["entries"]) == len(manifest.entries)
    assert data["entries"][0]["source_digest"] == manifest.source_digest
