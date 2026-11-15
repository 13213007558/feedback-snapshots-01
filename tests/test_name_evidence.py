import io
import socket
import struct

import pytest

from pcapng.name_evidence import (
    EVIDENCE_DISCLAIMER,
    STATUS_CORRUPTED,
    STATUS_PARSED,
    STATUS_UNEXPLAINED,
    NameEvidenceView,
)

BYTE_ORDER_MAGIC = 0x1A2B3C4D
BLK_SECTION_HEADER = 0x0A0D0D0A
BLK_NAME_RESOLUTION = 0x00000004


def build_block(block_type, body, endianness="<"):
    padding = -len(body) % 4
    total = 12 + len(body) + padding
    return (
        struct.pack(endianness + "II", block_type, total)
        + body
        + b"\x00" * padding
        + struct.pack(endianness + "I", total)
    )


def build_shb(endianness="<"):
    body = struct.pack(endianness + "IHHq", BYTE_ORDER_MAGIC, 1, 0, -1)
    return build_block(BLK_SECTION_HEADER, body, endianness)


def nrb_record(record_type, value, endianness="<"):
    padding = -len(value) % 4
    return (
        struct.pack(endianness + "HH", record_type, len(value))
        + value
        + b"\x00" * padding
    )


def ipv4_record(address, names, endianness="<"):
    value = socket.inet_aton(address)
    value += b"".join(n.encode("utf-8") + b"\x00" for n in names)
    return nrb_record(0x0001, value, endianness)


def ipv6_record(address, names, endianness="<"):
    value = socket.inet_pton(socket.AF_INET6, address)
    value += b"".join(n.encode("utf-8") + b"\x00" for n in names)
    return nrb_record(0x0002, value, endianness)


def build_nrb(records, endianness="<"):
    body = b"".join(records) + b"\x00\x00\x00\x00"
    return build_block(BLK_NAME_RESOLUTION, body, endianness)


def build_demo_capture():
    section0 = build_shb("<")
    section0 += build_nrb(
        [
            ipv4_record("10.0.0.1", ["alpha.example", "alpha-alias.example"]),
            ipv4_record("10.0.0.1", ["alpha2.example"]),
            ipv6_record("2001:db8::1", ["v6alpha.example"]),
            nrb_record(0x7777, b"\xde\xad\xbe\xef"),
            nrb_record(0x0001, socket.inet_aton("192.0.2.7") + b"webserv"),
        ],
        "<",
    )
    section1 = build_shb(">")
    section1 += build_nrb([ipv4_record("10.0.0.1", ["beta.example"], ">")], ">")
    return section0 + section1


@pytest.fixture
def view():
    return NameEvidenceView.from_stream(io.BytesIO(build_demo_capture()))


def test_multiple_names_in_single_record(view):
    evidence = view.claims_for("10.0.0.1")
    first = evidence.claims[0]
    assert first.status == STATUS_PARSED
    assert first.names == ("alpha.example", "alpha-alias.example")


def test_separate_records_same_address_preserved(view):
    evidence = view.claims_for("10.0.0.1")
    section0_claims = [c for c in evidence.claims if c.section_index == 0]
    assert len(section0_claims) == 2
    assert section0_claims[1].names == ("alpha2.example",)


def test_ipv6_claim(view):
    evidence = view.claims_for("2001:db8::1")
    assert len(evidence.claims) == 1
    assert evidence.claims[0].names == ("v6alpha.example",)
    # Non-canonical query forms resolve to the same claim, offline.
    assert view.claims_for("2001:0db8::1").claims == evidence.claims


def test_raw_record_and_provenance_kept(view):
    claim = view.claims_for("10.0.0.1").claims[0]
    assert claim.section_index == 0
    assert claim.block_index == 0
    assert claim.record_index == 0
    record_type, record_length = struct.unpack("<HH", claim.raw[:4])
    assert record_type == 0x0001
    value = claim.raw[4:4 + record_length]
    assert value.startswith(socket.inet_aton("10.0.0.1"))
    assert b"alpha.example\x00alpha-alias.example\x00" in value
    # raw includes the 32-bit padding after the record value
    assert len(claim.raw) == 4 + record_length + (-record_length % 4)


def test_conflict_between_sections_explained(view):
    evidence = view.claims_for("10.0.0.1")
    assert evidence.has_conflict
    assert evidence.name_sets_by_section() == {
        0: [("alpha.example", "alpha-alias.example"), ("alpha2.example",)],
        1: [("beta.example",)],
    }
    text = evidence.explain()
    assert "section 0" in text
    assert "section 1" in text
    assert "alpha.example" in text
    assert "beta.example" in text
    assert "CONFLICT" in text
    # The explanation must not present any name as currently valid.
    assert EVIDENCE_DISCLAIMER in text


def test_big_endian_section_parsed(view):
    claim = [c for c in view.claims_for("10.0.0.1").claims
             if c.section_index == 1][0]
    assert claim.names == ("beta.example",)


def test_unknown_record_type_is_unexplained(view):
    unexplained = view.unexplained
    assert len(unexplained) == 1
    record = unexplained[0]
    assert record.status == STATUS_UNEXPLAINED
    assert record.record_type == 0x7777
    assert record.address is None
    assert record.names == ()
    assert record.raw == b"ww\x04\x00\xde\xad\xbe\xef"
    assert "unknown record type" in record.problem


def test_truncated_name_is_corrupted_not_trusted(view):
    corrupted = view.corrupted
    assert len(corrupted) == 1
    record = corrupted[0]
    assert record.status == STATUS_CORRUPTED
    assert record.address == "192.0.2.7"
    assert record.names == ()
    assert "truncated name" in record.problem
    # The partial name must not show up as a trusted claim anywhere.
    evidence = view.claims_for("192.0.2.7")
    assert evidence.claims == []
    assert evidence.damaged == [record]
    assert "webserv" not in evidence.names
    assert "192.0.2.7" not in view.addresses()


def test_problems_collects_unexplained_and_corrupted(view):
    assert view.problems == view.unexplained + view.corrupted
    for record in view.problems:
        assert not record.is_name_claim


def test_no_online_resolution_for_queries(view):
    with pytest.raises(ValueError, match="no name resolution"):
        view.claims_for("alpha.example")


def test_unknown_address_has_no_claims(view):
    evidence = view.claims_for("203.0.113.9")
    assert evidence.claims == []
    assert evidence.damaged == []
    assert not evidence.has_conflict
    assert "no name claims" in evidence.explain()


def test_record_length_past_block_end_is_corrupted():
    body = struct.pack("<HH", 0x0001, 0x00FF) + b"\x0a\x00\x00\x01"
    capture = build_shb("<") + build_block(BLK_NAME_RESOLUTION, body, "<")
    view = NameEvidenceView.from_stream(io.BytesIO(capture))
    assert len(view.records) == 1
    assert view.records[0].status == STATUS_CORRUPTED
    assert "exceeds" in view.records[0].problem


def test_short_address_record_is_corrupted():
    capture = build_shb("<") + build_nrb([nrb_record(0x0001, b"\x0a\x00")], "<")
    view = NameEvidenceView.from_stream(io.BytesIO(capture))
    assert view.corrupted[0].problem.startswith("record too short")


def test_invalid_utf8_name_is_corrupted():
    value = socket.inet_aton("10.9.9.9") + b"bad-\xff-name\x00"
    capture = build_shb("<") + build_nrb([nrb_record(0x0001, value)], "<")
    view = NameEvidenceView.from_stream(io.BytesIO(capture))
    assert view.corrupted[0].address == "10.9.9.9"
    assert "UTF-8" in view.corrupted[0].problem
    assert view.claims_for("10.9.9.9").claims == []


def test_from_file(view, tmp_path):
    path = str(tmp_path / "demo.pcapng")
    with open(path, "wb") as fp:
        fp.write(build_demo_capture())
    file_view = NameEvidenceView.from_file(path)
    assert file_view.section_count == 2
    assert len(file_view.records) == len(view.records)
    assert file_view.claims_for("10.0.0.1").has_conflict
