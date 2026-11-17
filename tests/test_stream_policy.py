import shutil
import struct

import fixtures

import dnfile
from dnfile import StreamPolicy, StreamStatus


def _stream_headers(dn):
    return {entry.struct.Name: entry.struct.get_file_offset() for entry in dn.net.metadata.streams_list}


def _write_header(path, header_offset, name=None, offset=None, size=None):
    """Patch only a stream header; stream bodies are left untouched."""

    buf = bytearray(path.read_bytes())
    if offset is not None:
        buf[header_offset:header_offset + 4] = struct.pack("<I", offset)
    if size is not None:
        buf[header_offset + 4:header_offset + 8] = struct.pack("<I", size)
    if name is not None:
        # The caller is responsible for using a name that fits the existing
        # 4-byte-aligned name field.
        field = buf[header_offset + 8:header_offset + 8 + len(name) + 1]
        padded = name + b"\x00" * (len(field) - len(name))
        buf[header_offset + 8:header_offset + 8 + len(field)] = padded
    path.write_bytes(buf)


def _clone(tmp_path, fixture_name="hello-world.exe"):
    return fixtures.copy_fixture_to_tmp(tmp_path, fixture_name)


def _clone_invalid(tmp_path, fixture_name):
    src = fixtures.DATA / "invalid-streams" / fixture_name
    dst = tmp_path / fixture_name
    shutil.copyfile(src, dst)
    return dst


def _parse(path, policy=None):
    return dnfile.dnPE(path, stream_policy=policy) if policy else dnfile.dnPE(path)


def test_clean_stream_table_records_header_order_and_ranges():
    dn = _parse(fixtures.get_data_path_by_name("hello-world.exe"))
    report = dn.net.stream_report

    assert [e.name for e in report.entries] == [b"#~", b"#Strings", b"#US", b"#GUID", b"#Blob"]
    assert [e.slot for e in report.entries] == [0, 1, 2, 3, 4]
    assert report.is_complete is True
    assert report.is_clean is True
    assert dn.net.type_evidence == "confirmed"
    assert dn.net.resource_evidence == "confirmed"
    for entry in report.entries:
        assert entry.evidence == "confirmed"
        assert entry.header_offset is not None
        assert entry.read_size == entry.size
        assert entry.read_end_rva == entry.declared_end_rva
        assert entry.stream is not None
        assert entry.stream.declared_range == entry.declared_range
        assert entry.stream.read_range == entry.read_range


def test_zero_length_duplicate_cannot_shadow_a_legitimate_stream(tmp_path):
    path = _clone_invalid(tmp_path, "duplicate-stream.exe")
    headers = _stream_headers(dnfile.dnPE(path))
    us_headers = [entry.struct.get_file_offset() for entry in dnfile.dnPE(path).net.metadata.streams_list if entry.struct.Name == b"#US"]
    assert len(us_headers) == 2

    # Make the last #US empty while the first still has "AAAAAAAA".
    _write_header(path, us_headers[1], size=0)

    forensic = _parse(path, StreamPolicy.FORENSIC)
    report = forensic.net.stream_report
    selected = report.selected_entry(b"#US")

    assert selected is not None and selected.index == 2
    assert forensic.net.user_strings.get(1).value == "AAAAAAAA"
    assert report.selected_entry(b"#US").evidence == "candidate"
    assert report.is_complete is False
    assert report.is_clean is False
    assert any("Duplicate .NET stream name" in warning for warning in forensic.get_warnings())
    assert any("Zero-length .NET stream" in warning for warning in forensic.get_warnings())

    strict = _parse(path, StreamPolicy.STRICT)
    assert strict.net.metadata is None
    assert strict.net.mdtables is None
    assert strict.net.stream_report.rejected is True
    assert any("Duplicate .NET stream name" in warning for warning in strict.get_warnings())
    assert any("Zero-length .NET stream" in warning for warning in strict.get_warnings())
    assert any("rejected .NET stream table" in warning for warning in strict.get_warnings())


def test_duplicate_selection_is_order_independent_but_never_confirmed(tmp_path):
    # Both #US headers are legitimate, but only one has strings.  The old
    # implementation used the last header blindly, so swapping which one is
    # empty changed the parsed result.  Forensic selection keeps the non-empty
    # one in both arrangements; strict rejects both because the name is
    # ambiguous.
    outcomes = []
    for empty_last in (False, True):
        path = _clone_invalid(tmp_path, "duplicate-stream.exe")
        headers = [
            entry.struct.get_file_offset()
            for entry in dnfile.dnPE(path).net.metadata.streams_list
            if entry.struct.Name == b"#US"
        ]
        _write_header(path, headers[0], size=0 if empty_last else 0x14)
        _write_header(path, headers[1], size=0x14 if empty_last else 0)

        dn = _parse(path, StreamPolicy.FORENSIC)
        report = dn.net.stream_report
        legacy = report.legacy_name_winners()[b"#US"]
        selected = report.selected_entry(b"#US")
        legacy_value = None
        if legacy.stream is not None:
            item = legacy.stream.get(1)
            legacy_value = item.value if item is not None else None
        outcomes.append((legacy_value, selected.index, dn.net.user_strings.get(1).value, legacy.read_size))

        assert selected.evidence == "candidate"
        # #US is not an input to type or resource evidence, so those remain
        # confirmed even though the duplicate name is candidate-only.
        assert dn.net.type_evidence == "confirmed"
        assert dn.net.resource_evidence == "confirmed"
        assert report.is_complete is False

    # Legacy last-wins alternates between an empty stream and the populated
    # header that happens to be last; forensic selection always keeps the
    # stream that actually has data, while still refusing to confirm the
    # ambiguous name.
    assert [legacy for legacy, _, _, _ in outcomes] == [None, "BBBBBBBB"]
    assert [legacy_size for _, _, _, legacy_size in outcomes] == [0, 0x14]
    assert [selected for _, selected, _, _ in outcomes] == [2, 3]
    assert [value for _, _, value, _ in outcomes] == ["AAAAAAAA", "BBBBBBBB"]


def test_bad_last_duplicate_cannot_win_by_header_order(tmp_path):
    path = _clone(tmp_path, "hello-world.exe")
    headers = _stream_headers(dnfile.dnPE(path))
    blobs_header = headers[b"#Blob"]

    # The last #Blob header is renamed to a duplicate #GUID that points past
    # the metadata directory.  The earlier #GUID is untouched and valid.
    _write_header(path, blobs_header, offset=0x2F8, size=0x58)
    buf = bytearray(path.read_bytes())
    buf[blobs_header + 8:blobs_header + 13] = b"#GUID"
    path.write_bytes(buf)

    forensic = _parse(path, StreamPolicy.FORENSIC)
    report = forensic.net.stream_report
    legacy = report.legacy_name_winners()[b"#GUID"]

    # Old behavior: the last header wins, so #GUID becomes the broken stream.
    assert legacy.index == 4
    assert legacy.evidence == "candidate"
    assert legacy.read_size == 0

    # New behavior: the valid earlier #GUID remains usable and confirmed.
    selected = report.selected_entry(b"#GUID")
    assert selected.index == 3
    assert selected.evidence == "confirmed"
    assert forensic.net.guids is selected.stream
    assert forensic.net.guids.get(1) is not None
    assert report.is_complete is False
    assert any("outside the metadata directory" in warning for warning in forensic.get_warnings())

    strict = _parse(path, StreamPolicy.STRICT)
    assert strict.net.metadata is None
    assert any("outside_metadata" in warning for warning in strict.get_warnings())
    assert any("rejected .NET stream table" in warning for warning in strict.get_warnings())


def test_exact_alias_marks_both_streams_candidate_only(tmp_path):
    path = _clone(tmp_path)
    us_header = _stream_headers(dnfile.dnPE(path))[b"#US"]

    # #US declares exactly the #Strings range.  No byte belongs to one stream
    # alone, so neither can be confirmed.
    _write_header(path, us_header, offset=0x170, size=0x104)

    dn = _parse(path, StreamPolicy.FORENSIC)
    report = dn.net.stream_report
    strings = report.entries_by_name(b"#Strings")[0]
    us = report.entries_by_name(b"#US")[0]

    assert StreamStatus.OVERLAP_EXACT in strings.statuses
    assert StreamStatus.OVERLAP_EXACT in us.statuses
    assert strings.evidence == "candidate"
    assert us.evidence == "candidate"
    assert "overlap_exact" in strings.status_values()
    assert dn.net.strings is None
    assert dn.net.user_strings is None
    assert dn.net.type_evidence == "candidate"
    assert dn.net.resource_evidence == "candidate"
    assert any("Identical .NET stream ranges" in warning for warning in dn.get_warnings())

    strict = _parse(path, StreamPolicy.STRICT)
    assert strict.net.metadata is None
    assert any("overlap_exact" in warning for warning in strict.get_warnings())


def test_partial_overlap_marks_both_streams_candidate_only(tmp_path):
    path = _clone(tmp_path)
    headers = _stream_headers(dnfile.dnPE(path))

    # #US starts inside #Strings and extends past its end.
    _write_header(path, headers[b"#US"], offset=0x178, size=0x20)

    dn = _parse(path, StreamPolicy.FORENSIC)
    report = dn.net.stream_report
    strings = report.entries_by_name(b"#Strings")[0]
    us = report.entries_by_name(b"#US")[0]

    assert StreamStatus.OVERLAP_PARTIAL in strings.statuses
    assert StreamStatus.OVERLAP_PARTIAL in us.statuses
    assert strings.overlaps_with == [us.index]
    assert us.overlaps_with == [strings.index]
    assert us.read_range == (0x21E0, 0x2200)
    assert us.evidence == "candidate"
    assert any("Overlapping .NET stream ranges" in warning for warning in dn.get_warnings())

    strict = _parse(path, StreamPolicy.STRICT)
    assert strict.net.metadata is None


def test_zero_length_stream_is_empty_not_confirmed(tmp_path):
    path = _clone(tmp_path)
    headers = _stream_headers(dnfile.dnPE(path))
    _write_header(path, headers[b"#GUID"], size=0)

    dn = _parse(path, StreamPolicy.FORENSIC)
    report = dn.net.stream_report
    guid = report.selected_entry(b"#GUID")

    assert guid.evidence == "empty"
    assert guid.is_empty is True
    assert guid.read_range == (guid.declared_rva, guid.declared_rva)
    assert dn.net.guids is not None
    assert dn.net.type_evidence == "candidate"
    assert any("Zero-length .NET stream" in warning for warning in dn.get_warnings())

    strict = _parse(path, StreamPolicy.STRICT)
    assert strict.net.metadata is None
    assert any("zero_length" in warning for warning in strict.get_warnings())


def test_declared_range_outside_metadata_is_never_read(tmp_path):
    path = _clone(tmp_path)
    headers = _stream_headers(dnfile.dnPE(path))

    # 0x2f8 is exactly at the end of the metadata directory.
    _write_header(path, headers[b"#Blob"], offset=0x2F8, size=0x58)

    dn = _parse(path, StreamPolicy.FORENSIC)
    report = dn.net.stream_report
    blob = report.entries_by_name(b"#Blob")[0]

    assert blob.evidence == "candidate"
    assert blob.read_size == 0
    assert blob.read_range == (blob.declared_rva, blob.declared_rva)
    assert StreamStatus.OUTSIDE_METADATA in blob.statuses
    assert dn.net.blobs is None
    assert dn.net.type_evidence == "candidate"
    assert dn.net.resource_evidence == "candidate"
    assert any("outside the metadata directory" in warning for warning in dn.get_warnings())

    strict = _parse(path, StreamPolicy.STRICT)
    assert strict.net.metadata is None


def test_truncated_read_keeps_true_read_range(tmp_path):
    path = _clone(tmp_path)
    baseline = dnfile.dnPE(path)
    blob_entry = baseline.net.stream_report.entries_by_name(b"#Blob")[0]

    # Cut the file in the middle of the Blob stream body.  Only headers are
    # not modified here; this case checks the "true bytes read" bookkeeping.
    fixtures.truncate_file(path, blob_entry.data_file_offset + 8)

    dn = _parse(path, StreamPolicy.FORENSIC)
    report = dn.net.stream_report
    blob = report.entries_by_name(b"#Blob")[0]

    assert blob.read_size == 8
    assert blob.read_end_rva == blob.declared_rva + 8
    assert blob.declared_end_rva == blob.declared_rva + blob.size
    assert StreamStatus.TRUNCATED in blob.statuses
    assert blob.evidence == "candidate"
    assert dn.net.type_evidence == "candidate"
    assert any("only 0x8 bytes were readable" in warning for warning in dn.get_warnings())

    strict = _parse(path, StreamPolicy.STRICT)
    assert strict.net.metadata is None


def test_unreadable_header_is_preserved_as_missing_slot(tmp_path):
    path = _clone(tmp_path)
    baseline = dnfile.dnPE(path)
    strings_entry = baseline.net.stream_report.entries_by_name(b"#Strings")[0]

    fixtures.patch_bytes(path, strings_entry.header_offset, b"\xff" * 16)

    forensic = _parse(path, StreamPolicy.FORENSIC)
    report = forensic.net.stream_report

    assert report.invalid_slots == [strings_entry.header_rva]
    assert [e.slot for e in report.entries] == [0, 2, 3, 4]
    assert report.is_complete is False
    assert forensic.net.strings is None
    assert forensic.net.type_evidence == "candidate"
    assert any("Skipped unreadable .NET stream slot 2" in warning for warning in forensic.get_warnings())

    strict = _parse(path, StreamPolicy.STRICT)
    assert strict.net.metadata is None
    assert strict.net.stream_report.invalid_slots == [strings_entry.header_rva]
