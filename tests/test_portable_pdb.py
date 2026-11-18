import struct
import builtins

import pytest
import fixtures
from portable_pdb_fixtures import build_portable_pdb, read_codeview_rsds_id, encode_sequence_points

import dnfile
import dnfile.portable_pdb as pp


def _module_code_path():
    return fixtures.get_data_path_by_name("ModuleCode_x86.exe")


def _module_code_amd64_path():
    return fixtures.DATA / "mixed-mode" / "ModuleCode" / "bin" / "ModuleCode_amd64.exe"


def _hello_world_path():
    return fixtures.get_data_path_by_name("hello-world.exe")


def _rsds_id(path):
    return read_codeview_rsds_id(dnfile.dnPE(path))


def _simple_points(document_row_id=1):
    return encode_sequence_points(
        [
            {"il_offset": 0, "start_line": 10, "start_column": 5, "end_line": 10, "end_column": 20},
            {"il_offset": 7, "start_line": 11, "start_column": 9, "end_line": 11, "end_column": 30},
            {"il_offset": 12, "is_hidden": True},
        ],
        document_row_id,
    )


def _association_pdb(pdb_id, **overrides):
    values = dict(
        pdb_id=pdb_id,
        external_counts={6: 89},
        entry_point_token=0x06000045,
        documents=[(ord("/"), [b"src", b"Program.cs"])],
        method_debug_information=[(1, _simple_points()), (1, _simple_points())],
    )
    values.update(overrides)
    return build_portable_pdb(**values)


def _reason_codes(association):
    return [reason["code"] for reason in association.reasons]


def _find_method(result, row_id):
    for method in result.methods:
        if method.methoddef_row_id == row_id:
            return method
    raise AssertionError("method rid %d not present" % row_id)


def test_external_methoddef_row_count_controls_index_width_at_boundary():
    rsds = _rsds_id(_module_code_path())

    below = pp.read_portable_pdb(
        build_portable_pdb(
            pdb_id=rsds,
            external_counts={6: 0xFFFF},
            documents=[(ord("/"), [b"src", b"Program.cs"])],
            method_debug_information=[(1, _simple_points())],
            state_machine_methods=[(0xFFFF, 2)],
        )
    )
    above = pp.read_portable_pdb(
        build_portable_pdb(
            pdb_id=rsds,
            external_counts={6: 0x10000},
            documents=[(ord("/"), [b"src", b"Program.cs"])],
            method_debug_information=[(1, _simple_points())],
            state_machine_methods=[(0x10000, 2)],
        )
    )

    assert below.external_methoddef_row_count == 0xFFFF
    assert above.external_methoddef_row_count == 0x10000
    assert below.table_index_size("MethodDef") == 2
    assert above.table_index_size("MethodDef") == 4

    # StateMachineMethod is two MethodDef references, so its row grows from
    # 4 to 8 bytes exactly at the external boundary.
    assert below.table_row_sizes[pp.TABLE_STATE_MACHINE_METHOD] == 4
    assert above.table_row_sizes[pp.TABLE_STATE_MACHINE_METHOD] == 8
    assert len(below.state_machine_methods[0].raw) == 4
    assert len(above.state_machine_methods[0].raw) == 8
    assert below.state_machine_methods[0].move_next_method_row_id == 0xFFFF
    assert above.state_machine_methods[0].move_next_method_row_id == 0x10000
    assert below.state_machine_methods[0].kickoff_method_row_id == 2
    assert above.state_machine_methods[0].kickoff_method_row_id == 2

    # The in-scope tables do not use MethodDef references, so their widths must
    # not move with the external row count.
    assert below.table_row_sizes[pp.TABLE_METHOD_DEBUG_INFORMATION] == 4
    assert above.table_row_sizes[pp.TABLE_METHOD_DEBUG_INFORMATION] == 4
    below_row = below.get_method_debug_information(1)
    above_row = above.get_method_debug_information(1)
    assert below_row.Document.Name == "src/Program.cs"
    assert above_row.Document.Name == "src/Program.cs"
    assert below.MethodDebugInformation.get_with_row_index(1) is below_row
    assert below.MethodDebugInformation[0] is below_row
    assert len(below.Document) == 1
    assert below.tables[pp.TABLE_STATE_MACHINE_METHOD].num_rows == 1
    assert below.state_machine_methods[0].MoveNextMethod == 0xFFFF
    assert above.state_machine_methods[0].MoveNextMethod == 0x10000
    assert below_row.SequencePoints[0].StartLine == 10


def test_document_index_width_comes_from_internal_row_count():
    rsds = _rsds_id(_module_code_path())
    pdb = pp.read_portable_pdb(
        build_portable_pdb(
            pdb_id=rsds,
            external_counts={6: 4},
            documents=[(ord("/"), [b"a.cs"]), (ord("/"), [b"b.cs"])],
            method_debug_information=[(2, _simple_points(2))],
        )
    )

    assert pdb.document_row_count == 2
    assert pdb.table_row_sizes[pp.TABLE_METHOD_DEBUG_INFORMATION] == 4
    row = pdb.get_method_debug_information(1)
    assert row.document_row_id == 2
    assert row.document is not None
    assert row.document.name == "b.cs"


def test_association_matches_identity_and_reports_evidence():
    pdb = pp.read_portable_pdb(_association_pdb(_rsds_id(_module_code_path())))
    result = pdb.associate(_module_code_path())

    data = result.to_dict()
    assert data["identity"]["status"] == "match"
    assert [check["check"] for check in data["identity"]["checks"]] == [
        "pdb-id",
        "methoddef-row-count",
        "entry-point",
    ]
    assert data["summary"]["associated"] == 2
    assert data["summary"]["methods_total"] == 89
    assert data["summary"]["missing_debug_records"] == 87

    method = _find_method(result, 1)
    assert method.status == "associated"
    assert method.methoddef_token == 0x06000001
    assert method.line_check["status"] == "ok"
    assert method.line_check["visible_point_count"] == 2
    assert method.line_check["hidden_point_count"] == 1
    assert method.document is not None
    assert method.document.name == "src/Program.cs"

    payload = method.to_dict()
    assert payload["identifier"]["methoddef_token"] == 0x06000001
    assert payload["identifier"]["methoddef_token_hex"] == "0x06000001"
    assert payload["identifier"]["pdb_row_id"] == 1
    assert payload["identifier"]["identity_kind"] == "codeview-rsds-20-byte-pdb-id"
    assert payload["raw_records"]["method_debug_information"] == method.pdb_row.raw.hex()
    assert payload["raw_records"]["sequence_points_blob"] == method.pdb_row.sequence_points_blob.hex()
    assert payload["raw_records"]["document"] == method.document.raw.hex()
    assert payload["status"] == "associated"
    assert payload["unresolved_reasons"] == []
    assert payload["trusted"] is False

    # Methods beyond the two MethodDebugInformation rows are missing debug
    # records, not missing documents.
    missing = _find_method(result, 3)
    assert missing.status == "unresolved"
    assert _reason_codes(missing) == ["missing-debug-record"]
    assert missing.line_check["status"] == "unavailable"

    assert any("evidence only" in note for note in data["notes"])
    assert any("does not assert" in note for note in data["notes"])


def test_wrong_assembly_does_not_attach_any_source_location():
    wrong_id = _rsds_id(_module_code_amd64_path())
    correct_id = _rsds_id(_module_code_path())
    assert wrong_id != correct_id

    pdb = pp.read_portable_pdb(_association_pdb(correct_id))

    result = pdb.associate(_module_code_amd64_path(), max_methods=3)
    data = result.to_dict()

    assert data["identity"]["status"] == "mismatch"
    assert "pdb-id-mismatch" in [reason["code"] for reason in data["identity"]["reasons"]]
    assert data["summary"]["associated"] == 0
    for method in result.methods:
        assert method.status == "unresolved"
        assert _reason_codes(method) == ["identity-not-established"]
        assert method.line_check["status"] == "not-checked"

    payload = result.methods[0].to_dict()
    assert payload["pdb_side_evidence_withheld"] is True
    assert payload["document"] is None
    assert payload["sequence_points"] == []
    assert payload["raw_records"]["document_name_blob"] is None
    # Raw table records remain available as rejected evidence.
    assert payload["raw_records"]["method_debug_information"] is not None
    assert payload["raw_records"]["document"] is not None

    # A matching PDB *file name* is not evidence of identity and must not help.
    same_name = pp.PortablePdb.from_bytes(bytes(pdb.data), name="mixed.pdb")
    same_name_result = same_name.associate(_module_code_amd64_path(), max_methods=1)
    assert same_name_result.to_dict()["summary"]["associated"] == 0
    assert same_name_result.identity.status == "mismatch"


def test_wrong_methoddef_row_count_is_a_separate_identity_failure():
    pdb = pp.read_portable_pdb(_association_pdb(_rsds_id(_module_code_path()), external_counts={6: 88}))
    result = pdb.associate(_module_code_path(), max_methods=2)
    data = result.to_dict()

    assert data["identity"]["status"] == "mismatch"
    assert "methoddef-rowcount-mismatch" in [reason["code"] for reason in data["identity"]["reasons"]]
    assert data["summary"]["associated"] == 0
    assert all(_reason_codes(method) == ["identity-not-established"] for method in result.methods)


def test_wrong_entry_point_is_a_separate_identity_failure():
    pdb = pp.read_portable_pdb(_association_pdb(_rsds_id(_module_code_path()), entry_point_token=0x06000001))
    result = pdb.associate(_module_code_path(), max_methods=2)
    data = result.to_dict()

    assert data["identity"]["status"] == "mismatch"
    assert "entrypoint-mismatch" in [reason["code"] for reason in data["identity"]["reasons"]]
    assert data["summary"]["associated"] == 0


def test_assembly_without_codeview_is_unavailable_not_a_match():
    # Row count matches hello-world (2 methods) so the only unavailable check is
    # the missing CodeView record.
    pdb = pp.read_portable_pdb(
        build_portable_pdb(
            pdb_id=_rsds_id(_module_code_path()),
            external_counts={6: 2},
            entry_point_token=0x06000001,
            documents=[(ord("/"), [b"src", b"Program.cs"])],
            method_debug_information=[(1, _simple_points())],
        )
    )
    result = pdb.associate(_hello_world_path(), max_methods=2)
    data = result.to_dict()

    assert data["identity"]["status"] == "unavailable"
    assert "assembly-no-codeview-rsds" in [reason["code"] for reason in data["identity"]["reasons"]]
    assert data["summary"]["associated"] == 0
    assert all(_reason_codes(method) == ["identity-not-established"] for method in result.methods)


def test_missing_document_table_is_reported_without_inventing_a_path():
    pdb = pp.read_portable_pdb(
        build_portable_pdb(
            pdb_id=_rsds_id(_module_code_path()),
            external_counts={6: 89},
            entry_point_token=0x06000045,
            documents=[(ord("/"), [b"src", b"Program.cs"])],
            method_debug_information=[(1, _simple_points())],
            include_document_table=False,
        )
    )
    result = pdb.associate(_module_code_path(), max_methods=1)
    method = result.methods[0]

    assert result.identity.status == "match"
    assert method.status == "unresolved"
    assert "missing-document" in _reason_codes(method)
    assert method.document is None
    payload = method.to_dict()
    assert payload["raw_records"]["document"] is None
    assert payload["document"] is None


def test_document_row_beyond_table_is_missing_document():
    pdb = pp.read_portable_pdb(
        _association_pdb(_rsds_id(_module_code_path()), method_debug_information=[(2, _simple_points(2))])
    )
    result = pdb.associate(_module_code_path(), max_methods=1)
    method = result.methods[0]

    assert result.identity.status == "match"
    assert method.status == "unresolved"
    codes = _reason_codes(method)
    assert "missing-document" in codes
    assert any("Document row(s) not present: 2" in reason.get("detail", "") for reason in method.reasons)


def test_nil_document_handle_is_missing_document():
    nil_document_points = encode_sequence_points(
        [
            {"il_offset": 0, "start_line": 1, "start_column": 0, "end_line": 1, "end_column": 4},
        ],
        0,
    )
    pdb = pp.read_portable_pdb(
        _association_pdb(_rsds_id(_module_code_path()), method_debug_information=[(0, nil_document_points)])
    )
    result = pdb.associate(_module_code_path(), max_methods=1)
    method = result.methods[0]

    assert method.status == "unresolved"
    assert "missing-document" in _reason_codes(method)
    assert "nil Document handle" in " ".join(reason.get("detail", "") for reason in method.reasons)


def test_missing_sequence_points_is_distinct_from_missing_debug_record():
    pdb = pp.read_portable_pdb(
        _association_pdb(
            _rsds_id(_module_code_path()),
            method_debug_information=[(1, None)],
        )
    )
    result = pdb.associate(_module_code_path(), max_methods=2)

    first = result.methods[0]
    second = result.methods[1]
    assert "missing-sequence-points" in _reason_codes(first)
    assert "missing-document" not in _reason_codes(first)
    assert _reason_codes(second) == ["missing-debug-record"]
    assert first.line_check["status"] == "empty"


def test_empty_debug_record_is_reported():
    pdb = pp.read_portable_pdb(
        _association_pdb(_rsds_id(_module_code_path()), method_debug_information=[(0, None)])
    )
    result = pdb.associate(_module_code_path(), max_methods=1)
    method = result.methods[0]

    assert method.status == "unresolved"
    assert _reason_codes(method) == ["empty-debug-record"]
    assert method.line_check["status"] == "empty"


def test_hidden_only_points_have_no_visible_line_but_keep_document_evidence():
    hidden_points = encode_sequence_points([{"il_offset": 0, "is_hidden": True}], 1)
    pdb = pp.read_portable_pdb(
        _association_pdb(_rsds_id(_module_code_path()), method_debug_information=[(1, hidden_points)])
    )
    result = pdb.associate(_module_code_path(), max_methods=1)
    method = result.methods[0]

    assert method.status == "unresolved"
    assert "no-visible-sequence-points" in _reason_codes(method)
    assert method.line_check["status"] == "hidden-only"
    assert method.document is not None
    assert not method.line_check["visible_point_count"]


def test_invalid_line_number_is_checked_separately():
    bad_line_points = encode_sequence_points(
        [
            {"il_offset": 0, "start_line": 5, "start_column": 0, "end_line": 5, "end_column": 4},
            {"il_offset": 4, "start_line": -3, "start_column": 0, "end_line": -2, "end_column": 4},
        ],
        1,
    )
    pdb = pp.read_portable_pdb(
        _association_pdb(_rsds_id(_module_code_path()), method_debug_information=[(1, bad_line_points)])
    )
    result = pdb.associate(_module_code_path(), max_methods=1)
    method = result.methods[0]

    assert method.status == "unresolved"
    assert "line-number-out-of-range" in _reason_codes(method)
    assert method.line_check["status"] == "invalid"
    assert "line-number-out-of-range" in method.line_check["reasons"]


def test_no_document_file_is_opened_during_association():
    pdb = pp.read_portable_pdb(_association_pdb(_rsds_id(_module_code_path())))
    assembly = dnfile.dnPE(_module_code_path())

    real_open = builtins.open

    def guarded_open(*args, **kwargs):
        raise AssertionError("association opened a file: %r" % (args,))

    builtins.open = guarded_open
    try:
        result = pdb.associate(assembly, max_methods=1)
    finally:
        builtins.open = real_open

    assert result.methods[0].status == "associated"
    assert result.methods[0].document.name == "src/Program.cs"


def test_association_entry_point_from_a_path_and_a_dnpe_are_equivalent():
    pdb = pp.read_portable_pdb(_association_pdb(_rsds_id(_module_code_path())))
    by_path = pdb.associate(_module_code_path(), max_methods=1)
    by_object = pdb.associate(dnfile.dnPE(_module_code_path()), max_methods=1)

    assert by_path.to_dict()["summary"] == by_object.to_dict()["summary"]
    assert by_path.methods[0].methoddef_token == by_object.methods[0].methoddef_token


def test_top_level_entry_points():
    pdb_bytes = _association_pdb(_rsds_id(_module_code_path()))
    pdb = dnfile.read_portable_pdb(pdb_bytes)
    result = dnfile.associate_debug_records(pdb, _module_code_path(), max_methods=1)

    assert pdb.external_methoddef_row_count == 89
    assert result.methods[0].status == "associated"


def test_reader_rejects_non_pdb_data():
    with pytest.raises(pp.PortablePdbError):
        pp.read_portable_pdb(b"not a portable pdb")


def test_reader_rejects_missing_pdb_stream():
    data = bytearray(_association_pdb(_rsds_id(_module_code_path())))
    # Rename #Pdb to #Pdx in the stream headers; the stream table is scanned by
    # the reader for the literal name.
    offset = data.find(b"#Pdb")
    assert offset >= 0
    data[offset:offset + 4] = b"#Pdx"
    with pytest.raises(pp.PortablePdbError):
        pp.read_portable_pdb(bytes(data))


def test_reader_reports_forbidden_external_mask_bits_as_warning():
    data = _association_pdb(_rsds_id(_module_code_path()))
    parsed = pp.read_portable_pdb(data)
    offset = parsed.streams_by_name[b"#Pdb"].offset
    buf = bytearray(data)
    mask = struct.unpack_from("<Q", buf, offset + 24)[0] | (1 << 3)
    struct.pack_into("<Q", buf, offset + 24, mask)
    pdb = pp.read_portable_pdb(bytes(buf))
    assert any("forbidden bits" in warning for warning in pdb.warnings)


def test_document_name_with_invalid_part_handle_is_reported_as_evidence_problem():
    data = build_portable_pdb(
        pdb_id=_rsds_id(_module_code_path()),
        external_counts={6: 89},
        documents=[(ord("/"), [b"src"])],
        method_debug_information=[(1, _simple_points())],
    )
    pdb = pp.read_portable_pdb(data)
    blob_stream = pdb.streams_by_name[b"#Blob"]
    name_blob_relative = blob_stream.data.find(bytes([ord("/")]) + bytes([1]))
    assert name_blob_relative >= 0
    corrupted = bytearray(data)
    # Point the part handle at an offset past the #Blob heap.
    corrupted[blob_stream.offset + name_blob_relative + 1] = 0x7F
    corrupted_pdb = pp.read_portable_pdb(bytes(corrupted))

    document = corrupted_pdb.documents[0]
    assert document.separator == ord("/")
    assert document.name_parts == []
    assert document.name == ""
    assert document.decode_error is not None
    assert "invalid blob handle" in document.decode_error
    assert document.to_dict()["name_is_evidence_only"] is True


def test_document_name_with_zero_separator_has_no_separator():
    pdb = pp.read_portable_pdb(
        build_portable_pdb(
            pdb_id=_rsds_id(_module_code_path()),
            external_counts={6: 89},
            documents=[(0, [b"src", b"Program.cs"])],
            method_debug_information=[(1, _simple_points())],
        )
    )
    assert pdb.documents[0].separator == 0
    assert pdb.documents[0].name == "srcProgram.cs"
