from pathlib import Path

import pytest
import fixtures

import dnfile
from dnfile import security

SAMPLE = "security-declarations.exe"


def _sample_path():
    return Path(__file__).parent / "samples" / SAMPLE


def _analysis():
    dn = dnfile.dnPE(_sample_path())
    assert dn.net is not None
    return security.analyze(dn)


def test_small_sample_exposes_assembly_type_and_same_named_methods():
    analysis = _analysis()

    assert analysis.table_present is True
    assert analysis.declared_num_rows == 11
    assert analysis.parsed_num_rows == 11

    assembly = analysis.declarations_for_assembly()
    assert len(assembly) == 1
    assert assembly[0].action == security.DeclSecurityAction.RequestMinimum
    assert assembly[0].owner_display == 'Assembly "SecurityDeclSample"'
    assert assembly[0].owner_key == "assembly:0x20000001"
    assert assembly[0].parent_token == 0x20000001
    assert isinstance(assembly[0].parent_row, dnfile.mdtable.AssemblyRow)
    assert assembly[0].parent_row.Name == "SecurityDeclSample"

    type_a = analysis.declarations_for_type("TypeA")
    assert len(type_a) == 1
    assert type_a[0].parent_kind == "type"
    assert type_a[0].parent_token == 0x02000002
    assert type_a[0].parent_row_index == 2
    assert isinstance(type_a[0].parent_row, dnfile.mdtable.TypeDefRow)
    assert type_a[0].owner_name == "TypeA"

    type_b = analysis.declarations_for_type("TypeB")
    assert len(type_b) == 1
    assert type_b[0].parent_token == 0x02000003

    # Two different methods are both named "Run"; ownership must not merge them.
    run_declarations = analysis.declarations_for_method("Run")
    by_type = {}
    for declaration in run_declarations:
        by_type.setdefault(declaration.owner_type_name, []).append(declaration)
        assert declaration.parent_row.Name == "Run"
        assert isinstance(declaration.parent_row, dnfile.mdtable.MethodDefRow)

    assert set(by_type) == {"TypeA", "TypeB"}
    assert {d.action_raw for d in by_type["TypeA"]} >= {0x0002, 0x0006}
    assert {d.action_raw for d in by_type["TypeB"]} >= {0x0003, 0x0022}
    assert all(d.parent_token == 0x06000001 for d in by_type["TypeA"])
    assert all(d.parent_token == 0x06000002 for d in by_type["TypeB"])

    # Requesting only TypeB.Run must not return TypeA.Run.
    type_b_run = analysis.declarations_for_method("Run", owner_type="TypeB")
    assert {d.parent_token for d in type_b_run} == {0x06000002}


def test_different_actions_on_one_owner_do_not_overwrite_each_other():
    analysis = _analysis()
    type_a_run = analysis.declarations_for_method("Run", owner_type="TypeA")
    rows = [d.index for d in type_a_run]
    actions = [d.action_raw for d in type_a_run]

    # Row 10 has an unresolvable blob but the same owner, so it is still kept.
    assert rows == [4, 5, 10, 11]
    assert 0x0002 in actions and 0x0006 in actions
    assert analysis.by_owner["method:0x06000001"] == tuple(type_a_run)
    owner_group = [g for g in analysis.groups if g.key == "method:0x06000001"][0]
    assert [d.index for d in owner_group.declarations] == [4, 5, 10, 11]


def test_duplicate_declarations_are_reported_not_merged():
    analysis = _analysis()

    assert len(analysis.duplicates) == 1
    duplicate = analysis.duplicates[0]
    assert duplicate.owner_key == "method:0x06000001"
    assert duplicate.owner_display == 'Method "TypeA.Run"'
    assert duplicate.action_raw == 0x0002
    assert duplicate.row_indexes == (4, 11)
    assert duplicate.permission_set_blob.startswith(b"\x2e\x01")


def test_supported_subset_payloads_are_decoded_with_named_arguments():
    analysis = _analysis()

    assembly = analysis.declarations_for_assembly()[0]
    permission_set = assembly.permission_set_decoded
    assert permission_set.format == "binary"
    assert permission_set.status == "decoded"
    attribute = permission_set.attributes[0]
    assert attribute.attribute_type == "System.Security.Permissions.SecurityPermissionAttribute"
    assert [(a.kind, a.name, a.value) for a in attribute.named_arguments] == [
        ("property", "SkipVerification", True)
    ]

    type_a = analysis.declarations_for_type("TypeA")[0]
    file_io = type_a.permission_set_decoded.attributes[0]
    assert file_io.attribute_type == "System.Security.Permissions.FileIOPermissionAttribute"
    assert [(a.type_name, a.name, a.value) for a in file_io.named_arguments] == [
        ("string", "Read", "C:\\temp")
    ]

    type_b = analysis.declarations_for_type("TypeB")[0]
    environment, custom = type_b.permission_set_decoded.attributes
    assert environment.status == "decoded"
    assert environment.named_arguments[0].name == "Unrestricted"
    assert custom.status == "unsupported"
    assert custom.payload == b"\x01\x54\x02\x04Flag\x01"
    assert type_b.permission_set_decoded.status == "partial"


def test_raw_action_blob_and_coded_index_are_preserved():
    analysis = _analysis()
    declaration = analysis.declarations[3]

    assert declaration.action_raw == 0x0002
    assert declaration.parent_raw == 0x0005  # MethodDef rid 1, tag 1
    assert declaration.parent_table == "MethodDef"
    assert declaration.parent_row_index == 1
    assert declaration.permission_set_blob is not None
    assert declaration.permission_set_blob == declaration.permission_set.value_bytes()
    assert declaration.permission_set_blob_index == 314
    assert declaration.storage_facts["action_raw"] == 0x0002
    assert declaration.storage_facts["parent_raw"] == 0x0005
    assert declaration.storage_facts["parent_token"] == "0x06000001"
    assert declaration.storage_facts["permission_set_blob_hex"].startswith("2e018084")


def test_legacy_dotnet_fixture_is_decoded_too():
    dn = dnfile.dnPE(fixtures.get_data_path_by_name("ModuleCode_x86.exe"))
    analysis = security.analyze(dn)

    assert analysis.declared_num_rows == 3
    assert [d.parent_kind for d in analysis.declarations] == ["assembly", "method", "method"]
    assert analysis.declarations[0].owner_name == "ModuleCode"
    assert analysis.declarations[0].action == security.DeclSecurityAction.RequestMinimum
    assert analysis.declarations[1].action == security.DeclSecurityAction.Assert
    assert analysis.declarations[1].owner_name == "_initterm_m"
    assert analysis.declarations[1].permission_set_decoded.status == "decoded"
    assert analysis.declarations[1].permission_set_decoded.attributes[0].named_arguments[0].value is True


def test_unknown_action_is_not_reported_as_no_security():
    analysis = _analysis()
    declaration = [d for d in analysis.declarations if d.action_raw == 0x0022][0]

    assert declaration.action is None
    assert declaration.action_known is False
    assert declaration.action_name == "unknown(0x0022)"
    assert declaration.action_raw == 0x0022
    assert declaration.needs_manual_review is True
    assert declaration in analysis.unknown_action_declarations
    assert declaration.owner_display == 'Method "TypeB.Run"'
    # The payload is still decoded even though the action is unknown.
    assert declaration.permission_set_decoded.attributes[0].named_arguments[0].name == "Assertion"

    report = analysis.format_report()
    assert "unknown(0x0022)" in report
    assert "needs manual review" in report
    # The unknown row is reported, and the analysis never states that the
    # file has no security requirements.
    assert "0 DeclSecurity row" not in report
    assert "not as evidence that no security requirement exists" in report


def test_bad_parent_indexes_stay_attached_to_the_claimed_token():
    analysis = _analysis()

    dangling = analysis.declarations[7]
    assert dangling.parent_table == "TypeDef"
    assert dangling.parent_row_index == 99
    assert dangling.parent_token == 0x02000063
    assert dangling.parent_raw == 0x018C
    assert dangling.parent_row is None
    assert dangling.resolved is False
    assert dangling.owner_key == "type:0x02000063"
    assert dangling.owner_display.startswith("TypeDef[99] (unresolved")
    assert dangling.needs_manual_review is True
    assert dangling.permission_set_decoded.format == "legacy-xml"
    assert any("exceeds declared row count" in issue for issue in dangling.issues)

    invalid_tag = analysis.declarations[8]
    assert invalid_tag.parent_raw == 0x000F
    assert invalid_tag.parent_kind == "invalid"
    assert invalid_tag.parent_table is None
    assert invalid_tag.resolved is False
    assert invalid_tag.owner_key == "unresolved:parent=0x000f"
    assert any("invalid HasDeclSecurity parent tag" in issue for issue in invalid_tag.issues)

    assert analysis.unresolved_declarations == (analysis.declarations[7], analysis.declarations[8])


def test_bad_blob_index_is_an_unknown_not_an_empty_permission_set():
    analysis = _analysis()
    declaration = analysis.declarations[9]

    assert declaration.permission_set_blob_index == 0xFFFF
    assert declaration.permission_set_blob is None
    assert declaration.permission_set_decoded.format == "unavailable"
    assert declaration.permission_set_decoded.status == "unavailable"
    assert declaration.payload_interpretable is False
    assert declaration.needs_manual_review is True
    assert any("does not resolve" in issue for issue in declaration.issues)


def test_unknown_payload_form_is_not_treated_as_no_requirement():
    analysis = _analysis()

    legacy = analysis.declarations[7]
    assert legacy.permission_set_decoded.format == "legacy-xml"
    assert legacy.permission_set_decoded.status == "unsupported"
    assert legacy.permission_set_decoded.attributes == ()
    assert legacy.permission_set_decoded.raw.startswith(b"<PermissionSet")
    assert legacy.payload_interpretable is False

    malformed = analysis.declarations[8]
    assert malformed.permission_set_decoded.format == "binary"
    assert malformed.permission_set_decoded.status == "malformed"

    # A row whose blob itself could not be read is unknown, not "no security".
    assert analysis.declarations[9].permission_set_decoded.status == "unavailable"


def test_missing_or_empty_table_is_described_as_metadata_only():
    dn = dnfile.dnPE(fixtures.get_data_path_by_name("hello-world.exe"))
    analysis = security.analyze(dn)

    assert analysis.table_present is False
    assert analysis.has_declarations is False
    assert analysis.declarations == ()
    assert "no DeclSecurity metadata table" in analysis.security_presence
    assert analysis.needs_manual_review is False

    # The report must not turn absence of a table into a runtime guarantee.
    report = analysis.format_report()
    assert "does not establish whether a runtime" in report


def test_analysis_is_read_only_and_repeatable():
    dn = dnfile.dnPE(_sample_path())
    first = security.analyze(dn)
    second = security.analyze(dn)

    assert [d.index for d in first.declarations] == [d.index for d in second.declarations]
    assert [d.action_raw for d in first.declarations] == [d.action_raw for d in second.declarations]
    assert [d.owner_key for d in first.declarations] == [d.owner_key for d in second.declarations]
    assert [g.key for g in first.groups] == [g.key for g in second.groups]


def test_row_and_table_convenience_helpers_do_not_replace_raw_values():
    dn = dnfile.dnPE(_sample_path())
    table = dn.net.mdtables.DeclSecurity

    row = table.rows[6]
    assert row.Action == 0x0022
    assert row.ActionEnum is None
    assert row.PermissionSet is not None
    assert row.PermissionSetData.status == "decoded"
    assert row.PermissionSetData.attributes[0].named_arguments[0].name == "Assertion"

    known = table.rows[0]
    assert known.ActionEnum == security.DeclSecurityAction.RequestMinimum

    assert table.analyze().declared_num_rows == 11


def test_dnpe_shortcut_and_none_without_clr():
    dn = dnfile.dnPE(_sample_path())
    assert dn.analyze_security_declarations().declared_num_rows == 11

    hello = dnfile.dnPE(fixtures.get_data_path_by_name("hello-world.exe"))
    assert hello.analyze_security_declarations().declared_num_rows == 0


def test_decode_permission_set_rejects_unrecognized_forms_without_losing_bytes():
    raw = b"\x00\x01\x02not a permission set"
    decoded = security.decode_permission_set(raw)
    assert decoded.raw == raw
    assert decoded.format == "unknown"
    assert decoded.status == "unsupported"
    assert decoded.attributes == ()

    empty = security.decode_permission_set(b"")
    assert empty.format == "empty"
    assert empty.status == "empty"
    assert empty.raw == b""

    unavailable = security.decode_permission_set(None)
    assert unavailable.format == "unavailable"
    assert unavailable.status == "unavailable"

    # A count that promises more attributes than the blob contains is malformed
    # and must not be reported as an empty permission set.
    truncated = security.decode_permission_set(b"\x2e\x02")
    assert truncated.format == "binary"
    assert truncated.status == "malformed"
    assert truncated.raw == b"\x2e\x02"


def _compressed(value):
    if value <= 0x7F:
        return bytes((value,))
    if value <= 0x3FFF:
        return bytes((0x80 | (value >> 8), value & 0xFF))
    return bytes((0xC0 | (value >> 24), (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF))


def _serstring(value):
    if value is None:
        return b"\xff"
    raw = value.encode("utf-8")
    return _compressed(len(raw)) + raw


def _named(kind, type_code, name, value):
    return bytes((kind, type_code)) + _serstring(name) + value


def _attribute_blob(named_arguments):
    prefix = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib"
    payload = _compressed(len(named_arguments)) + b"".join(named_arguments)
    return b"\x2e\x01" + _serstring(prefix) + _compressed(len(payload)) + payload


def test_named_argument_scalar_and_collection_decoding():
    arguments = [
        _named(0x53, 0x04, "V", b"\xfb"),                                    # i1
        _named(0x53, 0x07, "W", (65535).to_bytes(2, "little")),              # u2
        _named(0x53, 0x08, "X", (-1).to_bytes(4, "little", signed=True)),    # i4
        _named(0x53, 0x0A, "Y", (-5).to_bytes(8, "little", signed=True)),    # i8
        _named(0x53, 0x0C, "R", __import__("struct").pack("<f", 1.5)),       # r4
        _named(0x53, 0x0E, "S", b"\xff"),                                    # null string
        _named(0x53, 0x02, "B", b"\x00"),                                    # false
        _named(0x53, 0x03, "C", b"A\x00"),                                   # char
        _named(0x53, 0x0E, "T", _serstring("text")),                         # string
    ]

    permission_set = security.decode_permission_set(_attribute_blob(arguments))
    assert permission_set.status == "decoded"
    attribute = permission_set.attributes[0]
    values = {argument.name: argument.value for argument in attribute.named_arguments}
    assert values == {
        "V": -5,
        "W": 65535,
        "X": -1,
        "Y": -5,
        "R": pytest.approx(1.5),
        "S": None,
        "B": False,
        "C": "A",
        "T": "text",
    }
    assert all(argument.kind == "field" for argument in attribute.named_arguments)


def test_named_argument_array_enum_and_type_decoding():
    # An SZARRAY type descriptor includes its element type before the name.
    array = (
        b"\x54\x1d\x0e"
        + _serstring("Names")
        + (2).to_bytes(4, "little")
        + _serstring("a")
        + _serstring("bc")
    )
    decoded = security.decode_permission_set(_attribute_blob([array])).attributes[0]
    argument = decoded.named_arguments[0]
    assert argument.type_name == "array<string>"
    assert argument.value == ["a", "bc"]
    assert argument.status == "decoded"

    # ENUM carries its serialized enum type before the field name.
    enum = (
        b"\x54\x55"
        + _serstring("System.Security.Permissions.SecurityAction")
        + _serstring("Action")
        + (256).to_bytes(4, "little", signed=True)
    )
    decoded = security.decode_permission_set(_attribute_blob([enum])).attributes[0]
    argument = decoded.named_arguments[0]
    assert argument.value == 256
    assert argument.type_name == "System.Security.Permissions.SecurityAction"
    assert "assumed to be int32" in argument.note
    assert decoded.status == "partial"

    type_value = _named(0x54, 0x50, "Kind", _serstring("System.String, mscorlib"))
    decoded = security.decode_permission_set(_attribute_blob([type_value])).attributes[0]
    assert decoded.status == "decoded"
    assert decoded.named_arguments[0].value == "System.String, mscorlib"


def test_unsupported_named_argument_keeps_the_rest_of_the_payload():
    unsupported = _named(0x53, 0x5B, "Flag", b"\x00")
    decoded = security.decode_permission_set(_attribute_blob([unsupported]))
    attribute = decoded.attributes[0]

    assert attribute.status == "partial"
    assert len(attribute.named_arguments) == 1
    argument = attribute.named_arguments[0]
    assert argument.name == "Flag"
    assert argument.status == "unsupported"
    assert argument.value is None
    assert argument.raw_value
    # Raw bytes are retained even though the value could not be interpreted.
    assert attribute.payload.endswith(argument.raw_value)


def test_unreadable_declared_rows_are_reported_not_dropped(tmp_path):
    import shutil

    source = _sample_path()
    patched = tmp_path / source.name
    shutil.copyfile(source, patched)

    dn = dnfile.dnPE(source)
    table = dn.net.mdtables.DeclSecurity
    # Cut inside the DeclSecurity rows, after the first one.
    fixtures.truncate_file(patched, table.file_offset + table.row_size + 1)

    damaged = dnfile.dnPE(patched)
    assert damaged.net is not None
    assert damaged.net.mdtables is not None
    assert damaged.net.mdtables.DeclSecurity is not None

    analysis = security.analyze(damaged)
    assert analysis.declared_num_rows == 11
    assert analysis.parsed_num_rows < 11
    # Every declared row still appears, and unreadable ones are not treated as
    # "no security requirement".
    assert len(analysis.declarations) == 11
    # Some rows exist as objects with no unpacked bytes; those are kept as
    # explicit unknowns rather than as zeroed "no security" rows.
    unread = [d for d in analysis.declarations if d.row is None or d.action_raw is None and d.parent_raw is None]
    assert unread
    for declaration in unread:
        assert declaration.resolved is False
        assert declaration.action_raw is None
        assert declaration.needs_manual_review is True
        assert declaration.owner_key == "unresolved:row={}".format(declaration.index)


def test_analysis_of_a_file_without_decl_security_table():
    dn = dnfile.dnPE(fixtures.get_data_path_by_name("hello-world.exe"))
    # The stream-level helper always returns an analysis object.
    analysis = dn.net.mdtables.analyze_security_declarations()
    assert analysis is not None
    assert analysis.table_present is False
    assert analysis.declarations == ()

    # The table-level helper only exists when the table does.
    assert not hasattr(dn.net.mdtables, "DeclSecurity") or dn.net.mdtables.DeclSecurity is None


def test_analysis_does_not_mutate_metadata_rows():
    dn = dnfile.dnPE(_sample_path())
    table = dn.net.mdtables.DeclSecurity
    before = [(row.Action, row.struct.Parent_CodedIndex, row.struct.PermissionSet_BlobIndex) for row in table.rows]

    security.analyze(dn)
    security.analyze(dn.net.mdtables)

    after = [(row.Action, row.struct.Parent_CodedIndex, row.struct.PermissionSet_BlobIndex) for row in table.rows]
    assert before == after
