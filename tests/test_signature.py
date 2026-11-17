import binascii

import fixtures
import dnfile
from dnfile import signature


def _blob(hex_string):
    return binascii.unhexlify(hex_string)


def _method_rows(path, name):
    dn = dnfile.dnPE(path)
    return [row for row in dn.net.mdtables.MethodDef.rows if row is not None and str(row.Name) == name]


def test_compressed_unsigned_integers_match_ecma335_examples():
    # ECMA-335 II.23.2 examples.
    assert signature._SignatureReader(_blob("03")).read_compressed_u32("$") == 0x03
    assert signature._SignatureReader(_blob("7F")).read_compressed_u32("$") == 0x7F
    assert signature._SignatureReader(_blob("8080")).read_compressed_u32("$") == 0x80
    assert signature._SignatureReader(_blob("AE57")).read_compressed_u32("$") == 0x2E57
    assert signature._SignatureReader(_blob("BFFF")).read_compressed_u32("$") == 0x3FFF
    assert signature._SignatureReader(_blob("C0004000")).read_compressed_u32("$") == 0x4000
    assert signature._SignatureReader(_blob("DFFFFFFF")).read_compressed_u32("$") == 0x1FFFFFFF


def test_compressed_signed_integers_match_ecma335_examples():
    # ECMA-335 II.23.2 examples, used by array lower bounds.
    reader = signature._SignatureReader
    assert reader(_blob("06")).read_compressed_u32("$", signed=True) == 3
    assert reader(_blob("7B")).read_compressed_u32("$", signed=True) == -3
    assert reader(_blob("8080")).read_compressed_u32("$", signed=True) == 64
    assert reader(_blob("01")).read_compressed_u32("$", signed=True) == -64
    assert reader(_blob("C0004000")).read_compressed_u32("$", signed=True) == 8192
    assert reader(_blob("8001")).read_compressed_u32("$", signed=True) == -8192
    assert reader(_blob("DFFFFFFE")).read_compressed_u32("$", signed=True) == 268435455
    assert reader(_blob("C0000001")).read_compressed_u32("$", signed=True) == -268435456


def test_truncated_compressed_integer_is_not_padded():
    parsed = signature.parse_signature(_blob("061380"))
    assert isinstance(parsed, signature.FieldSignature)
    assert parsed.incomplete is True
    bad = parsed.field_type
    assert isinstance(bad, signature.UnsupportedType)
    # The remaining bytes are exactly the bytes from the element start.
    assert bad.raw == _blob("1380")
    assert bad.consumed == _blob("13")
    assert bad.remaining == _blob("80")
    assert bad.path == "$.field.number"
    assert "truncated compressed integer" in bad.reason


def test_unsupported_element_type_keeps_blob_and_path():
    parsed = signature.parse_signature(_blob("061110ff"))
    # VALUETYPE consumes only the token; the stray byte stays unparsed.
    assert parsed.field_type.element_type == "VALUETYPE"
    assert parsed.trailing == _blob("ff")
    assert "unparsed" in parsed.to_programmer_string()

    parsed = signature.parse_signature(_blob("0612"))
    assert isinstance(parsed, signature.FieldSignature)
    assert parsed.incomplete is True
    assert isinstance(parsed.field_type, signature.UnsupportedType)
    assert parsed.field_type.raw == _blob("12")
    assert parsed.field_type.path == "$.field.token"


def test_truncated_method_parameter_preserves_prefix_and_path():
    parsed = signature.parse_signature(_blob("00032005010f11"))
    assert parsed.kind == "method"
    assert parsed.incomplete is True
    assert parsed.failure_path == "$.parameter[0].inner.token"
    pointer = parsed.parameters[0]
    assert pointer.element_type == "PTR"
    assert pointer.incomplete is True
    assert pointer.inner.element_type == "UNKNOWN"
    assert pointer.inner.raw == _blob("11")


def test_same_named_overloads_are_distinguished_by_signature_and_token():
    path = fixtures.get_data_path_by_name("ModuleCode_x86.exe")
    rows = _method_rows(path, ".ctor")
    assert len(rows) >= 3

    by_blob = {row.Signature.value_bytes(): row for row in rows if row.Signature is not None}
    signatures = [row.ParsedSignature for row in rows]

    rendered = {row.SignatureEvidence["token_hex"]: sig.to_programmer_string(str(row.Name)) for row, sig in zip(rows, signatures)}
    assert rendered["0x0600004e"] == "instance void .ctor(string, class System.Exception)"
    assert rendered["0x0600004f"] == "instance void .ctor(string)"
    assert rendered["0x06000051"] == "instance void .ctor(string, class System.Exception, class System.Exception)"

    # Two rows may share one blob (0x0600004d / 0x06000050); that is not identity.
    shared = [row for row in rows if row.Signature.value_bytes() == _blob("20020112511155")]
    assert len(shared) >= 2
    assert {row.SignatureEvidence["token_hex"] for row in shared} == {"0x0600004d", "0x06000050"}
    assert len({sig.to_programmer_string(str(row.Name)) for row, sig in zip(shared, [r.ParsedSignature for r in shared])}) == 1


def test_nested_generic_instance_keeps_recursive_structure():
    table = dnfile.dnPE(fixtures.get_data_path_by_name("ModuleCode_x86.exe")).net.mdtables

    # class <Module><System.Exception, valuetype TriBool<!0>>
    # outer -> TypeDef row 1, Exception -> TypeRef row 19, TriBool -> TypeDef row 10.
    raw = _blob("06" "15" "12" "04" "02" "12" "4d" "15" "11" "28" "01" "13" "00")
    parsed = signature.parse_signature(raw, table)
    assert isinstance(parsed, signature.FieldSignature)

    outer = parsed.field_type
    assert outer.element_type == "GENERICINST"
    assert outer.generic_kind == "CLASS"
    assert outer.token.table_name == "TypeDef"
    assert outer.token.row_index == 1
    assert outer.token.resolved is True
    assert outer.raw == raw[1:]
    assert len(outer.arguments) == 2

    reference_argument = outer.arguments[0]
    assert reference_argument.element_type == "CLASS"
    assert reference_argument.token.table_name == "TypeRef"
    assert reference_argument.token.name == "System.Exception"
    assert reference_argument.token.row is table.TypeRef.get_with_row_index(19)

    inner = outer.arguments[1]
    assert inner.element_type == "GENERICINST"
    assert inner.generic_kind == "VALUETYPE"
    assert inner.token.table_name == "TypeDef"
    assert inner.token.row_index == 10
    assert inner.token.name.endswith("TriBool")
    assert inner.arguments[0].element_type == "VAR"
    assert inner.arguments[0].number == 0
    assert parsed.incomplete is False
    assert parsed.trailing == b""


def test_array_dimension_and_bounds_are_interpreted():
    # instance void M(int32[0..., 10, 11])
    # rank 3, two sizes (10, 11), two lower bounds (0, -3)
    raw = _blob("20" "01" "01" "14" "08" "03" "02" "0a" "0b" "02" "00" "7b")
    parsed = signature.parse_method_signature(raw)
    array = parsed.parameters[0]
    assert array.element_type == "ARRAY"
    assert array.array_rank == 3
    assert array.array_sizes == [10, 11]
    assert array.array_lower_bounds == [0, -3]
    assert array.inner.element_type == "I4"


def test_class_and_valuetype_tokens_reach_the_right_metadata_tables():
    path = fixtures.get_data_path_by_name("ModuleCode_x86.exe")
    dn = dnfile.dnPE(path)
    table = dn.net.mdtables

    # A field typed as the enum Progress uses VALUETYPE with a TypeDef token.
    field_row = table.Field.rows[5]
    parsed = field_row.ParsedSignature
    assert parsed.field_type.element_type == "VALUETYPE"
    token = parsed.field_type.token
    assert token.table_name == "TypeDef"
    assert token.resolved is True
    assert token.row is table.TypeDef.get_with_row_index(token.row_index)
    assert token.name.endswith("Progress")

    # A CLASS token from a method parameter points at the TypeRef for System.Exception.
    ctor_with_exception = next(row for row in table.MethodDef.rows if row is not None and row.SignatureEvidence["token_hex"] == "0x0600004e")
    exception_type = ctor_with_exception.ParsedSignature.parameters[1]
    assert exception_type.element_type == "CLASS"
    assert exception_type.token.table_name == "TypeRef"
    assert exception_type.token.name == "System.Exception"
    assert exception_type.is_reference_type_hint is True


def test_reference_type_and_value_type_counterexample():
    path = fixtures.get_data_path_by_name("ModuleCode_x86.exe")
    table = dnfile.dnPE(path).net.mdtables

    # A method parameter declared with CLASS TypeRef System.Exception.
    ref_param = table.MethodDef.rows[77].ParsedSignature.parameters[1]
    # A field declared with VALUETYPE TypeDef __s_GUID (a struct), reached
    # through its modopt prefix.
    value_outer = table.Field.rows[4].ParsedSignature.field_type
    assert value_outer.element_type == "CMOD_OPT"
    value_field = value_outer.inner

    assert ref_param.element_type == "CLASS"
    assert value_field.element_type == "VALUETYPE"
    assert ref_param.token.table_name != value_field.token.table_name
    assert ref_param.is_reference_type_hint is True
    assert value_field.is_reference_type_hint is False
    assert ref_param.to_programmer_string().startswith("class ")
    assert value_field.to_programmer_string().startswith("valuetype ")

    # Both tokens resolve to real metadata rows, not invented names.
    assert ref_param.token.resolved and value_field.token.resolved
    assert str(ref_param.token.row.TypeName) == "Exception"
    assert str(value_field.token.row.TypeName) == "__s_GUID"
    # The value-type TypeDef row itself extends System.ValueType; this is why
    # "CLASS" in the signature is a syntax marker, not a runtime kind oracle.
    assert str(value_field.token.row.Extends.row.TypeName) == "ValueType"


def test_field_and_local_signature_entry_points():
    path = fixtures.get_data_path_by_name("ModuleCode_x86.exe")
    table = dnfile.dnPE(path).net.mdtables

    field = table.Field.rows[1].ParsedSignature
    assert isinstance(field, signature.FieldSignature)
    assert field.field_type.element_type == "U8"

    locals_ = table.StandAloneSig.rows[4].ParsedSignature
    assert isinstance(locals_, signature.LocalSignature)
    assert [local.element_type for local in locals_.locals] == ["I4"] * 5

    # A standalone signature blob that happens to carry a method signature
    # is still interpreted by its actual first byte.
    assert table.StandAloneSig.rows[8].ParsedSignature.kind == "method"

    # Explicit per-kind accessors exist and agree with the generic entry point.
    assert table.MethodDef.rows[0].ParsedMethodSignature.kind == "method"
    assert table.Field.rows[1].ParsedFieldSignature.kind == "field"
    assert table.StandAloneSig.rows[4].ParsedLocalSignature.kind == "locals"


def test_deeply_nested_blob_is_bounded_and_reported():
    raw = b"\x06" + b"\x1d" * 200 + b"\x08"
    parsed = signature.parse_signature(raw)
    assert parsed.incomplete is True
    node = parsed.field_type.unparsed
    assert "nesting exceeds" in node.reason
    # The node keeps the unread tail from the point where the bound was hit.
    assert node.raw == raw[1 + signature._SignatureReader.max_type_depth:]
    assert node.raw.endswith(b"\x08")


def test_evidence_keeps_raw_blob_token_and_structured_result():
    path = fixtures.get_data_path_by_name("ModuleCode_x86.exe")
    table = dnfile.dnPE(path).net.mdtables
    row = table.MethodDef.rows[78]

    summary = row.SignatureSummary
    assert summary["table"] == "MethodDef"
    assert summary["token_hex"] == "0x0600004f"
    assert summary["blob_index"] == 566
    assert summary["blob_hex"] == "2001010e"
    assert summary["blob"] == row.Signature.value_bytes()
    assert isinstance(summary["blob_rva"], int)
    assert summary["parsed_kind"] == "method"
    assert summary["parsed"].to_programmer_string("Demo") == "instance void Demo(string)"


def test_mid_signature_truncation_preserves_blob_path_and_prefix():
    table = dnfile.dnPE(fixtures.get_data_path_by_name("ModuleCode_x86.exe")).net.mdtables
    row = next(row for row in table.MethodDef.rows if row is not None and row.SignatureEvidence["token_hex"] == "0x0600004d")

    full = row.Signature.value_bytes()
    # Real blob: 20 02 01 12 51 11 55.  Drop the final token byte so the second
    # parameter's VALUETYPE token is cut mid-element.
    truncated = full[:-1]
    assert full == _blob("20020112511155")
    assert truncated == _blob("200201125111")

    parsed = signature.parse_signature(truncated, table)
    assert parsed.kind == "method"
    assert parsed.parameter_count == 2
    assert parsed.interpreted_parameter_count == 2
    assert parsed.incomplete is True
    assert parsed.failure_path == "$.parameter[1].token"
    assert parsed.parameters[0].element_type == "CLASS"
    assert parsed.parameters[0].token.name == "System.Runtime.Serialization.SerializationInfo"
    bad = parsed.parameters[1]
    assert bad.element_type == "UNKNOWN"
    assert bad.raw == _blob("11")
    assert bad.reason.startswith("unexpected end of signature blob")
    assert parsed.raw == truncated
    assert "incomplete" in parsed.to_programmer_string(str(row.Name))


def test_malformed_blob_does_not_raise_from_rows():
    path = fixtures.get_data_path_by_name("hello-world.exe")
    table = dnfile.dnPE(path).net.mdtables
    # A real method row with a synthetic truncated blob, exercising the same
    # table context and evidence path without editing the fixture.
    row = table.MethodDef.rows[0]
    row.__dict__["Signature"] = type(row.Signature)(b"\x04\x20\x01\x01\x11", rva=row.Signature.rva)
    parsed = signature.parse_row_signature(row)
    assert parsed.incomplete is True
    assert parsed.return_type.element_type == "VOID"
    assert isinstance(parsed.parameters[0], signature.UnsupportedType)
    assert parsed.parameters[0].raw == _blob("11")
