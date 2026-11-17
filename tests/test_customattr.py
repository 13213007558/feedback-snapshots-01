import sys
import struct
from unittest import mock

import pytest

import fixtures

import dnfile
from dnfile import customattr


class _Heap:
    def __init__(self, data):
        self.value = data


class _Index:
    # Stand-in for MDTableIndex / CodedIndex used by table rows.
    def __init__(self, table, row_index):
        self.table = table
        self.row_index = row_index

    @property
    def row(self):
        return self.table.get_with_row_index(self.row_index) if self.table else None


class _Table:
    def __init__(self, name, rows):
        self.name = name
        self.rows = list(rows)
        self.num_rows = len(self.rows)

    def get_with_row_index(self, row_index):
        if row_index < 1 or row_index > len(self.rows):
            return None
        return self.rows[row_index - 1]


class _Row:
    def __init__(self, **kw):
        for key, value in kw.items():
            setattr(self, key, value)


class _Tables:
    pass


def _strings(s):
    return str(s)


def _sig(*bytes_):
    return _Heap(bytes(bytes_))


def _method_sig(param_types, return_type=b"\x01", conv=0x20):
    return bytes([conv, len(param_types)]) + return_type + b"".join(param_types)


def _field_sig(field_type):
    return b"\x06" + field_type


def _ser_string(s):
    if s is None:
        return b"\xff"
    raw = s.encode("utf-8")
    assert len(raw) <= 0x7F
    return bytes([len(raw)]) + raw


def _custom_attribute(ctor_table, ctor_row, blob):
    return _Row(Parent=_Index(_Table("TypeDef", [_Row()]), 1), Type=_Index(ctor_table, ctor_row), Value=_Heap(blob))


def _tables(**kwargs):
    tables = _Tables()
    for name, table in kwargs.items():
        setattr(tables, name, table)
    return tables


def _member_ref(name, signature, class_index):
    return _Row(Name=_strings(name), Signature=_sig(*[signature]) if isinstance(signature, int) else _Heap(signature), Class=class_index)


def _typeref(namespace, name, resolution_scope=None):
    return _Row(TypeNamespace=_strings(namespace), TypeName=_strings(name), ResolutionScope=resolution_scope)


def _typedef(namespace, name, field_list):
    return _Row(TypeNamespace=_strings(namespace), TypeName=_strings(name), FieldList=field_list)


def _field(name, signature):
    return _Row(Name=_strings(name), Signature=_Heap(signature))


def _constant(type_code, value_bytes):
    return _Row(Type=type_code, Value=_Heap(value_bytes))


def _build_enum_assembly():
    """
    Synthetic, self-contained metadata:

      namespace Fixtures {
        enum SampleMode : ushort { None = 0, First = 1, Second = 2 }
        class SampleAttribute : System.Attribute {
          .ctor(SampleMode, int32[] mode, string text)
        }
      }
    """
    field_table = _Table("Field", [
        _field("value__", _field_sig(b"\x07")),      # row 1: ushort
        _field("None", _field_sig(b"\x07")),         # row 2
        _field("First", _field_sig(b"\x07")),        # row 3
        _field("Second", _field_sig(b"\x07")),       # row 4
    ])
    typedef_table = _Table("TypeDef", [
        _typedef("", "<Module>", []),
        _typedef("Fixtures", "SampleMode", [_Index(field_table, 1), _Index(field_table, 2),
                                            _Index(field_table, 3), _Index(field_table, 4)]),
        _typedef("Fixtures", "SampleAttribute", []),
    ])
    constant_table = _Table("Constant", [
        _Row(Type=0x07, Parent=_Index(field_table, 2), Value=_Heap(b"\x00\x00")),
        _Row(Type=0x07, Parent=_Index(field_table, 3), Value=_Heap(b"\x01\x00")),
        _Row(Type=0x07, Parent=_Index(field_table, 4), Value=_Heap(b"\x02\x00")),
    ])
    enum_ctor_sig = _method_sig([b"\x11\x08", b"\x1d\x08", b"\x0e"])
    ctor = _member_ref(".ctor", enum_ctor_sig, _Index(typedef_table, 3))
    memberref_table = _Table("MemberRef", [ctor])
    tables = _tables(
        TypeDef=typedef_table,
        TypeRef=_Table("TypeRef", []),
        Field=field_table,
        Constant=constant_table,
        MemberRef=memberref_table,
        CustomAttribute=_Table("CustomAttribute", []),
        Assembly=_Table("Assembly", [_Row(Name=_strings("Fixtures"))]),
    )
    blob = (
        b"\x01\x00"
        + struct.pack("<H", 1)
        + struct.pack("<I", 3)
        + struct.pack("<iii", 2, 1, 0)
        + _ser_string("payload")
        + b"\x00\x00"
    )
    return tables, _custom_attribute(memberref_table, 1, blob)


def test_custom_enum_and_array_are_interpreted_statically():
    tables, row = _build_enum_assembly()

    result = customattr.decode_custom_attribute(row, tables)

    assert result.status == customattr.InterpretationStatus.COMPLETE
    assert result.constructor.declaring_type == "Fixtures.SampleAttribute"
    assert result.constructor.external is False

    fixed = result.fixed_args
    assert [arg.declared_type for arg in fixed] == ["enum Fixtures.SampleMode", "SZARRAY<System.Int32>", "System.String"]
    assert [arg.value for arg in fixed] == [1, [2, 1, 0], "payload"]
    assert [arg.status for arg in fixed] == [customattr.InterpretationStatus.COMPLETE] * 3

    assert fixed[0].extra["enum_underlying"] == "System.UInt16"
    assert fixed[0].extra["enum_member"] == "First"
    assert fixed[1].extra["count"] == 3
    assert result.trailing == b""

    # The value provenance must be traceable to signatures, not to a default.
    assert any("TypeDef#2.value__" in line for line in fixed[0].basis)
    assert any("param[0]" in line for line in fixed[0].basis)
    assert any("count=3" in line for line in fixed[1].basis)

    assert result.provenance["assembly_loaded"] is False
    assert result.provenance["attribute_instantiated"] is False
    assert result.provenance["analyzed_file_imported"] is False


def test_empty_array_is_not_confused_with_null_array():
    tables, _ = _build_enum_assembly()
    blob = (
        b"\x01\x00"
        + struct.pack("<H", 1)
        + struct.pack("<I", 0)
        + _ser_string("text")
        + b"\x00\x00"
    )
    row = _custom_attribute(tables.MemberRef, 1, blob)

    result = customattr.decode_custom_attribute(row, tables)

    assert result.status == customattr.InterpretationStatus.COMPLETE
    empty = result.fixed_args[1]
    assert empty.value == []
    assert empty.extra == {"array": True, "null": False, "count": 0, "element_type": "System.Int32"}
    assert empty.status == customattr.InterpretationStatus.COMPLETE


def test_null_array_is_reported_as_null():
    tables, _ = _build_enum_assembly()
    blob = (
        b"\x01\x00"
        + struct.pack("<H", 1)
        + struct.pack("<I", 0xFFFFFFFF)
        + _ser_string("text")
        + b"\x00\x00"
    )
    row = _custom_attribute(tables.MemberRef, 1, blob)

    result = customattr.decode_custom_attribute(row, tables)

    assert result.status == customattr.InterpretationStatus.COMPLETE
    assert result.fixed_args[1].value is None
    assert result.fixed_args[1].extra["null"] is True


def test_external_constructor_is_named_but_enum_stays_indeterminate():
    path = fixtures.get_data_path_by_name("hello-world.exe")
    dn = dnfile.dnPE(path)
    tables = dn.net.mdtables

    result = customattr.decode_custom_attribute(tables.CustomAttribute[2], tables)

    assert result.constructor.declaring_type == "System.Diagnostics.DebuggableAttribute [mscorlib]"
    assert result.constructor.declaring_assembly == "mscorlib"
    assert result.constructor.external is True
    assert result.constructor.param_count == 1
    assert result.constructor.parameters == ["enum DebuggingModes [mscorlib]"]

    arg = result.fixed_args[0]
    assert arg.value is None
    assert arg.status == customattr.InterpretationStatus.INDETERMINATE
    assert "external-enum-underlying-unknown" in arg.reason
    assert result.status == customattr.InterpretationStatus.PARTIAL
    assert result.trailing == bytes.fromhex("070100000000")


def test_signature_and_blob_disagree_keeps_remaining_bytes_indeterminate():
    tables, _ = _build_enum_assembly()
    # Signature declares (enum, int32[], string); payload only supplies the enum.
    blob = b"\x01\x00" + struct.pack("<H", 1)
    row = _custom_attribute(tables.MemberRef, 1, blob)

    result = customattr.decode_custom_attribute(row, tables)

    assert result.status == customattr.InterpretationStatus.PARTIAL
    assert len(result.fixed_args) == 3
    assert result.fixed_args[0].value == 1
    assert [arg.status for arg in result.fixed_args[1:]] == [
        customattr.InterpretationStatus.INDETERMINATE,
        customattr.InterpretationStatus.INDETERMINATE,
    ]
    assert all(arg.value is None for arg in result.fixed_args[1:])
    assert "unexpected-end-of-blob" in result.diagnostics[0]


def test_trailing_payload_bytes_are_preserved():
    tables, _ = _build_enum_assembly()
    blob = (
        b"\x01\x00"
        + struct.pack("<H", 1)
        + struct.pack("<I", 0xFFFFFFFF)
        + _ser_string("text")
        + b"\x00\x00"
        + b"\xde\xad\xbe\xef"
    )
    row = _custom_attribute(tables.MemberRef, 1, blob)

    result = customattr.decode_custom_attribute(row, tables)

    assert result.status == customattr.InterpretationStatus.PARTIAL
    assert result.trailing == b"\xde\xad\xbe\xef"
    assert any("trailing-bytes" in line for line in result.diagnostics)


def test_unresolved_constructor_does_not_guess_arguments():
    tables, _ = _build_enum_assembly()
    blob = b"\x01\x00\x08\x00\x00\x00"
    row = _custom_attribute(_Table("Unused", [_Row()]), 1, blob)

    result = customattr.decode_custom_attribute(row, tables)

    assert result.status == customattr.InterpretationStatus.INDETERMINATE
    assert result.fixed_args == []
    assert result.named_args == []
    assert result.constructor.token == "Unused#1"
    assert result.constructor.reason


def test_unknown_named_argument_type_stops_without_defaults():
    tables, _ = _build_enum_assembly()
    blob = (
        b"\x01\x00"
        + struct.pack("<H", 3)
        + struct.pack("<I", 3)
        + struct.pack("<iii", 2, 1, 0)
        + _ser_string("text")
        + struct.pack("<H", 1)
        + b"\x54"          # named property
        + b"\x99"          # unsupported element type
        + _ser_string("Odd")
    )
    row = _custom_attribute(tables.MemberRef, 1, blob)

    result = customattr.decode_custom_attribute(row, tables)

    assert result.status == customattr.InterpretationStatus.PARTIAL
    assert result.named_args[0].value is None
    assert result.named_args[0].status == customattr.InterpretationStatus.INDETERMINATE
    assert "unsupported-named-argument-type" in result.named_args[0].reason


def test_recursive_enum_underlying_type_is_indeterminate():
    # value__ is declared as the enum itself, which would recurse forever.
    field_table = _Table("Field", [
        _field("value__", _field_sig(b"\x11\x08")),  # valuetype TypeDef#2 (itself)
    ])
    typedef_table = _Table("TypeDef", [
        _typedef("", "<Module>", []),
        _typedef("Fixtures", "RecursiveEnum", [_Index(field_table, 1)]),
    ])
    ctor = _member_ref(".ctor", _method_sig([b"\x11\x08"]), _Index(typedef_table, 1))
    tables = _tables(
        TypeDef=typedef_table,
        TypeRef=_Table("TypeRef", []),
        Field=field_table,
        Constant=_Table("Constant", []),
        MemberRef=_Table("MemberRef", [ctor]),
        CustomAttribute=_Table("CustomAttribute", []),
        Assembly=_Table("Assembly", [_Row(Name=_strings("Fixtures"))]),
    )
    row = _custom_attribute(tables.MemberRef, 1, b"\x01\x00\x01\x00\x00\x00")

    result = customattr.decode_custom_attribute(row, tables)

    assert result.status == customattr.InterpretationStatus.PARTIAL
    arg = result.fixed_args[0]
    assert arg.value is None
    assert arg.status == customattr.InterpretationStatus.INDETERMINATE
    assert "recursive-enum-type" in arg.reason


def test_interpretation_does_not_open_files_import_modules_or_instantiate(tmp_path):
    path = fixtures.get_data_path_by_name("hello-world.exe")
    dn = dnfile.dnPE(path)
    tables = dn.net.mdtables
    row = tables.CustomAttribute[2]

    before_modules = set(sys.modules)

    def _forbidden(*args, **kwargs):
        raise AssertionError("decoder opened a file")

    with mock.patch("builtins.open", _forbidden):
        result = customattr.decode_custom_attribute(row, tables)

    assert set(sys.modules) - before_modules == set()
    # The row itself is the parsed metadata row, not an instantiated attribute class.
    assert isinstance(row, dnfile.mdtable.CustomAttributeRow)
    assert result.provenance == {
        "assembly_loaded": False,
        "attribute_instantiated": False,
        "analyzed_file_imported": False,
        "executed_analyzed_code": False,
        "source": "dnfile metadata tables and raw #Blob bytes only",
    }


def test_char_and_system_type_arguments():
    # Signature: .ctor(char, System.Type)
    ctor = _member_ref(".ctor", _method_sig([b"\x03", b"\x50"]), _Index(_Table("TypeDef", [_Row()]), 1))
    tables = _tables(
        TypeDef=_Table("TypeDef", [_Row()]),
        TypeRef=_Table("TypeRef", []),
        Field=_Table("Field", []),
        Constant=_Table("Constant", []),
        MemberRef=_Table("MemberRef", [ctor]),
        CustomAttribute=_Table("CustomAttribute", []),
        Assembly=_Table("Assembly", [_Row(Name=_strings("Fixtures"))]),
    )
    blob = b"\x01\x00" + struct.pack("<H", 0x263A) + _ser_string("System.Int32") + b"\x00\x00"
    row = _custom_attribute(tables.MemberRef, 1, blob)

    result = customattr.decode_custom_attribute(row, tables)

    assert result.status == customattr.InterpretationStatus.COMPLETE
    assert [arg.value for arg in result.fixed_args] == [0x263A, "System.Int32"]
    assert [arg.declared_type for arg in result.fixed_args] == ["System.Char", "System.Type"]


def test_missing_constructor_row_is_not_guessed():
    tables, _ = _build_enum_assembly()
    row = _custom_attribute(tables.MemberRef, 7, b"\x01\x00\x00\x00")

    result = customattr.decode_custom_attribute(row, tables)

    assert result.status == customattr.InterpretationStatus.INDETERMINATE
    assert result.fixed_args == []
    assert "out of range" in result.constructor.reason


def test_non_ctor_method_reference_is_indeterminate():
    method = _Row(Name=_strings("NotAConstructor"), Signature=_Heap(_method_sig([])), Class=_Index(_Table("TypeDef", [_Row()]), 1))
    tables = _tables(
        TypeDef=_Table("TypeDef", [_Row()]),
        TypeRef=_Table("TypeRef", []),
        Field=_Table("Field", []),
        Constant=_Table("Constant", []),
        MemberRef=_Table("MemberRef", [method]),
        CustomAttribute=_Table("CustomAttribute", []),
        Assembly=_Table("Assembly", [_Row(Name=_strings("Fixtures"))]),
    )
    row = _custom_attribute(tables.MemberRef, 1, b"\x01\x00\x00\x00")

    result = customattr.decode_custom_attribute(row, tables)

    assert result.status == customattr.InterpretationStatus.INDETERMINATE
    assert "not .ctor/.cctor" in result.constructor.reason


def test_real_fixture_arguments_are_verified_against_signatures():
    path = fixtures.get_data_path_by_name("minimal-res.exe")
    dn = dnfile.dnPE(path)

    result = customattr.decode_custom_attribute(dn.net.mdtables.CustomAttribute[0], dn.net.mdtables)

    assert result.status == customattr.InterpretationStatus.COMPLETE
    assert result.constructor.declaring_type.endswith("TargetFrameworkAttribute [mscorlib]")
    assert result.fixed_args[0].value == ".NETFramework,Version=v4.5"
    assert result.named_args[0].name == "FrameworkDisplayName"
    assert result.named_args[0].value == ""
    assert "signature #Blob" in result.constructor.basis
