"""
Member ownership for uncompressed metadata ("#-") and the pointer tables.

The fixture is hand-annotated in tests/data-pointer-tables/README.md, so these
assertions are against an independently known layout, not against whatever
dnfile currently produces.
"""
import fixtures

import dnfile
import dnfile.base
from dnfile.base import MDTableRow


POINTER_SAMPLE = fixtures.CD / "data-pointer-tables" / "pointer-tables.exe"


def _names(table_indexes):
    return [str(index.row.Name) for index in table_indexes]


def _load_pointer_sample():
    dn = dnfile.dnPE(POINTER_SAMPLE)
    assert dn.net is not None
    assert dn.net.mdtables is not None
    return dn


def test_pointer_tables_are_parsed_from_uncompressed_metadata():
    dn = _load_pointer_sample()

    # uncompressed metadata stream, as opposed to the more common "#~"
    assert b"#-" in dn.net.metadata.streams
    assert b"#~" not in dn.net.metadata.streams

    assert dn.net.mdtables.FieldPtr.num_rows == 7
    assert dn.net.mdtables.MethodPtr.num_rows == 6
    assert dn.net.mdtables.ParamPtr.num_rows == 6


def test_typedef_field_runs_follow_fieldptr():
    dn = _load_pointer_sample()
    typedefs = {row.TypeName.value: row for row in dn.net.mdtables.TypeDef}

    # pointer rows 1 -> Field row 1
    assert _names(typedefs["<Module>"].FieldList) == ["f_alpha"]
    # pointer rows 2..3 both -> Field row 2 (repeated member, still per-owner)
    assert _names(typedefs["OwnerA"].FieldList) == ["f_beta", "f_beta"]
    # start == next owner start -> empty run
    assert _names(typedefs["OwnerEmpty"].FieldList) == []
    # pointer row 4 -> Field row 3
    assert _names(typedefs["OwnerShared"].FieldList) == ["f_gamma"]
    # FieldPtr[5] == 0 and FieldPtr[6] == 99 are invalid: skipped, not clamped
    assert _names(typedefs["OwnerInvalidPtr"].FieldList) == []
    # decreasing run: empty, not the rest of the table
    assert _names(typedefs["OwnerDecreasing"].FieldList) == []
    # pointer rows 5 and 6 are invalid: skipped
    assert _names(typedefs["OwnerTail"].FieldList) == []
    # final owner: runs to the last pointer row, where FieldPtr[7] -> Field row 2
    assert _names(typedefs["OwnerFinal"].FieldList) == ["f_beta"]

    for owner in typedefs.values():
        assert owner.FieldList.index_kind == "indirect"
        assert owner.FieldList.pointer_table == "FieldPtr"


def test_typedef_method_runs_follow_methodptr():
    dn = _load_pointer_sample()
    typedefs = {row.TypeName.value: row for row in dn.net.mdtables.TypeDef}

    # MethodPtr is out of order: 3, 1, 4, 2, 1, 4
    assert _names(typedefs["<Module>"].MethodList) == ["m_three"]
    assert _names(typedefs["OwnerA"].MethodList) == ["m_one", "m_four"]
    assert _names(typedefs["OwnerEmpty"].MethodList) == []
    assert _names(typedefs["OwnerShared"].MethodList) == ["m_two"]
    assert _names(typedefs["OwnerInvalidPtr"].MethodList) == ["m_one", "m_four"]
    assert _names(typedefs["OwnerDecreasing"].MethodList) == []
    assert _names(typedefs["OwnerTail"].MethodList) == ["m_four"]
    # final owner starts past the last pointer row: empty, not "to the end"
    assert _names(typedefs["OwnerFinal"].MethodList) == []

    for owner in typedefs.values():
        assert owner.MethodList.index_kind == "indirect"
        assert owner.MethodList.pointer_table == "MethodPtr"


def test_method_parameter_runs_follow_paramptr():
    dn = _load_pointer_sample()
    methods = {row.Name.value: row for row in dn.net.mdtables.MethodDef}

    # ParamPtr: 2, 1, 3, 2, 1, 99
    assert _names(methods["m_one"].ParamList) == ["p_second"]
    assert _names(methods["m_two"].ParamList) == ["p_first", "p_third"]
    assert _names(methods["m_three"].ParamList) == []
    # final method: ParamPtr[6] == 99 is out of range and skipped
    assert _names(methods["m_four"].ParamList) == ["p_second", "p_first"]

    for method in methods.values():
        assert method.ParamList.index_kind == "indirect"
        assert method.ParamList.pointer_table == "ParamPtr"


def test_pointer_targets_are_not_rewritten_by_physical_order():
    dn = _load_pointer_sample()
    typedefs = list(dn.net.mdtables.TypeDef)

    # These two owners point at the same FieldPtr row; each must keep its own
    # resolved run rather than sharing or mutating a single global mapping.
    owner_a = [row for row in typedefs if row.TypeName.value == "OwnerA"][0]
    owner_shared = [row for row in typedefs if row.TypeName.value == "OwnerShared"][0]
    assert owner_a.FieldList[0].row_index == 2
    assert owner_shared.FieldList[0].row_index == 3
    assert owner_a.FieldList[0].row is not owner_shared.FieldList[0].row


def test_invalid_pointers_warn_and_resolve_to_nothing(caplog):
    with caplog.at_level("WARNING", logger="dnfile.base"):
        dn = _load_pointer_sample()

    messages = [record.getMessage() for record in caplog.records]

    # zero and out-of-range FieldPtr values are reported, not silently clamped
    assert any("FieldPtr[5]=0" in message for message in messages)
    assert any("FieldPtr[6]=99" in message for message in messages)
    assert any("ParamPtr[6]=99" in message for message in messages)
    # decreasing run boundaries are reported
    assert any("decreasing" in message for message in messages)

    typedefs = {row.TypeName.value: row for row in dn.net.mdtables.TypeDef}
    assert typedefs["OwnerInvalidPtr"].FieldList == []
    assert typedefs["OwnerDecreasing"].MethodList == []


def test_pointer_row_index_lookup_is_bounds_checked():
    dn = _load_pointer_sample()
    fields = dn.net.mdtables.Field

    assert fields.get_with_row_index(1) is fields[0]
    assert fields.get_with_row_index(3) is fields[2]
    # 1-based and bounded: these must not wrap around to another row
    assert fields.get_with_row_index(0) is None
    assert fields.get_with_row_index(4) is None
    assert fields.get_with_row_index(-1) is None


def test_pointer_tables_expose_index_targets():
    dn = _load_pointer_sample()

    assert dn.net.mdtables.FieldPtr[0].Field.row_index == 1
    assert dn.net.mdtables.FieldPtr[0].Field.table.name == "Field"
    assert dn.net.mdtables.MethodPtr[0].Method.row_index == 3
    assert dn.net.mdtables.MethodPtr[0].Method.table.name == "MethodDef"
    assert dn.net.mdtables.ParamPtr[0].Param.row_index == 2
    assert dn.net.mdtables.ParamPtr[0].Param.table.name == "Param"

    # out-of-range pointer values keep their raw struct value, but there is no
    # MDTableIndex for the target row (it must not wrap around)
    assert dn.net.mdtables.FieldPtr[5].struct.Field_Index == 99
    assert dn.net.mdtables.FieldPtr[5].Field is None
    assert dn.net.mdtables.FieldPtr[4].struct.Field_Index == 0
    assert dn.net.mdtables.FieldPtr[4].Field is None


def test_compressed_metadata_keeps_direct_indexing():
    path = fixtures.get_data_path_by_name("ModuleCode_x86.exe")
    dn = dnfile.dnPE(path)
    assert dn.net is not None

    # ordinary "#~" metadata has no pointer tables
    assert b"#~" in dn.net.metadata.streams
    assert dn.net.mdtables.FieldPtr is None
    assert dn.net.mdtables.MethodPtr is None
    assert dn.net.mdtables.ParamPtr is None

    # field and method ownership is unchanged from the direct-index behavior
    typedefs = dn.net.mdtables.TypeDef
    assert typedefs[0].TypeName == "<Module>"
    assert typedefs[5].TypeName == "ModuleLoadException"
    assert len(typedefs[0].FieldList) == 52
    assert len(typedefs[5].FieldList) == 1
    assert len(typedefs[0].MethodList) == 76
    assert len(typedefs[5].MethodList) == 3
    assert typedefs[0].MethodList[0].row.Name == "rc4_init"
    assert typedefs[5].MethodList[0].row.Name == ".ctor"

    # report direct indexing rather than an indirection that is not present
    assert typedefs[0].FieldList.index_kind == "direct"
    assert typedefs[0].FieldList.pointer_table is None
    assert typedefs[0].MethodList.index_kind == "direct"
    assert typedefs[0].MethodList.pointer_table is None


def test_compressed_metadata_param_runs_keep_direct_indexing():
    path = fixtures.get_data_path_by_name("hello-world.exe")
    dn = dnfile.dnPE(path)
    assert dn.net is not None

    methods = dn.net.mdtables.MethodDef
    assert len(methods[0].ParamList) == 1
    assert len(methods[1].ParamList) == 0
    assert methods[0].ParamList[0].row.Name == "args"

    assert methods[0].ParamList.index_kind == "direct"
    assert methods[0].ParamList.pointer_table is None


def _run_bounds(row, struct_name, next_row, max_row):
    return MDTableRow._list_run_bounds(row, struct_name, next_row, max_row)


class _StubRow(MDTableRow):
    struct: object

    def _compute_format(self):
        raise NotImplementedError

    def __init__(self, struct_name, value):
        self.struct = type("StubStruct", (), {struct_name: value})()


def _stub(struct_name, value):
    return _StubRow(struct_name, value)


def test_run_bounds_for_adjacent_owners_and_final_owner():
    row = _stub("List_Index", 2)
    next_row = _stub("List_Index", 5)

    # next owner starts at 5, so this run is 2..4
    assert _run_bounds(row, "List_Index", next_row, 10) == (2, 4)
    # final owner runs to the end of the indexed table
    assert _run_bounds(row, "List_Index", None, 10) == (2, 10)
    # final owner starting at the last row still yields one row
    assert _run_bounds(_stub("List_Index", 10), "List_Index", None, 10) == (10, 10)
    # final owner starting one past the end is empty
    assert _run_bounds(_stub("List_Index", 11), "List_Index", None, 10) == (11, 10)


def test_run_bounds_reject_empty_decreasing_and_out_of_range():
    row = _stub("List_Index", 3)

    # start == next start -> empty
    assert _run_bounds(row, "List_Index", _stub("List_Index", 3), 10) == (3, 2)
    # decreasing boundary -> empty, not the rest of the table
    assert _run_bounds(row, "List_Index", _stub("List_Index", 2), 10) == (3, 2)
    # zero/absent 1-based start
    assert _run_bounds(_stub("List_Index", 0), "List_Index", None, 10) == (0, -1)
    # next owner past the end -> clamp to the table end, never past it
    assert _run_bounds(row, "List_Index", _stub("List_Index", 12), 10) == (3, 10)


class _StubTable:
    def __init__(self, name, rows, row_class):
        self.name = name
        self._rows = rows
        self.num_rows = len(rows)
        self._row_class = row_class

    def get_with_row_index(self, row_index):
        if row_index < 1 or row_index > len(self._rows):
            return None
        return self._rows[row_index - 1]


def test_eventptr_and_propertyptr_indirection():
    from dnfile.mdtable import (
        EventMapRow, EventPtrRow, PropertyMapRow, PropertyPtrRow,
    )

    events = _StubTable("Event", [object(), object(), object()], EventPtrRow)
    event_ptr = _StubTable(
        "EventPtr",
        [_StubRow("Event_Index", 3), _StubRow("Event_Index", 1)],
        EventPtrRow,
    )
    properties = _StubTable("Property", [object(), object()], PropertyPtrRow)
    property_ptr = _StubTable(
        "PropertyPtr",
        [_StubRow("Property_Index", 2), _StubRow("Property_Index", 1)],
        PropertyPtrRow,
    )
    tables = [events, event_ptr, properties, property_ptr]

    event_map = EventMapRow.__new__(EventMapRow)
    event_map.struct = type("S", (), {"Parent_Index": 0, "EventList_Index": 1})()
    EventMapRow._parse_struct_lists(event_map, tables, None)
    assert [i.row_index for i in event_map.EventList] == [3, 1]
    assert event_map.EventList.index_kind == "indirect"
    assert event_map.EventList.pointer_table == "EventPtr"

    property_map = PropertyMapRow.__new__(PropertyMapRow)
    property_map.struct = type("S", (), {"Parent_Index": 0, "PropertyList_Index": 1})()
    PropertyMapRow._parse_struct_lists(property_map, tables, None)
    assert [i.row_index for i in property_map.PropertyList] == [2, 1]
    assert property_map.PropertyList.index_kind == "indirect"
    assert property_map.PropertyList.pointer_table == "PropertyPtr"


def test_lazy_loading_uses_same_pointer_indirection():
    dn = dnfile.dnPE(POINTER_SAMPLE, clr_lazy_load=True)
    assert dn.net is not None

    typedefs = {row.TypeName.value: row for row in dn.net.mdtables.TypeDef}
    assert _names(typedefs["OwnerA"].FieldList) == ["f_beta", "f_beta"]
    assert _names(typedefs["OwnerA"].MethodList) == ["m_one", "m_four"]
    assert typedefs["OwnerA"].FieldList.index_kind == "indirect"

    methods = {row.Name.value: row for row in dn.net.mdtables.MethodDef}
    assert _names(methods["m_four"].ParamList) == ["p_second", "p_first"]
    assert methods["m_four"].ParamList.index_kind == "indirect"


def test_list_columns_are_wide_enough_for_pointer_tables():
    from dnfile.mdtable import MethodDefRow, TypeDefRow

    # Ordinary "#~" metadata: the list columns only need to index the target
    # tables.
    counts = [0] * 64
    assert TypeDefRow(counts, 2, 2, 2, None, None, None)._compute_format()[1][4] == "H,FieldList_Index"
    assert TypeDefRow(counts, 2, 2, 2, None, None, None)._compute_format()[1][5] == "H,MethodList_Index"
    assert MethodDefRow(counts, 2, 2, 2, None, None, None)._compute_format()[1][5] == "H,ParamList_Index"

    # Uncompressed metadata with large pointer tables: the same columns index
    # the pointer tables, so they must be 4-byte values.
    counts[3] = 70000   # FieldPtr
    counts[5] = 70000   # MethodPtr
    counts[7] = 70000   # ParamPtr
    assert TypeDefRow(counts, 2, 2, 2, None, None, None)._compute_format()[1][4] == "I,FieldList_Index"
    assert TypeDefRow(counts, 2, 2, 2, None, None, None)._compute_format()[1][5] == "I,MethodList_Index"
    assert MethodDefRow(counts, 2, 2, 2, None, None, None)._compute_format()[1][5] == "I,ParamList_Index"


def test_index_zero_never_resolves_to_the_last_row():
    from dnfile.base import MDTableIndex

    table = _StubTable("Field", [object(), object(), object()], None)

    assert MDTableIndex(table, 1).row is table._rows[0]
    assert MDTableIndex(table, 3).row is table._rows[2]
    # index 0 is not a valid 1-based row index and must not wrap to row 3
    assert MDTableIndex(table, 0).row is None
    assert MDTableIndex(table, 4).row is None
