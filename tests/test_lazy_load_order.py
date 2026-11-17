"""
Access-order differential tests for the lazy-loading metadata path.

A security analyst must reach the same conclusions about a sample no matter
whether resources or types are read first, and no matter whether the CLR
metadata is parsed eagerly (``clr_lazy_load=False``) or lazily
(``clr_lazy_load=True``).

These tests compare, for the same sample:
  * row identity      - lazy loading must not re-load a row into a second object
  * available fields  - the public attribute view of every row must match
  * warning sources   - warnings may be *delayed* until first access, but
                        already-discovered corruption must not be masked

Success is always judged through the public metadata access path
(``dn.net.mdtables.<Table>[i].<attr>``), never by inspecting the internal
load-state enum.
"""
import logging

import pytest

import fixtures

import dnfile
from dnfile import errors, resource
from dnfile.base import HeapItem, MDTableIndex, _row_class_struct_attrs

CLEAN_FIXTURES = ("hello-world.exe", "minimal-res.exe", "ModuleCode_x86.exe")

# field offsets within a TypeDef row (all-word indexes, as in hello-world.exe):
# I Flags, H TypeName, H TypeNamespace, H Extends, H FieldList, H MethodList
TYPEDEF_TYPE_NAME_OFFSET = 4
TYPEDEF_METHOD_LIST_OFFSET = 12
# field offsets within a MethodDef row:
# I Rva, H ImplFlags, H Flags, H Name, H Signature, H ParamList
METHODDEF_SIGNATURE_OFFSET = 10


def _normalize(value):
    if isinstance(value, HeapItem):
        return ("heap", value.value_bytes(), value.value)
    if isinstance(value, MDTableIndex):
        return ("index", value.table.name if value.table is not None else None, value.row_index)
    if isinstance(value, list):
        return tuple(_normalize(item) for item in value)
    return repr(value)


def _public_row_view(row):
    """A view of a row built only from public attribute access."""
    attrs, attrs_tables = _row_class_struct_attrs(row.__class__)
    view = {}
    for name in sorted(set(attrs) | set(attrs_tables)):
        try:
            value = getattr(row, name, None)
            had_error = False
        except Exception as e:
            # e.g. AttributeError for rows whose data could not be parsed
            value = type(e).__name__
            had_error = True
        view[name] = ("error", value) if had_error else _normalize(value)
    return view


def _snapshot(dn):
    """Snapshot of every metadata table row, taken via public access."""
    snap = {}
    for table in dn.net.mdtables.tables_list:
        for i in range(len(table.rows)):
            row = table.rows[i]
            snap[(table.name, i)] = None if row is None else _public_row_view(row)
    return snap


def _resources_view(dn):
    view = []
    for rsrc in dn.net.resources:
        data = rsrc.data
        if isinstance(data, resource.ResourceSet):
            data = ("ResourceSet", [(e.struct.Name, e.struct.DataOffset) for e in data.entries])
        name = rsrc.name.value if isinstance(rsrc.name, HeapItem) else rsrc.name
        view.append((name, data))
    return view


def _log_messages(caplog):
    return sorted(
        record.getMessage() for record in caplog.records
        if record.levelno >= logging.WARNING
    )


def _typedef_layout():
    baseline = dnfile.dnPE(fixtures.get_data_path_by_name("hello-world.exe"))
    table = baseline.net.mdtables.TypeDef
    return table.file_offset, table.row_size, table.num_rows


@pytest.mark.parametrize("fixture_name", CLEAN_FIXTURES)
@pytest.mark.parametrize("order", ("types-first", "resources-first"))
def test_access_order_does_not_change_analysis(caplog, fixture_name, order):
    """Reading resources before types (or vice versa) must yield the eager result."""
    path = fixtures.get_data_path_by_name(fixture_name)

    with caplog.at_level(logging.WARNING):
        eager = dnfile.dnPE(path, clr_lazy_load=False)
        eager_snap = _snapshot(eager)
        eager_warnings = list(eager.get_warnings())
        eager_logs = _log_messages(caplog)
        eager_resources = _resources_view(eager)

    caplog.clear()

    with caplog.at_level(logging.WARNING):
        lazy = dnfile.dnPE(path, clr_lazy_load=True)
        if order == "types-first":
            # a coded-index attribute forces a full metadata load
            lazy.net.mdtables.TypeDef[1].Extends
        else:
            # resource parsing walks the ManifestResource table
            lazy.net.resources
        lazy_snap = _snapshot(lazy)
        lazy_warnings = list(lazy.get_warnings())
        lazy_logs = _log_messages(caplog)
        lazy_resources = _resources_view(lazy)

    assert lazy_snap == eager_snap
    assert lazy_warnings == eager_warnings
    assert lazy_logs == eager_logs
    assert lazy_resources == eager_resources


def test_lazy_rows_keep_identity_across_full_load():
    """Lazy loading must not re-load a row into a second object."""
    path = fixtures.get_data_path_by_name("hello-world.exe")
    dn = dnfile.dnPE(path, clr_lazy_load=True)

    typedef = dn.net.mdtables.TypeDef[1]
    # coded-index access triggers the full load of all tables
    extends = typedef.Extends
    assert extends is not None
    # the row object must survive the full load, not be replaced
    assert dn.net.mdtables.TypeDef[1] is typedef
    assert dn.net.mdtables.TypeDef[1] is dn.net.mdtables.TypeDef[1]

    # coded-index targets are the same objects as direct table access
    assert extends.row is dn.net.mdtables.TypeRef.get_with_row_index(5)
    member_ref = dn.net.mdtables.MemberRef[0]
    assert member_ref.Class.row is dn.net.mdtables.TypeRef.get_with_row_index(1)

    # an intra-table coded index (nested type scope) resolves to a row of
    # the same table: DebuggingModes is nested in DebuggableAttribute
    typeref = dn.net.mdtables.TypeRef[3]
    assert typeref.ResolutionScope.row is dn.net.mdtables.TypeRef[2]

    # rows referenced through a member list are identical to direct access
    method = typedef.MethodList[0].row
    assert method is dn.net.mdtables.MethodDef.get_with_row_index(1)


def test_coded_index_chain_resolves_identically_in_both_orders():
    """Following mutually-referencing coded indexes gives the same endpoints."""
    path = fixtures.get_data_path_by_name("hello-world.exe")

    def chain(dn):
        extends = dn.net.mdtables.TypeDef[1].Extends.row
        scope = dn.net.mdtables.TypeRef.get_with_row_index(5).ResolutionScope.row
        return (
            extends.TypeName.value,
            scope.Name.value,
            dn.net.mdtables.CustomAttribute[0].Type.row.Name.value,
        )

    eager = dnfile.dnPE(path, clr_lazy_load=False)
    types_first = dnfile.dnPE(path, clr_lazy_load=True)
    types_first.net.mdtables.TypeDef[1].Extends
    resources_first = dnfile.dnPE(path, clr_lazy_load=True)
    resources_first.net.resources

    assert chain(types_first) == chain(eager) == ("Object", "mscorlib", ".ctor")
    assert chain(resources_first) == chain(eager)


@pytest.mark.parametrize("fixture_name", CLEAN_FIXTURES)
def test_member_list_end_matches_eager(fixture_name):
    """The last row's member list (no next row to bound it) must match eager."""
    path = fixtures.get_data_path_by_name(fixture_name)

    eager = dnfile.dnPE(path, clr_lazy_load=False)
    lazy = dnfile.dnPE(path, clr_lazy_load=True)

    eager_typedef = eager.net.mdtables.TypeDef
    lazy_typedef = lazy.net.mdtables.TypeDef
    last = eager_typedef.num_rows - 1

    assert _normalize(lazy_typedef[last].MethodList) == _normalize(eager_typedef[last].MethodList)
    assert _normalize(lazy_typedef[last].FieldList) == _normalize(eager_typedef[last].FieldList)
    # the final member of the list is the final row of the target table
    if eager_typedef[last].MethodList:
        assert eager_typedef[last].MethodList[-1].row_index == eager.net.mdtables.MethodDef.num_rows


def test_corrupted_member_list_end_matches_eager(tmp_path, caplog):
    """A corrupt MethodList index on the last TypeDef row is reported identically."""
    patched = fixtures.copy_fixture_to_tmp(tmp_path, "hello-world.exe")
    file_offset, row_size, num_rows = _typedef_layout()
    fixtures.patch_bytes(
        patched,
        file_offset + (num_rows - 1) * row_size + TYPEDEF_METHOD_LIST_OFFSET,
        b"\xff\xff",
    )

    with caplog.at_level(logging.WARNING):
        eager = dnfile.dnPE(patched, clr_lazy_load=False)
        eager_snap = _snapshot(eager)
        eager_logs = _log_messages(caplog)
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        lazy = dnfile.dnPE(patched, clr_lazy_load=True)
        lazy.net.resources
        lazy_snap = _snapshot(lazy)
        lazy_logs = _log_messages(caplog)

    assert lazy.net.mdtables.TypeDef[num_rows - 1].MethodList == []
    assert lazy_snap == eager_snap
    assert lazy_logs == eager_logs


def test_corrupted_string_heap_item_matches_eager(tmp_path, caplog):
    """An out-of-range #Strings index must surface as None plus a warning in both modes."""
    patched = fixtures.copy_fixture_to_tmp(tmp_path, "hello-world.exe")
    file_offset, row_size, _ = _typedef_layout()
    # second TypeDef row, TypeName string index
    fixtures.patch_bytes(patched, file_offset + row_size + TYPEDEF_TYPE_NAME_OFFSET, b"\xfe\xff")

    with caplog.at_level(logging.WARNING):
        eager = dnfile.dnPE(patched, clr_lazy_load=False)
        eager_snap = _snapshot(eager)
        eager_logs = _log_messages(caplog)
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        lazy = dnfile.dnPE(patched, clr_lazy_load=True)
        lazy.net.mdtables.TypeDef[1].Extends
        lazy_snap = _snapshot(lazy)
        lazy_logs = _log_messages(caplog)

    assert eager.net.mdtables.TypeDef[1].TypeName is None
    assert lazy.net.mdtables.TypeDef[1].TypeName is None
    assert "failed to fetch string: unable to parse data" in eager_logs
    assert lazy_snap == eager_snap
    assert lazy_logs == eager_logs
    assert lazy.get_warnings() == eager.get_warnings()


def test_corrupted_blob_heap_item_matches_eager(tmp_path, caplog):
    """An out-of-range #Blob index must surface as None plus a warning in both modes."""
    patched = fixtures.copy_fixture_to_tmp(tmp_path, "hello-world.exe")
    baseline = dnfile.dnPE(fixtures.get_data_path_by_name("hello-world.exe"))
    method_def = baseline.net.mdtables.MethodDef
    fixtures.patch_bytes(patched, method_def.file_offset + METHODDEF_SIGNATURE_OFFSET, b"\xfe\xff")

    with caplog.at_level(logging.WARNING):
        eager = dnfile.dnPE(patched, clr_lazy_load=False)
        eager_snap = _snapshot(eager)
        eager_logs = _log_messages(caplog)
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        lazy = dnfile.dnPE(patched, clr_lazy_load=True)
        lazy.net.mdtables.TypeDef[1].Extends
        lazy_snap = _snapshot(lazy)
        lazy_logs = _log_messages(caplog)

    assert eager.net.mdtables.MethodDef[0].Signature is None
    assert lazy.net.mdtables.MethodDef[0].Signature is None
    assert lazy_snap == eager_snap
    assert lazy_logs == eager_logs
    assert lazy.get_warnings() == eager.get_warnings()


def test_corrupted_coded_index_matches_eager(tmp_path, caplog):
    """An invalid coded-index tag must surface as None plus a warning in both modes."""
    patched = fixtures.copy_fixture_to_tmp(tmp_path, "hello-world.exe")
    baseline = dnfile.dnPE(fixtures.get_data_path_by_name("hello-world.exe"))
    member_ref = baseline.net.mdtables.MemberRef
    # MemberRef row 0, Class coded index (first field of the row)
    fixtures.patch_bytes(patched, member_ref.file_offset, b"\xff\xff")

    with caplog.at_level(logging.WARNING):
        eager = dnfile.dnPE(patched, clr_lazy_load=False)
        eager_snap = _snapshot(eager)
        eager_logs = _log_messages(caplog)
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        lazy = dnfile.dnPE(patched, clr_lazy_load=True)
        lazy.net.mdtables.TypeDef[1].Extends
        lazy_snap = _snapshot(lazy)
        lazy_logs = _log_messages(caplog)

    assert eager.net.mdtables.MemberRef[0].Class is None
    assert lazy.net.mdtables.MemberRef[0].Class is None
    assert "failed to fetch coded index: unable to parse data" in eager_logs
    assert lazy_snap == eager_snap
    assert lazy_logs == eager_logs


@pytest.mark.parametrize("order", ("types-first", "resources-first"))
def test_truncated_table_load_state_error_is_controlled(tmp_path, caplog, order):
    """Rows lost to truncation must fail with a controlled AttributeError.

    The lazy path used to die with RecursionError here, and rows in tables
    past the truncation point were None instead of dataless row objects.
    """
    patched = fixtures.copy_fixture_to_tmp(tmp_path, "hello-world.exe")
    file_offset, row_size, _ = _typedef_layout()
    # cut the file in the middle of the second TypeDef row
    fixtures.truncate_file(patched, file_offset + row_size + row_size // 2)

    with caplog.at_level(logging.WARNING):
        eager = dnfile.dnPE(patched, clr_lazy_load=False)
        eager_snap = _snapshot(eager)
        eager_warnings = list(eager.get_warnings())
        eager_logs = _log_messages(caplog)
    caplog.clear()

    with caplog.at_level(logging.WARNING):
        lazy = dnfile.dnPE(patched, clr_lazy_load=True)
        if order == "resources-first":
            lazy.net.resources
        row = lazy.net.mdtables.TypeDef[1]
        # controlled load-state error: AttributeError, never RecursionError
        with pytest.raises(AttributeError):
            row.Extends
        # re-access after the error raises the same controlled error
        with pytest.raises(AttributeError):
            row.Extends
        with pytest.raises(AttributeError):
            row.Flags
        # rows in tables past the truncation exist but have no usable fields
        stranded = lazy.net.mdtables.MemberRef[1]
        assert stranded is not None
        with pytest.raises(AttributeError):
            stranded.Name
        # re-access must not re-load the row into another object
        assert lazy.net.mdtables.TypeDef[1] is row
        assert lazy.net.mdtables.MemberRef[1] is stranded
        lazy_snap = _snapshot(lazy)
        lazy_warnings = list(lazy.get_warnings())
        lazy_logs = _log_messages(caplog)

    assert lazy_snap == eager_snap
    assert lazy_warnings == eager_warnings
    # warnings may be delayed or repeated by lazy loading, but the corruption
    # reported by the eager parse must not be masked
    assert set(eager_logs) <= set(lazy_logs)


def test_reaccess_after_attribute_error_on_clean_sample():
    """A failed attribute read must not corrupt the row's lazy-load state."""
    path = fixtures.get_data_path_by_name("hello-world.exe")
    dn = dnfile.dnPE(path, clr_lazy_load=True)

    row = dn.net.mdtables.TypeDef[1]
    with pytest.raises(AttributeError):
        row.NoSuchAttribute
    # the second access fails the same way, not with a different error
    with pytest.raises(AttributeError):
        row.NoSuchAttribute
    # valid attributes still load afterwards
    assert row.TypeName == "HelloWorld"
    # and the failure mode is unchanged once the row is fully loaded
    row.Extends
    with pytest.raises(AttributeError):
        row.NoSuchAttribute
    assert dn.net.mdtables.TypeDef[1] is row


def test_load_state_fault_is_controlled_and_recoverable():
    """Controlled load-state error criterion.

    Injecting a failing full-loader must surface the injected error as-is
    (no masking, no recursion), leave the row usable after recovery, and the
    success control is judged through the public metadata access path rather
    than the internal load-state enum.
    """
    path = fixtures.get_data_path_by_name("hello-world.exe")
    eager = dnfile.dnPE(path, clr_lazy_load=False)

    dn = dnfile.dnPE(path, clr_lazy_load=True)
    row = dn.net.mdtables.TypeDef[1]

    real_loader = row._full_loader

    def broken_loader():
        raise errors.dnFormatError("injected load-state fault")

    row._full_loader = broken_loader
    with pytest.raises(errors.dnFormatError):
        row.Extends
    # the failed attempt did not mark the row as loaded: recovery works
    row._full_loader = real_loader
    assert row.Extends is not None

    # success control via the public metadata access path
    assert row.Extends.row.TypeName == "Object"
    assert row.Extends.row.ResolutionScope.row.Name == "mscorlib"
    assert _snapshot(dn) == _snapshot(eager)
