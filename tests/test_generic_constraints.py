import pytest
from pe_builder import build_clr_pe
from generic_blob import owner_code, type_token, default_rows, replace_item, build_metadata

import dnfile
from dnfile.generic import analyze_generic_constraints


def load(rows=None):
    dn = dnfile.dnPE(data=build_clr_pe(build_metadata(rows)))
    assert dn.net is not None
    assert dn.net.mdtables is not None
    return dn, analyze_generic_constraints(dn.net.mdtables)


def codes(analysis):
    return [finding.code for finding in analysis.findings]


def finding(analysis, code):
    matches = [item for item in analysis.findings if item.code == code]
    assert matches, "expected finding {!r}, got {!r}".format(code, codes(analysis))
    return matches[0]


def test_valid_f_bound_is_not_rejected_as_a_cycle():
    _, analysis = load()

    assert analysis.errors == []
    assert analysis.structurally_consistent
    assert analysis.clr_loadable is None

    method_t = analysis.parameters[("MethodDef", 1, 0)]
    type_t = analysis.parameters[("TypeDef", 2, 0)]
    type_u = analysis.parameters[("TypeDef", 2, 1)]

    # The same number 0 in two different scopes remains two objects.
    assert method_t is not type_t
    assert method_t.number == type_t.number == 0
    assert len(analysis.parameters) == 4
    assert analysis.parameters[("TypeDef", 2, 1)] is type_u

    f_bounds = analysis.legal_f_bounds
    assert len(f_bounds) == 2
    assert {edge.source.key for edge in f_bounds} == {
        ("MethodDef", 1, 0),
        ("TypeDef", 2, 0),
    }
    for edge in f_bounds:
        assert edge.is_self_reference
        assert edge.is_legal_f_bound
        assert "GenericParamConstraint[" in edge.path[0].role + str(edge.path[0])
        assert any(ref.table == "TypeSpec" for ref in edge.path)

    # The graph genuinely has self-loops; they are legal, not errors.
    assert analysis.graph[("TypeDef", 2, 0)] == [("TypeDef", 2, 0)]
    assert analysis.graph[("MethodDef", 1, 0)] == [("MethodDef", 1, 0)]


def test_duplicate_parameter_number_in_one_owner_is_rejected():
    rows = default_rows()
    rows = replace_item(
        rows, "GenericParams", 2,
        (0, owner_code("TypeDef", 2), "UDuplicate"),
    )
    _, analysis = load(rows)

    item = finding(analysis, "duplicate-generic-parameter")
    assert item.severity == "error"
    assert item.details["key"] == ["TypeDef", 2, 0]
    assert {ref.table for ref in item.path} == {"GenericParam", "TypeDef"}
    assert len(analysis.parameters) == 3


def test_same_number_under_a_different_owner_is_not_a_duplicate():
    rows = default_rows()
    # Add a second method owned by Foo; method 1 keeps number 0, method 2 also uses 0.
    rows = dict(rows)
    rows["TypeDefs"] = (("<Module>", ()), ("Foo", ("Bar", "Baz")), ("IFoo", ()))
    rows["Methods"] = (("Bar", 1), ("Baz", 1))
    rows["GenericParams"] = (
        (0, owner_code("MethodDef", 1), "TMethod1"),
        (0, owner_code("MethodDef", 2), "TMethod2"),
        (0, owner_code("TypeDef", 2), "TType"),
        (1, owner_code("TypeDef", 2), "UType"),
    )
    _, analysis = load(rows)

    assert "duplicate-generic-parameter" not in codes(analysis)
    assert ("MethodDef", 1, 0) in analysis.parameters
    assert ("MethodDef", 2, 0) in analysis.parameters
    assert analysis.parameters[("MethodDef", 1, 0)] is not analysis.parameters[("MethodDef", 2, 0)]


def test_bare_self_constraint_is_not_the_legal_f_bound():
    rows = default_rows()
    rows = replace_item(rows, "TypeSpecs", 0, bytes((0x13, 0x00)))  # VAR 0, no GENERICINST
    _, analysis = load(rows)

    item = finding(analysis, "bare-self-parameter-constraint")
    assert item.severity == "error"
    assert item.path[-1].offset == 0
    # The method parameter's independent legal self-bound is untouched.
    assert [edge.source.key for edge in analysis.legal_f_bounds] == [("MethodDef", 1, 0)]


def test_type_parameter_constraint_cannot_use_mvar():
    rows = default_rows()
    rows = replace_item(
        rows, "Constraints", 1,
        (2, type_token("TypeSpec", 2)),  # TypeSpec 2 is MVAR 0
    )
    _, analysis = load(rows)

    item = finding(analysis, "method-parameter-in-type-constraint")
    assert item.severity == "error"
    assert item.path[0].table == "GenericParamConstraint"
    assert item.path[0].row_index == 2
    signature_ref = item.path[-1]
    assert signature_ref.table == "TypeSpec"
    assert signature_ref.offset == 4
    assert signature_ref.detail == "MVAR[0]"


def test_method_parameter_constraint_var_targets_enclosing_type():
    rows = default_rows()
    # TypeSpec 3 is VAR 1 (!1), i.e. Foo's second type parameter.
    rows = dict(rows)
    rows["TypeSpecs"] = tuple(rows["TypeSpecs"]) + (bytes((0x13, 0x01)),)
    rows["Constraints"] = (
        (1, type_token("TypeSpec", 3)),
        (2, type_token("TypeSpec", 1)),
    )
    _, analysis = load(rows)

    assert analysis.errors == []
    edge = analysis.edges[0]
    assert edge.source.key == ("MethodDef", 1, 0)
    assert edge.target.key == ("TypeDef", 2, 1)
    assert not edge.is_self_reference


def test_method_constraint_without_enclosing_type_is_undetermined():
    rows = default_rows()
    rows["TypeDefs"] = (("<Module>", ()), ("Foo", ("Bar",)), ("IFoo", ()))
    rows["Methods"] = (("Bar", 1), ("Orphan", 1))
    rows["GenericParams"] = (
        (0, owner_code("MethodDef", 2), "TMethod"),
        (0, owner_code("TypeDef", 2), "TType"),
        (1, owner_code("TypeDef", 2), "UType"),
        (0, owner_code("TypeDef", 3), "TInterface"),
    )
    rows["Constraints"] = (
        (1, type_token("TypeSpec", 3)),
        (2, type_token("TypeSpec", 1)),
    )
    rows["TypeSpecs"] = tuple(rows["TypeSpecs"]) + (bytes((0x13, 0x01)),)
    _, analysis = load(rows)

    item = finding(analysis, "constraint-parameter-target-missing")
    assert item.severity == "error"
    assert item.path[0].table == "GenericParamConstraint"
    assert item.details == {}
    assert analysis.clr_loadable is None


def test_missing_constraint_owner_row_is_rejected():
    rows = default_rows()
    rows = replace_item(rows, "Constraints", 0, (99, type_token("TypeSpec", 2)))
    _, analysis = load(rows)

    item = finding(analysis, "constraint-owner-missing")
    assert item.severity == "error"
    assert item.path[0].table == "GenericParamConstraint"


def test_missing_constraint_typespec_is_rejected():
    rows = default_rows()
    rows = replace_item(rows, "Constraints", 0, (1, type_token("TypeSpec", 99)))
    _, analysis = load(rows)

    item = finding(analysis, "constraint-target-row-missing")
    assert item.severity == "error"
    assert any(ref.table == "TypeSpec" and ref.row_index == 99 for ref in item.path)


def test_generic_instance_arity_mismatch_is_rejected():
    rows = default_rows()
    # Foo<!0, !0> while Foo declares two parameters: this is still arity 2.
    # Foo<!0, !1, !0> is a one-hit arity mutation if the type only declares two.
    rows = replace_item(
        rows, "TypeSpecs", 0,
        bytes((0x15, 0x12, type_token("TypeDef", 2), 0x03, 0x13, 0x00, 0x13, 0x01, 0x13, 0x00)),
    )
    _, analysis = load(rows)

    item = finding(analysis, "generic-instance-arity-mismatch")
    assert item.severity == "error"
    assert item.details == {"supplied": 3, "declared": 2}


def test_parameter_number_gap_is_rejected():
    rows = default_rows()
    rows = replace_item(rows, "GenericParams", 2, (2, owner_code("TypeDef", 2), "UGap"))
    _, analysis = load(rows)

    item = finding(analysis, "generic-parameter-number-gap")
    assert item.severity == "error"
    assert item.details["missing"] == [1]


def test_method_arity_mismatch_is_rejected():
    rows = default_rows()
    rows["Methods"] = (("Bar", 2),)
    _, analysis = load(rows)

    item = finding(analysis, "method-generic-parameter-arity-mismatch")
    assert item.severity == "error"
    assert item.details["arity"] == 2


def test_malformed_typespec_retains_offset_and_does_not_raise():
    rows = default_rows()
    rows = replace_item(rows, "TypeSpecs", 0, bytes((0x15, 0x12, 0x08, 0x01, 0x13)))
    _, analysis = load(rows)

    item = finding(analysis, "typespec-signature-invalid")
    assert item.severity == "unknown"
    assert item.details["offset"] == 5
    assert item.details["reason"]
    assert analysis.clr_loadable is None


def test_typespec_cycle_is_undetermined_not_errors():
    rows = default_rows()
    # TypeSpec 1 is a generic instance whose argument points back at TypeSpec 1.
    rows = replace_item(
        rows, "TypeSpecs", 0,
        bytes((0x15, 0x12, type_token("TypeDef", 3), 0x01, 0x12, type_token("TypeSpec", 1))),
    )
    _, analysis = load(rows)

    item = finding(analysis, "typespec-cycle")
    assert item.severity == "unknown"
    assert analysis.errors == []


def test_external_typeref_constraint_is_not_claimed_as_checked():
    rows = dict(default_rows())
    rows["TypeRefs"] = (("System", "IExternal"),)
    rows = replace_item(
        rows, "Constraints", 1,
        (2, type_token("TypeRef", 1)),
    )
    _, analysis = load(rows)

    item = finding(analysis, "external-constraint")
    assert item.severity == "unknown"
    assert analysis.clr_loadable is None


def test_describe_contains_tokens_and_limitations():
    _, analysis = load()
    text = analysis.describe()
    assert "generic parameters: 4" in text
    assert "clr_loadable: unknown" in text
    assert "Type arity is inferred" in text
    assert "no runtime binding or verification was performed" in text


def test_analyzer_rejects_missing_metadata_without_crashing():
    analysis = analyze_generic_constraints(None)
    assert analysis.clr_loadable is None
    assert codes(analysis) == ["metadata-tables-missing"]
    assert analysis.structurally_consistent


def test_generic_instance_accepts_all_declared_type_parameters():
    rows = default_rows()
    # Foo<!0, !1> is a legal use of the two parameters declared by Foo.
    rows = replace_item(
        rows, "TypeSpecs", 0,
        bytes((
            0x15, 0x12, type_token("TypeDef", 2), 0x02,
            0x13, 0x00, 0x13, 0x01,
        )),
    )
    _, analysis = load(rows)

    assert analysis.errors == []
    method_t = analysis.parameters[("MethodDef", 1, 0)]
    assert method_t is not analysis.parameters[("TypeDef", 2, 0)]
    assert analysis.structurally_consistent
    assert analysis.graph[("TypeDef", 2, 0)] == [("TypeDef", 2, 0), ("TypeDef", 2, 1)]


def test_direct_typedef_constraint_has_no_parameter_edge():
    rows = default_rows()
    rows = replace_item(rows, "Constraints", 1, (2, type_token("TypeDef", 3)))
    _, analysis = load(rows)

    assert analysis.errors == []
    assert analysis.edges[0].source.key == ("MethodDef", 1, 0)
    assert ("TypeDef", 2, 0) not in analysis.graph


def test_mutant_that_merges_by_number_would_be_caught():
    """The key must include owner; number 0 exists under three different owners."""
    _, analysis = load()
    zero_scoped = [
        parameter
        for parameter in analysis.parameters.values()
        if parameter.number == 0
    ]
    assert len(zero_scoped) == 3
    assert len({parameter.key for parameter in zero_scoped}) == 3

    method_t = analysis.parameters[("MethodDef", 1, 0)]
    type_t = analysis.parameters[("TypeDef", 2, 0)]
    interface_t = analysis.parameters[("TypeDef", 3, 0)]
    assert len({id(parameter) for parameter in (method_t, type_t, interface_t)}) == 3

    method_edges = analysis.graph[method_t.key]
    type_edges = analysis.graph[type_t.key]
    assert method_edges == [method_t.key]
    assert type_edges == [type_t.key]
    assert interface_t.key not in method_edges
    assert interface_t.key not in type_edges
    assert analysis.parameters[interface_t.key].owner_table == "TypeDef"


def test_mutually_recursive_f_bounds_are_legal():
    rows = default_rows()
    # T : IFoo<U> and U : IFoo<T> form a two-node cycle in the parameter graph.
    rows["TypeSpecs"] = (
        bytes((0x15, 0x12, type_token("TypeDef", 3), 0x01, 0x13, 0x01)),
        bytes((0x15, 0x12, type_token("TypeDef", 3), 0x01, 0x13, 0x00)),
    )
    # Constraint row 1 belongs to U (number 1), row 2 to T (number 0).
    rows["Constraints"] = (
        (3, type_token("TypeSpec", 2)),
        (2, type_token("TypeSpec", 1)),
    )
    _, analysis = load(rows)

    assert analysis.errors == []
    assert analysis.structurally_consistent
    type_t = ("TypeDef", 2, 0)
    type_u = ("TypeDef", 2, 1)
    assert analysis.graph[type_t] == [type_u]
    assert analysis.graph[type_u] == [type_t]
    assert all(not edge.is_legal_f_bound for edge in analysis.edges)


def test_type_constraint_var_target_must_exist():
    rows = default_rows()
    # TypeSpec 3 is VAR 5, which no GenericParam of Foo declares.
    rows = dict(rows)
    rows["TypeSpecs"] = tuple(rows["TypeSpecs"]) + (bytes((0x13, 0x05)),)
    rows["Constraints"] = (
        (1, type_token("TypeSpec", 2)),
        (2, type_token("TypeSpec", 3)),
    )
    _, analysis = load(rows)

    item = finding(analysis, "constraint-parameter-target-missing")
    assert item.severity == "error"
    assert item.path[-1].detail == "VAR[5]"
    assert item.path[-1].offset == 0


def test_truncated_signature_does_not_produce_structural_edges():
    rows = default_rows()
    # A complete VAR 0 followed by a truncated byte: the blob is undetermined,
    # so no constraint edge should be claimed from its prefix.
    rows = replace_item(rows, "TypeSpecs", 0, bytes((0x13, 0x00, 0x20)))
    _, analysis = load(rows)

    item = finding(analysis, "typespec-signature-invalid")
    assert item.severity == "unknown"
    assert analysis.edges[0].source.key == ("MethodDef", 1, 0)  # the untouched row
    assert ("TypeDef", 2, 0) not in analysis.graph
    assert not any(
        finding.code == "bare-self-parameter-constraint" for finding in analysis.findings
    )


def test_method_claimed_by_two_types_is_rejected():
    class MethodRef:
        row_index = 7

    class TypeRow:
        def __init__(self):
            self.MethodList = [MethodRef()]

    class TypeTable:
        name = "TypeDef"
        num_rows = 2

        def get_with_row_index(self, index):
            return TypeRow()

    class Tables:
        TypeDef = TypeTable()
        tables_list = [TypeDef]

    analysis = analyze_generic_constraints(Tables())

    item = finding(analysis, "method-multiple-type-owners")
    assert item.severity == "error"
    assert item.path[0].table == "MethodDef"
    assert item.path[0].row_index == 7
    assert [ref.row_index for ref in item.path[1:]] == [1, 2]


def test_duplicate_constraint_row_is_a_warning_not_a_second_edge():
    rows = default_rows()
    rows["Constraints"] = tuple(rows["Constraints"]) + ((2, type_token("TypeSpec", 1)),)
    _, analysis = load(rows)

    item = finding(analysis, "duplicate-constraint")
    assert item.severity == "warning"
    assert item.path[0].row_index == 3
    assert item.path[1].row_index == 2
    assert len(analysis.edges) == 2
    assert analysis.errors == []
