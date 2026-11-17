"""End-to-end constant recovery tests on hand-assembled, assembly-free IL."""

import pytest

from dncil.analysis import (
    AnalysisBudget,
    KnownOp,
    MethodBinding,
    Metadata,
    analyze_body,
    recover_strings,
)
from tests.analysis.ilbuild import assemble_body

# Synthetic tokens. They are plain integers exchanged through Metadata; nothing
# here resolves or loads a real .NET assembly.
STR_A = 0x70000001
STR_B = 0x70000002
STR_MISSING = 0x70FFFFFF
TOK_CONCAT = 0x0A000001
TOK_CTOR = 0x06000001
TOK_TO_CHAR = 0x0A000002
TOK_UNKNOWN = 0x0A000099
ELEM_TYPE = 0x01000001


@pytest.fixture
def metadata():
    return Metadata.from_tables(
        strings={STR_A: "AB"},
        methods={
            TOK_CONCAT: MethodBinding(KnownOp.STRING_CONCAT, "System.String::Concat(string,string)"),
            TOK_CTOR: MethodBinding(KnownOp.STRING_CTOR_CHARS, "System.String::.ctor(char[])"),
            TOK_TO_CHAR: MethodBinding(KnownOp.CONVERT_TO_CHAR, "System.Convert::ToChar(int32)"),
        },
    )


def _only(records):
    assert len(records) == 1
    return records[0]


def test_straight_line_constructs_and_concatenates(metadata):
    program = [
        ("ldc.i4.2", None),
        ("newarr", ELEM_TYPE),
        ("dup", None),
        ("ldc.i4.0", None),
        ("ldc.i4", 65),
        ("conv.u2", None),
        ("stelem.i2", None),
        ("dup", None),
        ("ldc.i4.1", None),
        ("ldc.i4", 66),
        ("conv.u2", None),
        ("stelem.i2", None),
        ("newobj", TOK_CTOR),
        ("ldstr", STR_A),
        ("call", TOK_CONCAT),
        ("ret", None),
    ]
    body = assemble_body(program)
    record = _only(recover_strings(body, metadata))

    assert record.certain is True
    assert record.text == "ABAB"
    assert record.gap_count == 0
    assert record.certainty_range == "all 4 character(s) determined"
    mnemonics = {item.mnemonic for item in record.evidence}
    assert {"newarr", "newobj", "ldstr", "call"}.issubset(mnemonics)
    # Every evidence item points back to concrete instruction bytes.
    assert all(item.bytes_hex for item in record.evidence)


def test_two_branches_same_value_is_certain(metadata):
    program = [
        ("ldarg.0", None),
        ("brtrue.s", "L1"),
        ("ldstr", STR_A),
        ("stloc.0", None),
        ("br.s", "L2"),
        ("label", "L1"),
        ("ldstr", STR_A),
        ("stloc.0", None),
        ("label", "L2"),
        ("ldloc.0", None),
        ("ret", None),
    ]
    record = _only(recover_strings(assemble_body(program), metadata))
    assert record.certain is True
    assert record.text == "AB"
    assert record.reasons == []


def test_two_branches_different_values_is_pending_with_both_candidates():
    metadata = Metadata.from_tables(strings={STR_A: "AB", STR_B: "CD"})
    program = [
        ("ldarg.0", None),
        ("brtrue.s", "L1"),
        ("ldstr", STR_A),
        ("stloc.0", None),
        ("br.s", "L2"),
        ("label", "L1"),
        ("ldstr", STR_B),
        ("stloc.0", None),
        ("label", "L2"),
        ("ldloc.0", None),
        ("ret", None),
    ]
    record = _only(recover_strings(assemble_body(program), metadata))
    assert record.certain is False
    assert record.text is None
    assert set(record.alternatives) == {"AB", "CD"}
    # Candidates must not be presented as a runtime-certain concatenation.
    assert record.known_pieces == []


def test_unknown_call_invalidates_result(metadata):
    program = [("ldstr", STR_A), ("call", TOK_UNKNOWN), ("ret", None)]
    record = _only(recover_strings(assemble_body(program), metadata))
    assert record.certain is False
    assert record.text is None
    assert any("unknown method call" in reason for reason in record.reasons)


def test_missing_string_token_is_pending_not_crash(metadata):
    program = [("ldstr", STR_MISSING), ("ret", None)]
    record = _only(recover_strings(assemble_body(program), metadata))
    assert record.certain is False
    assert any("not present in supplied metadata" in reason for reason in record.reasons)


def test_unwritten_array_slot_is_gap_never_zero_padded(metadata):
    program = [
        ("ldc.i4.3", None),
        ("newarr", ELEM_TYPE),
        ("dup", None),
        ("ldc.i4.0", None),
        ("ldc.i4", 65),
        ("conv.u2", None),
        ("stelem.i2", None),
        ("dup", None),
        ("ldc.i4.2", None),
        ("ldc.i4", 67),
        ("conv.u2", None),
        ("stelem.i2", None),
        ("newobj", TOK_CTOR),
        ("ret", None),
    ]
    record = _only(recover_strings(assemble_body(program), metadata))
    assert record.certain is False
    assert record.text is None
    assert record.known_pieces == ["A", "C"]
    assert record.gap_count == 1
    assert "NUL" not in "".join(record.known_pieces)
    assert "1 undetermined position(s)" in record.certainty_range


def test_convert_to_char_in_range_is_certain(metadata):
    program = [("ldc.i4", 72), ("call", TOK_TO_CHAR), ("ret", None)]
    record = _only(recover_strings(assemble_body(program), metadata))
    assert record.certain is True
    assert record.text == "H"


def test_convert_to_char_out_of_range_is_pending(metadata):
    program = [("ldc.i4", 70000), ("call", TOK_TO_CHAR), ("ret", None)]
    record = _only(recover_strings(assemble_body(program), metadata))
    assert record.certain is False
    assert record.text is None
    assert any("outside char range" in reason for reason in record.reasons)


def test_conv_u2_wraps_unsigned_16_bit(metadata):
    # 0x10041 wraps to 0x0041 -> 'A' per ECMA conv.u2 truncation.
    program = [("ldc.i4", 0x10041), ("conv.u2", None), ("ret", None)]
    record = _only(recover_strings(assemble_body(program), metadata))
    assert record.certain is True
    assert record.text == "A"


def test_loop_reaches_fixed_point_for_idempotent_writes(metadata):
    program = [
        ("ldc.i4.2", None),
        ("newarr", ELEM_TYPE),
        ("dup", None),
        ("ldc.i4.0", None),
        ("ldc.i4", 65),
        ("conv.u2", None),
        ("stelem.i2", None),
        ("dup", None),
        ("ldc.i4.1", None),
        ("ldc.i4", 66),
        ("conv.u2", None),
        ("stelem.i2", None),
        ("stloc.0", None),
        ("label", "LOOP"),
        ("ldc.i4.0", None),
        ("brtrue.s", "EXIT"),
        ("ldloc.0", None),
        ("ldc.i4.0", None),
        ("ldc.i4", 65),
        ("conv.u2", None),
        ("stelem.i2", None),
        ("pop", None),
        ("br.s", "LOOP"),
        ("label", "EXIT"),
        ("ldloc.0", None),
        ("newobj", TOK_CTOR),
        ("ret", None),
    ]
    body = assemble_body(program)
    result = analyze_body(body, metadata)
    assert result.limits.completed is True
    assert result.pending_reasons == []
    record = _only(recover_strings(body, metadata))
    assert record.certain is True
    assert record.text == "AB"


def test_conflicting_loop_induction_variable_stays_pending(metadata):
    # The counter merges 0 and 1 at the loop header, so the result must not be
    # claimed as certain even though one concrete trace would produce "ZZ".
    program = [
        ("ldc.i4.2", None),
        ("newarr", ELEM_TYPE),
        ("stloc.0", None),
        ("ldc.i4.0", None),
        ("stloc.1", None),
        ("label", "LOOP"),
        ("ldloc.1", None),
        ("ldc.i4.1", None),
        ("bge.s", "EXIT"),
        ("ldloc.0", None),
        ("ldc.i4.1", None),
        ("ldc.i4", 90),
        ("conv.u2", None),
        ("stelem.i2", None),
        ("pop", None),
        ("ldc.i4.1", None),
        ("stloc.1", None),
        ("br.s", "LOOP"),
        ("label", "EXIT"),
        ("ldloc.0", None),
        ("newobj", TOK_CTOR),
        ("ret", None),
    ]
    record = _only(recover_strings(assemble_body(program), metadata))
    assert record.certain is False
    assert record.text is None


def test_instruction_budget_aborts_with_pending_verdict(metadata):
    program = [
        ("ldc.i4.3", None),
        ("newarr", ELEM_TYPE),
        ("dup", None),
        ("ldc.i4.0", None),
        ("ldc.i4", 65),
        ("conv.u2", None),
        ("stelem.i2", None),
        ("newobj", TOK_CTOR),
        ("ret", None),
    ]
    budget = AnalysisBudget(max_instructions=3)
    body = assemble_body(program)
    result = analyze_body(body, metadata, budget)
    assert result.limits.completed is False
    assert result.limits.reason == "method exceeds max instruction budget"
    # The run stops before ret; nothing must be fabricated to look complete.
    records = recover_strings(body, metadata, budget)
    assert all(record.certain is False and record.text is None for record in records)
    assert "budget" in (result.limits.reason or "")


def test_iteration_budget_bounds_loop_processing(metadata):
    program = [
        ("ldc.i4.1", None),
        ("newarr", ELEM_TYPE),
        ("stloc.0", None),
        ("label", "LOOP"),
        ("ldc.i4.0", None),
        ("brtrue.s", "EXIT"),
        ("br.s", "LOOP"),
        ("label", "EXIT"),
        ("ldloc.0", None),
        ("ret", None),
    ]
    budget = AnalysisBudget(max_iterations=4)
    result = analyze_body(assemble_body(program), metadata, budget)
    assert result.limits.completed is False
    assert "budget" in (result.limits.reason or "")


def test_unsupported_opcode_is_conservatively_pending(metadata):
    # box is outside the whitelisted expression class.
    program = [("ldc.i4", 1), ("box", 0x02000001), ("ret", None)]
    record = _only(recover_strings(assemble_body(program), metadata))
    assert record.certain is False
    assert any("unsupported opcode box" in reason for reason in record.reasons)


def test_string_concat_two_literals_is_certain(metadata):
    second = 0x70000003
    metadata_local = Metadata.from_tables(
        strings={STR_A: "AB", second: "CD"},
        methods={TOK_CONCAT: MethodBinding(KnownOp.STRING_CONCAT, "Concat")},
    )
    program = [("ldstr", STR_A), ("ldstr", second), ("call", TOK_CONCAT), ("ret", None)]
    record = _only(recover_strings(assemble_body(program), metadata_local))
    assert record.certain is True
    assert record.text == "ABCD"


def test_evidence_offsets_reference_real_instructions(metadata):
    program = [
        ("ldc.i4.1", None),
        ("newarr", ELEM_TYPE),
        ("dup", None),
        ("ldc.i4.0", None),
        ("ldc.i4", 65),
        ("conv.u2", None),
        ("stelem.i2", None),
        ("newobj", TOK_CTOR),
        ("ret", None),
    ]
    body = assemble_body(program)
    record = _only(recover_strings(body, metadata))
    assert record.certain is True
    valid_offsets = {insn.offset for insn in body.instructions}
    assert all(item.offset in valid_offsets for item in record.evidence)
    assert any(item.mnemonic == "conv.u2" for item in record.evidence)


def test_dynamic_index_write_invalidates_array_content(metadata):
    # A non-constant index means the affected contents cannot be trusted.
    program = [
        ("ldc.i4.2", None),
        ("newarr", ELEM_TYPE),
        ("ldarg.0", None),
        ("ldc.i4", 65),
        ("conv.u2", None),
        ("stelem.i2", None),
        ("newobj", TOK_CTOR),
        ("ret", None),
    ]
    record = _only(recover_strings(assemble_body(program), metadata))
    assert record.certain is False
    assert record.text is None


def test_oversized_array_length_hits_budget_as_pending(metadata):
    budget = AnalysisBudget(max_array_length=2)
    program = [("ldc.i4", 5), ("newarr", ELEM_TYPE), ("ret", None)]
    result = analyze_body(assemble_body(program), metadata, budget)
    assert result.limits.completed is False
    assert "array length" in (result.limits.reason or "")
