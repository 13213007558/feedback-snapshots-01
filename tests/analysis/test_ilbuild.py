"""Tests proving the test assembler only emits bytes and round-trips via dncil."""

import pytest

from dncil.cil.body.reader import read_method_body_from_bytes
from dncil.cil.enums import OperandType

from tests.analysis.ilbuild import assemble_body, mnemonics


def test_assembled_body_is_parsed_by_dncil_without_assembly():
    body = assemble_body([("ldc.i4", 42), ("stloc.0", None), ("ldloc.0", None), ("ret", None)])
    assert [insn.mnemonic for insn in body.instructions] == ["ldc.i4", "stloc.0", "ldloc.0", "ret"]
    # Offsets begin after the 12-byte fat header and remain consistent.
    offsets = [insn.offset for insn in body.instructions]
    assert offsets[0] == 12
    assert offsets == sorted(offsets)


def test_short_branch_label_resolves_to_relative_offset():
    body = assemble_body([
        ("brtrue.s", "TARGET"),
        ("ldc.i4.0", None),
        ("label", "TARGET"),
        ("ret", None),
    ])
    branch = body.instructions[0]
    assert branch.opcode.operand_type is OperandType.ShortInlineBrTarget
    assert int(branch.operand) == body.instructions[2].offset


def test_long_branch_and_switch_labels():
    body = assemble_body([
        ("ldc.i4.0", None),
        ("switch", ["A", "B"]),
        ("br", "B"),
        ("label", "A"),
        ("nop", None),
        ("label", "B"),
        ("ret", None),
    ])
    switch = body.instructions[1]
    nop = body.instructions[3]
    ret = body.instructions[4]
    assert int(switch.operand[0]) == nop.offset
    assert int(switch.operand[1]) == ret.offset
    assert int(body.instructions[2].operand) == ret.offset


def test_token_operands_are_plain_integers():
    token = 0x70000001
    body = assemble_body([("ldstr", token), ("ret", None)])
    assert int(body.instructions[0].operand) == token


def test_raw_bytes_reparse_to_identical_body():
    body = assemble_body([("ldc.i4", 7), ("conv.u2", None), ("ret", None)])
    reparsed = read_method_body_from_bytes(body.get_bytes())
    assert mnemonics(reparsed) == mnemonics(body)
