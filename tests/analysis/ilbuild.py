"""Tiny test-only IL assembler.

The analyzer must be exercised without compiling or loading a .NET assembly.
This helper turns mnemonic listings into raw method-body bytes that
:func:`dncil.cil.body.reader.read_method_body_from_bytes` understands. It only
emits bytes - it never resolves tokens against metadata and never executes code.

A program is a list of tuples ``(mnemonic, operand=None)``. Labels are strings
used in place of a branch operand and declared by a ``("label", "name")``
pseudo-instruction. Integer operands encode per the opcode's operand type;
tokens are given as plain 32-bit integers.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple

from dncil.cil.body.reader import read_method_body_from_bytes
from dncil.cil.enums import OperandType
from dncil.cil.opcode import OpCodes

_OPCODES = OpCodes()
_BY_NAME = {}
for _table in (_OPCODES.one_byte_op_codes, _OPCODES.two_byte_op_codes):
    for _opcode in _table:
        if _opcode is not None:
            _BY_NAME[_opcode.name] = _opcode

Program = List[Tuple[str, Optional[object]]]


def _resolve_opcode(mnemonic: str):
    try:
        return _BY_NAME[mnemonic]
    except KeyError as exc:
        raise ValueError("unknown mnemonic %r" % mnemonic) from exc


def _is_branch(mnemonic: str) -> bool:
    opcode = _resolve_opcode(mnemonic)
    return opcode.operand_type in (OperandType.InlineBrTarget, OperandType.ShortInlineBrTarget)


def assemble_body(program: Program, max_stack: int = 8):
    """Assemble ``program`` into a parsed dncil method body."""
    labels = _label_offsets(program)
    code = bytearray()
    for mnemonic, operand in program:
        if mnemonic == "label":
            continue
        opcode = _resolve_opcode(mnemonic)
        code += opcode.value.to_bytes(opcode.size, "little")
        code += _encode_operand(opcode, operand, labels, len(code))
    header = _fat_header(len(code), max_stack=max_stack)
    return read_method_body_from_bytes(bytes(header) + bytes(code))


def _label_offsets(program: Program) -> Dict[str, int]:
    offsets: Dict[str, int] = {}
    cursor = 0
    for mnemonic, operand in program:
        if mnemonic == "label":
            offsets[str(operand)] = cursor
            continue
        opcode = _resolve_opcode(mnemonic)
        cursor += opcode.size
        cursor += _operand_size(opcode, operand)
    return offsets


def _operand_size(opcode, operand) -> int:
    operand_type = opcode.operand_type
    if operand_type in (OperandType.InlineNone, OperandType.InlinePhi):
        return 0
    if operand_type == OperandType.ShortInlineBrTarget:
        return 1
    if operand_type == OperandType.ShortInlineI:
        return 1
    if operand_type == OperandType.ShortInlineVar:
        return 1
    if operand_type == OperandType.ShortInlineR:
        return 4
    if operand_type == OperandType.InlineVar:
        return 2
    if operand_type in (
        OperandType.InlineBrTarget,
        OperandType.InlineField,
        OperandType.InlineI,
        OperandType.InlineMethod,
        OperandType.InlineSig,
        OperandType.InlineString,
        OperandType.InlineTok,
        OperandType.InlineType,
    ):
        return 4
    if operand_type in (OperandType.InlineI8, OperandType.InlineR):
        return 8
    if operand_type == OperandType.InlineSwitch:
        targets = operand or []
        return 4 + 4 * len(targets)
    raise ValueError("unsupported operand type %r" % operand_type)


def _encode_operand(opcode, operand, labels: Dict[str, int], code_cursor: int) -> bytes:
    operand_type = opcode.operand_type
    if operand_type in (OperandType.InlineNone, OperandType.InlinePhi):
        return b""
    if operand_type == OperandType.InlineSwitch:
        targets = operand or []
        payload = struct.pack("<I", len(targets))
        next_instruction = code_cursor + 4 + 4 * len(targets)
        for target in targets:
            payload += struct.pack("<i", labels[str(target)] - next_instruction)
        return payload
    if operand_type in (OperandType.InlineBrTarget, OperandType.ShortInlineBrTarget):
        target = labels[str(operand)]
        instruction_end = code_cursor + _operand_size(opcode, operand)
        delta = target - instruction_end
        if operand_type == OperandType.ShortInlineBrTarget:
            if not -128 <= delta <= 127:
                raise ValueError("short branch target out of range")
            return struct.pack("<b", delta)
        return struct.pack("<i", delta)
    if operand_type == OperandType.ShortInlineI:
        return struct.pack("<b", int(operand))
    if operand_type == OperandType.ShortInlineVar:
        return struct.pack("<B", int(operand))
    if operand_type == OperandType.InlineVar:
        return struct.pack("<H", int(operand))
    if operand_type == OperandType.ShortInlineR:
        return struct.pack("<f", float(operand))
    if operand_type == OperandType.InlineR:
        return struct.pack("<d", float(operand))
    if operand_type == OperandType.InlineI8:
        return struct.pack("<q", int(operand))
    if operand_type == OperandType.InlineI:
        return struct.pack("<i", int(operand))
    # All remaining inline token forms carry a 32-bit integer.
    return struct.pack("<I", int(operand) & 0xFFFFFFFF)


def _fat_header(code_size: int, max_stack: int) -> bytes:
    # Fat header: flags (0x3003 = fat format + 3 dwords), max stack, code size,
    # local var sig token (0 = no local signature; indices still parse).
    return struct.pack("<HHII", 0x3003, max_stack, code_size, 0)


def mnemonics(body) -> List[str]:
    """Convenience listing used when asserting on evidence."""
    return [insn.mnemonic for insn in body.instructions]
