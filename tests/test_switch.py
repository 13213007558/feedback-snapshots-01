import binascii

import pytest

from dncil.cil.body import CilMethodBody
from dncil.cil.enums import OpCodeValue
from dncil.cil.error import MethodBodyFormatError
from dncil.cil.instruction import Instruction
from dncil.cil.body.reader import CilMethodBodyReaderBytes

# Regression tests for switch (InlineSwitch) target resolution.
#
# CIL switch table entries are relative to the END OF THE WHOLE switch
# instruction (opcode + count + all entries), not to the position of each
# table entry. These tests pin that behavior using hand-annotated byte
# layouts: every expected target below is a literal taken from the offset
# map in the comment above each body, never derived from the reader.
#
# Note: dncil reports instruction offsets as stream offsets within the
# method body (i.e. including the 1-byte tiny header), so all annotated
# offsets below are stream offsets and code starts at 0x01.

# byte layout (stream offsets):
#   0x00: 56          tiny header, code size 0x15
#   0x01: 45          switch
#   0x02: 03000000    count = 3
#   0x06: 00000000    case 0: rel +0    -> 0x12 (fall-through, ret)
#   0x0A: EFFFFFFF    case 1: rel -17   -> 0x01 (back edge to switch itself)
#   0x0E: 03000000    case 2: rel +3    -> 0x15 (forward, ret)
#   0x12: 2A          ret
#   0x13: 00          nop
#   0x14: 00          nop
#   0x15: 2A          ret
# switch instruction spans 0x01..0x11, end of instruction = 0x12
switch_at_method_start = binascii.unhexlify(
    "56"  # tiny header, code size 0x15
    "45"  # switch
    "03000000"  # count = 3
    "00000000"  # case 0 -> 0x12
    "EFFFFFFF"  # case 1 -> 0x01
    "03000000"  # case 2 -> 0x15
    "2A"  # 0x12: ret
    "00"  # 0x13: nop
    "00"  # 0x14: nop
    "2A"  # 0x15: ret
)
SWITCH_AT_START_OFFSET = 0x01
SWITCH_AT_START_TARGETS = [0x12, 0x01, 0x15]

# byte layout (stream offsets): the same logical switch (identical count and
# identical relative entries) placed behind a 5-byte prefix.
#   0x00: 6A          tiny header, code size 0x1A
#   0x01: 17          ldc.i4.1
#   0x02: 18          ldc.i4.2
#   0x03: 58          add
#   0x04: 26          pop
#   0x05: 00          nop
#   0x06: 45          switch
#   0x07: 03000000    count = 3
#   0x0B: 00000000    case 0: rel +0    -> 0x17
#   0x0F: EFFFFFFF    case 1: rel -17   -> 0x06 (back edge to switch itself)
#   0x13: 03000000    case 2: rel +3    -> 0x1A
#   0x17: 2A          ret
#   0x18: 00          nop
#   0x19: 00          nop
#   0x1A: 2A          ret
# switch instruction spans 0x06..0x16, end of instruction = 0x17
switch_after_prefix = binascii.unhexlify(
    "6A"  # tiny header, code size 0x1A
    "17"  # ldc.i4.1
    "18"  # ldc.i4.2
    "58"  # add
    "26"  # pop
    "00"  # nop
    "45"  # switch
    "03000000"  # count = 3
    "00000000"  # case 0 -> 0x17
    "EFFFFFFF"  # case 1 -> 0x06
    "03000000"  # case 2 -> 0x1A
    "2A"  # 0x17: ret
    "00"  # 0x18: nop
    "00"  # 0x19: nop
    "2A"  # 0x1A: ret
)
SWITCH_AFTER_PREFIX_OFFSET = 0x06
SWITCH_AFTER_PREFIX_TARGETS = [0x17, 0x06, 0x1A]

# byte layout (stream offsets):
#   0x00: 1A          tiny header, code size 0x06
#   0x01: 45          switch
#   0x02: 00000000    count = 0
#   0x06: 2A          ret
# switch instruction spans 0x01..0x05, end of instruction = 0x06
switch_zero_branches = binascii.unhexlify(
    "1A"  # tiny header, code size 0x06
    "45"  # switch
    "00000000"  # count = 0
    "2A"  # 0x06: ret
)

# byte layout (stream offsets): two cases share one target, and the shared
# target is a back edge to the switch itself.
#   0x00: 3A          tiny header, code size 0x0E
#   0x01: 45          switch
#   0x02: 02000000    count = 2
#   0x06: F3FFFFFF    case 0: rel -13   -> 0x01 (switch itself)
#   0x0A: F3FFFFFF    case 1: rel -13   -> 0x01 (switch itself)
#   0x0E: 2A          ret
# switch instruction spans 0x01..0x0D, end of instruction = 0x0E
switch_shared_back_edge = binascii.unhexlify(
    "3A"  # tiny header, code size 0x0E
    "45"  # switch
    "02000000"  # count = 2
    "F3FFFFFF"  # case 0 -> 0x01
    "F3FFFFFF"  # case 1 -> 0x01
    "2A"  # 0x0E: ret
)

# byte layout (stream offsets): count says 3 but only 1 entry is present.
#   0x00: 46          tiny header, declared code size 0x11
#   0x01: 45          switch
#   0x02: 03000000    count = 3
#   0x06: 00000000    case 0 (cases 1 and 2 missing)
switch_truncated_entries = binascii.unhexlify(
    "46"  # tiny header, declared code size 0x11
    "45"  # switch
    "03000000"  # count = 3
    "00000000"  # only one entry present
)

# byte layout (stream offsets): the count field itself is cut short.
#   0x00: 0E          tiny header, declared code size 0x03
#   0x01: 45          switch
#   0x02: 0200        count field truncated after 2 of 4 bytes
switch_truncated_count = binascii.unhexlify(
    "0E"  # tiny header, declared code size 0x03
    "45"  # switch
    "0200"  # truncated count
)

# byte layout (stream offsets): case 0 lands inside the call operand.
#   0x00: 3E          tiny header, code size 0x0F
#   0x01: 45          switch
#   0x02: 01000000    count = 1
#   0x06: 01000000    case 0: rel +1    -> 0x0B (inside call token operand)
#   0x0A: 28          call
#   0x0B: 0B00000A    call operand (token 0x0A00000B)
#   0x0F: 2A          ret
# switch instruction spans 0x01..0x09, end of instruction = 0x0A
switch_target_into_operand = binascii.unhexlify(
    "3E"  # tiny header, code size 0x0F
    "45"  # switch
    "01000000"  # count = 1
    "01000000"  # case 0 -> 0x0B
    "28"  # 0x0A: call
    "0B00000A"  # 0x0B: call operand
    "2A"  # 0x0F: ret
)
SWITCH_INTO_OPERAND_TARGET = 0x0B
CALL_INSN_OFFSET = 0x0A

# byte layout (stream offsets): both cases jump outside the method body.
#   0x00: 3A          tiny header, code size 0x0E
#   0x01: 45          switch
#   0x02: 02000000    count = 2
#   0x06: 64000000    case 0: rel +100  -> 0x72 (past end of body)
#   0x0A: 9CFFFFFF    case 1: rel -100  -> -86 (before start of body)
#   0x0E: 2A          ret
# switch instruction spans 0x01..0x0D, end of instruction = 0x0E
switch_target_outside_method = binascii.unhexlify(
    "3A"  # tiny header, code size 0x0E
    "45"  # switch
    "02000000"  # count = 2
    "64000000"  # case 0 -> 0x72
    "9CFFFFFF"  # case 1 -> -86
    "2A"  # 0x0E: ret
)
SWITCH_OUTSIDE_TARGETS = [0x72, -86]


def read_body(body_bytes: bytes) -> CilMethodBody:
    return CilMethodBody(CilMethodBodyReaderBytes(body_bytes))


def get_switch(body: CilMethodBody) -> Instruction:
    for insn in body.instructions:
        if insn.opcode.value == OpCodeValue.Switch:
            return insn
    raise AssertionError("no switch instruction found")


def assert_switch_edges(insn: Instruction, expected_targets: list, layout: str):
    """check each switch edge individually so a failure names the miswired edge"""
    actual = list(insn.operand)
    assert len(actual) == len(expected_targets), (
        "%s: expected %d switch edges, got %d" % (layout, len(expected_targets), len(actual))
    )
    for i, (act, exp) in enumerate(zip(actual, expected_targets)):
        assert act == exp, "%s: switch edge %d miswired: target 0x%04X, expected 0x%04X" % (
            layout,
            i,
            act,
            exp,
        )


def test_switch_at_method_start():
    body = read_body(switch_at_method_start)
    insn = get_switch(body)

    assert insn.offset == SWITCH_AT_START_OFFSET
    assert_switch_edges(insn, SWITCH_AT_START_TARGETS, "switch_at_method_start")


def test_switch_after_prefix():
    body = read_body(switch_after_prefix)
    insn = get_switch(body)

    assert insn.offset == SWITCH_AFTER_PREFIX_OFFSET
    assert_switch_edges(insn, SWITCH_AFTER_PREFIX_TARGETS, "switch_after_prefix")


def test_switch_target_set_invariant_to_placement():
    # the same logical switch (same count, same relative entries) placed at
    # the method start and at a non-zero offset must yield the same target
    # set shifted by exactly the placement delta
    insn_start = get_switch(read_body(switch_at_method_start))
    insn_prefix = get_switch(read_body(switch_after_prefix))

    delta = insn_prefix.offset - insn_start.offset
    assert delta == 0x05

    assert set(insn_start.operand) == set(SWITCH_AT_START_TARGETS)
    assert set(insn_prefix.operand) == set(SWITCH_AFTER_PREFIX_TARGETS)
    assert set(insn_prefix.operand) == {t + delta for t in insn_start.operand}
    assert list(insn_prefix.operand) == [t + delta for t in insn_start.operand]


def test_switch_base_is_instruction_end_not_table_entry():
    # if targets were (incorrectly) computed relative to each table entry
    # (i.e. entry position + 4, as if every entry were its own branch
    # instruction), the entries of switch_at_method_start would resolve to:
    #   case 0 @ 0x06: 0x0A + 0   = 0x0A  (wrong: points into the table)
    #   case 1 @ 0x0A: 0x0E - 17  = -3    (wrong: before the method)
    #   case 2 @ 0x0E: 0x12 + 3   = 0x15  (coincides with the correct target)
    # so an entry-relative base silently corrupts edges 0 and 1 while edge 2
    # still looks right; this test names exactly those edges.
    entry_relative_targets = [0x0A, -3, 0x15]
    corrupted_edges = [
        i for i, (wrong, correct) in enumerate(zip(entry_relative_targets, SWITCH_AT_START_TARGETS)) if wrong != correct
    ]
    assert corrupted_edges == [0, 1]

    insn = get_switch(read_body(switch_at_method_start))
    for i in corrupted_edges:
        assert list(insn.operand)[i] == SWITCH_AT_START_TARGETS[i], (
            "switch edge %d established to 0x%04X; an entry-relative base would give 0x%04X, "
            "the correct instruction-end-relative target is 0x%04X"
            % (i, list(insn.operand)[i], entry_relative_targets[i], SWITCH_AT_START_TARGETS[i])
        )
        assert list(insn.operand)[i] != entry_relative_targets[i]


def test_switch_negative_offset_back_edge():
    body = read_body(switch_at_method_start)
    insn = get_switch(body)

    # case 1 is a legitimate back edge to the switch itself and must be kept
    assert insn.operand[1] == insn.offset == 0x01


def test_switch_zero_branches():
    body = read_body(switch_zero_branches)
    insn = get_switch(body)

    assert insn.offset == 0x01
    assert insn.operand == []
    assert insn.operand_bytes == binascii.unhexlify("00000000")
    assert insn.size == 0x05

    # the next instruction must start right after the empty table
    ret = body.instructions[body.instructions.index(insn) + 1]
    assert ret.offset == 0x06
    assert ret.opcode.value == OpCodeValue.Ret


def test_switch_duplicate_shared_targets_preserved():
    body = read_body(switch_shared_back_edge)
    insn = get_switch(body)

    # both cases share the same back-edge target; the reader must keep both
    # edges instead of deduplicating or dropping them
    assert list(insn.operand) == [0x01, 0x01]
    assert insn.operand[0] == insn.operand[1] == insn.offset


def test_switch_truncated_entries():
    with pytest.raises(MethodBodyFormatError):
        read_body(switch_truncated_entries)


def test_switch_truncated_count():
    with pytest.raises(MethodBodyFormatError):
        read_body(switch_truncated_count)


def test_switch_target_into_operand():
    body = read_body(switch_target_into_operand)
    insn = get_switch(body)

    # the reader reports the raw target even when it lands inside another
    # instruction's operand; it must not clamp, align, or reject it
    assert list(insn.operand) == [SWITCH_INTO_OPERAND_TARGET]

    call = body.instructions[body.instructions.index(insn) + 1]
    assert call.offset == CALL_INSN_OFFSET
    assert CALL_INSN_OFFSET < SWITCH_INTO_OPERAND_TARGET < CALL_INSN_OFFSET + call.size
    assert SWITCH_INTO_OPERAND_TARGET not in [i.offset for i in body.instructions]


def test_switch_target_outside_method():
    body = read_body(switch_target_outside_method)
    insn = get_switch(body)

    # out-of-body targets are computed arithmetically, not clamped or dropped
    assert list(insn.operand) == SWITCH_OUTSIDE_TARGETS
    assert insn.operand[0] > body.header_size + body.code_size
    assert insn.operand[1] < 0
