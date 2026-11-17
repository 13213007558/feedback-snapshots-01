# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import struct

from dncil.cil.body import CilMethodBody
from dncil.cil.prefix import (
    ISSUE_DUPLICATE_PREFIX,
    ISSUE_INCOMPATIBLE_OPERATION,
    ISSUE_INVALID_ORDER,
    ISSUE_MID_GROUP_ENTRY,
    ISSUE_ORPHAN_PREFIX,
    ISSUE_REGION_SPLIT,
    ISSUE_UNSUPPORTED_PREFIX,
    PrefixGroupEntry,
    analyze_prefix_groups,
    format_report,
)
from dncil.cil.body.reader import CilMethodBodyReaderBytes


def tiny_body(code: bytes) -> CilMethodBody:
    """wrap raw code bytes in a tiny-format method body header"""
    assert len(code) < 64
    return CilMethodBody(CilMethodBodyReaderBytes(bytes([(len(code) << 2) | 2]) + code))


def fat_body(code: bytes, exception_handler: bytes = b"") -> CilMethodBody:
    """wrap raw code bytes in a fat-format method body, optionally with one EH"""
    flags = 0x3013
    blob = struct.pack("<H", flags) + struct.pack("<H", 8) + struct.pack("<I", len(code))
    blob += struct.pack("<I", 0) + code
    if exception_handler:
        blob += b"\x00" * ((-len(blob)) % 4)
        blob += struct.pack("<I", (len(exception_handler) << 8) | 0x41) + exception_handler
        blob = struct.pack("<H", flags | 0x08) + blob[2:]
    return CilMethodBody(CilMethodBodyReaderBytes(blob))


def callvirt(token: int = 0x06000001) -> bytes:
    return b"\x6f" + struct.pack("<I", token)


def constrained(token: int = 0x01000001) -> bytes:
    return b"\xfe\x16" + struct.pack("<I", token)


TAIL = b"\xfe\x14"
VOLATILE = b"\xfe\x13"
UNALIGNED = b"\xfe\x12\x01"
READONLY = b"\xfe\x1e"
RET = b"\x2a"


def test_valid_constrained_call_groups():
    # nop; tail.; constrained.; callvirt; ret
    body = tiny_body(b"\x00" + TAIL + constrained() + callvirt() + RET)
    report = body.analyze_prefixes()

    assert report.structurally_consistent
    assert len(report.groups) == 1
    group = report.groups[0]
    assert group.start == 0x2
    assert group.operation is body.instructions[3]
    assert group.operation.mnemonic == "callvirt"
    assert [binding.operation_offset for binding in group.bindings] == [0xA, 0xA]
    assert group.get_bytes() == TAIL + constrained() + callvirt()


def test_valid_volatile_unaligned_combination():
    for code in (VOLATILE + UNALIGNED + b"\x4d" + RET, UNALIGNED + VOLATILE + b"\x4d" + RET):
        report = tiny_body(code).analyze_prefixes()
        assert report.structurally_consistent
        assert report.groups[0].operation.mnemonic == "ldind.i"
        assert len(report.groups[0].bindings) == 2


def test_valid_readonly_ldelema():
    report = tiny_body(READONLY + b"\x8f" + struct.pack("<I", 0x01000001) + RET).analyze_prefixes()
    assert report.structurally_consistent
    assert report.groups[0].operation.mnemonic == "ldelema"


def test_duplicate_prefix_keeps_each_original_instruction():
    body = tiny_body(TAIL + TAIL + b"\x28" + struct.pack("<I", 0x06000001) + RET)
    report = body.analyze_prefixes()

    group = report.groups[0]
    assert not group.structurally_consistent
    assert [insn.offset for insn in group.prefixes] == [0x1, 0x3]
    assert len(group.instructions) == 3
    issue = report.issues[0]
    assert issue.code == ISSUE_DUPLICATE_PREFIX
    assert issue.offset == 0x3
    assert issue.related_offset == 0x1
    assert issue.operation is body.instructions[2]


def test_invalid_prefix_order_points_at_both_prefixes():
    report = tiny_body(constrained() + TAIL + callvirt() + RET).analyze_prefixes()

    assert not report.structurally_consistent
    issue = report.issues[0]
    assert issue.code == ISSUE_INVALID_ORDER
    assert issue.offset == 0x7
    assert issue.related_offset == 0x1
    assert "tail." in issue.message


def test_orphan_trailing_prefix():
    body = tiny_body(RET + TAIL)
    report = body.analyze_prefixes()

    assert len(report.groups) == 1
    group = report.groups[0]
    assert group.operation is None
    assert group.issues[0].code == ISSUE_ORPHAN_PREFIX
    assert group.issues[0].offset == 0x2


def test_incompatible_prefix_operation():
    report = tiny_body(VOLATILE + RET).analyze_prefixes()

    issue = report.issues[0]
    assert issue.code == ISSUE_INCOMPATIBLE_OPERATION
    assert issue.offset == 0x1
    assert issue.operation.mnemonic == "ret"


def test_reserved_no_prefix_is_not_accepted():
    report = tiny_body(b"\xfe\x19\x00" + RET).analyze_prefixes()

    assert {issue.code for issue in report.issues} == {ISSUE_UNSUPPORTED_PREFIX}


def test_branch_into_middle_of_group_is_reported():
    # nop; br.s <target>; tail.; constrained.; callvirt; ret
    base = b"\x00" + b"\x2b\x00" + TAIL + constrained() + callvirt() + RET
    targets = {}

    for name, target in (("group_start", 0x4), ("second_prefix", 0x6), ("operation", 0xC)):
        code = bytearray(base)
        # br.s displacement is relative to the end of the branch instruction at 0x3
        code[2] = (target - 0x4) & 0xFF
        body = tiny_body(bytes(code))
        report = body.analyze_prefixes()
        targets[name] = report

        group = report.groups[0]
        assert group.start == 0x4
        assert group.operation.offset == 0xC
        entry = group.entries[0]
        assert entry.source_offset == 0x2

        if target == 0x4:
            assert entry.at_group_start
            assert report.structurally_consistent
        else:
            assert not entry.at_group_start
            issue = report.issues[0]
            assert issue.code == ISSUE_MID_GROUP_ENTRY
            assert issue.offset == target
            assert issue.related_offset == 0x4
            assert issue.source_offset == 0x2
            assert issue.operation.offset == 0xC

    # all three variants share the same decoded instructions and group layout
    second_prefix = targets["second_prefix"].groups[0]
    operation = targets["operation"].groups[0]
    assert [insn.offset for insn in second_prefix.prefixes] == [insn.offset for insn in operation.prefixes]


def test_switch_into_middle_of_group_is_reported():
    # nop; switch(1) <target>; tail.; constrained.; callvirt; ret
    # target 0xB + 2 lands on constrained. at 0xD
    switch = b"\x45" + struct.pack("<I", 1) + struct.pack("<i", 2)
    body = tiny_body(b"\x00" + switch + TAIL + constrained() + callvirt() + RET)
    report = body.analyze_prefixes()

    group = report.groups[0]
    assert group.start == 0xB
    entry = group.entries[0]
    assert entry.kind == PrefixGroupEntry.KIND_SWITCH
    assert entry.source_offset == 0x2
    assert not entry.at_group_start
    assert report.issues[0].code == ISSUE_MID_GROUP_ENTRY


def test_exception_region_into_middle_of_group_is_reported():
    # nop; tail.; constrained.; callvirt; ret
    code = b"\x00" + TAIL + constrained() + callvirt() + RET
    # first instruction is at offset 0xC; a handler start of 5 enters the second prefix
    eh = struct.pack("<IIIIII", 0, 0, 1, 2, 1, 0x01000001)
    body = fat_body(code, eh)
    assert body.header_size == 0xC

    report = body.analyze_prefixes()
    assert report.code_start == 0xC

    entry = report.groups[0].entries[0]
    assert entry.kind == PrefixGroupEntry.KIND_EXCEPTION_REGION
    assert entry.offset == 0xE
    assert entry.source_offset is None
    issue = report.issues[0]
    assert issue.code == ISSUE_MID_GROUP_ENTRY
    assert issue.offset == 0xE
    assert issue.related_offset == 0xD


def test_reports_do_not_modify_method_body():
    body = tiny_body(b"\x00" + TAIL + constrained() + callvirt() + RET)
    instructions = list(body.instructions)
    raw_bytes = body.get_bytes()
    offsets = [insn.offset for insn in body.instructions]
    operands = [insn.operand for insn in body.instructions]

    report = body.analyze_prefixes()

    assert body.instructions == instructions
    assert body.get_bytes() == raw_bytes
    assert body.get_instruction_bytes() == raw_bytes[body.header_size : body.header_size + body.code_size]
    assert [insn.offset for insn in body.instructions] == offsets
    assert [insn.operand for insn in body.instructions] == operands
    assert report.to_dict()["safety_proof"] is False


def test_report_dict_cites_offsets_and_operations():
    body = tiny_body(b"\x00" + b"\x2b\x00" + TAIL + constrained() + callvirt() + RET)
    data = body.analyze_prefixes().to_dict()

    group = data["groups"][0]
    assert group["start"] == 0x4
    assert group["operation"]["offset"] == 0xC
    assert [prefix["offset"] for prefix in group["prefixes"]] == [0x4, 0x6]
    assert group["entries"][0]["source_offset"] == 0x2
    assert data["scope"]


def test_format_report_cites_offsets():
    body = tiny_body(b"\x00" + b"\x2b\x00" + TAIL + constrained() + callvirt() + RET)
    report = body.analyze_prefixes()

    text = format_report(report)
    assert "0x0004 tail. constrains callvirt" in text
    assert "entry  branch from 0x0002 at 0x0004" in text
    assert "scope:" in text


def test_format_report_flags_mid_group_entry():
    body = tiny_body(b"\x00" + b"\x2b\x02" + TAIL + constrained() + callvirt() + RET)
    report = body.analyze_prefixes()

    text = format_report(report)
    assert "issue  mid_group_entry @ 0x0006" in text
    assert "affecting callvirt" in text


def test_exception_region_boundary_splitting_group_is_reported():
    # nop; tail.; constrained.; callvirt; ret
    code = b"\x00" + TAIL + constrained() + callvirt() + RET
    # code starts at 0xC; a try_end of 2 lands between the two prefixes
    eh = struct.pack("<IIIIII", 0, 0, 2, 0, 1, 0x01000001)
    body = fat_body(code, eh)

    report = body.analyze_prefixes()
    group = report.groups[0]
    assert group.start == 0xD
    entry = group.entries[0]
    assert entry.kind == PrefixGroupEntry.KIND_EXCEPTION_BOUNDARY
    assert entry.offset == 0xE
    issue = report.issues[0]
    assert issue.code == ISSUE_REGION_SPLIT
    assert issue.offset == 0xE
    assert issue.related_offset == 0xD


def test_group_boundary_exception_region_is_accepted():
    # nop; tail.; constrained.; callvirt; ret
    code = b"\x00" + TAIL + constrained() + callvirt() + RET
    # code starts at 0xC; try starts on the first prefix and ends after the group
    eh = struct.pack("<IIIIII", 0, 1, 0xD, 0xE, 1, 0x01000001)
    body = fat_body(code, eh)

    report = body.analyze_prefixes()
    assert report.structurally_consistent


def test_module_function_preserves_original_instructions():
    body = tiny_body(b"\x00" + TAIL + constrained() + callvirt() + RET)
    report = analyze_prefix_groups(body.instructions)

    assert report.code_start is None
    assert report.groups[0].prefixes[0] is body.instructions[1]
    assert report.groups[0].operation is body.instructions[3]
    assert report.groups[0].instructions == body.instructions[1:4]


def test_instruction_is_prefix():
    body = tiny_body(TAIL + constrained() + callvirt() + RET)

    assert body.instructions[0].is_prefix()
    assert body.instructions[1].is_prefix()
    assert not body.instructions[2].is_prefix()
    assert not body.instructions[3].is_prefix()


def test_tail_call_variants_are_not_rejected():
    for operation in (callvirt(), b"\x28" + struct.pack("<I", 0x06000001)):
        report = tiny_body(TAIL + operation + RET).analyze_prefixes()
        assert report.structurally_consistent

    report = tiny_body(TAIL + b"\x29" + struct.pack("<I", 0x06000001) + RET).analyze_prefixes()
    assert report.structurally_consistent


def test_switch_to_group_start_is_accepted():
    switch = b"\x45" + struct.pack("<I", 1) + struct.pack("<i", 0)
    body = tiny_body(b"\x00" + switch + TAIL + constrained() + callvirt() + RET)
    report = body.analyze_prefixes()

    entry = report.groups[0].entries[0]
    assert entry.kind == PrefixGroupEntry.KIND_SWITCH
    assert entry.at_group_start
    assert report.structurally_consistent
