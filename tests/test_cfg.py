# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import binascii
import struct

import pytest

from dncil.cil.body import CilMethodBody
from dncil.cil.body.reader import CilMethodBodyReaderBytes
from dncil.cil.cfg import (
    BasicBlock,
    ControlFlowGraph,
    ControlFlowGraphError,
    EdgeType,
    build_control_flow_graph,
)
from dncil.cil.enums import OpCodeValue
from test_method_body import method_body_fat


def _body(blob: bytes) -> CilMethodBody:
    return CilMethodBody(CilMethodBodyReaderBytes(blob))


# A short method with nested protected regions: an inner try guarded by both a
# filter handler and a finally handler, all wrapped in an outer try/finally.
#
# IL-relative layout (first IL byte == 0x00), code size 0x19:
#
#   00 nop
#   01 brtrue.s 0B                         ; conditional branch
#   03 leave.s  17                         ; exits both regions -> 0x17
#   05 nop
#   06 leave.s  10                         ; exits inner region -> 0x10
#   08 ldc.i4.0                            ; filter block start
#   09 endfilter                           ; filter handler start == 0x0B
#   0B pop
#   0C leave.s  10                         ; filter handler body -> 0x10
#   0E nop                                 ; inner finally start
#   0F endfinally                          ; inner finally end == 0x10
#   10 nop                                 ; outer finally start
#   11 ldstr "x"                           ; 5 bytes
#   16 endfinally                          ; outer finally end == 0x17
#   17 nop
#   18 ret
#
# Exception handler table (fat, 3 clauses):
#   eh[0] filter  try[0x01,0x08) filter 0x08 handler[0x0B,0x0E)
#   eh[1] finally try[0x01,0x08)                 handler[0x0E,0x10)
#   eh[2] finally try[0x00,0x10)                 handler[0x10,0x17)
METHOD_BODY_NESTED_EH = binascii.unhexlify(
    "1b3008001900000000000000002d08de1200de0816fe1126de0200dc007201000070dc002a"
    "000000415000000"
    "100000001000000070000000b0000000300000008000000"
    "0200000001000000070000000e0000000200000000000000"
    "020000000000000010000000100000000700000000000000"
)

# IL-relative offsets of the expected basic block leaders.
EXPECTED_BLOCK_OFFSETS = (0x0, 0x1, 0x3, 0x5, 0x8, 0xB, 0xE, 0x10, 0x17)


@pytest.fixture(scope="module")
def nested_cfg() -> ControlFlowGraph:
    return build_control_flow_graph(_body(METHOD_BODY_NESTED_EH))


def _il_offset(cfg: ControlFlowGraph, block: BasicBlock) -> int:
    return block.start - cfg.il_base


def _edges(cfg: ControlFlowGraph, edge_type: EdgeType):
    return [edge for edge in cfg.edges if edge.type == edge_type]


def test_cfg_is_read_only(nested_cfg: ControlFlowGraph):
    body = _body(METHOD_BODY_NESTED_EH)
    # the graph is built over a parsed method body without re-parsing or mutating IL
    assert len(nested_cfg.body.instructions) == len(body.instructions)
    assert all(isinstance(block, BasicBlock) for block in nested_cfg.blocks)
    # block instruction lists reference the very same Instruction objects
    graph_insns = {id(insn) for block in nested_cfg.blocks for insn in block.instructions}
    assert graph_insns == {id(insn) for insn in nested_cfg.body.instructions}
    assert nested_cfg.unresolved == []


def test_basic_blocks_come_from_real_instructions_and_region_boundaries(nested_cfg: ControlFlowGraph):
    assert len(nested_cfg.blocks) == len(EXPECTED_BLOCK_OFFSETS)
    assert tuple(_il_offset(nested_cfg, block) for block in nested_cfg.blocks) == EXPECTED_BLOCK_OFFSETS

    instruction_starts = {insn.offset for insn in nested_cfg.body.instructions}
    for block in nested_cfg.blocks:
        # every block starts on a real instruction boundary
        assert block.start in instruction_starts
        assert block.end > block.start
        # every instruction in the block is owned by exactly one block
        for insn in block.instructions:
            assert block.start <= insn.offset < block.end

    # all instructions are covered exactly once
    covered = [insn.offset for block in nested_cfg.blocks for insn in block.instructions]
    assert sorted(covered) == sorted(instruction_starts)


def test_structural_block_labels_from_eh_regions(nested_cfg: ControlFlowGraph):
    labels_by_offset = {
        _il_offset(nested_cfg, block): block.labels for block in nested_cfg.blocks
    }
    assert labels_by_offset[0x8] == ("filter",)
    assert labels_by_offset[0xB] == ("filter_handler",)
    assert labels_by_offset[0xE] == ("finally",)
    assert labels_by_offset[0x10] == ("finally",)
    # ordinary blocks carry no exception handler label
    assert labels_by_offset[0x0] == ()
    assert labels_by_offset[0x17] == ()


def test_explicit_edges_are_classified_and_evidenced(nested_cfg: ControlFlowGraph):
    # fallthrough: brtrue block continues into the leave at 0x03, and 0x17 -> ret
    fallthrough = _edges(nested_cfg, EdgeType.FALLTHROUGH)
    assert {(_il_offset(nested_cfg, e.source), _il_offset(nested_cfg, e.target)) for e in fallthrough} == {
        (0x0, 0x1),
        (0x1, 0x3),
    }
    assert {e.evidence.mnemonic for e in fallthrough} == {"nop", "brtrue.s"}

    # one ordinary conditional branch, kept distinct from leave
    cond = _edges(nested_cfg, EdgeType.CONDITIONAL_BRANCH)
    assert len(cond) == 1
    assert _il_offset(nested_cfg, cond[0].source) == 0x1
    assert _il_offset(nested_cfg, cond[0].target) == 0xB
    assert cond[0].evidence.mnemonic == "brtrue.s"

    # three leave exits, each evidenced by its own leave instruction; the source
    # is the block containing the leave (the block starts before the instruction)
    leave = _edges(nested_cfg, EdgeType.LEAVE)
    assert len(leave) == 3
    assert {(_il_offset(nested_cfg, e.source), _il_offset(nested_cfg, e.target)) for e in leave} == {
        (0x3, 0x17),
        (0x5, 0x10),
        (0xB, 0x10),
    }
    assert {e.evidence.mnemonic for e in leave} == {"leave.s"}
    assert all(e.evidence.is_leave() for e in leave)
    # leave must never be reported as an ordinary branch
    assert _edges(nested_cfg, EdgeType.BRANCH) == []

    # the single ret is a method exit
    exits = _edges(nested_cfg, EdgeType.METHOD_EXIT)
    assert len(exits) == 1
    assert exits[0].target is None
    assert exits[0].evidence.mnemonic == "ret"


def test_filter_dispatch_is_separate_from_exception_entry(nested_cfg: ControlFlowGraph):
    dispatch = _edges(nested_cfg, EdgeType.FILTER_DISPATCH)
    assert len(dispatch) == 1
    edge = dispatch[0]
    assert _il_offset(nested_cfg, edge.source) == 0x8
    assert _il_offset(nested_cfg, edge.target) == 0xB
    # the evidence is the EH clause (endfilter semantics), not a branch instruction
    assert edge.handler_index == 0
    assert edge.evidence is nested_cfg.body.exception_handlers[0]
    assert edge.is_exception_edge and not edge.is_normal_edge

    filter_entries = _edges(nested_cfg, EdgeType.EXCEPTION_FILTER)
    # the inner try body is made of three blocks, each can raise into the filter
    assert {_il_offset(nested_cfg, e.source) for e in filter_entries} == {0x1, 0x3, 0x5}
    assert all(_il_offset(nested_cfg, e.target) == 0x8 for e in filter_entries)
    assert all(e.handler_index == 0 for e in filter_entries)


def test_exception_edges_cover_every_protected_block(nested_cfg: ControlFlowGraph):
    inner_finally = _edges(nested_cfg, EdgeType.EXCEPTION_FINALLY)
    # eh[1] fires from the three inner-try blocks; eh[2] fires from all blocks
    # inside the outer try [0x0,0x10), i.e. the seven blocks below 0x10
    by_handler = {}
    for edge in inner_finally:
        by_handler.setdefault(edge.handler_index, set()).add(_il_offset(nested_cfg, edge.source))
    assert by_handler[1] == {0x1, 0x3, 0x5}
    assert by_handler[2] == {0x0, 0x1, 0x3, 0x5, 0x8, 0xB, 0xE}
    assert all(edge.is_exception_edge for edge in inner_finally)

    # region-derived exception edges cite the EH clause that justifies them;
    # FINALLY_EXIT is instead evidenced by the endfinally instruction
    for edge in nested_cfg.edges:
        if edge.is_exception_edge and edge.type != EdgeType.FINALLY_EXIT:
            assert edge.evidence is nested_cfg.body.exception_handlers[edge.handler_index]
            assert "eh[%d]" % edge.handler_index in edge.describe()
    assert all(
        edge.evidence.mnemonic == "endfinally"
        for edge in nested_cfg.edges
        if edge.type == EdgeType.FINALLY_EXIT
    )


def test_finally_exit_edges_resume_at_leave_targets(nested_cfg: ControlFlowGraph):
    finally_exit = _edges(nested_cfg, EdgeType.FINALLY_EXIT)
    # (source endfinally block -> resume target), IL-relative offsets
    resumed = {
        (_il_offset(nested_cfg, edge.source), _il_offset(nested_cfg, edge.target))
        for edge in finally_exit
    }
    # inner endfinally (0x0F in block 0xE): resumes into outer finally (0x10)
    # or at the outer-region leave target (0x17)
    assert (0xE, 0x10) in resumed
    assert (0xE, 0x17) in resumed
    # outer endfinally (block 0x10): resumes at the outer-region leave target (0x17)
    assert (0x10, 0x17) in resumed
    assert all(edge.evidence.mnemonic == "endfinally" for edge in finally_exit)


def test_exception_paths_are_not_merged_into_normal_reachability(nested_cfg: ControlFlowGraph):
    normal = {_il_offset(nested_cfg, block) for block in nested_cfg.reachable_blocks()}
    # normal flow never enters the filter, filter handler or either finally block;
    # block 0x5 is also excluded because the only branch reaching it is not taken
    assert normal == {0x0, 0x1, 0x3, 0xB, 0x10, 0x17}

    exception_only = {_il_offset(nested_cfg, block) for block in nested_cfg.exception_reachable_blocks()}
    assert exception_only == {0x8, 0xE}

    # the conditional-branch target 0x5 is not reachable on any static path
    assert {_il_offset(nested_cfg, block) for block in nested_cfg.unreachable_blocks()} == {0x5}


def test_branch_target_in_middle_of_operand_is_an_error():
    # 00 nop; 01 br.s -1 -> 0x02 which is the operand byte of br.s itself;
    # 03 ldstr (5 bytes); 08 ret
    code = bytes([0x00, 0x2B, 0xFF, 0x72, 0x11, 0x22, 0x33, 0x44, 0x2A])
    tiny = bytes([(len(code) << 2) | 0x02]) + code
    with pytest.raises(ControlFlowGraphError, match="middle of an instruction"):
        build_control_flow_graph(_body(tiny))


def test_eh_region_boundary_in_middle_of_instruction_is_an_error():
    # 00 nop; 01 ldstr (spans 0x01..0x06); 06 ret
    code = bytes([0x00, 0x72, 0x01, 0x00, 0x00, 0x70, 0x2A])
    header = struct.pack("<HHII", 0x301B, 0x08, len(code), 0)
    padding = b"\x00" * ((-(len(header) + len(code))) % 4)
    section_header = struct.pack("<I", ((8 + 24) << 8) | 0x41)
    # catch clause whose try_start (IL rel 0x02) lands inside the ldstr operand
    clause = struct.pack("<IIIIII", 0x0000, 0x02, 0x01, 0x06, 0x01, 0x01000001)
    fat = header + code + padding + section_header + clause

    with pytest.raises(ControlFlowGraphError, match="eh\\[0\\] try_start.*middle of an instruction"):
        build_control_flow_graph(_body(fat))


def test_unknown_semantics_remain_unresolved_and_do_not_execute_il():
    # prefixref is a reserved prefix: its transfer cannot be decided statically
    code = bytes([0xFF, 0x00, 0x2A])  # prefixref, nop, ret
    tiny = bytes([(len(code) << 2) | 0x02]) + code
    cfg = build_control_flow_graph(_body(tiny))
    unresolved = _edges(cfg, EdgeType.UNRESOLVED)
    assert len(unresolved) == 1
    assert unresolved[0].evidence.opcode.value == OpCodeValue.Prefixref
    assert cfg.unresolved == [unresolved[0].source.start]

    # jmp transfers out of the method; we model it as unresolved, never as a branch
    code_jmp = bytes([0x27, 0x01, 0x00, 0x00, 0x0A])  # jmp <method token>
    tiny_jmp = bytes([(len(code_jmp) << 2) | 0x02]) + code_jmp
    cfg_jmp = build_control_flow_graph(_body(tiny_jmp))
    jmp_edges = _edges(cfg_jmp, EdgeType.UNRESOLVED)
    assert len(jmp_edges) == 1
    assert jmp_edges[0].evidence.opcode.value == OpCodeValue.Jmp
    assert _edges(cfg_jmp, EdgeType.BRANCH) == []


def test_existing_catch_finally_fixture_keeps_exception_blocks_separate():
    cfg = build_control_flow_graph(_body(method_body_fat))

    leave = _edges(cfg, EdgeType.LEAVE)
    assert len(leave) == 2
    assert all(edge.evidence.is_leave() for edge in leave)

    catch = _edges(cfg, EdgeType.EXCEPTION_CATCH)
    assert len(catch) == 1
    assert catch[0].handler_index == 0

    finally_entries = _edges(cfg, EdgeType.EXCEPTION_FINALLY)
    assert {edge.handler_index for edge in finally_entries} == {1}
    # both the try body and the catch block can run the outer finally
    assert len(finally_entries) == 2

    # handler blocks are reachable only via exception edges
    exception_only = {_il_offset(cfg, block) for block in cfg.exception_reachable_blocks()}
    assert exception_only == {0xC, 0x19}
    assert cfg.unreachable_blocks() == ()


def test_naive_leave_as_branch_produces_wrong_graph(nested_cfg: ControlFlowGraph):
    """Contrast: interpreting leave as an ordinary br and ignoring EH edges.

    A naive builder treats the three leave instructions as plain unconditional
    branches and drops every exception-derived edge. We reconstruct that graph
    over the same real basic blocks and show why it is wrong.
    """
    cfg = nested_cfg
    block_by_il = {_il_offset(cfg, block): block for block in cfg.blocks}

    # naive edges: explicit instructions only, leave mislabelled as BRANCH,
    # and no exception/filter/finally edges at all
    naive = {EdgeType.FALLTHROUGH, EdgeType.CONDITIONAL_BRANCH, EdgeType.BRANCH, EdgeType.METHOD_EXIT}
    naive_edges = []
    for edge in cfg.edges:
        if edge.type == EdgeType.LEAVE:
            naive_edges.append((EdgeType.BRANCH, edge.source, edge.target))
        elif edge.type in naive:
            naive_edges.append((edge.type, edge.source, edge.target))

    seen = {block_by_il[0x0]}
    worklist = [block_by_il[0x0]]
    while worklist:
        current = worklist.pop()
        for edge_type, source, target in naive_edges:
            if source is current and target is not None and target not in seen:
                seen.add(target)
                worklist.append(target)
    naive_reachable = {_il_offset(cfg, block) for block in seen}

    # the naive graph wrongly treats leave as a normal branch ...
    assert any(edge_type == EdgeType.BRANCH for edge_type, _, _ in naive_edges)
    assert not any(edge_type == EdgeType.LEAVE for edge_type, _, _ in naive_edges)

    # ... with two concrete wrong consequences:
    # (1) the filter block and inner finally handler disappear entirely because
    #     only exception edges can enter them;
    assert {0x8, 0xE} - naive_reachable == {0x8, 0xE}
    # (2) the outer finally (0x10) is reached as if it were an ordinary branch
    #     target, i.e. without unwinding semantics, instead of via a leave resume.
    naive_into_outer = [
        (edge_type, _il_offset(cfg, source))
        for edge_type, source, target in naive_edges
        if target is block_by_il[0x10]
    ]
    assert (EdgeType.BRANCH, 0x5) in naive_into_outer
    assert (EdgeType.BRANCH, 0xB) in naive_into_outer
    assert all(edge_type != EdgeType.LEAVE for edge_type, _ in naive_into_outer)

    # the correct graph instead keeps leave distinct and reaches every block
    # except the genuinely dead conditional-branch target 0x5
    correct_normal = {_il_offset(cfg, block) for block in cfg.reachable_blocks()}
    correct_exception = {_il_offset(cfg, block) for block in cfg.exception_reachable_blocks()}
    assert 0x10 in correct_normal  # outer finally is a leave resume target
    assert (correct_normal | correct_exception) == set(EXPECTED_BLOCK_OFFSETS) - {0x5}
