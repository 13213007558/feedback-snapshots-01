# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Read-only control flow graph (CFG) analysis for managed method bodies.

This module builds a structural control flow graph from a parsed
:class:`dncil.cil.body.CilMethodBody`. It is intentionally read-only and purely
static: it never executes or emulates IL, never evaluates operands or the
evaluation stack, and never mutates the underlying method body.

Exception handling regions are first-class graph members rather than
annotations. Transfers are classified by :class:`EdgeType` so ordinary
intra-method jumps, ``leave`` exits and exception/filter/finally transfers can
never be merged into a single "reachable" path by mistake:

* normal transfers (:attr:`EdgeType.FALLTHROUGH`, :attr:`EdgeType.BRANCH`,
  :attr:`EdgeType.CONDITIONAL_BRANCH`, :attr:`EdgeType.SWITCH`,
  :attr:`EdgeType.METHOD_EXIT`, :attr:`EdgeType.UNRESOLVED`) describe explicit
  instruction-level control flow;
* :attr:`EdgeType.LEAVE` models ``leave``/``leave.s`` separately because a
  leave unwinds protected regions instead of behaving like ``br``;
* exception transfers (:attr:`EdgeType.EXCEPTION_CATCH`,
  :attr:`EdgeType.EXCEPTION_FILTER`, :attr:`EdgeType.EXCEPTION_FINALLY`,
  :attr:`EdgeType.EXCEPTION_FAULT`, :attr:`EdgeType.FILTER_DISPATCH`,
  :attr:`EdgeType.FINALLY_EXIT`) are derived from the exception handler table.

Basic block leaders come from real instruction offsets and from exception
handler region boundaries. Any branch or region boundary that lands in the
middle of an instruction (i.e. on an offset that is not an instruction start)
raises :class:`ControlFlowGraphError`.

When the static meaning of an instruction cannot be decided, an
:attr:`EdgeType.UNRESOLVED` edge is recorded and the graph keeps working; the
unknown transfer is never silently treated as an ordinary reachable edge.
"""

from __future__ import annotations

import enum
from typing import Dict, List, Optional, Sequence, Set, Tuple, TYPE_CHECKING

from dncil.cil.enums import FlowControl, OpCodeValue
from dncil.cil.error import MethodBodyFormatError

if TYPE_CHECKING:
    from dncil.cil.body import CilMethodBody
    from dncil.cil.exception import ExceptionHandler
    from dncil.cil.instruction import Instruction


class ControlFlowGraphError(MethodBodyFormatError):
    """raised when a method body cannot be turned into a control flow graph"""


class EdgeType(enum.Enum):
    """kind of control flow transfer represented by a :class:`FlowEdge`"""

    # explicit, instruction-level normal transfers
    FALLTHROUGH = "fallthrough"
    BRANCH = "branch"
    CONDITIONAL_BRANCH = "conditional_branch"
    SWITCH = "switch"
    METHOD_EXIT = "method_exit"
    # semantics that cannot be decided statically without executing IL
    UNRESOLVED = "unresolved"

    # leave/leave.s: unwind protected regions, never a plain branch
    LEAVE = "leave"

    # transfers derived from exception handler regions
    EXCEPTION_CATCH = "exception_catch"
    EXCEPTION_FILTER = "exception_filter"
    EXCEPTION_FINALLY = "exception_finally"
    EXCEPTION_FAULT = "exception_fault"
    FILTER_DISPATCH = "filter_dispatch"
    FINALLY_EXIT = "finally_exit"


NORMAL_EDGE_TYPES: Tuple[EdgeType, ...] = (
    EdgeType.FALLTHROUGH,
    EdgeType.BRANCH,
    EdgeType.CONDITIONAL_BRANCH,
    EdgeType.SWITCH,
    EdgeType.METHOD_EXIT,
    EdgeType.LEAVE,
    EdgeType.UNRESOLVED,
)

EXCEPTION_EDGE_TYPES: Tuple[EdgeType, ...] = (
    EdgeType.EXCEPTION_CATCH,
    EdgeType.EXCEPTION_FILTER,
    EdgeType.EXCEPTION_FINALLY,
    EdgeType.EXCEPTION_FAULT,
    EdgeType.FILTER_DISPATCH,
    EdgeType.FINALLY_EXIT,
)

# known instruction prefixes (FlowControl.Meta, OpCodeType.Prefix) which simply
# modify the following instruction and therefore fall through to it
_PREFIX_OPCODE_VALUES: Tuple[OpCodeValue, ...] = (
    OpCodeValue.Unaligned,
    OpCodeValue.Volatile,
    OpCodeValue.Tailcall,
    OpCodeValue.Constrained,
    OpCodeValue.No,
    OpCodeValue.Readonly,
)

# reserved/experimental prefixes whose semantics are not modeled
_RESERVED_PREFIX_OPCODE_VALUES: Tuple[OpCodeValue, ...] = (
    OpCodeValue.Prefix1,
    OpCodeValue.Prefix2,
    OpCodeValue.Prefix3,
    OpCodeValue.Prefix4,
    OpCodeValue.Prefix5,
    OpCodeValue.Prefix6,
    OpCodeValue.Prefix7,
    OpCodeValue.Prefixref,
)


class FlowEdge:
    """directed, typed transfer between two basic blocks (or method exit)"""

    def __init__(
        self,
        edge_type: EdgeType,
        source: "BasicBlock",
        target: Optional["BasicBlock"],
        evidence,
        handler_index: Optional[int] = None,
        case_index: Optional[int] = None,
    ):
        self.type: EdgeType = edge_type
        self.source: "BasicBlock" = source
        # target is None for METHOD_EXIT
        self.target: Optional["BasicBlock"] = target
        # Instruction for explicit edges, ExceptionHandler for region edges
        self.evidence = evidence
        # index into CilMethodBody.exception_handlers for exception-derived edges
        self.handler_index: Optional[int] = handler_index
        # switch case ordinal for SWITCH edges
        self.case_index: Optional[int] = case_index

    @property
    def is_exception_edge(self) -> bool:
        """whether this edge is derived from an exception handler region"""
        return self.type in EXCEPTION_EDGE_TYPES

    @property
    def is_normal_edge(self) -> bool:
        """whether this edge is an explicit instruction-level transfer"""
        return self.type in NORMAL_EDGE_TYPES

    def describe(self) -> str:
        """human-readable description of the instruction or EH clause behind this edge"""
        from dncil.cil.exception import ExceptionHandler

        if isinstance(self.evidence, ExceptionHandler):
            return _describe_exception_handler(self.evidence, self.handler_index)
        insn: Instruction = self.evidence
        if self.type in (EdgeType.SWITCH,) and self.case_index is not None:
            return "%s case %d" % (insn.mnemonic, self.case_index)
        return insn.mnemonic

    def __str__(self) -> str:
        target = "<exit>" if self.target is None else "block@0x%X" % self.target.start
        return "%s --%s [%s]--> %s" % (
            "block@0x%X" % self.source.start,
            self.type.value,
            self.describe(),
            target,
        )

    def __repr__(self) -> str:
        return str(self)


class BasicBlock:
    """maximal run of instructions with no leader in the middle"""

    def __init__(self, start: int, end: int, instructions: Sequence["Instruction"]):
        # absolute stream offset of first instruction
        self.start: int = start
        # absolute stream offset immediately after last instruction
        self.end: int = end
        self.instructions: List[Instruction] = list(instructions)
        self.incoming: List[FlowEdge] = []
        self.outgoing: List[FlowEdge] = []

    @property
    def last_instruction(self) -> Instruction:
        """final instruction of the block, which owns its explicit edges"""
        return self.instructions[-1]

    @property
    def labels(self) -> Tuple[str, ...]:
        """structural roles assigned from exception handler regions"""
        labels: Set[str] = set()
        for edge in self.incoming:
            if edge.type == EdgeType.EXCEPTION_CATCH:
                labels.add("catch")
            elif edge.type == EdgeType.EXCEPTION_FILTER:
                labels.add("filter")
            elif edge.type == EdgeType.EXCEPTION_FINALLY:
                labels.add("finally")
            elif edge.type == EdgeType.EXCEPTION_FAULT:
                labels.add("fault")
            elif edge.type == EdgeType.FILTER_DISPATCH:
                labels.add("filter_handler")
        return tuple(sorted(labels))

    def __str__(self) -> str:
        return "BasicBlock(0x%X-0x%X, %d instruction(s))" % (
            self.start,
            self.end,
            len(self.instructions),
        )

    def __repr__(self) -> str:
        return str(self)


def _describe_exception_handler(handler: "ExceptionHandler", handler_index: Optional[int]) -> str:
    if handler.is_filter():
        kind = "filter"
    elif handler.is_catch():
        kind = "catch"
    elif handler.is_finally():
        kind = "finally"
    elif handler.is_fault():
        kind = "fault"
    else:
        kind = "handler type 0x%X" % handler.exception_type
    return "eh[%d] %s try[0x%X,0x%X) handler[0x%X,0x%X)" % (
        -1 if handler_index is None else handler_index,
        kind,
        handler.try_start,
        handler.try_end,
        handler.filter_start if handler.is_filter() else handler.handler_start,
        handler.handler_end,
    )


def build_control_flow_graph(body: "CilMethodBody") -> "ControlFlowGraph":
    """build a read-only control flow graph from a parsed method body"""
    return ControlFlowGraph(body)


class ControlFlowGraph:
    """read-only structural control flow graph of a managed method body"""

    def __init__(self, body: "CilMethodBody"):
        self.body: "CilMethodBody" = body
        self.blocks: List[BasicBlock] = []
        self.edges: List[FlowEdge] = []
        # offsets whose transfer semantics could not be decided statically
        self.unresolved: List[int] = []

        self._block_by_start: Dict[int, BasicBlock] = {}
        self._edge_keys: Set[Tuple] = set()

        instructions: List[Instruction] = list(body.instructions)
        if not instructions:
            raise ControlFlowGraphError("method body contains no instructions")

        self.il_base: int = instructions[0].offset
        code_end: int = instructions[-1].offset + instructions[-1].size

        self._validate_instruction_stream(instructions, code_end)
        leaders: Set[int] = self._collect_leaders(instructions, code_end)
        self._build_blocks(instructions, leaders)
        self._build_explicit_edges(instructions, code_end)
        self._build_exception_edges(code_end)

    # ------------------------------------------------------------------
    # validation
    # ------------------------------------------------------------------
    def _validate_instruction_stream(self, instructions: Sequence["Instruction"], code_end: int) -> None:
        """ensure instructions are contiguous and region offsets use IL-relative addresses"""
        expected: int = self.il_base
        for insn in instructions:
            if insn.offset != expected:
                raise ControlFlowGraphError(
                    "non-contiguous instruction stream at 0x%X (expected 0x%X)" % (insn.offset, expected)
                )
            expected = insn.offset + insn.size
        if expected != code_end:
            raise ControlFlowGraphError("instruction stream does not span the full code region")

        for index, handler in enumerate(self.body.exception_handlers):
            for name, value in (
                ("try_start", handler.try_start),
                ("try_end", handler.try_end),
                ("handler_start", handler.handler_start),
                ("handler_end", handler.handler_end),
                ("filter_start", handler.filter_start),
            ):
                if value < 0:
                    # filter_start is -1 for non-filter handlers
                    if name == "filter_start" and not handler.is_filter():
                        continue
                    raise ControlFlowGraphError("eh[%d] has invalid %s 0x%X" % (index, name, value))
                absolute: int = self._to_absolute(value)
                if absolute > code_end:
                    raise ControlFlowGraphError(
                        "eh[%d] %s 0x%X is outside the method code" % (index, name, value)
                    )

    # ------------------------------------------------------------------
    # leaders and blocks
    # ------------------------------------------------------------------
    def _collect_leaders(self, instructions: Sequence["Instruction"], code_end: int) -> Set[int]:
        leaders: Set[int] = {self.il_base}
        instruction_starts: Set[int] = {insn.offset for insn in instructions}

        def require_instruction_start(offset: int, what: str) -> None:
            if offset < self.il_base or offset > code_end:
                raise ControlFlowGraphError("%s 0x%X is outside method code [0x%X,0x%X)" % (
                    what, offset, self.il_base, code_end))
            if offset != code_end and offset not in instruction_starts:
                raise ControlFlowGraphError(
                    "%s 0x%X lands in the middle of an instruction, not on an instruction boundary" % (
                        what, offset)
                )

        for insn in instructions:
            value: OpCodeValue = insn.opcode.value

            if self._is_branch(insn):
                require_instruction_start(self._branch_target(insn), "%s target" % insn.mnemonic)
                leaders.add(self._branch_target(insn))
            elif value == OpCodeValue.Switch:
                for case_index, target in enumerate(insn.operand):
                    require_instruction_start(target, "switch case %d target" % case_index)
                    leaders.add(target)

            if self._is_terminator(insn):
                next_offset: int = insn.offset + insn.size
                if next_offset < code_end:
                    require_instruction_start(next_offset, "instruction after terminator")
                    leaders.add(next_offset)

        # exception handler region boundaries are structural block leaders
        for index, handler in enumerate(self.body.exception_handlers):
            region_points: List[Tuple[str, int]] = [
                ("try_start", handler.try_start),
                ("try_end", handler.try_end),
                ("handler_start", handler.handler_start),
                ("handler_end", handler.handler_end),
            ]
            if handler.is_filter():
                region_points.append(("filter_start", handler.filter_start))
            for name, relative in region_points:
                absolute: int = self._to_absolute(relative)
                require_instruction_start(absolute, "eh[%d] %s" % (index, name))
                if absolute < code_end:
                    leaders.add(absolute)

        return leaders

    def _build_blocks(self, instructions: Sequence["Instruction"], leaders: Set[int]) -> None:
        sorted_leaders: List[int] = sorted(leaders)
        leader_to_block_end: Dict[int, int] = {
            leader: next_leader for leader, next_leader in zip(sorted_leaders, sorted_leaders[1:])
        }
        leader_to_block_end[sorted_leaders[-1]] = instructions[-1].offset + instructions[-1].size

        for leader in sorted_leaders:
            block_end: int = leader_to_block_end[leader]
            block_instructions: List[Instruction] = [
                insn for insn in instructions if leader <= insn.offset < block_end
            ]
            if not block_instructions:
                raise ControlFlowGraphError("no instruction found for block leader 0x%X" % leader)
            block: BasicBlock = BasicBlock(leader, block_end, block_instructions)
            self.blocks.append(block)
            self._block_by_start[leader] = block

    # ------------------------------------------------------------------
    # explicit instruction-level edges
    # ------------------------------------------------------------------
    def _build_explicit_edges(self, instructions: Sequence["Instruction"], code_end: int) -> None:
        for block in self.blocks:
            insn: Instruction = block.last_instruction
            value: OpCodeValue = insn.opcode.value

            if insn.is_leave():
                self._add_edge(EdgeType.LEAVE, block, self._block_at(self._branch_target(insn)), insn)
                continue

            if self._is_unconditional_branch(insn):
                self._add_edge(
                    EdgeType.BRANCH, block, self._block_at(self._branch_target(insn)), insn
                )
                continue

            if self._is_conditional_branch(insn):
                self._add_edge(
                    EdgeType.CONDITIONAL_BRANCH,
                    block,
                    self._block_at(self._branch_target(insn)),
                    insn,
                )
                self._fallthrough_edge(block, insn, code_end)
                continue

            if value == OpCodeValue.Switch:
                for case_index, target in enumerate(insn.operand):
                    self._add_edge(
                        EdgeType.SWITCH,
                        block,
                        self._block_at(target),
                        insn,
                        case_index=case_index,
                    )
                self._fallthrough_edge(block, insn, code_end)
                continue

            if value in (OpCodeValue.Ret, OpCodeValue.Throw, OpCodeValue.Rethrow):
                self._add_edge(EdgeType.METHOD_EXIT, block, None, insn)
                continue

            if value == OpCodeValue.Endfilter:
                # filter outcome dispatch is derived from the filter handler region
                continue

            if value == OpCodeValue.Endfinally:
                # resume targets are derived from leave instructions crossing this finally
                self._add_finally_exit_edges(block, insn)
                continue

            if value == OpCodeValue.Jmp or value in _RESERVED_PREFIX_OPCODE_VALUES:
                self.unresolved.append(insn.offset)
                self._add_edge(EdgeType.UNRESOLVED, block, None, insn)
                continue

            # ordinary instructions (including known prefixes) continue sequentially
            self._fallthrough_edge(block, insn, code_end)

    def _fallthrough_edge(self, block: BasicBlock, insn: "Instruction", code_end: int) -> None:
        # documented prefixes annotate the following instruction, so they fall through
        assert self._is_known_prefix(insn) or insn.opcode.flow_control != FlowControl.Meta
        next_offset: int = insn.offset + insn.size
        if next_offset >= code_end:
            # malformed IL: a non-terminating instruction ends the stream
            self.unresolved.append(insn.offset)
            self._add_edge(EdgeType.UNRESOLVED, block, None, insn)
            return
        self._add_edge(EdgeType.FALLTHROUGH, block, self._block_at(next_offset), insn)

    # ------------------------------------------------------------------
    # exception handler region edges
    # ------------------------------------------------------------------
    def _build_exception_edges(self, code_end: int) -> None:
        for index, handler in enumerate(self.body.exception_handlers):
            try_start: int = self._to_absolute(handler.try_start)
            try_end: int = self._to_absolute(handler.try_end)

            if handler.is_filter():
                entry_edge_type: EdgeType = EdgeType.EXCEPTION_FILTER
                entry_offset: int = self._to_absolute(handler.filter_start)
                handler_offset: int = self._to_absolute(handler.handler_start)
            elif handler.is_catch():
                entry_edge_type = EdgeType.EXCEPTION_CATCH
                entry_offset = self._to_absolute(handler.handler_start)
                handler_offset = entry_offset
            elif handler.is_finally():
                entry_edge_type = EdgeType.EXCEPTION_FINALLY
                entry_offset = self._to_absolute(handler.handler_start)
                handler_offset = entry_offset
            elif handler.is_fault():
                entry_edge_type = EdgeType.EXCEPTION_FAULT
                entry_offset = self._to_absolute(handler.handler_start)
                handler_offset = entry_offset
            else:
                self.unresolved.append(try_start)
                continue

            # every block making up the protected region can raise into the handler
            for block in self.blocks:
                if try_start <= block.start and block.end <= try_end:
                    self._add_edge(
                        entry_edge_type,
                        block,
                        self._block_at(entry_offset),
                        handler,
                        handler_index=index,
                    )
            if handler.is_filter():
                # endfilter transfers the filter decision to the handler body
                filter_block: BasicBlock = self._block_containing(self._to_absolute(handler.filter_start))
                self._add_edge(
                    EdgeType.FILTER_DISPATCH,
                    filter_block,
                    self._block_at(handler_offset),
                    handler,
                    handler_index=index,
                )
    def _add_finally_exit_edges(self, endfinally_block: BasicBlock, endfinally: "Instruction") -> None:
        resume_targets: Set[int] = set()
        for handler in self.body.exception_handlers:
            if not handler.is_finally():
                continue
            try_start: int = self._to_absolute(handler.try_start)
            try_end: int = self._to_absolute(handler.try_end)
            handler_start: int = self._to_absolute(handler.handler_start)
            handler_end: int = self._to_absolute(handler.handler_end)
            # only the endfinally that closes this finally handler region resumes it
            if not (handler_start <= endfinally_block.start < handler_end):
                continue
            for insn in self.body.instructions:
                if not insn.is_leave():
                    continue
                leave_target: int = self._branch_target(insn)
                # a leave resumes here only when it exits this finally's protected region
                if try_start <= insn.offset < try_end and not (try_start <= leave_target < try_end):
                    resume_targets.add(leave_target)
        for target in sorted(resume_targets):
            self._add_edge(EdgeType.FINALLY_EXIT, endfinally_block, self._block_at(target), endfinally)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _to_absolute(self, il_relative_offset: int) -> int:
        """convert an exception table IL-relative offset to a stream offset"""
        return self.il_base + il_relative_offset

    def _block_at(self, offset: int) -> BasicBlock:
        block: Optional[BasicBlock] = self._block_by_start.get(offset)
        if block is None:
            raise ControlFlowGraphError("no basic block starts at 0x%X" % offset)
        return block

    def _block_containing(self, offset: int) -> BasicBlock:
        for block in self.blocks:
            if block.start <= offset < block.end:
                return block
        raise ControlFlowGraphError("no basic block contains offset 0x%X" % offset)

    def _branch_target(self, insn: "Instruction") -> int:
        # branch/leave operands are already absolute stream offsets
        return insn.operand

    def _is_branch(self, insn: "Instruction") -> bool:
        return (
            self._is_unconditional_branch(insn)
            or self._is_conditional_branch(insn)
            or insn.is_leave()
        )

    def _is_unconditional_branch(self, insn: "Instruction") -> bool:
        return insn.is_br()

    def _is_conditional_branch(self, insn: "Instruction") -> bool:
        return insn.is_cond_br() or insn.is_br_false() or insn.is_br_true()

    def _is_known_prefix(self, insn: "Instruction") -> bool:
        # documented prefixes only annotate the next instruction and fall through
        return insn.opcode.value in _PREFIX_OPCODE_VALUES

    def _is_terminator(self, insn: "Instruction") -> bool:
        value: OpCodeValue = insn.opcode.value
        return (
            self._is_branch(insn)
            or value == OpCodeValue.Switch
            or value in (
                OpCodeValue.Ret,
                OpCodeValue.Throw,
                OpCodeValue.Rethrow,
                OpCodeValue.Endfilter,
                OpCodeValue.Endfinally,
                OpCodeValue.Jmp,
            )
            or value in _RESERVED_PREFIX_OPCODE_VALUES
        )

    def _add_edge(
        self,
        edge_type: EdgeType,
        source: BasicBlock,
        target: Optional[BasicBlock],
        evidence,
        handler_index: Optional[int] = None,
        case_index: Optional[int] = None,
    ) -> None:
        target_start: int = -1 if target is None else target.start
        key: Tuple = (edge_type, source.start, target_start, handler_index, case_index, id(evidence))
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        edge: FlowEdge = FlowEdge(edge_type, source, target, evidence, handler_index, case_index)
        self.edges.append(edge)
        source.outgoing.append(edge)
        if target is not None:
            target.incoming.append(edge)

    # ------------------------------------------------------------------
    # read-only queries
    # ------------------------------------------------------------------
    def get_block(self, offset: int) -> Optional[BasicBlock]:
        """get basic block starting at an absolute stream offset, if any"""
        return self._block_by_start.get(offset)

    def get_edges_from(self, block: BasicBlock) -> Tuple[FlowEdge, ...]:
        """get all outgoing edges of a block"""
        return tuple(block.outgoing)

    def get_edges_to(self, block: BasicBlock) -> Tuple[FlowEdge, ...]:
        """get all incoming edges of a block"""
        return tuple(block.incoming)

    def _reachable(self, allowed: Sequence[EdgeType]) -> Set[BasicBlock]:
        allowed_set: Set[EdgeType] = set(allowed)
        seen: Set[BasicBlock] = set()
        worklist: List[BasicBlock] = [self.blocks[0]]
        while worklist:
            block: BasicBlock = worklist.pop()
            if block in seen:
                continue
            seen.add(block)
            for edge in block.outgoing:
                if edge.type in allowed_set and edge.target is not None and edge.target not in seen:
                    worklist.append(edge.target)
        return seen

    def reachable_blocks(self) -> Tuple[BasicBlock, ...]:
        """blocks reachable through normal instruction-level transfers only"""
        return tuple(block for block in self.blocks if block in self._reachable(NORMAL_EDGE_TYPES))

    def exception_reachable_blocks(self) -> Tuple[BasicBlock, ...]:
        """blocks reachable only through exception/filter/finally transfers"""
        normal: Set[BasicBlock] = self._reachable(NORMAL_EDGE_TYPES)
        full: Set[BasicBlock] = self._reachable(NORMAL_EDGE_TYPES + EXCEPTION_EDGE_TYPES)
        return tuple(block for block in self.blocks if block in full and block not in normal)

    def unreachable_blocks(self) -> Tuple[BasicBlock, ...]:
        """blocks not reachable even when exception handler edges are followed"""
        full: Set[BasicBlock] = self._reachable(NORMAL_EDGE_TYPES + EXCEPTION_EDGE_TYPES)
        return tuple(block for block in self.blocks if block not in full)

    @property
    def entry_block(self) -> BasicBlock:
        """first basic block of the method"""
        return self.blocks[0]

    def __str__(self) -> str:
        lines: List[str] = []
        for block in self.blocks:
            labels: str = (" {" + ",".join(block.labels) + "}") if block.labels else ""
            lines.append("block@0x%X-0x%X%s" % (block.start, block.end, labels))
            for insn in block.instructions:
                lines.append("    %s" % insn)
            for edge in block.outgoing:
                lines.append("    -> %s [%s]" % (edge.type.value, edge.describe()))
        return "\n".join(lines)
