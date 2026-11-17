# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
"""Logical control-flow extraction from both dncil output and the layout record.

Everything here is expressed in logical labels.  Byte offsets are used only to find
which instruction a branch displacement points at; they never appear in the result, so
two layouts that differ by instruction widths compare equal when their logic matches.
"""

from __future__ import annotations

from typing import Set, Dict, List, Tuple, Mapping, Optional
from dataclasses import dataclass

from dncil.cil.body import CilMethodBody
from dncil.cil.enums import FlowControl, OpCodeValue
from dncil.cil.exception import ExceptionHandler
from dncil.cil.body.reader import read_method_body_from_bytes
from dncil.cil.instruction import Instruction
from tests.metamorphic.layout import MethodLayout
from tests.metamorphic.il_spec import BRANCHES, BRANCH_SEMANTICS

#: (source label, target label, edge kind); kind in {"branch", "cond", "switch", "fallthrough"}
Edge = Tuple[str, str, str]

#: (kind, try_start, try_end, handler_start, handler_end, filter_start) in logical labels
LogicalClause = Tuple[str, Optional[str], str, Optional[str], str, Optional[str]]


class DecodeError(Exception):
    """dncil output could not be interpreted in logical terms"""


@dataclass(frozen=True)
class MissingEdge:
    """an expected logical edge that the decoder did not report"""

    source: str
    target: str
    kind: str
    actual_target: Optional[str]
    actual_offset: Optional[int]
    note: str


@dataclass(frozen=True)
class UnexpectedEdge:
    """a logical edge the decoder reported that the specification does not contain"""

    source: str
    target: str
    kind: str
    actual_offset: int
    note: str


@dataclass(frozen=True)
class Mismatch:
    """difference between expected and actual logical control flow"""

    missing_edges: Tuple[MissingEdge, ...] = ()
    unexpected_edges: Tuple[UnexpectedEdge, ...] = ()
    missing_clauses: Tuple[LogicalClause, ...] = ()
    unexpected_clauses: Tuple[LogicalClause, ...] = ()
    notes: Tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.missing_edges or self.unexpected_edges or self.missing_clauses or self.unexpected_clauses)

    def describe(self) -> str:
        """one line per difference, e.g. a missing edge and the wrong edge that replaced it.

        Edges are named by logical labels; byte offsets are appended only to help a human
        locate the wrong target, and never take part in the comparison itself.
        """

        if not self:
            return "logical control flow matches"
        lines: List[str] = []
        for missing in self.missing_edges:
            actual = missing.actual_target or "outside the method"
            if missing.actual_offset is not None:
                actual = "%s (IL_%04X)" % (actual, missing.actual_offset)
            lines.append(
                "missing %s edge %s -> %s; decoder instead points at %s [%s]"
                % (missing.kind, missing.source, missing.target, actual, missing.note)
            )
        for unexpected in self.unexpected_edges:
            lines.append(
                "unexpected %s edge %s -> %s at IL_%04X [%s]"
                % (unexpected.kind, unexpected.source, unexpected.target, unexpected.actual_offset, unexpected.note)
            )
        for clause in self.missing_clauses:
            lines.append("missing exception clause %s" % (clause,))
        for clause in self.unexpected_clauses:
            lines.append("unexpected exception clause %s" % (clause,))
        for note in self.notes:
            lines.append(note)
        return "\n".join(lines)


@dataclass(frozen=True)
class LogicalCFG:
    """decoded control flow expressed in logical labels"""

    label_offsets: Mapping[str, int]
    edges: Set[Edge]
    clauses: Set[LogicalClause]
    mnemonics: Mapping[str, str]
    instruction_sizes: Mapping[str, int]
    code_size: int


def _branch_semantic(mnemonic: str) -> Optional[str]:
    return BRANCH_SEMANTICS.get(mnemonic)


def _is_switch(instruction: Instruction) -> bool:
    return instruction.opcode.value == OpCodeValue.Switch


def _label_map_from_layout(layout: MethodLayout) -> Dict[int, str]:
    return {instruction.offset: instruction.label for instruction in layout.instructions}


def extract_dncil_cfg(
    layout: MethodLayout,
    body: Optional[CilMethodBody] = None,
    tolerate_invalid_targets: bool = False,
) -> LogicalCFG:
    """decode ``layout.raw`` with dncil and convert it to logical labels.

    ``layout`` supplies the mapping from code-relative offsets to labels.  Using the
    layout's mapping (rather than inventing our own ordering) means a decoder that
    mis-sizes an instruction shows up as a wrong/missing label immediately.
    """

    if body is None:
        body = read_method_body_from_bytes(layout.raw)
    base = body.header_size
    by_offset = _label_map_from_layout(layout)

    label_offsets: Dict[str, int] = {}
    mnemonics: Dict[str, str] = {}
    sizes: Dict[str, int] = {}
    edges: Set[Edge] = set()

    ordered: List[Tuple[int, str]] = []
    for instruction in body.instructions:
        relative = instruction.offset - base
        label = by_offset.get(relative)
        if label is None:
            raise DecodeError(
                "decoder reports an instruction at IL_%04X, which is not the start of any "
                "instruction in the expected layout (expected starts: %s)"
                % (relative, ", ".join("IL_%04X" % offset for offset in sorted(by_offset)))
            )
        if instruction.size != layout.instruction(label).size:
            raise DecodeError(
                "decoder sizes instruction %s at IL_%04X as %d bytes, expected %d"
                % (label, relative, instruction.size, layout.instruction(label).size)
            )
        label_offsets[label] = relative
        mnemonics[label] = instruction.mnemonic
        sizes[label] = instruction.size
        ordered.append((relative, label))

    ordered.sort()
    if [label for _, label in ordered] != [instruction.label for instruction in layout.instructions]:
        raise DecodeError(
            "decoder found instructions in a different logical order than the layout: %s"
            % ", ".join(label for _, label in ordered)
        )

    def resolve(raw_target: int, source: str, kind: str) -> str:
        relative = raw_target - base
        if relative in by_offset:
            return by_offset[relative]
        enclosure = layout.enclosure(relative)
        if enclosure is not None:
            if not tolerate_invalid_targets:
                raise DecodeError(
                    "%s edge from %s points into the middle of instruction %s at IL_%04X (+%d bytes)"
                    % (kind, source, enclosure[0], relative, enclosure[1])
                )
            # a stable, label-shaped marker: the comparison reports it as a wrong target
            return "<inside %s +%d>" % (enclosure[0], enclosure[1])
        if not tolerate_invalid_targets:
            raise DecodeError("%s edge from %s points outside the method at IL_%04X" % (kind, source, relative))
        return "<outside method IL_%04X>" % relative

    for index, instruction in enumerate(body.instructions):
        source = by_offset[instruction.offset - base]
        semantic = _branch_semantic(instruction.mnemonic)
        if _is_switch(instruction):
            targets = instruction.operand
            if not isinstance(targets, list):
                raise DecodeError("switch %s has a non-list operand %r" % (source, targets))
            for raw_target in targets:
                edges.add((source, resolve(raw_target, source, "switch"), "switch"))
        elif semantic is not None:
            if not isinstance(instruction.operand, int):
                raise DecodeError("branch %s has a non-integer operand %r" % (source, instruction.operand))
            edges.add(
                (
                    source,
                    resolve(instruction.operand, source, "branch"),
                    "cond" if BRANCHES[semantic].conditional else "branch",
                )
            )
        # fallthrough is a property of the decoded opcode's flow control, not of the
        # expected layout, so a widening bug that swaps an opcode also shows up here
        if instruction.opcode.flow_control not in (FlowControl.Branch, FlowControl.Return, FlowControl.Throw):
            if index + 1 < len(body.instructions):
                edges.add((source, by_offset[body.instructions[index + 1].offset - base], "fallthrough"))

    clauses: Set[LogicalClause] = set()
    for handler in body.exception_handlers:
        clauses.add(_logical_clause_from_dncil(handler, layout, tolerate_invalid_targets))

    return LogicalCFG(
        label_offsets=label_offsets,
        edges=edges,
        clauses=clauses,
        mnemonics=mnemonics,
        instruction_sizes=sizes,
        code_size=body.code_size,
    )


def _logical_clause_from_dncil(
    handler: ExceptionHandler, layout: MethodLayout, tolerate_invalid_targets: bool = False
) -> LogicalClause:
    """convert one dncil ExceptionHandler to labels, validating boundaries are real"""

    def label_of(offset: int, what: str) -> str:
        label = layout.label_at(offset)
        if label is not None:
            return label
        enclosure = layout.enclosure(offset)
        if enclosure is not None:
            if tolerate_invalid_targets:
                return "<inside %s +%d>" % (enclosure[0], enclosure[1])
            raise DecodeError(
                "exception clause %s boundary IL_%04X lies inside instruction %s (+%d bytes)"
                % (what, offset, enclosure[0], enclosure[1])
            )
        if tolerate_invalid_targets:
            return "<outside method IL_%04X>" % offset
        raise DecodeError("exception clause %s boundary IL_%04X is outside the method" % (what, offset))

    try_start = label_of(handler.try_start, "try start")
    try_end = label_of(handler.try_end, "try end")
    handler_start = label_of(handler.handler_start, "handler start")
    handler_end = label_of(handler.handler_end, "handler end")
    if handler.is_catch():
        return ("catch", None, try_start, try_end, handler_start, handler_end)
    if handler.is_filter():
        filter_start = label_of(handler.filter_start, "filter start")
        return ("filter", filter_start, try_start, try_end, handler_start, handler_end)
    if handler.is_finally():
        return ("finally", None, try_start, try_end, handler_start, handler_end)
    if handler.is_fault():
        return ("fault", None, try_start, try_end, handler_start, handler_end)
    raise DecodeError("exception clause has an unknown kind 0x%02X" % handler.exception_type)


def expected_logical_clauses(layout: MethodLayout) -> Set[LogicalClause]:
    clauses: Set[LogicalClause] = set()
    for clause in layout.clauses:
        filter_label = layout.label_at(clause.filter_start) if clause.filter_start is not None else None
        clauses.add(
            (
                clause.kind,
                filter_label,
                layout.label_at(clause.try_start) or "?",
                layout.label_at(clause.try_end) or "?",
                layout.label_at(clause.handler_start) or "?",
                layout.label_at(clause.handler_end) or "?",
            )
        )
    return clauses


def expected_cfg(layout: MethodLayout) -> LogicalCFG:
    """logical CFG implied by the independent layout record (not by dncil)"""

    edges: Set[Edge] = set()
    label_offsets: Dict[str, int] = {}
    mnemonics: Dict[str, str] = {}
    sizes: Dict[str, int] = {}
    for index, instruction in enumerate(layout.instructions):
        label_offsets[instruction.label] = instruction.offset
        mnemonics[instruction.label] = instruction.opcode
        sizes[instruction.label] = instruction.size
        if instruction.is_switch:
            for target in instruction.targets:
                edges.add((instruction.label, target, "switch"))
        elif instruction.is_branch:
            kind = "cond" if BRANCHES[instruction.semantic].conditional else "branch"
            edges.add((instruction.label, instruction.targets[0], kind))
        if instruction.falls_through and index + 1 < len(layout.instructions):
            edges.add((instruction.label, layout.instructions[index + 1].label, "fallthrough"))
    return LogicalCFG(
        label_offsets=label_offsets,
        edges=edges,
        clauses=expected_logical_clauses(layout),
        mnemonics=mnemonics,
        instruction_sizes=sizes,
        code_size=layout.code_size,
    )


def compare_cfgs(expected: LogicalCFG, actual: LogicalCFG) -> Mismatch:
    """compare two logical CFGs; the result names every differing logical edge"""

    label_offsets = dict(actual.label_offsets)
    missing_edges: List[MissingEdge] = []
    unexpected_edges: List[UnexpectedEdge] = []
    notes: List[str] = []

    for edge in sorted(expected.edges - actual.edges):
        source, target, kind = edge
        candidates = [other for other in actual.edges if other[0] == source and other[2] == kind]
        if len(candidates) == 1:
            actual_target = candidates[0][1]
            actual_offset = label_offsets.get(actual_target)
            note = "single %s edge from this instruction" % kind
        elif candidates:
            actual_target = ",".join(sorted(other[1] for other in candidates))
            actual_offset = None
            note = "decoder split the %s edge into several" % kind
        else:
            actual_target = None
            actual_offset = None
            note = "decoder reported no %s edge from this instruction" % kind
        missing_edges.append(
            MissingEdge(
                source=source,
                target=target,
                kind=kind,
                actual_target=actual_target,
                actual_offset=actual_offset,
                note=note,
            )
        )

    for unexpected in sorted(actual.edges - expected.edges):
        source, target, kind = unexpected
        unexpected_edges.append(
            UnexpectedEdge(
                source=source,
                target=target,
                kind=kind,
                actual_offset=actual.label_offsets.get(target, -1),
                note="not present in the specification",
            )
        )

    missing_clauses = tuple(sorted(expected.clauses - actual.clauses))
    unexpected_clauses = tuple(sorted(actual.clauses - expected.clauses))
    if expected.code_size != actual.code_size:
        notes.append("code size differs: expected %d, decoded %d" % (expected.code_size, actual.code_size))

    return Mismatch(
        missing_edges=tuple(missing_edges),
        unexpected_edges=tuple(unexpected_edges),
        missing_clauses=missing_clauses,
        unexpected_clauses=unexpected_clauses,
        notes=tuple(notes),
    )
