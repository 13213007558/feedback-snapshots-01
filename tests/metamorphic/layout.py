# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
"""Independent byte layout for :mod:`tests.metamorphic.il_spec` method specifications.

This module is the "ground truth" side of the regression: it assigns every instruction a
logical label, a code-relative offset and a byte encoding, and it encodes every branch,
switch target and exception boundary from those labels.  Widening a method re-lays-out
all instructions and therefore re-resolves *every* label-derived value; nothing is
patched in place by absolute offset.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Tuple, Mapping, Optional, Sequence
from dataclasses import dataclass

from tests.metamorphic.il_spec import BRANCHES, TERMINATORS, SWITCH_OPCODE, SIMPLE_OPCODES, Form, InsnSpec, MethodSpec

#: CLR limit for a managed method body's IL stream
MAX_CODE_SIZE = 0x10000

#: fat exception section header limits
MAX_FAT_SECTION_SIZE = 0xFFFFFF


class LayoutError(Exception):
    """base class for fixture layout failures"""


class CannotWiden(LayoutError):
    """the method cannot be transformed safely; ``reasons`` says exactly why"""

    def __init__(self, reasons: Sequence[str]):
        self.reasons: Tuple[str, ...] = tuple(reasons)
        super().__init__("; ".join(self.reasons))

    def __str__(self) -> str:
        return "cannot widen method safely: " + "; ".join(self.reasons)


class InvalidMethod(LayoutError):
    """the method specification cannot be encoded as a well-formed body"""


@dataclass(frozen=True)
class InstructionLayout:
    """expected position and encoding of one logical instruction"""

    label: str
    offset: int
    size: int
    opcode: str
    semantic: str
    form: Optional[Form]
    targets: Tuple[str, ...]
    raw: bytes

    @property
    def end(self) -> int:
        return self.offset + self.size

    @property
    def is_branch(self) -> bool:
        return self.semantic in BRANCHES

    @property
    def is_switch(self) -> bool:
        return self.semantic == "switch"

    @property
    def is_terminator(self) -> bool:
        return self.semantic in TERMINATORS

    @property
    def falls_through(self) -> bool:
        if self.is_switch:
            return True
        if self.is_branch:
            return BRANCHES[self.semantic].conditional
        return not self.is_terminator


@dataclass(frozen=True)
class ClauseLayout:
    """expected position of one exception clause, in code-relative offsets"""

    index: int
    kind: str
    flags: int
    try_start: int
    try_end: int
    handler_start: int
    handler_end: int
    filter_start: Optional[int]
    catch_type: Optional[int]

    @property
    def try_length(self) -> int:
        return self.try_end - self.try_start

    @property
    def handler_length(self) -> int:
        return self.handler_end - self.handler_start


@dataclass(frozen=True)
class MethodLayout:
    """expected layout plus the exact bytes that encode it"""

    spec: MethodSpec
    instructions: Tuple[InstructionLayout, ...]
    clauses: Tuple[ClauseLayout, ...]
    label_offsets: Mapping[str, int]
    header_size: int
    header_format: str
    code_size: int
    section_format: Optional[str]
    section_offset: Optional[int]
    raw: bytes
    widened: bool = False
    mutation: Optional[str] = None

    def offset_of(self, label: str) -> int:
        return self.label_offsets[label]

    def instruction(self, label: str) -> InstructionLayout:
        for instruction in self.instructions:
            if instruction.label == label:
                return instruction
        raise KeyError("unknown instruction label %r" % label)

    def label_at(self, offset: int) -> Optional[str]:
        for instruction in self.instructions:
            if instruction.offset == offset:
                return instruction.label
        return None

    def enclosure(self, offset: int) -> Optional[Tuple[str, int]]:
        """label of the instruction containing ``offset`` and the byte delta into it"""

        for instruction in self.instructions:
            if instruction.offset <= offset < instruction.end:
                return instruction.label, offset - instruction.offset
        return None


def _branch_plan(spec: MethodSpec, widen_short: bool) -> Dict[str, Form]:
    plan: Dict[str, Form] = {}
    for insn in spec.instructions:
        if insn.is_branch:
            plan[insn.label] = Form.LONG if widen_short else insn.effective_form()
    return plan


def _offsets(spec: MethodSpec, forms: Mapping[str, Form]) -> Dict[str, int]:
    offsets: Dict[str, int] = {}
    cursor = 0
    for insn in spec.instructions:
        offsets[insn.label] = cursor
        cursor += insn.size(forms.get(insn.label))
    offsets["<end>"] = cursor
    return offsets


def _encode_branch(insn: InsnSpec, form: Form, offset: int, target_offset: int) -> bytes:
    encoding = insn.encoding
    opcode = encoding.short_byte if form is Form.SHORT else encoding.long_byte
    delta = target_offset - (offset + form.branch_size)
    if form is Form.SHORT:
        if not -128 <= delta <= 127:
            raise InvalidMethod(
                "short branch %s -> %s has byte displacement %d, outside int8"
                % (insn.label, insn.branch_target(), delta)
            )
        return bytes([opcode]) + struct.pack("<b", delta)
    return bytes([opcode]) + struct.pack("<i", delta)


def _encode_switch(insn: InsnSpec, offset: int, target_offsets: Sequence[int]) -> bytes:
    targets = insn.switch_targets()
    end = offset + 1 + 4 + 4 * len(targets)
    out = bytearray(SWITCH_OPCODE + struct.pack("<I", len(targets)))
    for target, target_offset in zip(targets, target_offsets):
        out += struct.pack("<i", target_offset - end)
    return bytes(out)


def _encode_code(
    spec: MethodSpec,
    forms: Mapping[str, Form],
    offsets: Mapping[str, int],
    branch_target_offsets: Optional[Mapping[str, int]] = None,
    switch_target_offsets: Optional[Mapping[Tuple[str, int], int]] = None,
) -> Tuple[bytes, Tuple[InstructionLayout, ...]]:
    out = bytearray()
    layout: List[InstructionLayout] = []
    for insn in spec.instructions:
        offset = offsets[insn.label]
        if insn.is_branch:
            form = forms[insn.label]
            target = insn.branch_target()
            target_offset = (
                branch_target_offsets[insn.label]
                if branch_target_offsets is not None and insn.label in branch_target_offsets
                else offsets[target]
            )
            raw = _encode_branch(insn, form, offset, target_offset)
            layout.append(
                InstructionLayout(
                    label=insn.label,
                    offset=offset,
                    size=len(raw),
                    opcode=insn.encoding.short_name if form is Form.SHORT else insn.encoding.long_name,
                    semantic=insn.opcode,
                    form=form,
                    targets=(target,),
                    raw=raw,
                )
            )
        elif insn.is_switch:
            targets = insn.switch_targets()
            target_offsets = []
            for index, target in enumerate(targets):
                if switch_target_offsets is not None and (insn.label, index) in switch_target_offsets:
                    target_offsets.append(switch_target_offsets[(insn.label, index)])
                else:
                    target_offsets.append(offsets[target])
            raw = _encode_switch(insn, offset, target_offsets)
            layout.append(
                InstructionLayout(
                    label=insn.label,
                    offset=offset,
                    size=len(raw),
                    opcode=insn.opcode,
                    semantic=insn.opcode,
                    form=None,
                    targets=targets,
                    raw=raw,
                )
            )
        else:
            raw = SIMPLE_OPCODES[insn.opcode]
            layout.append(
                InstructionLayout(
                    label=insn.label,
                    offset=offset,
                    size=len(raw),
                    opcode=insn.opcode,
                    semantic=insn.opcode,
                    form=None,
                    targets=(),
                    raw=raw,
                )
            )
        out += raw
    return bytes(out), tuple(layout)


def _clause_layouts(
    spec: MethodSpec,
    offsets: Mapping[str, int],
    overrides: Optional[Sequence[Mapping[str, Optional[int]]]] = None,
) -> Tuple[ClauseLayout, ...]:
    clauses: List[ClauseLayout] = []
    for index, clause in enumerate(spec.exception_handlers):
        values: Dict[str, Optional[int]] = {
            "try_start": offsets[clause.try_start],
            "try_end": offsets[clause.try_end],
            "handler_start": offsets[clause.handler_start],
            "handler_end": offsets[clause.handler_end],
            "filter_start": offsets[clause.filter_start] if clause.filter_start is not None else None,
        }
        if overrides is not None:
            values.update(overrides[index])
        clauses.append(
            ClauseLayout(
                index=index,
                kind=clause.kind,
                flags=clause.flags,
                try_start=_required(values, "try_start", index),
                try_end=_required(values, "try_end", index),
                handler_start=_required(values, "handler_start", index),
                handler_end=_required(values, "handler_end", index),
                filter_start=values["filter_start"],
                catch_type=clause.catch_type,
            )
        )
    return tuple(clauses)


def _required(values: Mapping[str, Optional[int]], key: str, index: int) -> int:
    value = values[key]
    if value is None:
        raise InvalidMethod("exception clause %d is missing its %s boundary" % (index, key))
    return value


def _tiny_clause_bytes(clause: ClauseLayout, extra: int) -> bytes:
    return struct.pack(
        "<HHBHBI",
        clause.flags,
        clause.try_start,
        clause.try_length,
        clause.handler_start,
        clause.handler_length,
        extra,
    )


def _fat_clause_bytes(clause: ClauseLayout, extra: int) -> bytes:
    return struct.pack(
        "<IIIIII",
        clause.flags,
        clause.try_start,
        clause.try_length,
        clause.handler_start,
        clause.handler_length,
        extra,
    )


def _clause_extra(clause: ClauseLayout, spec: MethodSpec) -> int:
    exception = spec.exception_handlers[clause.index]
    if exception.kind == "catch":
        assert clause.catch_type is not None
        return clause.catch_type
    if exception.kind == "filter":
        assert clause.filter_start is not None
        return clause.filter_start
    return 0


def check_widenability(spec: MethodSpec) -> Tuple[str, ...]:
    """return concrete reasons why the method cannot be safely widened.

    An empty tuple means every short branch can be replaced by its long form and the
    method header / exception section can encode the new layout without loss.
    """

    spec.validate()
    reasons: List[str] = []

    baseline_offsets = _offsets(spec, _branch_plan(spec, widen_short=False))
    for insn in spec.instructions:
        if not insn.is_branch or insn.effective_form() is not Form.SHORT:
            continue
        delta = baseline_offsets[insn.branch_target()] - (baseline_offsets[insn.label] + 2)
        if not -128 <= delta <= 127:
            reasons.append(
                "short branch %s -> %s already has byte displacement %d outside int8; "
                "the original method is not well-formed" % (insn.label, insn.branch_target(), delta)
            )

    if not spec.short_branch_labels():
        reasons.append(
            "method has no short branch to widen; the transform is a no-op and is not a meaningful " "metamorphic pair"
        )

    forms = _branch_plan(spec, widen_short=True)
    widened_offsets = _offsets(spec, forms)
    widened_code_size = widened_offsets["<end>"]

    if spec.header_format == "tiny" and widened_code_size > 63:
        reasons.append(
            "tiny method header cannot encode widened code size %d bytes (maximum 63); "
            "promote the method body to a fat header or leave it unwidened" % widened_code_size
        )
    if widened_code_size > MAX_CODE_SIZE:
        reasons.append(
            "widened code size %d bytes exceeds the %d-byte CLR method limit" % (widened_code_size, MAX_CODE_SIZE)
        )

    if spec.exception_handlers:
        widened_clauses = _clause_layouts(spec, widened_offsets)
        if spec.exception_section_format == "tiny":
            if len(widened_clauses) > 21:
                reasons.append(
                    "tiny exception section can encode at most 21 clauses, method has %d" % len(widened_clauses)
                )
            for clause in widened_clauses:
                if clause.try_length > 0xFF:
                    reasons.append(
                        "tiny exception section cannot encode try region [%s, %s) of %d bytes after "
                        "widening (maximum 255); use a fat exception section"
                        % (
                            spec.exception_handlers[clause.index].try_start,
                            spec.exception_handlers[clause.index].try_end,
                            clause.try_length,
                        )
                    )
                if clause.handler_length > 0xFF:
                    reasons.append(
                        "tiny exception section cannot encode handler region [%s, %s) of %d bytes after "
                        "widening (maximum 255); use a fat exception section"
                        % (
                            spec.exception_handlers[clause.index].handler_start,
                            spec.exception_handlers[clause.index].handler_end,
                            clause.handler_length,
                        )
                    )
        else:
            if len(widened_clauses) * 24 > MAX_FAT_SECTION_SIZE:
                reasons.append("fat exception section exceeds its 24-bit size field")
        for clause in widened_clauses:
            if clause.try_end < clause.try_start:
                reasons.append("clause %d try region has a negative length" % clause.index)
            if clause.handler_end < clause.handler_start:
                reasons.append("clause %d handler region has a negative length" % clause.index)

    return tuple(reasons)


def _assemble(
    spec: MethodSpec,
    forms: Mapping[str, Form],
    offsets: Mapping[str, int],
    layout: Tuple[InstructionLayout, ...],
    clauses: Tuple[ClauseLayout, ...],
    widened: bool,
    mutation: Optional[str],
    encoded_clauses: Optional[Tuple[ClauseLayout, ...]] = None,
) -> MethodLayout:
    """assemble the body bytes.

    ``clauses`` is the layout record the comparison uses; ``encoded_clauses`` may hold
    different (e.g. deliberately stale) values for the bytes actually written.
    """

    encoded_clauses = clauses if encoded_clauses is None else encoded_clauses
    code = b"".join(instruction.raw for instruction in layout)
    assert len(code) == offsets["<end>"]
    has_clauses = bool(clauses)

    if spec.header_format == "tiny":
        if has_clauses:
            raise InvalidMethod("tiny header cannot carry exception handlers")
        if len(code) > 63:
            raise InvalidMethod("tiny header code size %d exceeds 63" % len(code))
        header = bytes([(len(code) << 2) | 0x02])
    else:
        flags = 0x3003 | (0x10 if spec.init_locals else 0) | (0x08 if has_clauses else 0)
        header = struct.pack("<HHII", flags, spec.max_stack, len(code), spec.local_sig)

    body = bytearray(header)
    body += code
    if has_clauses:
        padding = (-len(body)) % 4
        body += b"\x00" * padding

    section_format: Optional[str] = None
    section_offset: Optional[int] = None
    section = bytearray()
    if has_clauses:
        section_format = spec.exception_section_format
        section_offset = len(body)
        if section_format == "tiny":
            if len(clauses) > 21:
                raise InvalidMethod("tiny exception section cannot encode %d clauses" % len(clauses))
            section.append(1)
            section.append(12 * len(clauses))
            section += b"\x00\x00"
            for clause in encoded_clauses:
                try:
                    section += _tiny_clause_bytes(clause, _clause_extra(clause, spec))
                except struct.error as e:
                    raise InvalidMethod("tiny exception clause %d does not fit: %s" % (clause.index, e))
        else:
            clauses_bytes = b"".join(
                _fat_clause_bytes(clause, _clause_extra(clause, spec)) for clause in encoded_clauses
            )
            total = len(clauses_bytes)
            if total > MAX_FAT_SECTION_SIZE:
                raise InvalidMethod("fat exception section is too large: %d bytes" % total)
            section.append(0x01 | 0x40)
            section += total.to_bytes(3, "little")
            section += clauses_bytes
        body += section

    return MethodLayout(
        spec=spec,
        instructions=layout,
        clauses=clauses,
        label_offsets={key: value for key, value in offsets.items() if key != "<end>"},
        header_size=len(header),
        header_format=spec.header_format,
        code_size=len(code),
        section_format=section_format,
        section_offset=section_offset,
        raw=bytes(body),
        widened=widened,
        mutation=mutation,
    )


def build(spec: MethodSpec, widen_short: bool = False) -> MethodLayout:
    """encode ``spec``, optionally replacing every short branch with its long form"""

    spec.validate()
    if widen_short:
        reasons = check_widenability(spec)
        if reasons:
            raise CannotWiden(reasons)
    forms = _branch_plan(spec, widen_short=widen_short)
    offsets = _offsets(spec, forms)
    code, layout = _encode_code(spec, forms, offsets)
    clauses = _clause_layouts(spec, offsets) if spec.exception_handlers else ()
    return _assemble(spec, forms, offsets, layout, clauses, widened=widen_short, mutation=None)


def build_with_stale_branch(spec: MethodSpec, label: str) -> MethodLayout:
    """build the widened body but leave one branch's displacement from the original layout.

    This models a transformer that updated the opcode and instruction size but forgot to
    re-resolve the displacement of a branch whose target crosses a widened instruction.
    The returned layout record still describes the *intended* mapping, so a regression
    using it must observe the stale target as a wrong logical edge.
    """

    baseline = build(spec, widen_short=False)
    stale_instruction = baseline.instruction(label)
    target_label = spec.instruction(label).branch_target()
    stale_delta = baseline.offset_of(target_label) - stale_instruction.end
    return _build_mutated(spec, branch_deltas={label: stale_delta}, mutation="stale branch %s" % label)


def build_with_stale_switch_target(spec: MethodSpec, label: str, index: int) -> MethodLayout:
    """build the widened body but leave one switch case's displacement unrelocated"""

    baseline = build(spec, widen_short=False)
    stale_instruction = baseline.instruction(label)
    target_label = spec.instruction(label).switch_targets()[index]
    stale_delta = baseline.offset_of(target_label) - stale_instruction.end
    return _build_mutated(
        spec,
        switch_deltas={(label, index): stale_delta},
        mutation="stale switch %s[%d]" % (label, index),
    )


def build_with_stale_exception_handlers(spec: MethodSpec) -> MethodLayout:
    """build the widened body but leave every exception clause boundary unrelocated"""

    baseline = build(spec, widen_short=False)
    overrides = [
        {
            "try_start": clause.try_start,
            "try_end": clause.try_end,
            "handler_start": clause.handler_start,
            "handler_end": clause.handler_end,
            "filter_start": clause.filter_start,
        }
        for clause in baseline.clauses
    ]
    return _build_mutated(spec, stale_clauses=overrides, mutation="stale exception handlers")


def _build_mutated(
    spec: MethodSpec,
    branch_deltas: Optional[Mapping[str, int]] = None,
    switch_deltas: Optional[Mapping[Tuple[str, int], int]] = None,
    stale_clauses: Optional[Sequence[Mapping[str, Optional[int]]]] = None,
    mutation: Optional[str] = None,
) -> MethodLayout:
    """build a widened body with selected displacements copied from the original layout.

    The deltas are the original relative displacements; the layout record still
    describes the intended mapping, so the regression can name the actual wrong edge
    the decoder reports.
    """

    reasons = check_widenability(spec)
    if reasons:
        raise CannotWiden(reasons)
    forms = _branch_plan(spec, widen_short=True)
    offsets = _offsets(spec, forms)

    branch_target_offsets = None
    if branch_deltas:
        branch_target_offsets = {}
        for label, delta in branch_deltas.items():
            instruction = spec.instruction(label)
            size = forms[label].branch_size
            branch_target_offsets[label] = offsets[label] + size + delta

    switch_target_offsets = None
    if switch_deltas:
        switch_target_offsets = {}
        for (label, index), delta in switch_deltas.items():
            end = offsets[label] + spec.instruction(label).size()
            switch_target_offsets[(label, index)] = end + delta

    code, layout = _encode_code(
        spec,
        forms,
        offsets,
        branch_target_offsets=branch_target_offsets,
        switch_target_offsets=switch_target_offsets,
    )
    clauses = _clause_layouts(spec, offsets) if spec.exception_handlers else ()
    encoded_clauses = _clause_layouts(spec, offsets, overrides=stale_clauses) if stale_clauses is not None else clauses
    return _assemble(
        spec,
        forms,
        offsets,
        layout,
        clauses,
        widened=True,
        mutation=mutation,
        encoded_clauses=encoded_clauses,
    )


def branches_needing_relocation(spec: MethodSpec) -> Tuple[str, ...]:
    """labels of branches whose displacement actually changes when the method is widened.

    A branch whose source and target both sit before (or both after) every widened
    instruction keeps its relative displacement, so forgetting to re-resolve it is not
    an error and the bytes stay identical.  Only the returned labels are meaningful
    "forgot to relocate" mutations.
    """

    baseline = build(spec, widen_short=False)
    widened = build(spec, widen_short=True)
    labels: List[str] = []
    for insn in spec.instructions:
        if not insn.is_branch:
            continue
        old_delta = baseline.offset_of(insn.branch_target()) - baseline.instruction(insn.label).end
        new_delta = widened.offset_of(insn.branch_target()) - widened.instruction(insn.label).end
        if old_delta != new_delta:
            labels.append(insn.label)
    return tuple(labels)


def switch_targets_needing_relocation(spec: MethodSpec, label: str) -> Tuple[int, ...]:
    """indices of switch cases whose displacement actually changes when widened"""

    baseline = build(spec, widen_short=False)
    widened = build(spec, widen_short=True)
    insn = spec.instruction(label)
    indices: List[int] = []
    for index, target in enumerate(insn.switch_targets()):
        old_delta = baseline.offset_of(target) - baseline.instruction(label).end
        new_delta = widened.offset_of(target) - widened.instruction(label).end
        if old_delta != new_delta:
            indices.append(index)
    return tuple(indices)


def describe_stale_target(spec: MethodSpec, label: str) -> Tuple[Optional[str], int]:
    """where an unrelocated branch from ``label`` lands in the widened body.

    Returns ``(label, delta)`` where ``label`` is the instruction it points at, or
    ``(None, delta)`` and the caller can consult :meth:`MethodLayout.enclosure` when the
    target falls inside an instruction.  ``delta`` is the byte delta into that
    instruction, or 0 for an exact instruction start.
    """

    baseline = build(spec, widen_short=False)
    widened = build(spec, widen_short=True)
    stale_delta = baseline.offset_of(spec.instruction(label).branch_target()) - baseline.instruction(label).end
    stale_offset = widened.instruction(label).end + stale_delta
    exact = widened.label_at(stale_offset)
    if exact is not None:
        return exact, 0
    enclosure = widened.enclosure(stale_offset)
    if enclosure is None:
        return None, -1
    return enclosure


def format_layout(layout: MethodLayout, title: Optional[str] = None) -> str:
    """human-readable listing using logical labels, never absolute branch offsets"""

    lines: List[str] = []
    header = "%s [%s]" % (layout.spec.name, "widened" if layout.widened else "original")
    if title:
        header = "%s: %s" % (title, header)
    lines.append(header)
    lines.append(
        "  header=%s (%d bytes) code=%d bytes section=%s"
        % (layout.header_format, layout.header_size, layout.code_size, layout.section_format or "none")
    )
    for instruction in layout.instructions:
        if instruction.is_branch:
            target = "-> %s" % instruction.targets[0]
        elif instruction.is_switch:
            target = "-> [%s]" % ", ".join(instruction.targets)
        else:
            target = ""
        lines.append("  IL_%04X %-22s %-12s %s" % (instruction.offset, instruction.label, instruction.opcode, target))
    for clause in layout.clauses:
        boundaries = "try [%s, %s) %s [%s, %s)" % (
            layout.label_at(clause.try_start) or "?",
            layout.label_at(clause.try_end) or "?",
            clause.kind,
            layout.label_at(clause.handler_start) or "?",
            layout.label_at(clause.handler_end) or "?",
        )
        if clause.filter_start is not None:
            boundaries += " filter %s" % (layout.label_at(clause.filter_start) or "?")
        if clause.catch_type is not None:
            boundaries += " type=0x%08X" % clause.catch_type
        lines.append("  EH%-2d %s" % (clause.index, boundaries))
    return "\n".join(lines)
