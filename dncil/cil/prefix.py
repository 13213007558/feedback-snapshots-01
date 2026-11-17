# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""structural analysis of CIL prefix groups.

CIL prefix instructions (``constrained.``, ``tail.``, ``volatile.``, ``unaligned.``,
``readonly.`` and ``no.``) decode as standalone instructions in a linear
disassembly, but their meaning is carried by the operation that follows them.
This module groups a maximal run of prefixes with that operation, keeps every
original :class:`~dncil.cil.instruction.Instruction` object untouched, and
records evidence for structural problems:

* a prefix repeated inside one group,
* prefixes that do not follow the canonical grouping order,
* a trailing prefix with no operation,
* control flow that enters a group somewhere other than its first prefix,
* a prefix whose operation is not one it can modify.

The analysis is purely structural.  It does not execute IL, does not rewrite
the method body, and a structurally consistent report is not evidence that a
method or assembly is safe to execute.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

from dncil.cil.enums import OpCodeValue, OperandType

if TYPE_CHECKING:
    from dncil.cil.instruction import Instruction
    from dncil.cil.exception import ExceptionHandler


# issue codes are stable so callers can filter on them
ISSUE_DUPLICATE_PREFIX = "duplicate_prefix"
ISSUE_INVALID_ORDER = "invalid_prefix_order"
ISSUE_ORPHAN_PREFIX = "orphan_prefix"
ISSUE_MID_GROUP_ENTRY = "mid_group_entry"
ISSUE_INCOMPATIBLE_OPERATION = "incompatible_operation"
ISSUE_UNSUPPORTED_PREFIX = "unsupported_prefix"
ISSUE_REGION_SPLIT = "region_split"


def _opcodes(*values: OpCodeValue) -> Set[OpCodeValue]:
    return set(values)


_LOAD_INDIRECT = _opcodes(
    OpCodeValue.Ldind_I1,
    OpCodeValue.Ldind_U1,
    OpCodeValue.Ldind_I2,
    OpCodeValue.Ldind_U2,
    OpCodeValue.Ldind_I4,
    OpCodeValue.Ldind_U4,
    OpCodeValue.Ldind_I8,
    OpCodeValue.Ldind_I,
    OpCodeValue.Ldind_R4,
    OpCodeValue.Ldind_R8,
    OpCodeValue.Ldind_Ref,
)

_STORE_INDIRECT = _opcodes(
    OpCodeValue.Stind_Ref,
    OpCodeValue.Stind_I1,
    OpCodeValue.Stind_I2,
    OpCodeValue.Stind_I4,
    OpCodeValue.Stind_I8,
    OpCodeValue.Stind_R4,
    OpCodeValue.Stind_R8,
    OpCodeValue.Stind_I,
)

_FIELD_ACCESS = _opcodes(
    OpCodeValue.Ldfld,
    OpCodeValue.Stfld,
    OpCodeValue.Ldsfld,
    OpCodeValue.Stsfld,
)

_OBJECT_ACCESS = _opcodes(
    OpCodeValue.Ldobj,
    OpCodeValue.Stobj,
    OpCodeValue.Cpobj,
    OpCodeValue.Initobj,
)

_ELEMENT_ACCESS = _opcodes(
    OpCodeValue.Ldelem,
    OpCodeValue.Ldelem_I,
    OpCodeValue.Ldelem_I1,
    OpCodeValue.Ldelem_I2,
    OpCodeValue.Ldelem_I4,
    OpCodeValue.Ldelem_I8,
    OpCodeValue.Ldelem_R4,
    OpCodeValue.Ldelem_R8,
    OpCodeValue.Ldelem_Ref,
    OpCodeValue.Ldelem_U1,
    OpCodeValue.Ldelem_U2,
    OpCodeValue.Ldelem_U4,
    OpCodeValue.Stelem,
    OpCodeValue.Stelem_I,
    OpCodeValue.Stelem_I1,
    OpCodeValue.Stelem_I2,
    OpCodeValue.Stelem_I4,
    OpCodeValue.Stelem_I8,
    OpCodeValue.Stelem_R4,
    OpCodeValue.Stelem_R8,
    OpCodeValue.Stelem_Ref,
    OpCodeValue.Ldelema,
)

# ECMA-335 lists ldsfld, stsfld, ldfld, stfld, ldind.*, stind.*, ldobj, stobj,
# cpobj and initobj for volatile.
_VOLATILE_TARGETS = _LOAD_INDIRECT | _STORE_INDIRECT | _FIELD_ACCESS | _OBJECT_ACCESS

_UNALIGNED_TARGETS = (
    _LOAD_INDIRECT
    | _STORE_INDIRECT
    | _opcodes(OpCodeValue.Ldfld, OpCodeValue.Stfld, OpCodeValue.Ldobj, OpCodeValue.Stobj)
    | _opcodes(OpCodeValue.Initblk, OpCodeValue.Cpblk)
)

_CALL_TARGETS = _opcodes(OpCodeValue.Call, OpCodeValue.Calli, OpCodeValue.Callvirt)
# ECMA-335 permits constrained. only on callvirt.
_CONSTRAINED_TARGETS = _opcodes(OpCodeValue.Callvirt)
_READONLY_TARGETS = _opcodes(OpCodeValue.Ldelema)


class _PrefixRule:
    """describe where one prefix may appear and what it may modify"""

    def __init__(
        self,
        value: OpCodeValue,
        mnemonic: str,
        rank: int,
        targets: Set[OpCodeValue],
        supported: bool = True,
    ):
        self.value: OpCodeValue = value
        self.mnemonic: str = mnemonic
        # lower rank must come first within one group
        self.rank: int = rank
        self.targets: Set[OpCodeValue] = targets
        self.supported: bool = supported


# Canonical order used to treat a run of prefixes as one atomic group:
# tail., constrained., readonly., then the independent access modifiers
# volatile. and unaligned. in either order, then the operation.  This mirrors
# the way ECMA-335 and the CLR group these prefixes around one instruction; a
# different order is reported rather than silently accepted.
_PREFIX_RULES: Dict[OpCodeValue, _PrefixRule] = {
    OpCodeValue.Tailcall: _PrefixRule(OpCodeValue.Tailcall, "tail.", 0, _CALL_TARGETS),
    OpCodeValue.Constrained: _PrefixRule(OpCodeValue.Constrained, "constrained.", 1, _CONSTRAINED_TARGETS),
    OpCodeValue.Readonly: _PrefixRule(OpCodeValue.Readonly, "readonly.", 2, _READONLY_TARGETS),
    OpCodeValue.Volatile: _PrefixRule(OpCodeValue.Volatile, "volatile.", 3, _VOLATILE_TARGETS),
    OpCodeValue.Unaligned: _PrefixRule(OpCodeValue.Unaligned, "unaligned.", 3, _UNALIGNED_TARGETS),
    # reserved by ECMA and not implemented by the CLR
    OpCodeValue.No: _PrefixRule(OpCodeValue.No, "no.", 4, set(), supported=False),
    OpCodeValue.Prefix1: _PrefixRule(OpCodeValue.Prefix1, "prefix1", 5, set(), supported=False),
    OpCodeValue.Prefix2: _PrefixRule(OpCodeValue.Prefix2, "prefix2", 5, set(), supported=False),
    OpCodeValue.Prefix3: _PrefixRule(OpCodeValue.Prefix3, "prefix3", 5, set(), supported=False),
    OpCodeValue.Prefix4: _PrefixRule(OpCodeValue.Prefix4, "prefix4", 5, set(), supported=False),
    OpCodeValue.Prefix5: _PrefixRule(OpCodeValue.Prefix5, "prefix5", 5, set(), supported=False),
    OpCodeValue.Prefix6: _PrefixRule(OpCodeValue.Prefix6, "prefix6", 5, set(), supported=False),
    OpCodeValue.Prefix7: _PrefixRule(OpCodeValue.Prefix7, "prefix7", 5, set(), supported=False),
    OpCodeValue.Prefixref: _PrefixRule(OpCodeValue.Prefixref, "prefixref", 5, set(), supported=False),
}


def is_prefix(insn: Instruction) -> bool:
    """check whether an instruction is a CIL prefix that binds to a successor"""
    return insn.opcode.value in _PREFIX_RULES


class PrefixBinding:
    """record which operation one decoded prefix constrains"""

    def __init__(self, prefix: Instruction, operation: Optional[Instruction]):
        self.prefix: Instruction = prefix
        self.operation: Optional[Instruction] = operation

    @property
    def prefix_offset(self) -> int:
        return self.prefix.offset

    @property
    def operation_offset(self) -> Optional[int]:
        return None if self.operation is None else self.operation.offset

    def __repr__(self) -> str:
        operation = "none" if self.operation is None else f"{self.operation.mnemonic}@{self.operation.offset:04X}"
        return f"PrefixBinding({self.prefix.mnemonic}@{self.prefix.offset:04X} -> {operation})"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "prefix": {
                "offset": self.prefix.offset,
                "mnemonic": self.prefix.mnemonic,
                "bytes": self.prefix.get_bytes().hex(),
            },
            "operation": None
            if self.operation is None
            else {
                "offset": self.operation.offset,
                "mnemonic": self.operation.mnemonic,
                "bytes": self.operation.get_bytes().hex(),
            },
        }


class PrefixIssue:
    """one structural problem observed in a prefix group"""

    def __init__(
        self,
        code: str,
        message: str,
        offset: int,
        operation: Optional[Instruction] = None,
        related_offset: Optional[int] = None,
        source_offset: Optional[int] = None,
    ):
        self.code: str = code
        self.message: str = message
        # original offset of the prefix (or group) the issue is attached to
        self.offset: int = offset
        self.operation: Optional[Instruction] = operation
        self.related_offset: Optional[int] = related_offset
        # for control-flow entries, the original offset of the source instruction
        self.source_offset: Optional[int] = source_offset

    def __repr__(self) -> str:
        if self.operation is None:
            operation = ""
        else:
            operation = f" operation={self.operation.mnemonic}@{self.operation.offset:04X}"
        return f"PrefixIssue({self.code}@{self.offset:04X}{operation})"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "offset": self.offset,
            "related_offset": self.related_offset,
            "source_offset": self.source_offset,
            "operation": None
            if self.operation is None
            else {
                "offset": self.operation.offset,
                "mnemonic": self.operation.mnemonic,
            },
        }


class PrefixGroupEntry:
    """control flow that enters a prefix group"""

    KIND_BRANCH = "branch"
    KIND_SWITCH = "switch"
    KIND_EXCEPTION_REGION = "exception_region"
    KIND_EXCEPTION_BOUNDARY = "exception_boundary"

    def __init__(
        self,
        offset: int,
        kind: str,
        source_offset: Optional[int] = None,
        at_group_start: bool = False,
    ):
        self.offset: int = offset
        self.kind: str = kind
        # original offset of the branch/switch instruction, if any
        self.source_offset: Optional[int] = source_offset
        self.at_group_start: bool = at_group_start

    def __repr__(self) -> str:
        source = "" if self.source_offset is None else f" from={self.source_offset:04X}"
        return f"PrefixGroupEntry({self.kind}@{self.offset:04X}{source})"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "offset": self.offset,
            "kind": self.kind,
            "source_offset": self.source_offset,
            "at_group_start": self.at_group_start,
        }


class PrefixGroup:
    """a maximal run of prefixes and the operation it constrains"""

    def __init__(self, prefixes: List[Instruction], operation: Optional[Instruction]):
        self.prefixes: List[Instruction] = prefixes
        self.operation: Optional[Instruction] = operation
        self.bindings: List[PrefixBinding] = [PrefixBinding(prefix, operation) for prefix in prefixes]
        self.entries: List[PrefixGroupEntry] = []
        self.issues: List[PrefixIssue] = []
        self._analyze()

    @property
    def start(self) -> int:
        """original offset of the first prefix"""
        return self.prefixes[0].offset

    @property
    def end(self) -> int:
        """original offset directly after the group"""
        last = self.operation if self.operation is not None else self.prefixes[-1]
        return last.offset + last.size

    @property
    def operation_offset(self) -> Optional[int]:
        return None if self.operation is None else self.operation.offset

    @property
    def instructions(self) -> List[Instruction]:
        """all original instructions in this group, prefixes first"""
        if self.operation is None:
            return list(self.prefixes)
        return [*self.prefixes, self.operation]

    @property
    def structurally_consistent(self) -> bool:
        return not self.issues

    @property
    def valid(self) -> bool:
        return self.structurally_consistent

    def get_bytes(self) -> bytes:
        """original bytes covered by the group, including its operation"""
        data = bytes()
        for insn in self.instructions:
            data += insn.get_bytes()
        return data

    def _analyze(self):
        first_seen: Dict[OpCodeValue, Instruction] = {}
        highest_rank: Optional[Tuple[int, Instruction]] = None

        for prefix in self.prefixes:
            rule = _PREFIX_RULES[prefix.opcode.value]

            if not rule.supported:
                self.issues.append(
                    PrefixIssue(
                        ISSUE_UNSUPPORTED_PREFIX,
                        f"{prefix.mnemonic} at 0x{prefix.offset:04X} is reserved and has no defined operation",
                        prefix.offset,
                        self.operation,
                    )
                )

            previous = first_seen.get(prefix.opcode.value)
            if previous is not None:
                self.issues.append(
                    PrefixIssue(
                        ISSUE_DUPLICATE_PREFIX,
                        f"{prefix.mnemonic} at 0x{prefix.offset:04X} repeats the prefix at 0x{previous.offset:04X}",
                        prefix.offset,
                        self.operation,
                        related_offset=previous.offset,
                    )
                )
            else:
                first_seen[prefix.opcode.value] = prefix

            if highest_rank is not None and rule.rank < highest_rank[0]:
                self.issues.append(
                    PrefixIssue(
                        ISSUE_INVALID_ORDER,
                        f"{prefix.mnemonic} at 0x{prefix.offset:04X} is out of order; "
                        f"canonical grouping places it before "
                        f"{highest_rank[1].mnemonic} at 0x{highest_rank[1].offset:04X}",
                        prefix.offset,
                        self.operation,
                        related_offset=highest_rank[1].offset,
                    )
                )
            if highest_rank is None or rule.rank > highest_rank[0]:
                highest_rank = (rule.rank, prefix)

            if self.operation is None:
                self.issues.append(
                    PrefixIssue(
                        ISSUE_ORPHAN_PREFIX,
                        f"{prefix.mnemonic} at 0x{prefix.offset:04X} has no following operation",
                        prefix.offset,
                        None,
                    )
                )
            elif rule.supported and self.operation.opcode.value not in rule.targets:
                self.issues.append(
                    PrefixIssue(
                        ISSUE_INCOMPATIBLE_OPERATION,
                        f"{prefix.mnemonic} at 0x{prefix.offset:04X} cannot modify "
                        f"{self.operation.mnemonic} at 0x{self.operation.offset:04X}",
                        prefix.offset,
                        self.operation,
                    )
                )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start": self.start,
            "end": self.end,
            "prefixes": [
                {"offset": prefix.offset, "mnemonic": prefix.mnemonic, "bytes": prefix.get_bytes().hex()}
                for prefix in self.prefixes
            ],
            "operation": None
            if self.operation is None
            else {
                "offset": self.operation.offset,
                "mnemonic": self.operation.mnemonic,
                "bytes": self.operation.get_bytes().hex(),
            },
            "bindings": [binding.to_dict() for binding in self.bindings],
            "entries": [entry.to_dict() for entry in self.entries],
            "issues": [issue.to_dict() for issue in self.issues],
            "structurally_consistent": self.structurally_consistent,
        }


class PrefixReport:
    """structural evidence for every prefix group in one method body.

    ``structurally_consistent`` only means that the recorded structural rules
    found no problem.  It says nothing about reachability, type safety, stack
    correctness, or whether the assembly is safe to execute.
    """

    #: what this report is allowed to conclude
    SCOPE = "structural prefix-group analysis only; not a safety proof"

    def __init__(self, groups: List[PrefixGroup], code_start: Optional[int] = None):
        self.groups: List[PrefixGroup] = groups
        self.code_start: Optional[int] = code_start

    @property
    def issues(self) -> List[PrefixIssue]:
        return [issue for group in self.groups for issue in group.issues]

    @property
    def structurally_consistent(self) -> bool:
        return not self.issues

    @property
    def valid_groups(self) -> List[PrefixGroup]:
        return [group for group in self.groups if group.structurally_consistent]

    @property
    def invalid_groups(self) -> List[PrefixGroup]:
        return [group for group in self.groups if not group.structurally_consistent]

    def __repr__(self) -> str:
        return f"PrefixReport(groups={len(self.groups)}, issues={len(self.issues)})"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scope": self.SCOPE,
            "safety_proof": False,
            "code_start": self.code_start,
            "groups": [group.to_dict() for group in self.groups],
            "issue_count": len(self.issues),
            "structurally_consistent": self.structurally_consistent,
        }


def _branch_targets(insn: Instruction) -> List[Tuple[int, str]]:
    """get absolute targets of one instruction with their entry kind"""
    if insn.opcode.operand_type in (OperandType.InlineBrTarget, OperandType.ShortInlineBrTarget):
        target = insn.operand
        if isinstance(target, int):
            return [(target, PrefixGroupEntry.KIND_BRANCH)]
    elif insn.opcode.operand_type == OperandType.InlineSwitch:
        targets = insn.operand
        if isinstance(targets, list):
            return [(target, PrefixGroupEntry.KIND_SWITCH) for target in targets if isinstance(target, int)]
    return []


def _exception_region_offsets(
    exception_handlers: List[ExceptionHandler], code_start: int
) -> List[Tuple[int, str]]:
    """get absolute exception-region starts and ends.

    dncil stores exception handler offsets relative to the first instruction;
    instructions store original stream offsets.
    """
    offsets: List[Tuple[int, str]] = []
    for handler in exception_handlers:
        for relative in (handler.try_start, handler.handler_start, handler.filter_start):
            if relative >= 0:
                offsets.append((code_start + relative, PrefixGroupEntry.KIND_EXCEPTION_REGION))
        for relative in (handler.try_end, handler.handler_end):
            if relative >= 0:
                offsets.append((code_start + relative, PrefixGroupEntry.KIND_EXCEPTION_BOUNDARY))
    return offsets


def _collect_entries(
    instructions: List[Instruction],
    groups: List[PrefixGroup],
    exception_handlers: List[ExceptionHandler],
    code_start: Optional[int],
) -> None:
    entries: List[Tuple[int, str, Optional[int]]] = []
    for insn in instructions:
        for target, kind in _branch_targets(insn):
            entries.append((target, kind, insn.offset))
    if code_start is not None:
        for target, kind in _exception_region_offsets(exception_handlers, code_start):
            entries.append((target, kind, None))

    # a switch may list the same target twice and several handlers may share a
    # region boundary; keep one entry per (target, kind, source)
    unique_entries: List[Tuple[int, str, Optional[int]]] = []
    seen_entries: Set[Tuple[int, str, Optional[int]]] = set()
    for entry in entries:
        if entry in seen_entries:
            continue
        seen_entries.add(entry)
        unique_entries.append(entry)

    for group in groups:
        for target, kind, source in unique_entries:
            # region ends may legally sit on either group boundary; starts and
            # control flow may only sit on the group start
            if kind == PrefixGroupEntry.KIND_EXCEPTION_BOUNDARY:
                inside = group.start < target < group.end
                at_start = False
            else:
                inside = group.start <= target < group.end
                at_start = target == group.start

            if not inside:
                continue

            group.entries.append(PrefixGroupEntry(target, kind, source, at_start))
            if at_start:
                continue

            if kind == PrefixGroupEntry.KIND_EXCEPTION_BOUNDARY:
                group.issues.append(
                    PrefixIssue(
                        ISSUE_REGION_SPLIT,
                        f"exception region boundary at 0x{target:04X} splits the prefix group "
                        f"starting at 0x{group.start:04X}",
                        target,
                        group.operation,
                        related_offset=group.start,
                    )
                )
                continue

            source_text = "method entry" if source is None else f"0x{source:04X}"
            group.issues.append(
                PrefixIssue(
                    ISSUE_MID_GROUP_ENTRY,
                    f"{kind} from {source_text} enters at 0x{target:04X}, inside the prefix group "
                    f"starting at 0x{group.start:04X}",
                    target,
                    group.operation,
                    related_offset=group.start,
                    source_offset=source,
                )
            )

        group.entries.sort(
            key=lambda entry: (entry.offset, entry.kind, -1 if entry.source_offset is None else entry.source_offset)
        )
        group.issues.sort(key=lambda issue: (issue.offset, issue.code))


def analyze_prefix_groups(
    instructions: List[Instruction],
    exception_handlers: Optional[List[ExceptionHandler]] = None,
    code_start: Optional[int] = None,
) -> PrefixReport:
    """build structural prefix-group evidence for decoded instructions.

    ``instructions`` is only read; every original instruction is preserved in
    the returned groups.  ``exception_handlers`` offsets are interpreted
    relative to ``code_start`` (the original offset of the first instruction),
    matching :class:`~dncil.cil.body.CilMethodBody`.
    """
    groups: List[PrefixGroup] = []
    index = 0
    while index < len(instructions):
        if not is_prefix(instructions[index]):
            index += 1
            continue

        start_index = index
        while index < len(instructions) and is_prefix(instructions[index]):
            index += 1
        prefixes = instructions[start_index:index]
        operation = instructions[index] if index < len(instructions) else None
        groups.append(PrefixGroup(prefixes, operation))

    _collect_entries(instructions, groups, exception_handlers or [], code_start)
    return PrefixReport(groups, code_start)


def format_report(report: PrefixReport) -> str:
    """render a prefix report as text that cites original offsets"""
    lines: List[str] = []
    for group in report.groups:
        operation = "none" if group.operation is None else group.operation.mnemonic
        operation_offset = "-" if group.operation is None else f"0x{group.operation.offset:04X}"
        lines.append(
            f"group 0x{group.start:04X}-0x{group.end:04X} -> {operation} @ {operation_offset}"
            f" ({'consistent' if group.structurally_consistent else 'inconsistent'})"
        )
        for prefix in group.prefixes:
            lines.append(f"  prefix 0x{prefix.offset:04X} {prefix.mnemonic} constrains {operation}")
        for entry in group.entries:
            if entry.source_offset is None:
                lines.append(f"  entry  {entry.kind} at 0x{entry.offset:04X}")
            else:
                lines.append(f"  entry  {entry.kind} from 0x{entry.source_offset:04X} at 0x{entry.offset:04X}")
        for issue in group.issues:
            target = "" if issue.operation is None else f" affecting {issue.operation.mnemonic}"
            lines.append(f"  issue  {issue.code} @ 0x{issue.offset:04X}{target}: {issue.message}")
    if not lines:
        lines.append("no prefix groups")
    lines.append(f"scope: {PrefixReport.SCOPE}")
    return "\n".join(lines)
