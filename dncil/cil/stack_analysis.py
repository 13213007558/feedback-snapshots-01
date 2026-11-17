# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Bounded evaluation-stack height analysis for a single CIL method body.

The analysis is deliberately limited to stack *heights*.  It does not model
runtime values or types, which keeps it useful as a quick structural check during
security review:

* every reachable control-flow join must agree on the evaluation-stack height;
* exception-handler entries must start at an instruction boundary and with the
  height required by the CLR: one value for catch and filter handlers, zero for
  finally and fault handlers;
* a call or ``calli`` contributes only when the caller-provided resolver returns
  an explicit :class:`CallSignature`.  A missing signature becomes an ``UNKNOWN``
  state that propagates through successors, so an unknown branch can never make a
  different path look verified.

The fixpoint is a worklist over ``(instruction, height)`` states.  A state is
propagated once, which makes legal loops converge.  Positive unbounded growth
(for example ``loop: ldc.i4.0; br loop``) is stopped at
``max_heights_per_instruction`` and reported as a conflict instead of being
followed forever.

``leave``, ``ret``, ``throw`` and the handler entries each have their own rule:

* ``leave`` clears the evaluation stack and branches with height zero;
* ``ret`` terminates the method and, when the caller supplies the method's
  return shape, must leave exactly zero (void) or one value;
* ``throw`` pops the exception object and terminates the path; ``rethrow``
  terminates the path without a stack requirement;
* catch/filter entries start at height one, finally/fault entries at height
  zero.

The caller-provided resolver is the only source of call signatures.  It is never
bypassed with a zero-parameter default: an unavailable signature is reported as
``UNKNOWN`` and is not treated as a verified result.

Exceptional control flow is not simulated edge by edge.  Handlers are seeded at
their declared entry points with the CLR-mandated height, and a ``throw`` ends
its path without adding an edge to a handler.  This keeps the analysis bounded
and makes the handler-entry assumption explicit; it is not a model of runtime
object state or exception dispatch.
"""

from __future__ import annotations

import enum
from typing import (
    TYPE_CHECKING,
    Any,
    Set,
    Dict,
    List,
    Deque,
    Tuple,
    Union,
    Mapping,
    Callable,
    Optional,
    Protocol,
    Sequence,
)
from collections import deque
from dataclasses import field, dataclass

from dncil.cil.enums import OpCodeType, OpCodeValue, StackBehaviour
from dncil.clr.token import Token

if TYPE_CHECKING:
    from dncil.cil.body import CilMethodBody
    from dncil.cil.instruction import Instruction

__all__ = [
    "CallSignature",
    "InstructionStackReport",
    "MaxStackRelation",
    "StackAnalysisResult",
    "StackAnalyzer",
    "StackIssue",
    "StackIssueKind",
    "StackPath",
    "SignatureResolver",
    "StackStatus",
    "TokenSignatureResolver",
    "analyze_stack",
]


class StackStatus(str, enum.Enum):
    """Verdict for a stack-height question.

    ``KNOWN`` means all reachable paths were accounted for and no inconsistency
    was found.  ``CONFLICT`` means at least one definite height inconsistency was
    found.  ``UNKNOWN`` means the available information is insufficient, for
    example because a call signature is missing.  ``UNKNOWN`` is never treated
    as success.  ``UNREACHABLE`` is reported per instruction when no path from
    the method entry, and no exception entry, reaches it.
    """

    KNOWN = "known"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"
    UNREACHABLE = "unreachable"


class MaxStackRelation(str, enum.Enum):
    """Relationship between the header's ``.maxstack`` and the derivation."""

    WITHIN = "within"
    EXCEEDED = "exceeded"
    UNKNOWN = "unknown"


class StackIssueKind(str, enum.Enum):
    """Kinds of findings produced by :class:`StackAnalyzer`."""

    JOIN_CONFLICT = "join_conflict"
    STACK_UNDERFLOW = "stack_underflow"
    UNRESOLVED_SIGNATURE = "unresolved_signature"
    UNRESOLVED_STACK_EFFECT = "unresolved_stack_effect"
    UNKNOWN_BRANCH_TARGET = "unknown_branch_target"
    INVALID_EXCEPTION_HANDLER = "invalid_exception_handler"
    UNBOUNDED_STACK_GROWTH = "unbounded_stack_growth"
    MAX_STACK_EXCEEDED = "max_stack_exceeded"
    FALLTHROUGH_PAST_END = "fallthrough_past_end"
    RET_HEIGHT = "ret_height"
    ENDFILTER_HEIGHT = "endfilter_height"
    ENDFINALLY_HEIGHT = "endfinally_height"
    JMP_STACK_NOT_EMPTY = "jmp_stack_not_empty"
    EMPTY_METHOD = "empty_method"


@dataclass(frozen=True)
class CallSignature:
    """Height-relevant portion of a resolved call signature.

    ``parameter_count`` excludes the implicit ``this`` argument.  ``has_this``
    marks an instance signature, which consumes a receiver for ``call``,
    ``callvirt`` and ``calli``.  ``returns_value`` says whether the callee leaves
    one value on the caller's stack.  A constructor resolved for ``newobj``
    normally has ``has_this=True`` in metadata, but ``newobj`` creates the
    receiver instead of consuming one, so the analyzer does not charge for it.
    """

    parameter_count: int
    has_this: bool = False
    returns_value: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.parameter_count, bool) or not isinstance(self.parameter_count, int):
            raise TypeError("parameter_count must be an int")
        if self.parameter_count < 0:
            raise ValueError("parameter_count must not be negative")


class TokenSignatureResolver(Protocol):
    """Structural interface for a caller-provided signature resolver.

    In practice a resolver is a callable ``resolver(token) -> CallSignature |
    None``.  An object exposing ``resolve(token)`` or ``resolve_signature(token)``
    is also accepted.  Returning ``None``, or raising an exception, means the
    signature is unavailable and is reported as ``UNKNOWN``; it is never
    interpreted as a zero-argument call.
    """

    def resolve(self, token: Token) -> Optional[CallSignature]: ...


SignatureResolver = Union[Callable[[Token], Optional[CallSignature]], TokenSignatureResolver]


@dataclass(frozen=True)
class StackPath:
    """One representative instruction chain for a height observation.

    ``offsets`` begins at a method or handler entry and ends at the instruction
    the observation applies to.  ``reason`` is set when the height is unknown and
    identifies the instruction where the uncertainty began.
    """

    height: Optional[int]
    offsets: Tuple[int, ...]
    reason: str = ""
    origin: str = "method entry"


@dataclass(frozen=True)
class StackIssue:
    """A finding together with the instruction chain(s) that justify it."""

    kind: StackIssueKind
    offset: int
    message: str
    paths: Tuple[StackPath, ...] = ()


@dataclass(frozen=True)
class InstructionStackReport:
    """Stack-height result for one instruction.

    ``height`` is the incoming height when exactly one known predecessor exists
    and no unknown predecessor reaches the instruction.  It is still useful when
    the instruction's own effect is unknown, for example at an unresolved call.
    ``known_heights`` retains the alternatives at a conflicting join and
    ``paths`` holds the corresponding chains.
    """

    offset: int
    mnemonic: str
    status: StackStatus
    height: Optional[int]
    known_heights: Tuple[int, ...]
    paths: Tuple[StackPath, ...]
    issues: Tuple[StackIssueKind, ...]

    @property
    def chain(self) -> Optional[Tuple[int, ...]]:
        """Return the only chain when there is exactly one observation."""
        if len(self.paths) == 1:
            return self.paths[0].offsets
        return None

    @property
    def chains(self) -> Tuple[Tuple[int, ...], ...]:
        """Return every representative instruction chain."""
        return tuple(path.offsets for path in self.paths)


@dataclass(frozen=True)
class StackAnalysisResult:
    """Outcome of an analysis for one method body."""

    status: StackStatus
    instructions: Mapping[int, InstructionStackReport]
    issues: Tuple[StackIssue, ...]
    declared_max_stack: int
    derived_max_stack: int
    max_stack_relation: MaxStackRelation
    max_stack_is_complete: bool
    entry_offset: Optional[int]
    max_stack_path: Optional[StackPath] = None
    joins: Mapping[int, Tuple[StackPath, ...]] = field(default_factory=dict)

    @property
    def verified(self) -> bool:
        """True only when every reachable path is understood and consistent."""
        return self.status is StackStatus.KNOWN

    @property
    def max_stack_exceeded(self) -> bool:
        return self.max_stack_relation is MaxStackRelation.EXCEEDED

    def format_report(self) -> str:
        """Render a human-readable report that includes every issue chain."""
        relation = self.max_stack_relation.value
        if not self.max_stack_is_complete:
            relation += " (lower bound; unknown path(s) present)"
        lines = [
            f"status: {self.status.value}",
            f"max_stack: declared={self.declared_max_stack} derived={self.derived_max_stack} relation={relation}",
        ]
        if self.max_stack_path is not None:
            lines.append("max_stack_path: " + self._format_path(self.max_stack_path, label="depth after instruction"))

        if self.joins:
            lines.append("merges:")
            for offset in sorted(self.joins):
                paths = self.joins[offset]
                heights = sorted({path.height for path in paths if path.height is not None})
                unknown_count = sum(1 for path in paths if path.height is None)
                if not heights:
                    label = "unknown height"
                elif len(heights) == 1 and unknown_count:
                    label = f"height {heights[0]} with {unknown_count} unknown path(s)"
                elif len(heights) == 1:
                    label = f"converged at height {heights[0]}"
                else:
                    label = "conflicting heights " + ", ".join(str(height) for height in heights)
                    if unknown_count:
                        label += f" (plus {unknown_count} unknown path(s))"
                lines.append(f"  IL_{offset:04X} {self.instructions[offset].mnemonic}: {label}")
                for path in paths:
                    lines.append("    " + self._format_path(path))

        if not self.issues:
            lines.append("issues: none")
            return "\n".join(lines)

        lines.append("issues:")
        for issue in self.issues:
            lines.append(f"  [{issue.kind.value}] IL_{issue.offset:04X}: {issue.message}")
            for path in issue.paths:
                lines.append("    " + self._format_path(path))
        return "\n".join(lines)

    def _format_path(self, path: StackPath, label: str = "height") -> str:
        prefix = f"[{path.origin}] " if path.origin != "method entry" else ""
        parts = []
        for offset in path.offsets:
            report = self.instructions.get(offset)
            mnemonic = report.mnemonic if report is not None else "?"
            parts.append(f"IL_{offset:04X} {mnemonic}")
        text = prefix + " -> ".join(parts)
        if path.height is None:
            text += " (unknown height"
            if path.reason:
                text += f": {path.reason}"
            text += ")"
        else:
            text += f" ({label} {path.height})"
        return text

    def __str__(self) -> str:
        return self.format_report()


# dncil's StackBehaviour is a compact description of the stack effect.  The
# tables below convert it into exact pop/push counts.  Variable behaviour is
# handled before the tables are consulted, so a missing entry is a hard
# "unknown", never an assumed zero.
_POPS: Dict[StackBehaviour, int] = {
    StackBehaviour.Pop0: 0,
    StackBehaviour.Pop1: 1,
    StackBehaviour.Pop1_pop1: 2,
    StackBehaviour.Popi: 1,
    StackBehaviour.Popi_pop1: 2,
    StackBehaviour.Popi_popi: 2,
    StackBehaviour.Popi_popi8: 2,
    StackBehaviour.Popi_popi_popi: 3,
    StackBehaviour.Popi_popr4: 2,
    StackBehaviour.Popi_popr8: 2,
    StackBehaviour.Popref: 1,
    StackBehaviour.Popref_pop1: 2,
    StackBehaviour.Popref_popi: 2,
    StackBehaviour.Popref_popi_popi: 3,
    StackBehaviour.Popref_popi_popi8: 3,
    StackBehaviour.Popref_popi_popr4: 3,
    StackBehaviour.Popref_popi_popr8: 3,
    StackBehaviour.Popref_popi_popref: 3,
    StackBehaviour.Popref_popi_pop1: 3,
}

_PUSHES: Dict[StackBehaviour, int] = {
    StackBehaviour.Push0: 0,
    StackBehaviour.Push1: 1,
    StackBehaviour.Push1_push1: 2,
    StackBehaviour.Pushi: 1,
    StackBehaviour.Pushi8: 1,
    StackBehaviour.Pushr4: 1,
    StackBehaviour.Pushr8: 1,
    StackBehaviour.Pushref: 1,
}

_CONFLICT_KINDS = frozenset(
    (
        StackIssueKind.JOIN_CONFLICT,
        StackIssueKind.STACK_UNDERFLOW,
        StackIssueKind.UNBOUNDED_STACK_GROWTH,
        StackIssueKind.MAX_STACK_EXCEEDED,
        StackIssueKind.ENDFILTER_HEIGHT,
        StackIssueKind.JMP_STACK_NOT_EMPTY,
        StackIssueKind.ENDFINALLY_HEIGHT,
        StackIssueKind.RET_HEIGHT,
    )
)

_UNKNOWN_KINDS = frozenset(
    (
        StackIssueKind.UNRESOLVED_SIGNATURE,
        StackIssueKind.UNRESOLVED_STACK_EFFECT,
        StackIssueKind.UNKNOWN_BRANCH_TARGET,
        StackIssueKind.INVALID_EXCEPTION_HANDLER,
        StackIssueKind.FALLTHROUGH_PAST_END,
        StackIssueKind.EMPTY_METHOD,
    )
)


class StackAnalyzer:
    """Analyze the evaluation-stack height of a parsed method body.

    Parameters:
        body: parsed :class:`dncil.cil.body.CilMethodBody`.
        resolve_signature: caller-provided token signature resolver.  It is the
            only source of call/calli stack effects.
        signatures: optional pre-resolved mapping keyed by ``Token`` or token
            value.  Used only when ``resolve_signature`` yields nothing.
        return_value: ``True`` when the method returns one value, ``False`` for
            void.  If omitted, the method signature is not checked; ``ret``
            still rejects more than one value because that is never returnable.
        max_heights_per_instruction: convergence bound on distinct heights at
            one instruction.  Legal loops settle below it; positive unbounded
            growth is reported as a conflict.
        max_steps: optional bound on total accepted ``(instruction, height)``
            states.  Defaults to a multiple of the method length.

    An instance may be reused; every call to :meth:`analyze` starts from a clean
    slate.
    """

    def __init__(
        self,
        body: "CilMethodBody",
        resolve_signature: Optional[SignatureResolver] = None,
        *,
        signatures: Optional[Mapping[Union[Token, int], CallSignature]] = None,
        return_value: Optional[bool] = None,
        max_heights_per_instruction: int = 64,
        max_steps: Optional[int] = None,
    ) -> None:
        if max_heights_per_instruction < 1:
            raise ValueError("max_heights_per_instruction must be positive")
        if max_steps is not None and max_steps < 1:
            raise ValueError("max_steps must be positive when provided")

        self.body = body
        self.resolve_signature = resolve_signature
        self.signatures = signatures
        self.return_value = return_value
        self.max_heights_per_instruction = max_heights_per_instruction
        # A global bound complements the per-instruction bound: a program can
        # grow the height at many instructions at once, and the analysis must
        # still terminate.  Counting accepted states rather than queue pops
        # keeps duplicate worklist entries in dense switch/branch graphs from
        # triggering a false non-convergence report.
        self.max_steps = (
            max_steps if max_steps is not None else max_heights_per_instruction * max(8, len(body.instructions))
        )

        self._instructions: Tuple["Instruction", ...] = tuple(body.instructions)
        self._by_offset: Dict[int, "Instruction"] = {insn.offset: insn for insn in self._instructions}
        self._code_base: int = body.offset + body.header_size
        self._entry_offset: Optional[int] = self._instructions[0].offset if self._instructions else None

        self._states: Dict[int, Dict[Optional[int], StackPath]] = {}
        self._queue: Deque[Tuple[int, Optional[int], StackPath]] = deque()
        self._transfer_conflicts: Set[int] = set()
        self._transfer_unknown: Set[int] = set()
        self._nonconvergent: Set[int] = set()
        self._extra_paths: Dict[int, Dict[Optional[int], StackPath]] = {}
        self._issues: List[StackIssue] = []
        self._issue_keys: Set[Tuple[StackIssueKind, int, str]] = set()
        self._has_unknown = False
        self._derived_max = 0
        self._max_path: Optional[StackPath] = None

    # ------------------------------------------------------------------ API
    def analyze(self) -> StackAnalysisResult:
        """Run the fixpoint and return a :class:`StackAnalysisResult`."""
        self._reset()

        if not self._instructions:
            self._add_issue(StackIssueKind.EMPTY_METHOD, 0, "method body contains no instructions")
            return self._build_result()

        assert self._entry_offset is not None
        self._enqueue(self._entry_offset, 0, StackPath(0, (self._entry_offset,), origin="method entry"))
        self._seed_exception_handlers()

        states_accepted = 0
        last_path: Optional[StackPath] = None
        while self._queue:
            offset, height, path = self._queue.popleft()
            last_path = path
            states = self._states.setdefault(offset, {})
            if height in states:
                # Already propagated.  This is what lets a legal loop converge
                # instead of being visited forever.  Retain one alternative
                # chain so a converged join can still cite both paths.
                extra = self._extra_paths.setdefault(offset, {})
                if height not in extra and states[height].offsets != path.offsets:
                    extra[height] = path
                continue

            known_count = sum(1 for known in states if known is not None)
            if height is not None and known_count >= self.max_heights_per_instruction:
                self._nonconvergent.add(offset)
                self._transfer_conflicts.add(offset)
                self._add_issue(
                    StackIssueKind.UNBOUNDED_STACK_GROWTH,
                    offset,
                    (
                        "stack height did not converge after "
                        f"{self.max_heights_per_instruction} distinct heights; "
                        "positive unbounded stack growth is likely"
                    ),
                    (path,),
                )
                continue

            if states_accepted >= self.max_steps:
                self._add_issue(
                    StackIssueKind.UNBOUNDED_STACK_GROWTH,
                    last_path.offsets[-1] if last_path is not None else 0,
                    f"analysis exceeded {self.max_steps} distinct stack states without converging",
                    (last_path,) if last_path is not None else (),
                )
                self._has_unknown = True
                break
            states_accepted += 1

            states[height] = path
            if height is None:
                self._has_unknown = True
            else:
                self._record_height(height, path)

            self._process(self._by_offset[offset], height, path)

        # Describe joins once all of their incoming states are known.
        for offset in sorted(self._states):
            if offset in self._nonconvergent:
                continue
            states = self._states[offset]
            heights = sorted(known for known in states if known is not None)
            if len(heights) > 1:
                self._transfer_conflicts.add(offset)
                self._add_issue(
                    StackIssueKind.JOIN_CONFLICT,
                    offset,
                    "incoming control-flow paths disagree on evaluation-stack height: "
                    + ", ".join(str(known) for known in heights),
                    tuple(states[known] for known in heights),
                )

        self._check_max_stack()
        return self._build_result()

    def _reset(self) -> None:
        self._states = {}
        self._queue = deque()
        self._transfer_conflicts = set()
        self._transfer_unknown = set()
        self._nonconvergent = set()
        self._extra_paths = {}
        self._issues = []
        self._issue_keys = set()
        self._has_unknown = False
        self._derived_max = 0
        self._max_path = None

    # ------------------------------------------------------------- worklist
    def _enqueue(self, offset: int, height: Optional[int], path: StackPath) -> None:
        self._queue.append((offset, height, path))

    def _enqueue_target(self, target: int, height: Optional[int], base_path: StackPath, source: "Instruction") -> None:
        if target not in self._by_offset:
            self._transfer_unknown.add(source.offset)
            self._add_issue(
                StackIssueKind.UNKNOWN_BRANCH_TARGET,
                source.offset,
                f"branch target IL_{target:04X} is not an instruction boundary in this method body",
                (base_path,),
            )
            return
        self._enqueue(target, height, self._extend(base_path, target, height))

    @staticmethod
    def _extend(path: StackPath, target: int, height: Optional[int], reason: str = "") -> StackPath:
        if reason:
            return StackPath(None, path.offsets + (target,), reason=reason, origin=path.origin)
        return StackPath(height, path.offsets + (target,), reason=path.reason, origin=path.origin)

    def _enqueue_next(
        self,
        insn: "Instruction",
        height: Optional[int],
        base_path: StackPath,
        *,
        reason: str = "",
    ) -> None:
        target = insn.offset + insn.size
        if target not in self._by_offset:
            self._transfer_unknown.add(insn.offset)
            self._add_issue(
                StackIssueKind.FALLTHROUGH_PAST_END,
                insn.offset,
                "instruction falls through past the end of the method body",
                (base_path,),
            )
            return
        self._enqueue(target, height, self._extend(base_path, target, height, reason=reason))

    # ---------------------------------------------------------------- seeds
    def _seed_exception_handlers(self) -> None:
        for handler in self.body.exception_handlers:
            if handler.handler_start < 0:
                self._add_issue(
                    StackIssueKind.INVALID_EXCEPTION_HANDLER,
                    self._code_base,
                    "exception handler has no handler start",
                )
                continue

            handler_offset = self._code_base + handler.handler_start
            if handler.is_catch():
                self._seed_handler_entry(handler_offset, 1, "catch handler entry")
            elif handler.is_filter():
                if handler.filter_start < 0:
                    self._add_issue(
                        StackIssueKind.INVALID_EXCEPTION_HANDLER,
                        self._code_base,
                        "filter handler has no filter start",
                    )
                else:
                    self._seed_handler_entry(self._code_base + handler.filter_start, 1, "filter entry")
                # After a successful filter the handler receives the exception
                # object, so its entry height is also one.
                self._seed_handler_entry(handler_offset, 1, "filter handler entry")
            elif handler.is_finally() or handler.is_fault():
                self._seed_handler_entry(handler_offset, 0, "finally/fault handler entry")
            else:
                self._add_issue(
                    StackIssueKind.INVALID_EXCEPTION_HANDLER,
                    handler_offset,
                    f"unsupported exception handler type 0x{handler.exception_type:X}",
                )

    def _seed_handler_entry(self, offset: int, height: int, origin: str) -> None:
        if offset not in self._by_offset:
            self._add_issue(
                StackIssueKind.INVALID_EXCEPTION_HANDLER,
                offset,
                f"{origin} offset IL_{offset:04X} is not an instruction boundary",
            )
            self._has_unknown = True
            return
        self._enqueue(offset, height, StackPath(height, (offset,), origin=origin))

    # ------------------------------------------------------------- transfer
    def _process(self, insn: "Instruction", height: Optional[int], path: StackPath) -> None:
        op = insn.opcode.value

        if op in (OpCodeValue.Leave, OpCodeValue.Leave_S):
            # leave discards the evaluation stack and branches with height 0.
            target = insn.operand
            if isinstance(target, int):
                self._enqueue_target(target, 0, path, insn)
                if height is None:
                    # The target height is deterministic (0), but the path is
                    # still tainted by an upstream unknown.  Record both: the
                    # known height gives converged evidence, while the unknown
                    # state prevents the target from being called verified.
                    self._enqueue_target(target, None, path, insn)
            else:
                self._unknown_target(insn, path)
            return

        if op == OpCodeValue.Ret:
            self._process_ret(insn, height, path)
            return

        if op == OpCodeValue.Throw:
            if height is not None:
                self._require(insn, height, 1, path)
            return

        if op == OpCodeValue.Rethrow:
            # rethrow has no operand, no stack requirement and no fallthrough.
            return

        if op == OpCodeValue.Endfinally:
            # endfinally finishes a finally/fault region; it neither falls
            # through nor joins the normal continuation path, and the region
            # must have left the evaluation stack empty.
            if height is not None and height != 0:
                self._transfer_conflicts.add(insn.offset)
                self._add_issue(
                    StackIssueKind.ENDFINALLY_HEIGHT,
                    insn.offset,
                    f"endfinally requires an empty evaluation stack, found {height} value(s)",
                    (path,),
                )
            return

        if op == OpCodeValue.Endfilter:
            self._process_endfilter(insn, height, path)
            return

        if op == OpCodeValue.Jmp:
            if height is not None and height != 0:
                self._transfer_conflicts.add(insn.offset)
                self._add_issue(
                    StackIssueKind.JMP_STACK_NOT_EMPTY,
                    insn.offset,
                    "jmp requires an empty evaluation stack",
                    (path,),
                )
            return

        if insn.opcode.op_code_type == OpCodeType.Prefix:
            # Prefixes are annotations; they do not change the height.
            self._enqueue_next(insn, height, path)
            return

        if height is None:
            self._propagate_unknown(insn, path, "incoming stack height is unknown")
            return

        if op in (OpCodeValue.Call, OpCodeValue.Callvirt, OpCodeValue.Newobj, OpCodeValue.Calli):
            self._process_call(insn, height, path)
            return

        if op in (OpCodeValue.Br, OpCodeValue.Br_S):
            target = insn.operand
            if isinstance(target, int):
                self._enqueue_target(target, height, path, insn)
            else:
                self._unknown_target(insn, path)
            return

        if op == OpCodeValue.Switch:
            targets = insn.operand
            after = self._require(insn, height, 1, path)
            if after is None:
                return
            if not isinstance(targets, list):
                self._unknown_target(insn, path)
                return
            for target in targets:
                self._enqueue_target(target, after, path, insn)
            self._enqueue_next(insn, after, path)
            return

        if insn.is_cond_br():
            target = insn.operand
            pops = _POPS.get(insn.opcode.stack_pop)
            if pops is None:
                self._unknown_effect(
                    insn,
                    path,
                    f"{insn.mnemonic} has unresolved stack behaviour",
                    StackIssueKind.UNRESOLVED_STACK_EFFECT,
                )
                return
            after = self._require(insn, height, pops, path)
            if after is None:
                return
            if isinstance(target, int):
                self._enqueue_target(target, after, path, insn)
            else:
                self._unknown_target(insn, path)
            self._enqueue_next(insn, after, path)
            return

        pops = _POPS.get(insn.opcode.stack_pop)
        pushes = _PUSHES.get(insn.opcode.stack_push)
        if pops is None or pushes is None:
            # A variable effect that was not handled above is missing
            # information, not a zero-height operation.
            self._unknown_effect(
                insn,
                path,
                f"{insn.mnemonic} has unresolved stack behaviour",
                StackIssueKind.UNRESOLVED_STACK_EFFECT,
            )
            return

        after = self._require(insn, height, pops, path)
        if after is None:
            return
        after += pushes
        if after > height:
            self._record_height(after, _path_to(insn.offset, after, path))
        self._enqueue_next(insn, after, path)

    def _process_ret(self, insn: "Instruction", height: Optional[int], path: StackPath) -> None:
        if height is None:
            return
        if self.return_value is None:
            # The method body does not carry the return shape.  A ret with a
            # non-empty stack is still legal for a method returning one value,
            # so no verdict is possible without the caller's MethodDef
            # signature.  Report the dependency rather than guessing.
            if height > 1:
                self._transfer_conflicts.add(insn.offset)
                self._add_issue(
                    StackIssueKind.RET_HEIGHT,
                    insn.offset,
                    f"ret has {height} values but at most one can be returned; "
                    "pass return_value to identify the exact signature mismatch",
                    (path,),
                )
            return
        expected = 1 if self.return_value else 0
        if height != expected:
            self._transfer_conflicts.add(insn.offset)
            self._add_issue(
                StackIssueKind.RET_HEIGHT,
                insn.offset,
                f"ret has {height} value(s) on the stack but the method signature expects {expected}",
                (path,),
            )

    def _process_endfilter(self, insn: "Instruction", height: Optional[int], path: StackPath) -> None:
        if height is None:
            return
        # ECMA-335 requires exactly one value (the filter result) at endfilter.
        if height != 1:
            self._transfer_conflicts.add(insn.offset)
            self._add_issue(
                StackIssueKind.ENDFILTER_HEIGHT,
                insn.offset,
                f"endfilter requires exactly one stack value, found {height}",
                (path,),
            )

    def _process_call(self, insn: "Instruction", height: int, path: StackPath) -> None:
        signature, reason = self._resolve_call(insn)
        if signature is None:
            self._unknown_effect(insn, path, reason)
            return

        op = insn.opcode.value
        pops = signature.parameter_count
        if op in (OpCodeValue.Call, OpCodeValue.Callvirt):
            if signature.has_this:
                pops += 1
        elif op == OpCodeValue.Calli:
            if signature.has_this:
                pops += 1
            pops += 1  # the function pointer
        # newobj never consumes a receiver; it creates one.

        after = self._require(insn, height, pops, path)
        if after is None:
            return
        if op == OpCodeValue.Newobj or signature.returns_value:
            after += 1
        self._record_height(after, _path_to(insn.offset, after, path))
        self._enqueue_next(insn, after, path)

    def _resolve_call(self, insn: "Instruction") -> Tuple[Optional[CallSignature], str]:
        token = insn.operand
        signature: Any = None
        error = ""

        if self.resolve_signature is not None:
            resolver: Any = self.resolve_signature
            try:
                if callable(resolver):
                    signature = resolver(token)
                elif hasattr(resolver, "resolve"):
                    signature = resolver.resolve(token)
                elif hasattr(resolver, "resolve_signature"):
                    signature = resolver.resolve_signature(token)
                else:
                    error = "signature resolver is neither callable nor has resolve()"
            except Exception as exc:  # noqa: BLE001 - a failing resolver means missing information
                error = f"signature resolver raised {type(exc).__name__}: {exc}"

        if signature is None and self.signatures is not None:
            key: Any = token
            if key not in self.signatures and isinstance(token, Token):
                key = token.value
            signature = self.signatures.get(key)

        if signature is None:
            detail = f"unresolved call signature for {token} at {insn.mnemonic}"
            if error:
                detail += f" ({error})"
            return None, detail
        if isinstance(signature, CallSignature):
            return signature, ""
        return None, f"resolver returned {type(signature).__name__} for {token}, expected CallSignature"

    def _require(self, insn: "Instruction", height: int, pops: int, path: StackPath) -> Optional[int]:
        if height < pops:
            self._transfer_conflicts.add(insn.offset)
            self._add_issue(
                StackIssueKind.STACK_UNDERFLOW,
                insn.offset,
                f"{insn.mnemonic} pops {pops} value(s) but only {height} are available",
                (path,),
            )
            return None
        return height - pops

    def _unknown_target(self, insn: "Instruction", path: StackPath) -> None:
        self._transfer_unknown.add(insn.offset)
        self._add_issue(
            StackIssueKind.UNKNOWN_BRANCH_TARGET,
            insn.offset,
            f"cannot determine the branch target of {insn.mnemonic}",
            (path,),
        )

    def _unknown_effect(
        self,
        insn: "Instruction",
        path: StackPath,
        reason: str,
        kind: StackIssueKind = StackIssueKind.UNRESOLVED_SIGNATURE,
    ) -> None:
        self._transfer_unknown.add(insn.offset)
        self._add_issue(kind, insn.offset, reason, (path,))
        self._propagate_unknown(insn, path, reason)

    def _propagate_unknown(self, insn: "Instruction", path: StackPath, reason: str) -> None:
        """Propagate an unknown height to every successor of ``insn``.

        Keeping the unknown state explicit is what prevents an unresolved call
        on one branch from making a different branch appear verified.
        """
        op = insn.opcode.value
        unknown_path = StackPath(None, path.offsets, reason=reason, origin=path.origin)

        if op in (
            OpCodeValue.Ret,
            OpCodeValue.Endfinally,
            OpCodeValue.Endfilter,
            OpCodeValue.Jmp,
            OpCodeValue.Throw,
            OpCodeValue.Rethrow,
        ):
            return

        if op == OpCodeValue.Switch:
            targets = insn.operand
            if isinstance(targets, list):
                for target in targets:
                    self._enqueue_target(target, None, unknown_path, insn)
            self._enqueue_next(insn, None, unknown_path, reason=reason)
            return

        if insn.is_cond_br():
            target = insn.operand
            if isinstance(target, int):
                self._enqueue_target(target, None, unknown_path, insn)
            self._enqueue_next(insn, None, unknown_path, reason=reason)
            return

        if op in (OpCodeValue.Br, OpCodeValue.Br_S):
            target = insn.operand
            if isinstance(target, int):
                self._enqueue_target(target, None, unknown_path, insn)
            return

        self._enqueue_next(insn, None, unknown_path, reason=reason)

    # -------------------------------------------------------------- helpers
    def _record_height(self, height: int, path: StackPath) -> None:
        if height > self._derived_max:
            self._derived_max = height
            self._max_path = path

    def _add_issue(
        self,
        kind: StackIssueKind,
        offset: int,
        message: str,
        paths: Sequence[StackPath] = (),
    ) -> None:
        key = (kind, offset, message)
        if key in self._issue_keys:
            return
        self._issue_keys.add(key)
        self._issues.append(StackIssue(kind=kind, offset=offset, message=message, paths=tuple(paths)))

    def _check_max_stack(self) -> None:
        declared = int(self.body.max_stack)
        if self._derived_max > declared:
            path = self._max_path
            self._add_issue(
                StackIssueKind.MAX_STACK_EXCEEDED,
                path.offsets[-1] if path is not None else 0,
                f"derived stack height {self._derived_max} exceeds declared .maxstack {declared}",
                (path,) if path is not None else (),
            )

    def _build_result(self) -> StackAnalysisResult:
        declared = int(self.body.max_stack)
        issues_by_offset: Dict[int, List[StackIssueKind]] = {}
        for issue in self._issues:
            issues_by_offset.setdefault(issue.offset, []).append(issue.kind)

        reports: Dict[int, InstructionStackReport] = {}
        for insn in self._instructions:
            states = self._states.get(insn.offset, {})
            known_heights = tuple(sorted(known for known in states if known is not None))
            has_unknown = None in states
            conflict = len(known_heights) > 1 or insn.offset in self._transfer_conflicts
            if conflict:
                status = StackStatus.CONFLICT
            elif has_unknown or insn.offset in self._transfer_unknown:
                status = StackStatus.UNKNOWN
            elif len(known_heights) == 1:
                status = StackStatus.KNOWN
            else:
                # No incoming state at all.  This is unreachable code, which is
                # distinct from a reachable path whose height is unknown.
                status = StackStatus.UNREACHABLE
            height = known_heights[0] if len(known_heights) == 1 and not has_unknown else None
            # One representative path per distinct height.  Additional
            # same-height chains from a loop are exposed through
            # ``StackAnalysisResult.joins`` instead, keeping ``chain``
            # unambiguous for a converged loop head.
            paths = tuple(states[known] for known in sorted(states, key=lambda h: (h is None, h or 0)))
            reports[insn.offset] = InstructionStackReport(
                offset=insn.offset,
                mnemonic=insn.mnemonic,
                status=status,
                height=height,
                known_heights=known_heights,
                paths=paths,
                issues=tuple(issues_by_offset.get(insn.offset, ())),
            )

        has_conflict = any(issue.kind in _CONFLICT_KINDS for issue in self._issues)
        has_unknown = (
            self._has_unknown
            or bool(self._transfer_unknown)
            or any(issue.kind in _UNKNOWN_KINDS for issue in self._issues)
        )
        if has_conflict:
            status = StackStatus.CONFLICT
        elif has_unknown:
            status = StackStatus.UNKNOWN
        else:
            status = StackStatus.KNOWN

        if self._derived_max > declared:
            relation = MaxStackRelation.EXCEEDED
        elif has_unknown:
            relation = MaxStackRelation.UNKNOWN
        else:
            relation = MaxStackRelation.WITHIN

        joins: Dict[int, Tuple[StackPath, ...]] = {}
        for offset in sorted(self._states):
            states = self._states[offset]
            extra = self._extra_paths.get(offset, {})
            merge_paths = list(states.values()) + list(extra.values())
            unique: Dict[Tuple[int, ...], StackPath] = {}
            for merge_path in merge_paths:
                unique.setdefault(merge_path.offsets, merge_path)
            if len(unique) > 1:
                joins[offset] = tuple(unique.values())

        return StackAnalysisResult(
            status=status,
            instructions=reports,
            issues=tuple(self._issues),
            declared_max_stack=declared,
            derived_max_stack=self._derived_max,
            max_stack_relation=relation,
            max_stack_is_complete=not has_unknown,
            entry_offset=self._entry_offset,
            max_stack_path=self._max_path,
            joins=joins,
        )


def _path_to(offset: int, height: int, path: StackPath) -> StackPath:
    """Return a copy of ``path`` ending at ``offset`` with ``height``."""
    offsets = path.offsets
    if not offsets or offsets[-1] != offset:
        offsets = offsets + (offset,)
    return StackPath(height, offsets, reason=path.reason, origin=path.origin)


def analyze_stack(
    body: "CilMethodBody",
    resolve_signature: Optional[SignatureResolver] = None,
    **kwargs: Any,
) -> StackAnalysisResult:
    """Convenience wrapper around :class:`StackAnalyzer` for one method body."""
    return StackAnalyzer(body, resolve_signature, **kwargs).analyze()
