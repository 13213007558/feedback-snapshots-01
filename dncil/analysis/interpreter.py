"""Bounded worklist interpreter implementing the supported constant recovery.

The interpreter walks the CFG implied by dncil instructions with a classic
chaotic-iteration worklist. Because the abstract domain (:mod:`dncil.analysis.domain`)
is a finite-height lattice, repeated processing of loop headers reaches a fixed
point. Every instruction has a single merged entry state; a merge that cannot
agree on a constant promotes that slot to top instead of choosing a side.

Safety boundaries:

* only dncil-parsed instructions and caller-supplied :class:`Metadata` tables
  are inspected - no assembly is loaded and no metadata token is executed;
* calls to methods outside :class:`KnownOp` invalidate the evaluation stack
  (its results become unknown) and mark the flow pending;
* every :class:`AnalysisBudget` limit aborts the run with a pending verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from dncil.cil.body import CilMethodBody
from dncil.cil.enums import OpCodeValue
from dncil.cil.instruction import Instruction
from dncil.clr.token import Token

from dncil.analysis.domain import (
    TOP,
    ArrayValue,
    CharValue,
    Confidence,
    IntValue,
    StringValue,
    Value,
    _Top,
    merge_values,
    top_with_fragments,
)
from dncil.analysis.metadata import (
    AnalysisBudget,
    KnownOp,
    LimitExceeded,
    Metadata,
    MethodBinding,
)


@dataclass
class AnalysisLimits:
    """Public summary of whether a run stayed inside its budget."""

    completed: bool
    reason: Optional[str]
    iterations: int
    states_visited: int


@dataclass
class RecoveredExpression:
    """One value observed at a ``ret`` boundary or requested inspection point."""

    offset: int
    value: Value
    confidence: Confidence


@dataclass
class AnalysisResult:
    """Output of :func:`analyze_body`."""

    recovered: List[RecoveredExpression]
    limits: AnalysisLimits
    pending_reasons: List[str] = field(default_factory=list)


class _AbstractState:
    """Merged abstract state at one program point: evaluation stack + locals."""

    def __init__(self, num_locals: int, budget: AnalysisBudget):
        self.stack: List[Value] = []
        self.locals: List[Value] = [TOP for _ in range(num_locals)]
        self.budget = budget
        self.pending: List[str] = []

    def clone(self) -> "_AbstractState":
        other = _AbstractState(len(self.locals), self.budget)
        other.stack = list(self.stack)
        other.locals = list(self.locals)
        other.pending = list(self.pending)
        return other

    def note_pending(self, reason: str) -> None:
        if reason not in self.pending:
            self.pending.append(reason)

    def push(self, value: Value) -> None:
        if len(self.stack) >= self.budget.max_stack_depth:
            raise LimitExceeded("max evaluation stack depth exceeded")
        self.stack.append(value)

    def pop(self) -> Value:
        if not self.stack:
            # Underflow means the IL pattern is outside the supported model.
            self.note_pending("evaluation stack underflow")
            return TOP
        return self.stack.pop()

    def pop_n(self, count: int) -> List[Value]:
        if len(self.stack) < count:
            self.note_pending("evaluation stack underflow")
            available = list(self.stack)
            self.stack = []
            tops = [TOP] * (count - len(available))
            return tops + available
        if count == 0:
            return []
        popped = self.stack[-count:]
        del self.stack[-count:]
        return popped


def _merge_state(existing: Optional[_AbstractState], incoming: _AbstractState) -> _AbstractState:
    """Merge ``incoming`` into the state for a program point.

    Stack depth conflicts invalidate the whole stack (never silently truncate);
    locals and individual stack slots join through the value lattice.
    """
    if existing is None:
        return incoming
    merged = existing.clone()
    if len(merged.stack) != len(incoming.stack):
        merged.note_pending("conflicting evaluation stack depth at control-flow join")
        # An empty stack is the only choice that stays bounded; pushing tops
        # here could grow without limit on malformed/unsupported input.
        merged.stack = []
    else:
        merged.stack = [merge_values(a, b) for a, b in zip(merged.stack, incoming.stack)]
    if len(merged.locals) != len(incoming.locals):
        merged.note_pending("conflicting local count at control-flow join")
    else:
        merged.locals = [merge_values(a, b) for a, b in zip(merged.locals, incoming.locals)]
    for reason in incoming.pending:
        if reason not in merged.pending:
            merged.pending.append(reason)
    return merged


class _Interpreter:
    def __init__(self, body: CilMethodBody, metadata: Metadata, budget: AnalysisBudget):
        self.body = body
        self.metadata = metadata
        self.budget = budget
        self.instructions: Dict[int, Instruction] = {insn.offset: insn for insn in body.instructions}
        self.order: List[int] = [insn.offset for insn in body.instructions]
        max_local_index = -1
        for insn in body.instructions:
            local = insn.get_stloc() if insn.is_stloc() else insn.get_ldoc() if insn.is_ldloc() else None
            if local is not None:
                max_local_index = max(max_local_index, int(local))
        self.num_locals = max_local_index + 1
        self.states: Dict[int, _AbstractState] = {}
        self._recovered_by_offset: Dict[int, Value] = {}
        self.pending_reasons: List[str] = []
        self.iterations = 0
        self.states_visited = 0
        self.abort_reason: Optional[str] = None

    def run(self) -> AnalysisResult:
        if len(self.instructions) > self.budget.max_instructions:
            return self._abort("method exceeds max instruction budget")
        worklist: List[int] = []
        if self.order:
            entry = _AbstractState(self.num_locals, self.budget)
            self.states[self.order[0]] = entry
            worklist.append(self.order[0])
        while worklist:
            offset = worklist.pop(0)
            if offset not in self.instructions:
                # Jump into unknown code (e.g. leave target outside the body).
                self._record_pending("branch target outside analyzed instruction stream")
                continue
            state = self.states[offset]
            self.iterations += 1
            self.states_visited += 1
            if self.iterations > self.budget.max_iterations:
                return self._abort("fixed-point iteration budget exceeded")
            if self.states_visited > self.budget.max_states:
                return self._abort("state visit budget exceeded")
            insn = self.instructions[offset]
            try:
                successors = self._transfer(insn, state)
            except LimitExceeded as exc:
                return self._abort(str(exc))
            for target, target_state in successors:
                if target not in self.instructions:
                    # Jump outside the analyzed stream (e.g. an unmodeled target).
                    self._record_pending("branch target outside analyzed instruction stream")
                    continue
                if target == self.order[0]:
                    # The method entry has a fixed empty-stack initial state; it
                    # must never be re-entered through a backward edge.
                    self._record_pending("backward edge targets the method entry")
                    continue
                prior = self.states.get(target)
                merged = _merge_state(prior, target_state)
                # Always persist the merged state so evidence accumulates; the
                # worklist is only extended when lattice semantics actually move.
                self.states[target] = merged
                if (prior is None or not _state_equivalent(prior, merged)) and target not in worklist:
                    worklist.append(target)
        self._collect_pending()
        return AnalysisResult(
            recovered=self._build_recovered(),
            limits=AnalysisLimits(True, None, self.iterations, self.states_visited),
            pending_reasons=list(self.pending_reasons),
        )

    def _build_recovered(self) -> List[RecoveredExpression]:
        recovered: List[RecoveredExpression] = []
        for offset in sorted(self._recovered_by_offset):
            value = self._recovered_by_offset[offset]
            recovered.append(RecoveredExpression(offset, value, value.confidence))
        return recovered

    def _abort(self, reason: str) -> AnalysisResult:
        self.abort_reason = reason
        self._collect_pending()
        if reason not in self.pending_reasons:
            self.pending_reasons.append(reason)
        # Keep whatever expressions were recovered, but mark them pending.
        recovered = [
            RecoveredExpression(offset, value, Confidence.PENDING)
            for offset, value in sorted(self._recovered_by_offset.items())
        ]
        return AnalysisResult(
            recovered=recovered,
            limits=AnalysisLimits(False, reason, self.iterations, self.states_visited),
            pending_reasons=list(self.pending_reasons),
        )

    def _record_pending(self, reason: str) -> None:
        if reason not in self.pending_reasons:
            self.pending_reasons.append(reason)

    def _collect_pending(self) -> None:
        for state in self.states.values():
            for reason in state.pending:
                self._record_pending(reason)

    # ------------------------------------------------------------------
    # transfer
    # ------------------------------------------------------------------
    def _transfer(self, insn: Instruction, state: _AbstractState) -> List[Tuple[int, _AbstractState]]:
        op = insn.opcode.value
        offset = insn.offset
        handler = self._HANDLERS.get(op)
        if handler is None:
            return self._unsupported(insn, state)
        next_offset = self._next_offset(offset)
        return handler(self, insn, state, offset, next_offset)

    def _next_offset(self, offset: int) -> Optional[int]:
        try:
            index = self.order.index(offset)
        except ValueError:
            return None
        if index + 1 >= len(self.order):
            return None
        return self.order[index + 1]

    def _unsupported(self, insn: Instruction, state: _AbstractState) -> List[Tuple[int, _AbstractState]]:
        state.note_pending("unsupported opcode %s" % insn.mnemonic)
        # Conservatively invalidate everything the unknown instruction may touch.
        state.stack = []
        state.locals = [TOP for _ in state.locals]
        nxt = self._next_offset(insn.offset)
        return [(nxt, state)] if nxt is not None else []

    # ----- constant / local / argument loads -------------------------------
    def _ldc(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        const = insn.get_ldc()
        if isinstance(const, float):
            state.note_pending("floating-point constant outside supported domain")
            state.push(TOP.with_evidence([offset]))
        else:
            state.push(IntValue(frozenset({offset}), int(const)))
        return [(nxt, state)] if nxt is not None else []

    def _ldstr(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        token_value = int(insn.operand)
        text = self.metadata.lookup_string(token_value)
        if text is None:
            state.note_pending("ldstr token 0x%08X not present in supplied metadata" % token_value)
            state.push(TOP.with_evidence([offset]))
        else:
            if len(text) > self.budget.max_string_length:
                raise LimitExceeded("string literal exceeds max string length budget")
            state.push(StringValue(frozenset({offset}), text))
        return [(nxt, state)] if nxt is not None else []

    def _ldloc(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        local = insn.get_ldoc()
        index = int(local)
        if index >= len(state.locals):
            state.push(TOP.with_evidence([offset]))
        else:
            state.push(state.locals[index].with_evidence([offset]))
        return [(nxt, state)] if nxt is not None else []

    def _stloc(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        local = insn.get_stloc()
        index = int(local)
        value = state.pop()
        if index < len(state.locals):
            state.locals[index] = value.with_evidence([offset])
        else:
            state.note_pending("stloc index %d outside local table" % index)
        return [(nxt, state)] if nxt is not None else []

    def _ldarg(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        # Method arguments have no tracked constant value; this is a domain
        # boundary rather than an analysis failure, so no pending reason is
        # recorded for a plain argument load.
        state.push(TOP.with_evidence([offset]))
        return [(nxt, state)] if nxt is not None else []

    def _starg(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        state.pop()
        state.note_pending("starg writes an untracked method argument")
        return [(nxt, state)] if nxt is not None else []

    # ----- stack plumbing ---------------------------------------------------
    def _nop(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        return [(nxt, state)] if nxt is not None else []

    def _dup(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        if not state.stack:
            state.note_pending("evaluation stack underflow")
            state.push(TOP.with_evidence([offset]))
            return [(nxt, state)] if nxt is not None else []
        state.push(state.stack[-1].with_evidence([offset]))
        return [(nxt, state)] if nxt is not None else []

    def _pop(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        state.pop()
        return [(nxt, state)] if nxt is not None else []

    # ----- arrays -----------------------------------------------------------
    def _newarr(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        size_value = state.pop()
        if not isinstance(size_value, IntValue):
            state.note_pending("newarr with non-constant length")
            state.push(TOP.with_evidence([offset]))
            return [(nxt, state)] if nxt is not None else []
        if size_value.value < 0:
            state.note_pending("newarr with negative length")
            state.push(TOP.with_evidence([offset]))
            return [(nxt, state)] if nxt is not None else []
        if size_value.value > self.budget.max_array_length:
            raise LimitExceeded("array length exceeds max array length budget")
        state.push(ArrayValue(frozenset({offset}), size_value.value, {}))
        return [(nxt, state)] if nxt is not None else []

    def _ldlen(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        array_value = state.pop()
        if not isinstance(array_value, ArrayValue):
            state.note_pending("ldlen on unknown or non-array value")
            state.push(TOP.with_evidence([offset]))
        else:
            state.push(IntValue(frozenset(set(array_value.evidence) | {offset}), array_value.length))
        return [(nxt, state)] if nxt is not None else []

    def _stelem(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        value = state.pop()
        index_value = state.pop()
        array_value = state.pop()
        if not isinstance(array_value, ArrayValue):
            state.note_pending("stelem target is not a tracked array")
            state.push(TOP.with_evidence([offset]))
            return [(nxt, state)] if nxt is not None else []
        if not isinstance(index_value, IntValue):
            # A dynamic index could overwrite any slot, so the whole array's
            # contents can no longer be trusted; length alone is not enough.
            state.note_pending("stelem with non-constant index invalidates array contents")
            state.push(TOP.with_evidence(list(array_value.evidence) + [offset]))
            return [(nxt, state)] if nxt is not None else []
        updated = array_value.write(index_value.value, value.with_evidence([offset]))
        if updated is None:
            state.note_pending("stelem index %d out of array bounds" % index_value.value)
            state.push(TOP.with_evidence(list(array_value.evidence) + [offset]))
        else:
            state.push(updated)
        return [(nxt, state)] if nxt is not None else []

    def _ldelem(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        index_value = state.pop()
        array_value = state.pop()
        if not isinstance(array_value, ArrayValue):
            state.note_pending("ldelem on unknown or non-array value")
            state.push(TOP.with_evidence([offset]))
        elif not isinstance(index_value, IntValue):
            state.note_pending("ldelem with non-constant index")
            state.push(TOP.with_evidence([offset]))
        else:
            slot = array_value.read(index_value.value)
            if slot is TOP:
                state.note_pending("array slot %d was never written or is out of bounds" % index_value.value)
            state.push(slot.with_evidence(list(slot.evidence) + [offset]))
        return [(nxt, state)] if nxt is not None else []

    # ----- char conversion --------------------------------------------------
    def _conv_u2(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        value = state.pop()
        if not isinstance(value, IntValue):
            state.note_pending("conv.u2 on non-integer value")
            state.push(TOP.with_evidence([offset]))
        else:
            # ECMA conv.u2: truncate to unsigned 16-bit wrap, no exception.
            state.push(CharValue(frozenset(set(value.evidence) | {offset}), value.value & 0xFFFF))
        return [(nxt, state)] if nxt is not None else []

    # ----- calls ------------------------------------------------------------
    def _token_value(self, insn: Instruction) -> int:
        operand = insn.operand
        return int(operand) if isinstance(operand, Token) else int(operand)

    def _call(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        token_value = self._token_value(insn)
        binding = self.metadata.lookup_method(token_value)
        if binding is None:
            return self._unknown_call(insn, state, offset, nxt)
        if binding.op is KnownOp.CONVERT_TO_CHAR or binding.op is KnownOp.CONVERT_TO_CHAR_FROM_CHAR:
            return self._convert_to_char(binding, insn, state, offset, nxt)
        if binding.op is KnownOp.STRING_CONCAT:
            return self._string_concat(binding, insn, state, offset, nxt)
        state.note_pending("bound method %s has no interpreter semantics" % binding.name)
        return self._unknown_call(insn, state, offset, nxt)

    def _unknown_call(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        # The method may read/write any reachable object; drop stack and locals.
        state.note_pending("unknown method call at IL_%04X" % offset)
        state.stack = []
        state.locals = [TOP for _ in state.locals]
        # A call conventionally leaves one (unknown) result on the stack.
        state.push(TOP.with_evidence([offset]))
        return [(nxt, state)] if nxt is not None else []

    def _convert_to_char(
        self, binding: MethodBinding, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]
    ):
        value = state.pop()
        if binding.op is KnownOp.CONVERT_TO_CHAR_FROM_CHAR:
            if isinstance(value, CharValue):
                state.push(CharValue(frozenset(set(value.evidence) | {offset}), value.code))
            else:
                state.note_pending("Convert.ToChar(char) received non-char value")
                state.push(TOP.with_evidence([offset]))
        elif isinstance(value, IntValue):
            if not 0 <= value.value <= 0xFFFF:
                state.note_pending("Convert.ToChar(int) argument 0x%X outside char range" % value.value)
                state.push(TOP.with_evidence([offset]))
            else:
                state.push(CharValue(frozenset(set(value.evidence) | {offset}), value.value))
        else:
            state.note_pending("Convert.ToChar(int) received non-integer value")
            state.push(TOP.with_evidence([offset]))
        return [(nxt, state)] if nxt is not None else []

    def _string_concat(
        self, binding: MethodBinding, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]
    ):
        # Two static shapes are modeled: concat of two strings, and concat of a
        # params string[] / char[] built by newarr in the same stream.
        first = state.stack[-1] if state.stack else TOP
        if isinstance(first, ArrayValue):
            array_value = state.pop()
            return self._concat_array(array_value, insn, state, offset, nxt)
        right = state.pop()
        left = state.pop()
        if isinstance(left, StringValue) and isinstance(right, StringValue):
            combined = left.text + right.text
            if len(combined) > self.budget.max_string_length:
                raise LimitExceeded("concatenated string exceeds max string length budget")
            evidence = frozenset(set(left.evidence) | set(right.evidence) | {offset})
            state.push(StringValue(evidence, combined))
        else:
            state.note_pending("String.Concat with non-constant or unsupported operands")
            state.push(TOP.with_evidence([offset]))
        return [(nxt, state)] if nxt is not None else []

    def _concat_array(
        self, array_value: Value, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]
    ):
        if not isinstance(array_value, ArrayValue):
            state.note_pending("String.Concat params argument is not a tracked array")
            state.push(TOP.with_evidence([offset]))
            return [(nxt, state)] if nxt is not None else []
        pieces: List[str] = []
        slot_evidence: set[int] = set()
        for index in range(array_value.length):
            slot = array_value.read(index)
            slot_evidence.update(slot.evidence)
            if isinstance(slot, StringValue):
                pieces.append(slot.text)
            elif isinstance(slot, CharValue):
                pieces.append(chr(slot.code))
            else:
                state.note_pending("String.Concat array slot %d is not constant" % index)
                gaps = sum(
                    1
                    for slot_index in range(array_value.length)
                    if not isinstance(array_value.read(slot_index), (StringValue, CharValue))
                )
                state.push(
                    top_with_fragments(
                        frozenset(set(array_value.evidence) | slot_evidence | {offset}), pieces, gaps
                    )
                )
                return [(nxt, state)] if nxt is not None else []
        combined = "".join(pieces)
        if len(combined) > self.budget.max_string_length:
            raise LimitExceeded("concatenated string exceeds max string length budget")
        evidence = frozenset(set(array_value.evidence) | slot_evidence | {offset})
        state.push(StringValue(evidence, combined))
        return [(nxt, state)] if nxt is not None else []

    def _newobj(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        token_value = self._token_value(insn)
        binding = self.metadata.lookup_method(token_value)
        if binding is None or binding.op is not KnownOp.STRING_CTOR_CHARS:
            state.note_pending("unsupported constructor token 0x%08X" % token_value)
            return self._unknown_call(insn, state, offset, nxt)
        array_value = state.pop()
        if not isinstance(array_value, ArrayValue):
            state.note_pending("String(char[]) received a non-array value")
            state.push(TOP.with_evidence([offset]))
            return [(nxt, state)] if nxt is not None else []
        pieces: List[str] = []
        gaps = 0
        buffer = ""
        slot_evidence: set[int] = set()
        for index in range(array_value.length):
            slot = array_value.read(index)
            slot_evidence.update(slot.evidence)
            if isinstance(slot, CharValue):
                buffer += chr(slot.code)
            elif isinstance(slot, StringValue):
                if buffer:
                    pieces.append(buffer)
                    buffer = ""
                pieces.append(slot.text)
            else:
                if buffer:
                    pieces.append(buffer)
                    buffer = ""
                gaps += 1
        if buffer:
            pieces.append(buffer)
        ctor_evidence = frozenset(set(array_value.evidence) | slot_evidence | {offset})
        if gaps:
            state.push(top_with_fragments(ctor_evidence, pieces, gaps))
            return [(nxt, state)] if nxt is not None else []
        combined = "".join(pieces)
        if len(combined) > self.budget.max_string_length:
            raise LimitExceeded("constructed string exceeds max string length budget")
        state.push(StringValue(ctor_evidence, combined))
        return [(nxt, state)] if nxt is not None else []

    # ----- control flow -----------------------------------------------------
    def _ret(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        value = state.pop() if state.stack else TOP
        prior = self._recovered_by_offset.get(offset)
        self._recovered_by_offset[offset] = value if prior is None else merge_values(prior, value)
        return []

    def _unconditional_br(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        target = int(insn.operand)
        return [(target, state)]

    def _conditional_br(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        # Both successors are explored; each needs its own state copy so mutable
        # stacks never alias. brtrue/brfalse consume one value, the comparison
        # branches consume two.
        pops = 1 if insn.is_br_false() or insn.is_br_true() else 2
        state.pop_n(pops)
        target = int(insn.operand)
        successors = []
        if nxt is not None:
            successors.append((nxt, state.clone()))
        successors.append((target, state.clone()))
        return successors

    def _switch(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        state.pop()
        targets = list(insn.operand)
        successors = []
        if nxt is not None:
            successors.append((nxt, state.clone()))
        for target in targets:
            successors.append((int(target), state.clone()))
        return successors

    def _leave(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        # Exception flow is not modeled; the target must be analyzed conservatively.
        state.note_pending("leave instruction: exception handler flow is not modeled")
        return [(int(insn.operand), state)]

    def _throw(self, insn: Instruction, state: _AbstractState, offset: int, nxt: Optional[int]):
        state.pop()
        state.note_pending("throw terminates flow without a recoverable value")
        return []


def _state_equivalent(left: _AbstractState, right: _AbstractState) -> bool:
    """Lattice-semantic equality; evidence accumulation is intentionally ignored."""
    if len(left.stack) != len(right.stack) or len(left.locals) != len(right.locals):
        return False
    if left.pending != right.pending:
        return False
    for a, b in zip(left.stack, right.stack):
        if not _value_equivalent(a, b):
            return False
    for a, b in zip(left.locals, right.locals):
        if not _value_equivalent(a, b):
            return False
    return True


def _value_equivalent(left: Value, right: Value) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, _Top):
        return _alternative_signature(left) == _alternative_signature(right)  # type: ignore[arg-type]
    if isinstance(left, ArrayValue):
        if left.length != right.length or set(left.slots) != set(right.slots):  # type: ignore[union-attr]
            return False
        return all(_value_equivalent(left.slots[i], right.slots[i]) for i in left.slots)  # type: ignore[union-attr]
    if isinstance(left, IntValue):
        return left.value == right.value  # type: ignore[union-attr]
    if isinstance(left, CharValue):
        return left.code == right.code  # type: ignore[union-attr]
    if isinstance(left, StringValue):
        return left.text == right.text  # type: ignore[union-attr]
    return False


def _alternative_signature(top_value: "_Top") -> tuple:
    signature = []
    for alternative in top_value.alternatives:
        if isinstance(alternative, StringValue):
            signature.append(("s", alternative.text))
        elif isinstance(alternative, IntValue):
            signature.append(("i", alternative.value))
        elif isinstance(alternative, CharValue):
            signature.append(("c", alternative.code))
    return tuple(signature)


def analyze_body(
    body: CilMethodBody,
    metadata: Optional[Metadata] = None,
    budget: Optional[AnalysisBudget] = None,
) -> AnalysisResult:
    """Run bounded constant propagation on one parsed method body.

    The function only reads dncil structures and the supplied metadata tables;
    it performs no assembly loads and no method execution.
    """
    interpreter = _Interpreter(body, metadata or Metadata(), budget or AnalysisBudget())
    return interpreter.run()


# Dispatch table built once from OpCodeValue members.
_Interpreter._HANDLERS = {
    OpCodeValue.Nop: _Interpreter._nop,
    OpCodeValue.Ldc_I4_M1: _Interpreter._ldc,
    OpCodeValue.Ldc_I4_0: _Interpreter._ldc,
    OpCodeValue.Ldc_I4_1: _Interpreter._ldc,
    OpCodeValue.Ldc_I4_2: _Interpreter._ldc,
    OpCodeValue.Ldc_I4_3: _Interpreter._ldc,
    OpCodeValue.Ldc_I4_4: _Interpreter._ldc,
    OpCodeValue.Ldc_I4_5: _Interpreter._ldc,
    OpCodeValue.Ldc_I4_6: _Interpreter._ldc,
    OpCodeValue.Ldc_I4_7: _Interpreter._ldc,
    OpCodeValue.Ldc_I4_8: _Interpreter._ldc,
    OpCodeValue.Ldc_I4_S: _Interpreter._ldc,
    OpCodeValue.Ldc_I4: _Interpreter._ldc,
    OpCodeValue.Ldc_I8: _Interpreter._ldc,
    OpCodeValue.Ldstr: _Interpreter._ldstr,
    OpCodeValue.Ldloc: _Interpreter._ldloc,
    OpCodeValue.Ldloc_S: _Interpreter._ldloc,
    OpCodeValue.Ldloc_0: _Interpreter._ldloc,
    OpCodeValue.Ldloc_1: _Interpreter._ldloc,
    OpCodeValue.Ldloc_2: _Interpreter._ldloc,
    OpCodeValue.Ldloc_3: _Interpreter._ldloc,
    OpCodeValue.Stloc: _Interpreter._stloc,
    OpCodeValue.Stloc_S: _Interpreter._stloc,
    OpCodeValue.Stloc_0: _Interpreter._stloc,
    OpCodeValue.Stloc_1: _Interpreter._stloc,
    OpCodeValue.Stloc_2: _Interpreter._stloc,
    OpCodeValue.Stloc_3: _Interpreter._stloc,
    OpCodeValue.Ldarg: _Interpreter._ldarg,
    OpCodeValue.Ldarg_S: _Interpreter._ldarg,
    OpCodeValue.Ldarg_0: _Interpreter._ldarg,
    OpCodeValue.Ldarg_1: _Interpreter._ldarg,
    OpCodeValue.Ldarg_2: _Interpreter._ldarg,
    OpCodeValue.Ldarg_3: _Interpreter._ldarg,
    OpCodeValue.Starg: _Interpreter._starg,
    OpCodeValue.Starg_S: _Interpreter._starg,
    OpCodeValue.Dup: _Interpreter._dup,
    OpCodeValue.Pop: _Interpreter._pop,
    OpCodeValue.Newarr: _Interpreter._newarr,
    OpCodeValue.Ldlen: _Interpreter._ldlen,
    OpCodeValue.Ldelem: _Interpreter._ldelem,
    OpCodeValue.Ldelem_I: _Interpreter._ldelem,
    OpCodeValue.Ldelem_I1: _Interpreter._ldelem,
    OpCodeValue.Ldelem_U1: _Interpreter._ldelem,
    OpCodeValue.Ldelem_I2: _Interpreter._ldelem,
    OpCodeValue.Ldelem_U2: _Interpreter._ldelem,
    OpCodeValue.Ldelem_I4: _Interpreter._ldelem,
    OpCodeValue.Ldelem_U4: _Interpreter._ldelem,
    OpCodeValue.Ldelem_I8: _Interpreter._ldelem,
    OpCodeValue.Ldelem_Ref: _Interpreter._ldelem,
    OpCodeValue.Stelem: _Interpreter._stelem,
    OpCodeValue.Stelem_I: _Interpreter._stelem,
    OpCodeValue.Stelem_I1: _Interpreter._stelem,
    OpCodeValue.Stelem_I2: _Interpreter._stelem,
    OpCodeValue.Stelem_I4: _Interpreter._stelem,
    OpCodeValue.Stelem_I8: _Interpreter._stelem,
    OpCodeValue.Stelem_Ref: _Interpreter._stelem,
    OpCodeValue.Conv_U2: _Interpreter._conv_u2,
    OpCodeValue.Call: _Interpreter._call,
    OpCodeValue.Callvirt: _Interpreter._call,
    OpCodeValue.Newobj: _Interpreter._newobj,
    OpCodeValue.Ret: _Interpreter._ret,
    OpCodeValue.Br: _Interpreter._unconditional_br,
    OpCodeValue.Br_S: _Interpreter._unconditional_br,
    OpCodeValue.Leave: _Interpreter._leave,
    OpCodeValue.Leave_S: _Interpreter._leave,
    OpCodeValue.Brtrue: _Interpreter._conditional_br,
    OpCodeValue.Brtrue_S: _Interpreter._conditional_br,
    OpCodeValue.Brfalse: _Interpreter._conditional_br,
    OpCodeValue.Brfalse_S: _Interpreter._conditional_br,
    OpCodeValue.Beq: _Interpreter._conditional_br,
    OpCodeValue.Beq_S: _Interpreter._conditional_br,
    OpCodeValue.Bne_Un: _Interpreter._conditional_br,
    OpCodeValue.Bne_Un_S: _Interpreter._conditional_br,
    OpCodeValue.Bge: _Interpreter._conditional_br,
    OpCodeValue.Bge_S: _Interpreter._conditional_br,
    OpCodeValue.Bgt: _Interpreter._conditional_br,
    OpCodeValue.Bgt_S: _Interpreter._conditional_br,
    OpCodeValue.Blt: _Interpreter._conditional_br,
    OpCodeValue.Blt_S: _Interpreter._conditional_br,
    OpCodeValue.Ble: _Interpreter._conditional_br,
    OpCodeValue.Ble_S: _Interpreter._conditional_br,
    OpCodeValue.Bge_Un: _Interpreter._conditional_br,
    OpCodeValue.Bge_Un_S: _Interpreter._conditional_br,
    OpCodeValue.Bgt_Un: _Interpreter._conditional_br,
    OpCodeValue.Bgt_Un_S: _Interpreter._conditional_br,
    OpCodeValue.Blt_Un: _Interpreter._conditional_br,
    OpCodeValue.Blt_Un_S: _Interpreter._conditional_br,
    OpCodeValue.Ble_Un: _Interpreter._conditional_br,
    OpCodeValue.Ble_Un_S: _Interpreter._conditional_br,
    OpCodeValue.Switch: _Interpreter._switch,
    OpCodeValue.Throw: _Interpreter._throw,
}
