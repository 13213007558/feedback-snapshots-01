# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

import enum
from typing import Any, Set, Dict, List, Tuple, Union, Iterable, Optional, cast
from dataclasses import field, dataclass

from dncil.cil.body import CilMethodBody
from dncil.cil.error import MethodBodyFormatError
from dncil.clr.token import Token
from dncil.cil.opcode import OpCodeValue
from dncil.cil.body.reader import read_method_body_from_bytes
from dncil.cil.instruction import Instruction
from dncil.analysis.metadata import MetadataView, MethodRecord, MetadataError, MethodReference


class Decision(enum.Enum):
    """outcome for one entry point."""

    REJECT = "reject"
    MANUAL_REVIEW = "manual_review"
    NO_REACHABLE_FINDING = "no_reachable_finding"


class FindingKind(enum.Enum):
    """why a reachable instruction matters to the reviewer."""

    PINVOKE = "pinvoke"
    UNSAFE_MEMORY = "unsafe_memory"


class UnresolvedKind(enum.Enum):
    """why a call target could not be determined."""

    CALLI = "calli"
    FUNCTION_POINTER = "function_pointer"
    VIRTUAL_DISPATCH = "virtual_dispatch"
    GENERIC_TARGET = "generic_target"
    EXTERNAL_TARGET = "external_target"
    UNKNOWN_TOKEN = "unknown_token"
    ABSTRACT_TARGET = "abstract_target"
    BODY_UNAVAILABLE = "body_unavailable"
    INVALID_BODY = "invalid_body"


# these instructions can read or write memory through a pointer, or move the
# stack pointer. they are legal CIL, so they are review signals rather than
# unconditional rejects.
UNSAFE_MEMORY_OPCODES = frozenset(
    {
        OpCodeValue.Ldind_I,
        OpCodeValue.Ldind_I1,
        OpCodeValue.Ldind_I2,
        OpCodeValue.Ldind_I4,
        OpCodeValue.Ldind_I8,
        OpCodeValue.Ldind_R4,
        OpCodeValue.Ldind_R8,
        OpCodeValue.Ldind_Ref,
        OpCodeValue.Ldind_U1,
        OpCodeValue.Ldind_U2,
        OpCodeValue.Ldind_U4,
        OpCodeValue.Stind_I,
        OpCodeValue.Stind_I1,
        OpCodeValue.Stind_I2,
        OpCodeValue.Stind_I4,
        OpCodeValue.Stind_I8,
        OpCodeValue.Stind_R4,
        OpCodeValue.Stind_R8,
        OpCodeValue.Stind_Ref,
        OpCodeValue.Localloc,
        OpCodeValue.Cpblk,
        OpCodeValue.Initblk,
    }
)

UNCONDITIONAL_BRANCHES = frozenset({OpCodeValue.Br, OpCodeValue.Br_S, OpCodeValue.Leave, OpCodeValue.Leave_S})
TERMINAL_INSTRUCTIONS = frozenset(
    {
        OpCodeValue.Ret,
        OpCodeValue.Throw,
        OpCodeValue.Rethrow,
        OpCodeValue.Endfinally,
        OpCodeValue.Endfilter,
        OpCodeValue.Jmp,
    }
)
DIRECT_CALLS = frozenset({OpCodeValue.Call, OpCodeValue.Newobj, OpCodeValue.Jmp})
VIRTUAL_CALLS = frozenset({OpCodeValue.Callvirt})
FUNCTION_POINTERS = frozenset({OpCodeValue.Ldftn, OpCodeValue.Ldvirtftn})
INDIRECT_CALLS = frozenset({OpCodeValue.Calli})


@dataclass(frozen=True)
class ReviewLimits:
    """bounds that keep the walk finite on adversarial metadata."""

    max_methods: int = 256
    max_depth: int = 32
    max_instructions: int = 20000


@dataclass(frozen=True)
class CallSite:
    """one instruction, or one entry declaration, of interest.

    ``offset`` is the raw offset reported by dncil (a file offset for dnfile
    backed views). ``il_offset`` is relative to the first CIL byte, which is
    the value used by disassemblers and by exception handlers.
    """

    method: MethodRecord
    offset: int
    il_offset: int
    mnemonic: str
    operand_token: Optional[Token]
    operand: str
    target_token: Optional[Token] = None
    target: Optional[str] = None

    @property
    def has_instruction(self) -> bool:
        return self.offset >= 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "caller": self.method.display,
            "caller_token": _hex(self.method.token),
            "offset": _hex(self.offset) if self.has_instruction else None,
            "il_offset": _hex(self.il_offset) if self.has_instruction else None,
            "instruction": self.mnemonic,
            "operand": self.operand,
            "operand_token": _hex(self.operand_token) if self.operand_token else None,
            "target": self.target,
            "target_token": _hex(self.target_token) if self.target_token else None,
        }

    def format(self) -> str:
        if not self.has_instruction:
            return f"{self.method.display} {_hex(self.method.token)} <{self.mnemonic}>"
        return (
            f"{self.method.display} {_hex(self.method.token)}"
            f" @ {_hex(self.offset)} (IL_{self.il_offset:04X}) {self.mnemonic}"
            f" {self.operand}"
        )


@dataclass(frozen=True)
class ReachableMethod:
    """a MethodDef reached from an entry point, with the edge that found it."""

    method: MethodRecord
    depth: int
    via: Optional[CallSite]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method.display,
            "token": _hex(self.method.token),
            "depth": self.depth,
            "via": self.via.to_dict() if self.via else None,
        }


@dataclass(frozen=True)
class UnresolvedCall:
    """a control transfer whose target cannot be determined statically.

    blocking calls force manual review; recorded calls are outside the scope
    of this review (for example, a call into another assembly) but are still
    reported.
    """

    kind: UnresolvedKind
    site: CallSite
    detail: str
    blocking: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind.value,
            "blocking": self.blocking,
            "detail": self.detail,
            "site": self.site.to_dict(),
        }


@dataclass(frozen=True)
class Finding:
    """a reachable instruction that motivates rejection or manual review.

    ``path`` is the call chain from the entry method to the method holding
    ``site``; each edge names its caller token, call instruction offset, and
    operand token. the terminal instruction is ``site`` itself.
    """

    kind: FindingKind
    site: CallSite
    detail: str
    path: Tuple[CallSite, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind.value,
            "detail": self.detail,
            "site": self.site.to_dict(),
            "path": [edge.to_dict() for edge in self.path],
        }


@dataclass
class EntryReview:
    """result for a single entry point."""

    entry: MethodRecord
    decision: Decision
    findings: List[Finding] = field(default_factory=list)
    unresolved: List[UnresolvedCall] = field(default_factory=list)
    reachable: List[ReachableMethod] = field(default_factory=list)
    truncated: bool = False
    notes: List[str] = field(default_factory=list)

    @property
    def rejected(self) -> bool:
        return self.decision is Decision.REJECT

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry": self.entry.display,
            "entry_token": _hex(self.entry.token),
            "decision": self.decision.value,
            "truncated": self.truncated,
            "findings": [finding.to_dict() for finding in self.findings],
            "unresolved": [call.to_dict() for call in self.unresolved],
            "reachable": [method.to_dict() for method in self.reachable],
            "notes": list(self.notes),
        }


@dataclass
class ReviewReport:
    """aggregate result for one or more entry points."""

    entries: List[EntryReview] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def decision(self) -> Decision:
        decisions = {entry.decision for entry in self.entries}
        if Decision.REJECT in decisions:
            return Decision.REJECT
        if Decision.MANUAL_REVIEW in decisions:
            return Decision.MANUAL_REVIEW
        return Decision.NO_REACHABLE_FINDING

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "entries": [entry.to_dict() for entry in self.entries],
            "notes": list(self.notes),
            "scope": (
                "static reachability over determinable intra-assembly calls only; "
                "this does not prove the CLR sandbox or the plugin safe"
            ),
        }

    def format_text(self) -> str:
        """render a stable, line-oriented report for humans and logs."""
        lines: List[str] = [f"decision: {self.decision.value}"]
        for note in self.notes:
            lines.append(f"note: {note}")

        for entry in self.entries:
            lines.append("")
            lines.append(f"entry: {entry.entry.display} ({_hex(entry.entry.token)})")
            lines.append(f"decision: {entry.decision.value}")
            if entry.truncated:
                lines.append("truncated: yes (review limits reached)")

            if entry.findings:
                lines.append("findings:")
                for finding in entry.findings:
                    lines.append(f"  - {finding.kind.value}: {finding.site.format()}")
                    for step in finding.path:
                        lines.append(f"      via {step.format()} -> {step.target or '?'}")
                    if finding.site.target:
                        lines.append(f"      target: {finding.site.target}")
                    lines.append(f"      reason: {finding.detail}")

            if entry.unresolved:
                lines.append("unresolved:")
                for call in entry.unresolved:
                    marker = "blocking" if call.blocking else "recorded"
                    lines.append(f"  - {call.kind.value} ({marker}): {call.site.format()}")
                    lines.append(f"      reason: {call.detail}")

            if entry.reachable:
                lines.append("reachable methods:")
                for reached in entry.reachable:
                    origin = f" via {reached.via.format()}" if reached.via else ""
                    lines.append(
                        f"  - {reached.method.display} {_hex(reached.method.token)}" f" depth={reached.depth}{origin}"
                    )

            if entry.notes:
                for note in entry.notes:
                    lines.append(f"note: {note}")
        return "\n".join(lines)


def _hex(value: Optional[Union[int, Token]]) -> str:
    if value is None:
        return "0x00000000"
    return "0x%08X" % int(value)


def _coerce_token(value: Union[Token, MethodRecord, int]) -> Token:
    if isinstance(value, Token):
        return value
    if isinstance(value, MethodRecord):
        return value.token
    return Token(int(value))


class _MethodWalker:
    """walk the reachable instructions of one method body."""

    def __init__(self, method: MethodRecord, body: CilMethodBody):
        self.method = method
        self.body = body
        self.code_start = body.offset + body.header_size
        self.by_offset: Dict[int, Instruction] = {insn.offset: insn for insn in body.instructions}

    def roots(self) -> List[int]:
        roots: List[int] = []
        if self.body.instructions:
            roots.append(self.body.instructions[0].offset)
        for handler in self.body.exception_handlers:
            for relative in (handler.handler_start, handler.filter_start):
                if relative < 0:
                    continue
                absolute = self.code_start + relative
                if absolute in self.by_offset and absolute not in roots:
                    roots.append(absolute)
        return roots

    def successors(self, insn: Instruction) -> List[int]:
        next_offset = insn.offset + insn.size
        value = insn.opcode.value

        if value in UNCONDITIONAL_BRANCHES:
            targets = [_as_offset(insn.operand)]
        elif insn.is_cond_br():
            targets = [_as_offset(insn.operand), next_offset]
        elif value == OpCodeValue.Switch:
            switches = cast(List[Union[int, float]], insn.operand or [])
            targets = [int(target) for target in switches]
            targets.append(next_offset)
        elif value in TERMINAL_INSTRUCTIONS:
            targets = []
        else:
            targets = [next_offset]
        return [target for target in targets if target in self.by_offset]


def _as_offset(operand: Any) -> int:
    if isinstance(operand, (int, float)):
        return int(operand)
    raise MetadataError(f"branch operand is not an offset: {operand!r}")


def _parse_body(view: MetadataView, method: MethodRecord) -> CilMethodBody:
    return read_method_body_from_bytes(view.method_body(method))


def _unreadable_reason(method: MethodRecord) -> Optional[str]:
    if not method.has_body:
        if method.is_pinvoke:
            return "P/Invoke declaration has no managed body"
        if method.is_abstract:
            return "abstract method has no body"
        return "method has no managed body"
    return None


class _ReviewState:
    def __init__(self, view: MetadataView, entry: MethodRecord, limits: ReviewLimits):
        self.view = view
        self.entry = entry
        self.limits = limits
        self.methods_by_rid: Dict[int, MethodRecord] = {method.token.rid: method for method in view.methods()}
        self.parent: Dict[int, Tuple[Optional[int], Optional[CallSite]]] = {entry.token.rid: (None, None)}
        self.depths: Dict[int, int] = {entry.token.rid: 0}
        self.order: List[MethodRecord] = [entry]
        self.queue: List[MethodRecord] = [entry]
        self.review = EntryReview(entry=entry, decision=Decision.NO_REACHABLE_FINDING)
        self.visited_instructions = 0

    def find(self, token: Token) -> Optional[MethodRecord]:
        return self.methods_by_rid.get(token.rid)

    def path_to(self, method: MethodRecord) -> Tuple[CallSite, ...]:
        edges: List[CallSite] = []
        current: Optional[int] = method.token.rid
        seen: Set[int] = set()
        while current is not None and current not in seen:
            seen.add(current)
            item = self.parent.get(current)
            if item is None:
                break
            parent_rid, edge = item
            if edge is not None:
                edges.append(edge)
            current = parent_rid
        edges.reverse()
        return tuple(edges)

    def add_finding(self, kind: FindingKind, site: CallSite, detail: str) -> None:
        self.review.findings.append(Finding(kind=kind, site=site, detail=detail, path=self.path_to(site.method)))

    def add_unresolved(self, kind: UnresolvedKind, site: CallSite, detail: str, blocking: bool = True) -> None:
        self.review.unresolved.append(UnresolvedCall(kind=kind, site=site, detail=detail, blocking=blocking))

    def enqueue(self, target: MethodRecord, caller: MethodRecord, site: CallSite) -> None:
        if target.token.rid in self.parent:
            return
        if len(self.order) >= self.limits.max_methods:
            self.review.truncated = True
            return
        self.parent[target.token.rid] = (caller.token.rid, site)
        self.depths[target.token.rid] = self.depths[caller.token.rid] + 1
        self.order.append(target)
        self.queue.append(target)


def _review_entry(view: MetadataView, entry: MethodRecord, limits: ReviewLimits) -> EntryReview:
    state = _ReviewState(view, entry, limits)
    review = state.review

    if entry.is_pinvoke:
        site = _declaration_site(entry, "pinvoke-entry")
        review.findings.append(
            Finding(
                kind=FindingKind.PINVOKE,
                site=site,
                detail=(
                    f"entry point is a P/Invoke declaration"
                    f" ({entry.pinvoke_module or '?'}!{entry.pinvoke_name or entry.name})"
                ),
            )
        )
        review.reachable.append(ReachableMethod(entry, 0, None))
        review.decision = Decision.REJECT
        return review

    while state.queue:
        current = state.queue.pop(0)
        depth = state.depths[current.token.rid]
        if depth > limits.max_depth:
            review.truncated = True
            review.notes.append(f"depth limit reached at {current.display}")
            continue

        reason = _unreadable_reason(current)
        if reason is not None:
            state.add_unresolved(
                UnresolvedKind.BODY_UNAVAILABLE,
                _declaration_site(current, "method"),
                reason,
            )
            continue

        try:
            body = _parse_body(view, current)
        except (MetadataError, MethodBodyFormatError) as error:
            state.add_unresolved(
                UnresolvedKind.INVALID_BODY,
                _declaration_site(current, "method"),
                f"cannot parse method body: {error}",
            )
            continue

        _walk_body(state, current, body)

    review.reachable = [
        ReachableMethod(method, state.depths[method.token.rid], state.parent[method.token.rid][1])
        for method in state.order
    ]
    review.findings.sort(key=lambda finding: (finding.site.method.token.rid, finding.site.offset, finding.kind.value))
    review.unresolved.sort(key=lambda call: (call.site.method.token.rid, call.site.offset, call.kind.value))

    if any(finding.kind is FindingKind.PINVOKE for finding in review.findings):
        review.decision = Decision.REJECT
    elif review.truncated or review.findings or any(call.blocking for call in review.unresolved):
        review.decision = Decision.MANUAL_REVIEW
    return review


def _walk_body(state: _ReviewState, method: MethodRecord, body: CilMethodBody) -> None:
    walker = _MethodWalker(method, body)
    seen: Set[int] = set()
    pending: List[int] = list(walker.roots())

    while pending:
        offset = pending.pop(0)
        if offset in seen:
            continue
        seen.add(offset)
        insn = walker.by_offset.get(offset)
        if insn is None:
            continue

        state.visited_instructions += 1
        if state.visited_instructions > state.limits.max_instructions:
            state.review.truncated = True
            state.review.notes.append("instruction limit reached")
            return

        site = _instruction_site(method, walker, insn)
        value = insn.opcode.value

        if value in UNSAFE_MEMORY_OPCODES:
            state.add_finding(
                FindingKind.UNSAFE_MEMORY,
                site,
                f"{insn.mnemonic} can read or write memory through a pointer",
            )

        if value in INDIRECT_CALLS:
            state.add_unresolved(UnresolvedKind.CALLI, site, "calli target comes from the evaluation stack")
        elif value in FUNCTION_POINTERS:
            state.add_unresolved(
                UnresolvedKind.FUNCTION_POINTER,
                site,
                f"{insn.mnemonic} produces a function pointer that can be invoked indirectly",
            )
        elif value in VIRTUAL_CALLS:
            reference = _try_resolve(state.view, insn.operand)
            if reference is None:
                state.add_unresolved(
                    UnresolvedKind.UNKNOWN_TOKEN,
                    site,
                    f"cannot resolve callvirt operand {insn.operand}",
                )
            else:
                state.add_unresolved(
                    UnresolvedKind.VIRTUAL_DISPATCH,
                    site,
                    f"callvirt {reference.display} may dispatch to an override",
                )
        elif value in DIRECT_CALLS:
            _follow_direct_call(state, method, site, insn.operand)

        for successor in walker.successors(insn):
            pending.append(successor)


def _follow_direct_call(state: _ReviewState, caller: MethodRecord, site: CallSite, operand: Any) -> None:
    reference = _try_resolve(state.view, operand)
    if reference is None:
        state.add_unresolved(
            UnresolvedKind.UNKNOWN_TOKEN,
            site,
            f"cannot resolve method token {operand}",
        )
        return

    if reference.module is not None:
        state.add_finding(
            FindingKind.PINVOKE,
            _with_target(site, reference),
            f"reachable P/Invoke into {reference.module}!{reference.name}" f" via token {_hex(reference.token)}",
        )
        return

    if reference.generic:
        state.add_unresolved(
            UnresolvedKind.GENERIC_TARGET,
            _with_target(site, reference),
            f"generic target {reference.display} cannot be resolved to one concrete body",
        )
        return

    if reference.method_def_token is None:
        state.add_unresolved(
            UnresolvedKind.EXTERNAL_TARGET,
            _with_target(site, reference),
            f"external target {reference.display} is outside this assembly",
            blocking=False,
        )
        return

    target = state.find(reference.method_def_token)
    if target is None:
        state.add_unresolved(
            UnresolvedKind.UNKNOWN_TOKEN,
            site,
            f"token {_hex(reference.method_def_token)} does not name a MethodDef row",
        )
        return

    edge = _with_target(site, reference, target.token)

    if target.is_pinvoke:
        state.add_finding(
            FindingKind.PINVOKE,
            edge,
            f"reachable P/Invoke {target.display}"
            f" ({target.pinvoke_module or '?'}!{target.pinvoke_name or target.name})",
        )
        return

    if target.is_abstract:
        state.add_unresolved(
            UnresolvedKind.ABSTRACT_TARGET,
            edge,
            f"{target.display} is abstract and has no body",
        )
        return

    if target.is_generic:
        state.add_unresolved(
            UnresolvedKind.GENERIC_TARGET,
            edge,
            f"{target.display} is generic; its body depends on type arguments",
        )
        return

    state.enqueue(target, caller, edge)


def _try_resolve(view: MetadataView, operand: Any) -> Optional[MethodReference]:
    if not isinstance(operand, Token):
        return None
    try:
        return view.resolve(operand)
    except MetadataError:
        return None


def _declaration_site(method: MethodRecord, mnemonic: str) -> CallSite:
    return CallSite(
        method=method,
        offset=-1,
        il_offset=0,
        mnemonic=mnemonic,
        operand_token=None,
        operand="",
    )


def _instruction_site(method: MethodRecord, walker: _MethodWalker, insn: Instruction) -> CallSite:
    return CallSite(
        method=method,
        offset=insn.offset,
        il_offset=insn.offset - walker.code_start,
        mnemonic=insn.mnemonic,
        operand_token=insn.operand if isinstance(insn.operand, Token) else None,
        operand=str(insn.operand) if insn.operand is not None else "",
    )


def _with_target(site: CallSite, reference: MethodReference, token: Optional[Token] = None) -> CallSite:
    return CallSite(
        method=site.method,
        offset=site.offset,
        il_offset=site.il_offset,
        mnemonic=site.mnemonic,
        operand_token=site.operand_token,
        operand=site.operand,
        target_token=token or reference.token,
        target=reference.display,
    )


def review_entry_point(
    view: MetadataView,
    entry: Union[Token, MethodRecord, int],
    limits: Optional[ReviewLimits] = None,
) -> EntryReview:
    """walk determinable intra-assembly calls starting at ``entry``.

    no method is executed. only method bodies and metadata rows are read.
    """
    limits = limits or ReviewLimits()
    token = _coerce_token(entry)
    method = None
    for candidate in view.methods():
        if candidate.token.rid == token.rid:
            method = candidate
            break
    if method is None:
        raise MetadataError(f"MethodDef token {_hex(token)} is not present in the assembly")
    return _review_entry(view, method, limits)


def review_entry_points(
    view: MetadataView,
    entries: Optional[Iterable[Union[Token, MethodRecord, int]]] = None,
    limits: Optional[ReviewLimits] = None,
) -> ReviewReport:
    """review each entry point, or the metadata entry point when omitted."""
    selected: List[Union[Token, MethodRecord, int]]
    if entries is None:
        declared = view.entry_point()
        if declared is None:
            raise MetadataError("no entry point was given and metadata declares none")
        selected = [declared]
    else:
        selected = list(entries)

    report = ReviewReport()
    report.notes.append(
        "review only follows determinable intra-assembly calls; indirect, virtual, "
        "generic, and external targets are reported as unresolved"
    )
    report.notes.append("a clean result is not proof that the CLR sandbox or the plugin is safe")
    for selected_entry in selected:
        report.entries.append(review_entry_point(view, selected_entry, limits))
    return report
