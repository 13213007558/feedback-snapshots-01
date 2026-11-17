"""User-facing string recovery built on the bounded interpreter.

:func:`recover_strings` turns interpreter outputs into self-describing
:class:`RecoveredString` records. A record always states whether it is certain;
pending records expose only the fragments that were actually proven and describe
the gaps instead of padding missing characters (for example with NUL).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from dncil.cil.body import CilMethodBody
from dncil.cil.instruction import Instruction

from dncil.analysis.domain import (
    ArrayValue,
    CharValue,
    Confidence,
    IntValue,
    StringValue,
    Value,
    _Top,
)
from dncil.analysis.interpreter import AnalysisResult, RecoveredExpression, analyze_body
from dncil.analysis.metadata import AnalysisBudget, Metadata


@dataclass
class EvidenceItem:
    """One instruction that contributed to a recovered string."""

    offset: int
    mnemonic: str
    bytes_hex: str


@dataclass
class RecoveredString:
    """A recovered string candidate with its provenance and certainty range.

    ``certain`` distinguishes fully proven strings from pending candidates;
    pending candidates never claim to be values the program must produce at
    runtime. ``known_pieces`` lists only proven fragments and ``gap_count``
    counts undetermined positions.
    """

    text: Optional[str]
    certain: bool
    return_offset: int
    evidence: List[EvidenceItem] = field(default_factory=list)
    known_pieces: List[str] = field(default_factory=list)
    gap_count: int = 0
    alternatives: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)

    @property
    def certainty_range(self) -> str:
        """Human-readable statement of what is and is not determined."""
        if self.certain:
            length = len(self.text or "")
            return "all %d character(s) determined" % length
        known = sum(len(piece) for piece in self.known_pieces)
        return "%d determined character(s), %d undetermined position(s)" % (known, self.gap_count)


def _index_instructions(body: CilMethodBody) -> Dict[int, Instruction]:
    return {insn.offset: insn for insn in body.instructions}


def _evidence_items(offsets: Sequence[int], index: Dict[int, Instruction]) -> List[EvidenceItem]:
    items: List[EvidenceItem] = []
    for offset in sorted(set(offsets)):
        insn = index.get(offset)
        if insn is None:
            continue
        items.append(
            EvidenceItem(offset=offset, mnemonic=insn.mnemonic, bytes_hex=insn.get_bytes().hex())
        )
    return items


def _collect_offsets(value: Value) -> List[int]:
    offsets = set(value.evidence)
    if isinstance(value, ArrayValue):
        for slot in value.slots.values():
            offsets.update(_collect_offsets(slot))
    return sorted(offsets)


def _array_fragment_summary(value: ArrayValue) -> tuple[List[str], int]:
    pieces: List[str] = []
    gaps = 0
    buffer = ""
    for index in range(value.length):
        slot = value.read(index)
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
    return pieces, gaps


def _known_pieces(value: Value) -> tuple[List[str], int]:
    """Return proven text fragments and the count of undetermined positions."""
    if isinstance(value, StringValue):
        return [value.text], 0
    if isinstance(value, CharValue):
        return [chr(value.code)], 0
    if isinstance(value, ArrayValue):
        return _array_fragment_summary(value)
    if isinstance(value, _Top):
        return list(value.fragments), value.gap_count
    return [], 0


def _alternative_texts(value: Value) -> List[str]:
    """Extract concrete constants that met at a conflicting join."""
    if not isinstance(value, _Top):
        return []
    texts: List[str] = []
    for alternative in value.alternatives:
        if isinstance(alternative, StringValue):
            texts.append(alternative.text)
        elif isinstance(alternative, CharValue):
            texts.append(chr(alternative.code))
        elif isinstance(alternative, IntValue):
            texts.append(str(alternative.value))
    return texts


def recover_strings(
    body: CilMethodBody,
    metadata: Optional[Metadata] = None,
    budget: Optional[AnalysisBudget] = None,
) -> List[RecoveredString]:
    """Recover string-returning expressions from one method body.

    Only statically proven constants are reported as certain; everything else
    is returned as an explicitly pending record with its proven fragments and
    reasons. The function never executes the method or loads its assembly.
    """
    result: AnalysisResult = analyze_body(body, metadata=metadata, budget=budget)
    index = _index_instructions(body)
    recovered: List[RecoveredString] = []
    for expression in result.recovered:
        recovered.append(_build_record(expression, index, result))
    return recovered


def _build_record(
    expression: RecoveredExpression, index: Dict[int, Instruction], result: AnalysisResult
) -> RecoveredString:
    value = expression.value
    evidence = _evidence_items(_collect_offsets(value), index)
    pieces, gaps = _known_pieces(value)
    alternatives = _alternative_texts(value)
    certain = expression.confidence is Confidence.CERTAIN and result.limits.completed and gaps == 0
    if isinstance(value, StringValue) and certain:
        text: Optional[str] = value.text
    elif isinstance(value, CharValue) and certain:
        text = chr(value.code)
    else:
        text = None
    reasons = list(result.pending_reasons)
    if not result.limits.completed and result.limits.reason and result.limits.reason not in reasons:
        reasons.append(result.limits.reason)
    return RecoveredString(
        text=text,
        certain=certain,
        return_offset=expression.offset,
        evidence=evidence,
        known_pieces=pieces,
        gap_count=gaps,
        alternatives=alternatives,
        reasons=reasons,
    )
