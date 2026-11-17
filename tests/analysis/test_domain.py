"""Tests for the finite abstract lattice and its conflict/gap semantics."""

import pytest

from dncil.analysis.domain import (
    TOP,
    ArrayValue,
    CharValue,
    Confidence,
    IntValue,
    StringValue,
    merge_values,
    top_with_fragments,
)


def test_identical_integers_merge_to_constant():
    left = IntValue(frozenset({1}), 5)
    right = IntValue(frozenset({2}), 5)
    joined = merge_values(left, right)
    assert isinstance(joined, IntValue)
    assert joined.value == 5
    assert joined.evidence == frozenset({1, 2})
    assert joined.confidence is Confidence.CERTAIN


def test_conflicting_integers_become_pending_with_alternatives():
    joined = merge_values(IntValue(frozenset(), 1), IntValue(frozenset(), 2))
    assert joined.confidence is Confidence.PENDING
    assert {alternative.value for alternative in joined.alternatives} == {1, 2}


def test_conflicting_strings_keep_both_candidates_but_never_pick_one():
    joined = merge_values(StringValue(frozenset(), "AB"), StringValue(frozenset(), "CD"))
    assert joined.confidence is Confidence.PENDING
    assert [alternative.text for alternative in joined.alternatives] == ["AB", "CD"]


def test_type_mismatch_is_pending():
    assert merge_values(IntValue(frozenset(), 1), StringValue(frozenset(), "x")).confidence is Confidence.PENDING


def test_array_read_of_unwritten_slot_is_top_not_zero():
    array_value = ArrayValue(frozenset(), 3, {0: CharValue(frozenset(), 65)})
    assert array_value.read(0) == CharValue(frozenset(), 65)
    assert array_value.read(1) is TOP
    assert array_value.read(9) is TOP


def test_array_write_out_of_bounds_returns_none():
    array_value = ArrayValue(frozenset(), 1, {})
    assert array_value.write(1, IntValue(frozenset(), 0)) is None


def test_array_merge_keeps_only_agreed_slots():
    left = ArrayValue(frozenset(), 2, {
        0: CharValue(frozenset(), 65),
        1: CharValue(frozenset(), 66),
    })
    right = ArrayValue(frozenset(), 2, {
        0: CharValue(frozenset(), 65),
        1: CharValue(frozenset(), 90),
    })
    joined = merge_values(left, right)
    assert isinstance(joined, ArrayValue)
    assert set(joined.slots) == {0}
    assert joined.slots[0].code == 65


def test_array_length_conflict_is_pending():
    joined = merge_values(ArrayValue(frozenset(), 1, {}), ArrayValue(frozenset(), 2, {}))
    assert joined.confidence is Confidence.PENDING


def test_top_fragments_never_become_certain():
    pending = top_with_fragments(frozenset({7}), ["A"], 1)
    assert pending.confidence is Confidence.PENDING
    assert pending.fragments == ("A",)
    assert pending.gap_count == 1
    assert pending.with_evidence([9]).confidence is Confidence.PENDING
