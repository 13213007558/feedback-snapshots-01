# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
"""Metamorphic regression: dncil's decoded logic must not depend on branch encoding.

Each method is assembled twice from the same symbolic specification: once with its
original short branches and once with every short branch widened to the long form.
Widening re-lays-out the whole method, so every branch displacement, switch target and
exception-clause boundary is recomputed from logical labels.  dncil's decoded control
flow is then mapped back to those labels and compared against the independent layout
record, so equal logic must compare equal even though byte offsets and code size differ.
"""

from __future__ import annotations

import pytest

from dncil.cil.body.reader import read_method_body_from_bytes
from tests.metamorphic.cfg import DecodeError, compare_cfgs, expected_cfg, extract_dncil_cfg
from tests.metamorphic.layout import (
    CannotWiden,
    MethodLayout,
    build,
    format_layout,
    check_widenability,
    describe_stale_target,
    build_with_stale_branch,
    branches_needing_relocation,
    build_with_stale_switch_target,
    switch_targets_needing_relocation,
    build_with_stale_exception_handlers,
)
from tests.metamorphic.methods import SWITCH_CASES, BRANCHES_AND_EH, methods_for_widening, methods_that_cannot_widen

WIDENABLE = methods_for_widening()
WIDENABLE_IDS = [spec.name for spec in WIDENABLE]


def _cfgs(layout: MethodLayout, tolerate_invalid_targets: bool = False):
    body = read_method_body_from_bytes(layout.raw)
    actual = extract_dncil_cfg(layout, body=body, tolerate_invalid_targets=tolerate_invalid_targets)
    return expected_cfg(layout), actual


def _assert_matches(layout: MethodLayout) -> None:
    expected, actual = _cfgs(layout)
    mismatch = compare_cfgs(expected, actual)
    assert not mismatch, mismatch.describe()


@pytest.mark.parametrize("spec", WIDENABLE, ids=WIDENABLE_IDS)
def test_original_layout_decodes_to_its_own_logic(spec):
    """baseline: the independent layout record agrees with dncil on the original method"""

    layout = build(spec, widen_short=False)
    _assert_matches(layout)


def test_demonstration_pair_original_and_widened():
    """pin the concrete original/widened pair; format_layout renders it for review"""

    original = build(BRANCHES_AND_EH, widen_short=False)
    widened = build(BRANCHES_AND_EH, widen_short=True)

    # every control-flow shape required by the task is present in this one method
    mnemonics = [instruction.opcode for instruction in original.instructions]
    assert "brtrue.s" in mnemonics  # forward conditional branch
    assert "blt.s" in mnemonics  # backward branch
    assert "switch" in mnemonics
    assert [clause.kind for clause in original.clauses] == ["catch", "finally"]

    assert original.code_size == 61
    assert widened.code_size == 82
    assert original.offset_of("after_eh") == 0x3C
    assert widened.offset_of("after_eh") == 0x51
    # the branch and its target both moved, and the displacement stayed logically equal
    assert original.instruction("leave_try").offset == 0x30
    assert widened.instruction("leave_try").offset == 0x3F
    assert original.offset_of("catch_pop") == 0x32
    assert widened.offset_of("catch_pop") == 0x44

    assert expected_cfg(widened).edges == expected_cfg(original).edges
    assert expected_cfg(widened).clauses == expected_cfg(original).clauses
    _assert_matches(original)
    _assert_matches(widened)


@pytest.mark.parametrize("spec", WIDENABLE, ids=WIDENABLE_IDS)
def test_widened_layout_decodes_to_the_same_logic(spec):
    """the metamorphic property: only the encoding changes, not the logical CFG"""

    original = build(spec, widen_short=False)
    widened = build(spec, widen_short=True)

    if spec.short_branch_labels():
        assert widened.code_size > original.code_size
        assert widened.raw != original.raw
    assert {instruction.label for instruction in widened.instructions} == {
        instruction.label for instruction in original.instructions
    }
    assert expected_cfg(widened).edges == expected_cfg(original).edges
    assert expected_cfg(widened).clauses == expected_cfg(original).clauses

    _assert_matches(widened)
    expected_original, actual_original = _cfgs(original)
    expected_widened, actual_widened = _cfgs(widened)
    mismatch = compare_cfgs(expected_original, actual_widened)
    assert not mismatch, "original vs widened logical CFG differ:\n%s" % mismatch.describe()
    assert not compare_cfgs(expected_widened, actual_original)


@pytest.mark.parametrize("spec", WIDENABLE, ids=WIDENABLE_IDS)
def test_widened_form_changes_encodings_and_relocates_targets(spec):
    """guard the transform itself: every short branch really became long and moved"""

    original = build(spec, widen_short=False)
    widened = build(spec, widen_short=True)

    for instruction in widened.instructions:
        original_instruction = original.instruction(instruction.label)
        if instruction.is_branch:
            assert instruction.size == 5
            assert original_instruction.size in (2, 5)
            if original_instruction.size == 2:
                assert instruction.opcode == spec.instruction(instruction.label).encoding.long_name
        else:
            # switch tables and ordinary instructions are re-emitted in both layouts; only
            # the layout record, not the bytes, must be identical for a switch's targets
            assert instruction.size == original_instruction.size
        # target still names the same logical instruction
        assert instruction.targets == original_instruction.targets
        assert instruction.offset == widened.offset_of(instruction.label)

    for clause in widened.clauses:
        assert clause.kind == original.clauses[clause.index].kind
        assert (clause.try_start, clause.try_end, clause.handler_start, clause.handler_end) == (
            widened.offset_of(spec.exception_handlers[clause.index].try_start),
            widened.offset_of(spec.exception_handlers[clause.index].try_end),
            widened.offset_of(spec.exception_handlers[clause.index].handler_start),
            widened.offset_of(spec.exception_handlers[clause.index].handler_end),
        )


def test_missing_branch_relocation_is_detected():
    """the demonstration method: forget one branch that crosses the replacement point"""

    # `leave_try` is a `leave.s` in the try block whose target is the `ret` after the
    # exception handlers; widening every branch inside the try moves that target from
    # IL_003C to IL_0051 while the branch itself moves from IL_0030 to IL_003F.
    label = "leave_try"
    assert label in branches_needing_relocation(BRANCHES_AND_EH)

    stale = build_with_stale_branch(BRANCHES_AND_EH, label)
    expected, actual = _cfgs(stale, tolerate_invalid_targets=True)
    mismatch = compare_cfgs(expected, actual)

    assert mismatch, "the deliberately stale branch was not detected"
    assert [(edge.source, edge.target) for edge in mismatch.missing_edges] == [
        (label, BRANCHES_AND_EH.instruction(label).branch_target())
    ]
    # and it names the actual wrong edge the decoder reported
    assert [(edge.source, edge.target) for edge in mismatch.unexpected_edges] == [(label, "finally_ldloc")]
    assert mismatch.unexpected_edges[0].actual_offset == stale.offset_of("finally_ldloc")
    assert "missing branch edge leave_try -> after_eh" in mismatch.describe()
    assert "unexpected branch edge leave_try -> finally_ldloc" in mismatch.describe()


@pytest.mark.parametrize("spec", WIDENABLE, ids=WIDENABLE_IDS)
def test_every_relocatable_branch_is_actually_checked(spec):
    """exhaustive stale-branch sweep: each unrelocated displacement is caught"""

    labels = branches_needing_relocation(spec)
    assert labels, "fixture has no branch that crosses a widening point"

    for label in labels:
        stale = build_with_stale_branch(spec, label)
        expected, actual = _cfgs(stale, tolerate_invalid_targets=True)
        mismatch = compare_cfgs(expected, actual)
        assert mismatch, "unrelocated branch %s (target %s) was not detected. decoded target: %s" % (
            label,
            spec.instruction(label).branch_target(),
            describe_stale_target(spec, label),
        )
        assert any(edge.source == label for edge in mismatch.missing_edges), mismatch.describe()


def test_switch_targets_must_be_relocated():
    """a switch is a table, not an opcode: every case displacement needs re-resolution"""

    indices = switch_targets_needing_relocation(SWITCH_CASES, "dispatch")
    assert indices, "switch fixture has no case that crosses a widened instruction"

    for index in indices:
        stale = build_with_stale_switch_target(SWITCH_CASES, "dispatch", index)
        expected, actual = _cfgs(stale, tolerate_invalid_targets=True)
        mismatch = compare_cfgs(expected, actual)
        assert mismatch, "stale switch case %d was not detected" % index
        intended = SWITCH_CASES.instruction("dispatch").switch_targets()[index]
        assert ("dispatch", intended, "switch") in expected.edges
        assert any(edge.source == "dispatch" for edge in mismatch.missing_edges), mismatch.describe()


def test_exception_boundaries_must_be_relocated():
    """exception clauses are code-relative ranges; stale boundaries must be caught"""

    stale = build_with_stale_exception_handlers(BRANCHES_AND_EH)
    expected, actual = _cfgs(stale, tolerate_invalid_targets=True)
    mismatch = compare_cfgs(expected, actual)
    assert mismatch, "stale exception boundaries were not detected"
    assert len(mismatch.missing_clauses) == len(BRANCHES_AND_EH.exception_handlers)
    assert mismatch.unexpected_clauses


def test_decoder_rejects_control_flow_into_the_middle_of_an_instruction():
    """strict mode turns an intra-instruction target into a hard failure, not a silent edge"""

    stale = build_with_stale_branch(BRANCHES_AND_EH, "skip_block")
    body = read_method_body_from_bytes(stale.raw)
    with pytest.raises(DecodeError):
        extract_dncil_cfg(stale, body=body)


def test_tiny_method_with_eh_has_no_tiny_header():
    """a tiny header cannot carry exception clauses, so that combination is rejected up front"""

    from tests.metamorphic.il_spec import InsnSpec, MethodSpec, ExceptionSpec

    spec = MethodSpec(
        name="TinyWithEh",
        header_format="tiny",
        instructions=(InsnSpec("start", "nop"), InsnSpec("done", "ret")),
        exception_handlers=(
            ExceptionSpec(
                kind="finally",
                try_start="start",
                try_end="done",
                handler_start="start",
                handler_end="done",
            ),
        ),
    )
    with pytest.raises(ValueError):
        spec.validate()


def test_unrepresentable_methods_are_rejected_with_reasons():
    """a method that cannot be safely widened must be declined, with concrete reasons"""

    for spec, fragments in methods_that_cannot_widen():
        reasons = check_widenability(spec)
        assert reasons, "%s should not be widenable" % spec.name
        for fragment in fragments:
            assert any(fragment in reason for reason in reasons), (spec.name, fragment, reasons)
        with pytest.raises(CannotWiden) as excinfo:
            build(spec, widen_short=True)
        assert excinfo.value.reasons == reasons


def test_tiny_header_reason_names_the_limit():
    reasons = check_widenability(next(spec for spec, _ in methods_that_cannot_widen() if spec.name == "TinyBody"))
    assert any("63" in reason for reason in reasons)


def test_original_fixture_still_parses_with_dncil_fixture_semantics():
    """the demonstration method uses the same reader/conventions as tests/test_method_body.py"""

    from tests.test_method_body import method_body_fat

    body = read_method_body_from_bytes(method_body_fat)
    assert body.code_size == 0x25
    assert len(body.instructions) == 0xB
    assert len(body.exception_handlers) == 2


def test_layout_record_is_independently_rendered():
    """smoke-test the human-readable record used to explain originals/widened pairs"""

    original = build(BRANCHES_AND_EH, widen_short=False)
    widened = build(BRANCHES_AND_EH, widen_short=True)
    original_text = format_layout(original)
    widened_text = format_layout(widened)

    assert "leave.s" in original_text and "leave" in widened_text
    assert "-> after_eh" in widened_text
    assert "brtrue.s" in original_text and "brtrue" in widened_text
    assert "original" in original_text
    assert "widened" in widened_text
