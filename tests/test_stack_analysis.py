# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

import pytest
import stack_fixtures as fixtures

from dncil.clr.token import Token
from dncil.cil.stack_analysis import (
    StackStatus,
    CallSignature,
    StackAnalyzer,
    StackIssueKind,
    MaxStackRelation,
    analyze_stack,
)


def kinds(result):
    return [issue.kind for issue in result.issues]


def issue(result, kind):
    matches = [candidate for candidate in result.issues if candidate.kind is kind]
    assert matches, f"expected a {kind} issue, got {kinds(result)}"
    return matches[0]


def chain(body, relative_offsets):
    return fixtures.absolute_chain(body, relative_offsets)


# ---------------------------------------------------------------------------
# Legal loop
# ---------------------------------------------------------------------------
def test_legal_loop_converges_and_verifies():
    body = fixtures.read_body(fixtures.LOOP_BODY)
    result = analyze_stack(
        body,
        lambda token: CallSignature(2, returns_value=True) if token == Token(fixtures.LOOP_CALL_TOKEN) else None,
        return_value=False,
    )

    assert result.status is StackStatus.KNOWN
    assert result.verified
    assert result.issues == ()
    assert result.entry_offset == chain(body, (0x0,))[0]

    loop_head = body.instructions[0].offset
    loop_back_edge = chain(body, fixtures.LOOP_CALL_CHAIN)[-1]
    loop_report = result.instructions[loop_head]
    assert loop_report.status is StackStatus.KNOWN
    assert loop_report.height == 0
    assert loop_report.chain == chain(body, (0x0,))
    assert loop_head in result.joins
    assert {path.offsets for path in result.joins[loop_head]} == {
        chain(body, (0x0,)),
        chain(body, (0x0, 0x1, 0x3, 0x4, 0x5, 0xA, 0xB, 0x0)),
    }
    assert loop_back_edge == chain(body, (0x5,))[0]

    # The call site's proven chain starts at the method entry and passes
    # through both constant loads.
    call_report = result.instructions[chain(body, (0x5,))[0]]
    assert call_report.status is StackStatus.KNOWN
    assert call_report.height == 2
    assert call_report.chain == chain(body, fixtures.LOOP_CALL_CHAIN)

    # max_stack is declared as 2 and the derivation reaches exactly 2.
    assert result.declared_max_stack == 2
    assert result.derived_max_stack == 2
    assert result.max_stack_relation is MaxStackRelation.WITHIN
    assert result.max_stack_path is not None
    assert result.max_stack_path.offsets == chain(body, (0x0, 0x1, 0x3, 0x4))


def test_legal_loop_is_reported_as_converged_merge():
    body = fixtures.read_body(fixtures.LOOP_BODY)
    result = analyze_stack(body, lambda token: CallSignature(2, returns_value=True), return_value=False)

    loop_head = body.instructions[0].offset
    assert loop_head in result.joins
    assert "converged at height 0" in result.format_report()


# ---------------------------------------------------------------------------
# Join conflict
# ---------------------------------------------------------------------------
def test_join_conflict_cites_both_incoming_chains():
    body = fixtures.read_body(fixtures.JOIN_BODY)
    result = analyze_stack(body, return_value=False)

    assert result.status is StackStatus.CONFLICT
    assert not result.verified

    conflict = issue(result, StackIssueKind.JOIN_CONFLICT)
    merge_offset = chain(body, (fixtures.JOIN_MERGE_OFFSET,))[0]
    assert conflict.offset == merge_offset
    assert [path.offsets for path in conflict.paths] == [
        chain(body, fixtures.JOIN_BRANCH_CHAIN),
        chain(body, fixtures.JOIN_FALLTHROUGH_CHAIN),
    ]
    assert [path.height for path in conflict.paths] == [0, 1]

    merge_report = result.instructions[merge_offset]
    assert merge_report.status is StackStatus.CONFLICT
    assert merge_report.known_heights == (0, 1)
    assert merge_report.chains == (
        chain(body, fixtures.JOIN_BRANCH_CHAIN),
        chain(body, fixtures.JOIN_FALLTHROUGH_CHAIN),
    )
    assert StackIssueKind.JOIN_CONFLICT in merge_report.issues

    # The conflict propagates to the shared ret, which cannot be verified.
    ret_report = result.instructions[chain(body, (0x7,))[0]]
    assert ret_report.status is StackStatus.CONFLICT
    assert ret_report.height is None


def test_conflict_does_not_require_a_call_signature():
    body = fixtures.read_body(fixtures.JOIN_BODY)

    def fail_on_call(token):
        raise AssertionError("this fixture has no call instructions")

    result = analyze_stack(body, fail_on_call, return_value=False)
    assert result.status is StackStatus.CONFLICT


# ---------------------------------------------------------------------------
# Missing call signature
# ---------------------------------------------------------------------------
def test_missing_call_signature_is_unknown_not_zero_arguments():
    body = fixtures.read_body(fixtures.MISSING_SIGNATURE_BODY)
    result = analyze_stack(body, lambda token: None, return_value=False)

    assert result.status is StackStatus.UNKNOWN
    assert not result.verified
    assert result.max_stack_relation is MaxStackRelation.UNKNOWN
    assert not result.max_stack_is_complete

    unresolved = issue(result, StackIssueKind.UNRESOLVED_SIGNATURE)
    call_offset = chain(body, (0x4,))[0]
    assert unresolved.offset == call_offset
    assert "unresolved call signature" in unresolved.message
    assert unresolved.paths[0].offsets == chain(body, fixtures.MISSING_SIGNATURE_CALL_CHAIN)

    call_report = result.instructions[call_offset]
    assert call_report.status is StackStatus.UNKNOWN
    assert call_report.height == 1
    assert StackIssueKind.UNRESOLVED_SIGNATURE in call_report.issues

    # The known branch reaches ret at height 0, but ret has an unknown
    # predecessor too.  It must therefore remain unknown, not verified.
    ret_offset = chain(body, (fixtures.MISSING_SIGNATURE_RET_OFFSET,))[0]
    ret_report = result.instructions[ret_offset]
    assert ret_report.status is StackStatus.UNKNOWN
    assert ret_report.height is None
    assert ret_report.known_heights == (0,)
    assert len(ret_report.chains) == 2


def test_missing_signature_does_not_become_a_zero_parameter_call():
    body = fixtures.read_body(fixtures.MISSING_SIGNATURE_BODY)
    result = analyze_stack(body, return_value=False)

    # If the analyzer had assumed a zero-argument call, the call would have
    # been treated as a verified push-0/pop-0 and ret would be known.  The
    # explicit unresolved issue and unknown status prove otherwise.
    call_offset = chain(body, (0x4,))[0]
    assert result.instructions[call_offset].status is StackStatus.UNKNOWN
    assert any(issue.kind is StackIssueKind.UNRESOLVED_SIGNATURE for issue in result.issues)


def test_resolver_raising_is_reported_as_missing_information():
    body = fixtures.read_body(fixtures.MISSING_SIGNATURE_BODY)

    def broken(token):
        raise LookupError("metadata table unavailable")

    result = analyze_stack(body, broken, return_value=False)
    assert result.status is StackStatus.UNKNOWN
    unresolved = issue(result, StackIssueKind.UNRESOLVED_SIGNATURE)
    assert "LookupError" in unresolved.message
    assert "metadata table unavailable" in unresolved.message


def test_resolver_object_method_is_accepted():
    class Resolver:
        def resolve(self, token):
            if token.value == fixtures.MISSING_SIGNATURE_CALL_TOKEN:
                return CallSignature(1)
            return None

    body = fixtures.read_body(fixtures.MISSING_SIGNATURE_BODY)
    result = analyze_stack(body, Resolver(), return_value=False)
    assert result.status is StackStatus.KNOWN
    assert result.instructions[chain(body, (0x4,))[0]].height == 1


def test_signature_mapping_is_used_when_resolver_returns_nothing():
    body = fixtures.read_body(fixtures.MISSING_SIGNATURE_BODY)
    result = analyze_stack(
        body,
        lambda token: None,
        signatures={fixtures.MISSING_SIGNATURE_CALL_TOKEN: CallSignature(1)},
        return_value=False,
    )
    assert result.status is StackStatus.KNOWN


# ---------------------------------------------------------------------------
# Call/calli height effects
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "code, max_stack, signature, expected_height, expected_derived",
    [
        # static: no receiver, two args, no return
        (bytes.fromhex("16" "16" "280100000A" "2A"), 2, CallSignature(2), 0, 2),
        # instance: receiver + no args, returns void
        (bytes.fromhex("16" "6F0100000A" "2A"), 2, CallSignature(0, has_this=True), 0, 1),
        # newobj: the constructor's this is not consumed; one arg is, object pushed
        (bytes.fromhex("16" "730100000A" "26" "2A"), 2, CallSignature(1, has_this=True), 0, 1),
        # newobj with a zero-arg instance ctor: the receiver is created, not consumed
        (bytes.fromhex("16" "730100000A" "26" "26" "2A"), 2, CallSignature(0, has_this=True), 0, 2),
        # calli: function pointer + one arg, returns one value
        (bytes.fromhex("16" "16" "290100000A" "2A"), 2, CallSignature(1, returns_value=True), 1, 2),
    ],
)
def test_call_height_rules(code, max_stack, signature, expected_height, expected_derived):
    body = fixtures.read_body(fixtures.build_fat_method_body(code, max_stack=max_stack))
    result = analyze_stack(body, lambda token: signature)

    ret = result.instructions[body.instructions[-1].offset]
    assert ret.status is StackStatus.KNOWN
    assert ret.height == expected_height
    assert result.derived_max_stack == expected_derived


def test_call_underflow_is_a_conflict():
    body = fixtures.read_body(fixtures.build_fat_method_body(bytes.fromhex("280100000A" "2A"), max_stack=1))
    result = analyze_stack(body, lambda token: CallSignature(1), return_value=False)

    assert result.status is StackStatus.CONFLICT
    underflow = issue(result, StackIssueKind.STACK_UNDERFLOW)
    assert underflow.offset == body.instructions[0].offset
    assert underflow.paths[0].offsets == (body.instructions[0].offset,)


# ---------------------------------------------------------------------------
# Exception handler entries
# ---------------------------------------------------------------------------
def test_catch_entry_starts_at_height_one_and_merges_with_normal_exit():
    body = fixtures.read_body(fixtures.CATCH_BODY)
    result = analyze_stack(body, lambda token: CallSignature(1), return_value=False)

    assert result.status is StackStatus.KNOWN
    assert result.issues == ()

    catch_entry = body.instructions[3].offset  # pop
    catch_report = result.instructions[catch_entry]
    assert catch_report.status is StackStatus.KNOWN
    assert catch_report.height == 1
    assert catch_report.paths[0].origin == "catch handler entry"
    assert catch_report.chain == (catch_entry,)

    ret = result.instructions[body.instructions[-1].offset]
    assert ret.height == 0
    ret_offset = ret.offset
    origins = {path.origin for path in result.joins[ret_offset]}
    assert origins == {"method entry", "catch handler entry"}
    assert {path.height for path in result.joins[ret_offset]} == {0}


def test_finally_entry_starts_at_height_zero():
    body = fixtures.read_body(fixtures.FINALLY_BODY)
    result = analyze_stack(body, return_value=False)

    assert result.status is StackStatus.KNOWN
    finally_entry = body.instructions[2].offset  # endfinally
    finally_report = result.instructions[finally_entry]
    assert finally_report.height == 0
    assert finally_report.paths[0].origin == "finally/fault handler entry"


def test_bad_catch_entry_is_missing_information():
    # The catch handler starts on a non-instruction boundary.
    raw = fixtures.build_fat_method_body(
        bytes.fromhex("DE00" "2A"),
        max_stack=1,
        handlers=((0, 0x0, 0x1, 0x3, 0x1, 0x01000002),),
    )
    body = fixtures.read_body(raw)
    result = analyze_stack(body, return_value=False)

    assert result.status is StackStatus.UNKNOWN
    assert not result.verified
    invalid = issue(result, StackIssueKind.INVALID_EXCEPTION_HANDLER)
    assert "catch handler entry" in invalid.message


# ---------------------------------------------------------------------------
# leave / ret / throw / endfilter rules
# ---------------------------------------------------------------------------
def test_leave_clears_the_stack_before_branching():
    # ldc.i4.0; leave.s ret; ret -- leave must branch at height 0, not 1.
    code = bytes.fromhex("16" "DE00" "2A")
    body = fixtures.read_body(fixtures.build_fat_method_body(code, max_stack=1))
    result = analyze_stack(body, return_value=False)

    assert result.status is StackStatus.KNOWN
    ret = result.instructions[body.instructions[-1].offset]
    assert ret.height == 0
    assert ret.chain == (
        body.instructions[0].offset,
        body.instructions[1].offset,
        body.instructions[2].offset,
    )


def test_ret_height_mismatch_is_a_conflict():
    body = fixtures.read_body(fixtures.build_fat_method_body(bytes.fromhex("16" "2A"), max_stack=1))
    result = analyze_stack(body, return_value=False)

    assert result.status is StackStatus.CONFLICT
    ret_issue = issue(result, StackIssueKind.RET_HEIGHT)
    assert ret_issue.offset == body.instructions[-1].offset
    assert "expects 0" in ret_issue.message


def test_throw_terminates_without_falling_through():
    # ldc.i4.0; throw; ret (ret is unreachable)
    body = fixtures.read_body(fixtures.build_fat_method_body(bytes.fromhex("16" "7A" "2A"), max_stack=1))
    result = analyze_stack(body, return_value=False)

    assert result.status is StackStatus.KNOWN
    throw_report = result.instructions[body.instructions[1].offset]
    assert throw_report.status is StackStatus.KNOWN
    assert throw_report.height == 1
    ret_report = result.instructions[body.instructions[2].offset]
    assert ret_report.status is StackStatus.UNREACHABLE
    assert ret_report.height is None


def test_rethrow_terminates_without_a_stack_requirement():
    body = fixtures.read_body(fixtures.build_fat_method_body(bytes.fromhex("FE1A" "2A"), max_stack=1))
    result = analyze_stack(body, return_value=False)

    assert result.status is StackStatus.KNOWN
    assert result.instructions[body.instructions[0].offset].height == 0
    assert result.instructions[body.instructions[1].offset].status is StackStatus.UNREACHABLE


def test_endfilter_requires_exactly_one_value():
    # try { leave.s handler } filter { ldc.i4.0; ldc.i4.0; endfilter } handler { pop; leave.s end } end: ret
    code = bytes.fromhex(
        "DE06"  # 00 leave.s IL_0008
        "16"  # 02 ldc.i4.0
        "16"  # 03 ldc.i4.0
        "FE11"  # 04 endfilter
        "26"  # 06 pop
        "2B00"  # 07 br.s IL_0009
        "2A"  # 09 ret
    )
    raw = fixtures.build_fat_method_body(
        code,
        max_stack=2,
        handlers=((1, 0x0, 0x2, 0x6, 0x3, 0x2),),
    )
    body = fixtures.read_body(raw)
    result = analyze_stack(body, return_value=False)

    assert result.status is StackStatus.CONFLICT
    endfilter = issue(result, StackIssueKind.ENDFILTER_HEIGHT)
    assert "exactly one" in endfilter.message
    assert endfilter.paths[0].origin == "filter entry"
    assert endfilter.paths[0].height == 3


# ---------------------------------------------------------------------------
# max_stack declaration vs derivation
# ---------------------------------------------------------------------------
def test_max_stack_exceeded_reports_chain_to_deepest_point():
    body = fixtures.read_body(fixtures.build_fat_method_body(bytes.fromhex("16" "16" "2A"), max_stack=1))
    result = analyze_stack(body, return_value=False)

    assert result.max_stack_relation is MaxStackRelation.EXCEEDED
    assert result.declared_max_stack == 1
    assert result.derived_max_stack == 2
    exceeded = issue(result, StackIssueKind.MAX_STACK_EXCEEDED)
    assert exceeded.paths[0].offsets == (
        body.instructions[0].offset,
        body.instructions[1].offset,
    )
    assert "exceeds declared .maxstack 1" in exceeded.message


def test_unknown_path_makes_max_stack_relation_unknown():
    body = fixtures.read_body(fixtures.MISSING_SIGNATURE_BODY)
    result = analyze_stack(body, return_value=False)

    assert result.max_stack_relation is MaxStackRelation.UNKNOWN
    assert not result.max_stack_is_complete
    assert "lower bound" in result.format_report()


def test_declared_max_stack_is_reported_even_when_within():
    body = fixtures.read_body(fixtures.LOOP_BODY)
    result = analyze_stack(body, lambda token: CallSignature(2, returns_value=True), return_value=False)

    assert result.declared_max_stack == 2
    assert result.derived_max_stack == 2
    assert "declared=2" in result.format_report()
    assert "derived=2" in result.format_report()


# ---------------------------------------------------------------------------
# Convergence and other structural guards
# ---------------------------------------------------------------------------
def test_unbounded_growth_is_bounded_and_reported_as_conflict():
    # loop: ldc.i4.0; br.s loop -- height grows forever in real IL.
    body = fixtures.read_body(fixtures.build_fat_method_body(bytes.fromhex("16" "2BFD"), max_stack=1))
    result = StackAnalyzer(body, max_heights_per_instruction=4, max_steps=50).analyze()

    assert result.status is StackStatus.CONFLICT
    assert StackIssueKind.UNBOUNDED_STACK_GROWTH in kinds(result)
    growth = issue(result, StackIssueKind.UNBOUNDED_STACK_GROWTH)
    assert "did not converge" in growth.message
    assert growth.paths[0].offsets[-1] == body.instructions[0].offset


def test_unsupported_opcode_effect_is_unknown_not_zero():
    body = fixtures.read_body(fixtures.build_fat_method_body(bytes.fromhex("FE00" "26" "2A"), max_stack=1))
    result = analyze_stack(body, return_value=False)
    # arglist is a normal one-push opcode, so this body verifies.
    assert result.status is StackStatus.KNOWN

    # An opcode whose effect table entry is missing must never be assumed to be
    # a no-op.  Use a monkeypatched table removal for a deterministic check.
    import dncil.cil.stack_analysis as analysis

    original = analysis._POPS.pop(analysis.StackBehaviour.Pop1)
    try:
        underflow_body = fixtures.read_body(fixtures.build_fat_method_body(bytes.fromhex("1626" "2A"), max_stack=1))
        missing_effect = analyze_stack(underflow_body, return_value=False)
    finally:
        analysis._POPS[analysis.StackBehaviour.Pop1] = original

    assert missing_effect.status is StackStatus.UNKNOWN
    assert StackIssueKind.UNRESOLVED_STACK_EFFECT in kinds(missing_effect)


def test_unknown_branch_target_is_not_verified():
    # br.s +5 from the end: target is outside the instruction stream.
    body = fixtures.read_body(fixtures.build_fat_method_body(bytes.fromhex("2B05"), max_stack=1))
    result = analyze_stack(body, return_value=False)

    assert result.status is StackStatus.UNKNOWN
    assert not result.verified
    assert StackIssueKind.UNKNOWN_BRANCH_TARGET in kinds(result)


def test_jmp_requires_empty_stack():
    body = fixtures.read_body(fixtures.build_fat_method_body(bytes.fromhex("16" "270100000A"), max_stack=1))
    result = analyze_stack(body, return_value=False)

    assert result.status is StackStatus.CONFLICT
    assert StackIssueKind.JMP_STACK_NOT_EMPTY in kinds(result)


def test_empty_method_body_is_unknown():
    body = fixtures.read_body(fixtures.build_fat_method_body(b"", max_stack=0))
    result = analyze_stack(body, return_value=False)

    assert result.status is StackStatus.UNKNOWN
    assert StackIssueKind.EMPTY_METHOD in kinds(result)
    assert result.entry_offset is None


def test_analyzer_can_be_reused():
    body = fixtures.read_body(fixtures.MISSING_SIGNATURE_BODY)
    analyzer = StackAnalyzer(body, return_value=False)

    first = analyzer.analyze()
    second = analyzer.analyze()
    assert first.status is StackStatus.UNKNOWN
    assert second.status is StackStatus.UNKNOWN
    assert [issue.kind for issue in first.issues] == [issue.kind for issue in second.issues]


def test_report_contains_issue_chains():
    body = fixtures.read_body(fixtures.JOIN_BODY)
    report = analyze_stack(body, return_value=False).format_report()

    assert "join_conflict" in report
    assert "IL_000C ldc.i4.0 -> IL_000D brtrue.s -> IL_0012 nop" in report
    assert "IL_000C ldc.i4.0 -> IL_000D brtrue.s -> IL_000F ldc.i4.0 -> IL_0010 br.s -> IL_0012 nop" in report


def test_ret_with_overfull_stack_is_a_conflict_without_return_shape():
    body = fixtures.read_body(fixtures.build_fat_method_body(bytes.fromhex("16" "16" "2A"), max_stack=2))
    result = analyze_stack(body)

    # More than one value can never be returned, regardless of the method
    # signature, so this is definite even without return_value.
    assert result.status is StackStatus.CONFLICT
    ret_issue = issue(result, StackIssueKind.RET_HEIGHT)
    assert "at most one" in ret_issue.message
    assert result.instructions[body.instructions[-1].offset].status is StackStatus.CONFLICT


def test_method_body_convenience_api():
    body = fixtures.read_body(fixtures.MISSING_SIGNATURE_BODY)
    result = body.analyze_stack(return_value=False)

    assert result.status is StackStatus.UNKNOWN
    assert result.entry_offset == body.instructions[0].offset


def test_missing_signature_is_never_reported_as_zero_argument():
    """A resolver that cannot resolve must not be equivalent to CallSignature(0)."""
    body = fixtures.read_body(fixtures.MISSING_SIGNATURE_BODY)

    unknown = analyze_stack(body, lambda token: None, return_value=False)
    assumed = analyze_stack(body, lambda token: CallSignature(0), return_value=False)

    assert unknown.status is StackStatus.UNKNOWN
    assert assumed.status is not StackStatus.UNKNOWN
    assert unknown.status is not assumed.status


def test_unknown_predecessor_does_not_let_join_look_verified():
    body = fixtures.read_body(fixtures.MISSING_SIGNATURE_BODY)
    result = analyze_stack(body, return_value=False)

    ret_offset = chain(body, (fixtures.MISSING_SIGNATURE_RET_OFFSET,))[0]
    ret_report = result.instructions[ret_offset]
    # One incoming branch is a clean height 0; the other is unknown.  The
    # single known height must not win.
    assert ret_report.known_heights == (0,)
    assert ret_report.status is StackStatus.UNKNOWN
    assert ret_report.height is None
    assert result.max_stack_relation is MaxStackRelation.UNKNOWN


def test_signature_mapping_accepts_token_keys():
    body = fixtures.read_body(fixtures.MISSING_SIGNATURE_BODY)
    result = analyze_stack(
        body,
        signatures={Token(fixtures.MISSING_SIGNATURE_CALL_TOKEN): CallSignature(1)},
        return_value=False,
    )
    assert result.status is StackStatus.KNOWN
