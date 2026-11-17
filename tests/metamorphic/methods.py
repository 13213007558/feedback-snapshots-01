# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
"""Method fixtures for the branch-width metamorphic regression.

``BRANCHES_AND_EH`` is the demonstration method: it has a forward ``br.s`` that skips a
block, a backward ``blt.s`` loop, a ``switch`` with three cases, and two exception
clauses (catch + finally).  ``layout.format_layout`` prints its original and widened
forms side by side using logical labels.

The remaining methods exist to pin down the "unrepresentable" half of the contract:
each one names a reason why it cannot be widened, and the tests assert both the reason
and that no bytes are invented for it.
"""

from __future__ import annotations

from typing import Tuple

from tests.metamorphic.il_spec import Form, InsnSpec, MethodSpec, ExceptionSpec

CATCH_TYPE = 0x0100000D


def _insns(rows) -> Tuple[InsnSpec, ...]:
    return tuple(rows)


#: main demonstration method: forward branch, backward branch, switch, catch + finally
BRANCHES_AND_EH = MethodSpec(
    name="BranchesAndEh",
    max_stack=2,
    instructions=_insns(
        [
            InsnSpec("entry_ldc", "ldc.i4.0"),
            InsnSpec("entry_stloc", "stloc.0"),
            # long branch from the prologue to the loop header, crossing the widening
            # point of `skip_block`; it is already in long form on purpose so the
            # widened output has a mix of short and long branches.
            InsnSpec("jump_to_loop", "br", "loop_head", form=Form.LONG),
            InsnSpec("pad0", "nop"),
            InsnSpec("pad1", "nop"),
            InsnSpec("pad2", "nop"),
            InsnSpec("pad3", "nop"),
            InsnSpec("pad4", "nop"),
            # forward conditional branch across the widened region
            InsnSpec("skip_block", "brtrue", "loop_head"),
            InsnSpec("skip0", "nop"),
            InsnSpec("skip1", "nop"),
            InsnSpec("skip2", "nop"),
            InsnSpec("switch_operand", "ldloc.0"),
            InsnSpec("dispatch", "switch", ("case0", "case1", "case2")),
            InsnSpec("case0", "nop"),
            InsnSpec("leave_case0", "leave", "after_eh"),
            InsnSpec("case1", "nop"),
            InsnSpec("leave_case1", "leave", "after_eh"),
            InsnSpec("case2", "nop"),
            InsnSpec("leave_case2", "leave", "after_eh"),
            # backward branch whose displacement changes by the widened region size
            InsnSpec("loop_head", "ldloc.0"),
            InsnSpec("loop_limit", "ldc.i4.4"),
            InsnSpec("loop_back", "blt", "loop_head"),
            InsnSpec("leave_try", "leave", "after_eh"),
            # catch handler
            InsnSpec("catch_pop", "pop"),
            InsnSpec("catch_ldloc", "ldloc.0"),
            InsnSpec("catch_two", "ldc.i4.2"),
            InsnSpec("catch_add", "add"),
            InsnSpec("catch_stloc", "stloc.0"),
            InsnSpec("catch_leave", "leave", "after_eh"),
            # finally handler: the leave must target the first instruction after the
            # protected region rather than the endfinally itself
            InsnSpec("finally_ldloc", "ldloc.0"),
            InsnSpec("finally_pop", "pop"),
            InsnSpec("finally_end", "endfinally"),
            InsnSpec("after_eh", "ret"),
        ]
    ),
    exception_handlers=(
        ExceptionSpec(
            kind="catch",
            try_start="entry_ldc",
            try_end="catch_pop",
            handler_start="catch_pop",
            handler_end="finally_ldloc",
            catch_type=CATCH_TYPE,
        ),
        ExceptionSpec(
            kind="finally",
            try_start="entry_ldc",
            try_end="catch_pop",
            handler_start="finally_ldloc",
            handler_end="after_eh",
        ),
    ),
)


#: every short branch opcode, in both directions; no exception handlers
ALL_BRANCH_FORMS = MethodSpec(
    name="AllBranchForms",
    max_stack=2,
    init_locals=False,
    instructions=_insns(
        [
            InsnSpec("start", "ldc.i4.0"),
            InsnSpec("forward_br", "br", "back_anchor"),
            InsnSpec("forward_brtrue", "brtrue", "back_anchor"),
            InsnSpec("forward_brfalse", "brfalse", "back_anchor"),
            InsnSpec("forward_beq", "beq", "back_anchor"),
            InsnSpec("forward_bge", "bge", "back_anchor"),
            InsnSpec("forward_bgt", "bgt", "back_anchor"),
            InsnSpec("forward_ble", "ble", "back_anchor"),
            InsnSpec("forward_blt", "blt", "back_anchor"),
            InsnSpec("forward_bne", "bne.un", "back_anchor"),
            InsnSpec("forward_bge_un", "bge.un", "back_anchor"),
            InsnSpec("forward_bgt_un", "bgt.un", "back_anchor"),
            InsnSpec("forward_ble_un", "ble.un", "back_anchor"),
            InsnSpec("forward_blt_un", "blt.un", "back_anchor"),
            InsnSpec("back_anchor", "nop"),
            InsnSpec("backward_br", "br", "start"),
            InsnSpec("tail", "ret"),
        ]
    ),
)


#: a switch whose cases are only distinguishable after labels are re-resolved
SWITCH_CASES = MethodSpec(
    name="SwitchCases",
    max_stack=1,
    init_locals=False,
    instructions=_insns(
        [
            InsnSpec("entry", "ldloc.0"),
            InsnSpec("dispatch", "switch", ("case0", "case1", "case2", "case3")),
            InsnSpec("case0", "nop"),
            InsnSpec("case0_br", "br", "case3"),
            InsnSpec("case1", "nop"),
            InsnSpec("case1_br", "br", "case0"),
            InsnSpec("case2", "nop"),
            InsnSpec("case2_br", "br", "case1"),
            InsnSpec("case3", "nop"),
            InsnSpec("done", "ret"),
        ]
    ),
)


#: tiny method body: 14 short branches fit in 63 bytes today, but their long forms do not
TINY_BODY = MethodSpec(
    name="TinyBody",
    header_format="tiny",
    init_locals=False,
    max_stack=8,
    instructions=_insns([InsnSpec("b%02d" % index, "br", "done") for index in range(14)] + [InsnSpec("done", "ret")]),
)


#: tiny exception section: the try region fits in 255 bytes today, not after widening
TINY_EH_SECTION = MethodSpec(
    name="TinyEhSection",
    max_stack=1,
    init_locals=False,
    exception_section_format="tiny",
    instructions=_insns(
        [InsnSpec("try_%02d" % index, "br", "leave_try") for index in range(60)]
        + [
            InsnSpec("leave_try", "leave", "after"),
            InsnSpec("handler_start", "pop"),
            InsnSpec("after", "ret"),
        ]
    ),
    exception_handlers=(
        ExceptionSpec(
            kind="catch",
            try_start="try_00",
            try_end="handler_start",
            handler_start="handler_start",
            handler_end="after",
            catch_type=CATCH_TYPE,
        ),
    ),
)


#: fat header, but widening pushes the method past the 64 KiB CLR code limit
HUGE_METHOD = MethodSpec(
    name="HugeMethod",
    max_stack=1,
    init_locals=False,
    header_format="fat",
    instructions=_insns(
        [InsnSpec("pad_%05d" % index, "nop") for index in range(65531)]
        + [
            InsnSpec("tail_br", "br", "done"),
            InsnSpec("done", "ret"),
        ]
    ),
)


#: only long branches: there is nothing to widen, so the transform must decline
NO_SHORT_BRANCHES = MethodSpec(
    name="NoShortBranches",
    max_stack=1,
    init_locals=False,
    instructions=_insns(
        [
            InsnSpec("entry", "nop"),
            InsnSpec("jump", "br", "done", form=Form.LONG),
            InsnSpec("done", "ret"),
        ]
    ),
)


def methods_for_widening() -> Tuple[MethodSpec, ...]:
    """methods that must widen cleanly"""

    return (BRANCHES_AND_EH, ALL_BRANCH_FORMS, SWITCH_CASES)


def methods_that_cannot_widen() -> Tuple[Tuple[MethodSpec, Tuple[str, ...]], ...]:
    """methods that must be rejected, paired with the reason fragment to expect"""

    return (
        (TINY_BODY, ("tiny method header", "63")),
        (TINY_EH_SECTION, ("tiny exception section", "255")),
        (HUGE_METHOD, ("exceeds the", "65536")),
        (NO_SHORT_BRANCHES, ("no short branch", "no-op")),
    )
