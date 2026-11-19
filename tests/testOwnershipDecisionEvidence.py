import unittest

from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

BASE = 0x1000
SIZE = 0x2000

#: push ebp; mov ebp, esp; cmp dword ptr [ebp + 8], 0; jz +5; mov eax, 1; <shared tail: pop ebp; ret>
T_BODY = bytes.fromhex("558BEC837D08007405B8010000005DC3")
SHARED_TAIL_OFFSET = 0x0E
#: push ebp; mov ebp, esp; mov eax, [ebp + 8]; pop ebp; ret
T_FN = bytes.fromhex("558BEC8B45085DC3")
#: a function that only calls another: push ebp; mov ebp, esp; call <rel32>; pop ebp; ret
CALLER_PREFIX = bytes.fromhex("558BEC")
CALLER_SUFFIX = bytes.fromhex("5DC3")


def _emit(image, addr, data):
    image[addr - BASE : addr - BASE + len(data)] = data


def _caller_fn(call_from, target):
    rel = target - (call_from + 5)
    return CALLER_PREFIX + b"\xe8" + rel.to_bytes(4, "little", signed=True) + CALLER_SUFFIX


def _jmp_fn(jmp_from, target, prefix=b""):
    rel = target - (jmp_from + len(prefix) + 5)
    return prefix + b"\xe9" + rel.to_bytes(4, "little", signed=True)


def _analyze(image, oep=None):
    config = SmdaConfig()
    config.RESOLVE_TAILCALLS = True
    report = Disassembler(config, backend="intel").disassembleBuffer(
        bytes(image), base_addr=BASE, bitness=32, oep=oep, architecture="intel"
    )
    assert report.status == "ok"
    return report


def _ownership(report):
    """Which function owns which instruction: the final ownership map of the report."""
    return {function.offset: {ins.offset for ins in function.getInstructions()} for function in report.getFunctions()}


def _xrefs(report):
    return {
        function.offset: (
            {src: sorted(targets) for src, targets in function.outrefs.items()},
            sorted(function.inrefs),
        )
        for function in report.getFunctions()
    }


def _decisions(report):
    return [
        (d.decision, d.basis, d.target_addr, d.source_addr, d.function_addr, d.previous_owner)
        for d in report.ownership_decisions
    ]


class OwnershipRoundTripMixin:
    """After export and reload, final ownership, cross references and decision evidence agree."""

    def assertRoundTripConsistent(self, report):
        reloaded = SmdaReport.fromDict(report.toDict())
        self.assertEqual(_ownership(reloaded), _ownership(report))
        self.assertEqual(_xrefs(reloaded), _xrefs(report))
        self.assertEqual(
            [d.toDict() for d in reloaded.ownership_decisions],
            [d.toDict() for d in report.ownership_decisions],
        )


class SharedTailOwnershipTest(OwnershipRoundTripMixin, unittest.TestCase):
    """Two functions reach one epilogue block; who owns it is decided by the tailcall pass.

    T's body ends in a shared tail (pop ebp; ret) that C also jumps to. The layout is fixed;
    only the discovery order changes: without an OEP the candidate tie breaks to the lower
    address (T first), with C as OEP the caller is analyzed first and absorbs the tail before
    T exists. Either way the tailcall pass splits the tail off its interim owner, so both
    orders converge on the same three functions - and the evidence says whose body was split.
    """

    def _image(self):
        image = bytearray(b"\xcc" * SIZE)
        _emit(image, 0x1000, T_BODY)
        _emit(image, 0x1800, _jmp_fn(0x1800, 0x1000 + SHARED_TAIL_OFFSET, prefix=bytes.fromhex("558BEC31C0")))
        return image

    def setUp(self):
        self.target_first = _analyze(self._image())
        self.caller_first = _analyze(self._image(), oep=0x800)

    def testBothOrdersConvergeOnTheSameCfg(self):
        self.assertEqual(_ownership(self.target_first), _ownership(self.caller_first))
        self.assertEqual(_xrefs(self.target_first), _xrefs(self.caller_first))

    def testTheTailIsItsOwnFunctionOwnedByNobodyElse(self):
        ownership = _ownership(self.target_first)
        self.assertEqual(sorted(ownership), [0x1000, 0x100E, 0x1800])
        self.assertEqual(ownership[0x100E], {0x100E, 0x100F})
        self.assertNotIn(0x100E, ownership[0x1000])
        self.assertNotIn(0x100E, ownership[0x1800])

    def testBothBranchesIntoTheTailAreCrossReferences(self):
        outrefs, _ = _xrefs(self.target_first)[0x1000]
        self.assertEqual(outrefs, {0x1007: [0x100E]})
        outrefs, _ = _xrefs(self.target_first)[0x1800]
        self.assertEqual(outrefs, {0x1805: [0x100E]})
        _, inrefs = _xrefs(self.target_first)[0x100E]
        self.assertEqual(inrefs, [0x1007, 0x1805])

    def testTargetFirstSplitsTheEarlierDiscoveredFunction(self):
        decisions = _decisions(self.target_first)
        self.assertIn(
            ("split", "jump_into_owned_function_body", 0x100E, 0x1805, 0x1000, 0x1000),
            decisions,
        )
        self.assertIn(
            ("reanalyzed", "previous_owner_truncated_at_shared_tail", 0x1000, 0x1805, 0x1000, 0x1000),
            decisions,
        )

    def testCallerFirstSplitsTheCallerThatAbsorbedTheTail(self):
        decisions = _decisions(self.caller_first)
        self.assertIn(
            ("split", "jump_into_owned_function_body", 0x100E, 0x1007, 0x1800, 0x1800),
            decisions,
        )
        self.assertIn(
            ("reanalyzed", "previous_owner_truncated_at_shared_tail", 0x1800, 0x1007, 0x1800, 0x1800),
            decisions,
        )

    def testTheSplitRecordKeepsTheOwnerCandidateEvidence(self):
        split = next(d for d in self.target_first.ownership_decisions if d.decision == "split")
        self.assertIn(0x1000, split.candidates)
        self.assertGreater(split.candidates[0x1000]["prologue_score"], 0)

    def testRoundTrip(self):
        self.assertRoundTripConsistent(self.target_first)
        self.assertRoundTripConsistent(self.caller_first)


class TrueTailcallOwnershipTest(OwnershipRoundTripMixin, unittest.TestCase):
    """A jmp to a function entry is a tailcall: the target keeps its own function.

    C ends in an unconditional jmp to T's entry; D calls T, so T carries entry evidence of
    its own. Discovered first (its call reference outranks C's prologue) or second (C is the
    OEP), T is never merged into C - the only thing the order changes is whether the jump
    meets an owned function ("tailcall") or a known candidate ("deferred").
    """

    def _image(self):
        image = bytearray(b"\xcc" * SIZE)
        _emit(image, 0x1000, _jmp_fn(0x1000, 0x1800, prefix=bytes.fromhex("558BEC31C0")))
        _emit(image, 0x1800, T_FN)
        _emit(image, 0x1A00, _caller_fn(0x1A03, 0x1800))
        return image

    def setUp(self):
        self.target_first = _analyze(self._image())
        self.caller_first = _analyze(self._image(), oep=0x0)

    def testBothOrdersConvergeOnTheSameCfg(self):
        self.assertEqual(_ownership(self.target_first), _ownership(self.caller_first))
        self.assertEqual(_xrefs(self.target_first), _xrefs(self.caller_first))

    def testTheTargetStaysAWholeFunction(self):
        ownership = _ownership(self.target_first)
        self.assertEqual(sorted(ownership), [0x1000, 0x1800, 0x1A00])
        self.assertEqual(ownership[0x1800], {0x1800, 0x1801, 0x1803, 0x1806, 0x1807})
        self.assertFalse(ownership[0x1000] & ownership[0x1800])

    def testTheTailcallAndTheCallAreCrossReferences(self):
        outrefs, _ = _xrefs(self.target_first)[0x1000]
        self.assertEqual(outrefs, {0x1005: [0x1800]})
        outrefs, _ = _xrefs(self.target_first)[0x1A00]
        self.assertEqual(outrefs, {0x1A03: [0x1800]})

    def testTargetFirstRecordsTheOwnedEntryAndItsCallers(self):
        decisions = _decisions(self.target_first)
        self.assertIn(
            ("tailcall", "jump_target_is_owned_function_entry", 0x1800, 0x1005, 0x1000, 0x1800),
            decisions,
        )
        tailcall = next(d for d in self.target_first.ownership_decisions if d.decision == "tailcall")
        self.assertEqual(tailcall.candidates[0x1800]["call_ref_sources"], [0x1A03])

    def testCallerFirstDefersToTheUnanalyzedCandidate(self):
        decisions = _decisions(self.caller_first)
        self.assertIn(
            ("deferred", "jump_target_is_unanalyzed_candidate", 0x1800, 0x1005, 0x1000, None),
            decisions,
        )

    def testNoAbsorbOrSplitIsRecorded(self):
        for report in (self.target_first, self.caller_first):
            self.assertEqual({d.decision for d in report.ownership_decisions} - {"tailcall", "deferred"}, set())

    def testRoundTrip(self):
        self.assertRoundTripConsistent(self.target_first)
        self.assertRoundTripConsistent(self.caller_first)


class JumpStubOwnershipTest(OwnershipRoundTripMixin, unittest.TestCase):
    """A function whose entry is a lone jmp is a stub, not a merge into the target.

    S is a single jmp to T. T carries no prologue and is called by nobody, so nothing but
    the discovery order ever names it: found first by the gap scan (it sits below S), S's
    jump meets an owned function and is a tailcall; with S as the OEP, the jump meets an
    address nobody knows and the stub decision keeps S to its one instruction. A seed
    function keeps the gap pass alive in an otherwise candidate-less image.
    """

    def _image(self):
        image = bytearray(b"\xcc" * SIZE)
        _emit(image, 0x1000, bytes.fromhex("31C0C3"))
        _emit(image, 0x1800, _jmp_fn(0x1800, 0x1000))
        _emit(image, 0x1F00, bytes.fromhex("558BEC31C05DC3"))
        return image

    def setUp(self):
        self.target_first = _analyze(self._image())
        self.caller_first = _analyze(self._image(), oep=0x800)

    def testBothOrdersConvergeOnTheSameCfg(self):
        self.assertEqual(_ownership(self.target_first), _ownership(self.caller_first))
        self.assertEqual(_xrefs(self.target_first), _xrefs(self.caller_first))

    def testTheStubKeepsItsSingleInstructionAndTheTargetStaysFree(self):
        ownership = _ownership(self.target_first)
        self.assertEqual(sorted(ownership), [0x1000, 0x1800, 0x1F00])
        self.assertEqual(ownership[0x1800], {0x1800})
        self.assertEqual(ownership[0x1000], {0x1000, 0x1002})

    def testTheStubJumpIsTheOnlyCrossReference(self):
        outrefs, _ = _xrefs(self.target_first)[0x1800]
        self.assertEqual(outrefs, {0x1800: [0x1000]})
        _, inrefs = _xrefs(self.target_first)[0x1000]
        self.assertEqual(inrefs, [0x1800])

    def testTargetFirstSeesAnOwnedFunctionEntry(self):
        decisions = _decisions(self.target_first)
        self.assertIn(
            ("tailcall", "jump_target_is_owned_function_entry", 0x1000, 0x1800, 0x1800, 0x1000),
            decisions,
        )

    def testCallerFirstSeesAnUnknownTargetAndKeepsTheStub(self):
        decisions = _decisions(self.caller_first)
        self.assertIn(
            ("stub", "unconditional_jump_at_function_entry", 0x1000, 0x1800, 0x1800, None),
            decisions,
        )

    def testRoundTrip(self):
        self.assertRoundTripConsistent(self.target_first)
        self.assertRoundTripConsistent(self.caller_first)


class AbsorbOwnershipTest(OwnershipRoundTripMixin, unittest.TestCase):
    """A prologue-shaped body behind an early return is absorbed into its owner.

    C branches over its early `ret` to a body that opens with a prologue, so the body is a
    candidate in its own right. Analyzed first (the body wins the candidate order while C
    waits for the gap pass), the body is reverted and decoded as C's own blocks; analyzed
    second (C is the OEP and takes the body before it ever runs), the body's candidate is
    refused against C's ownership. Both orders end with one function and no overlap.
    """

    def _image(self):
        image = bytearray(b"\xcc" * SIZE)
        # cmp eax, 0; jz 0x1008; xor eax, eax; ret; body: push ebp; mov ebp, esp; mov eax, [ebp+8]; pop ebp; ret
        _emit(image, 0x1000, bytes.fromhex("83F800740333C0C3558BEC8B45085DC3"))
        return image

    def setUp(self):
        self.target_first = _analyze(self._image())
        self.caller_first = _analyze(self._image(), oep=0x0)

    def testBothOrdersConvergeOnASingleFunction(self):
        self.assertEqual(_ownership(self.target_first), _ownership(self.caller_first))
        ownership = _ownership(self.target_first)
        self.assertEqual(sorted(ownership), [0x1000])
        self.assertEqual(
            ownership[0x1000],
            {0x1000, 0x1003, 0x1005, 0x1007, 0x1008, 0x1009, 0x100B, 0x100E, 0x100F},
        )

    def testTargetFirstAbsorbsTheBodyAnalyzedBeforeItsCaller(self):
        decisions = _decisions(self.target_first)
        self.assertIn(
            ("absorbed", "conditional_branch_to_body_behind_return", 0x1008, 0x1003, 0x1000, 0x1008),
            decisions,
        )

    def testTheAbsorbRecordKeepsTheBodyCandidateEvidence(self):
        absorbed = next(d for d in self.target_first.ownership_decisions if d.decision == "absorbed")
        self.assertIn(0x1008, absorbed.candidates)
        self.assertEqual(absorbed.candidates[0x1008]["call_ref_sources"], [])
        self.assertGreater(absorbed.candidates[0x1008]["prologue_score"], 0)

    def testCallerFirstRefusesTheBodyCandidateAgainstExistingOwnership(self):
        decisions = _decisions(self.caller_first)
        self.assertIn(
            ("refused", "candidate_entry_already_owned", 0x1008, None, 0x1008, 0x1000),
            decisions,
        )

    def testRoundTrip(self):
        self.assertRoundTripConsistent(self.target_first)
        self.assertRoundTripConsistent(self.caller_first)


if __name__ == "__main__":
    unittest.main()
