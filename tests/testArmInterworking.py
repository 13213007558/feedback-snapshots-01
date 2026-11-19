"""Interworking evidence and consistent target identity across A32 and T32 code.

A function pointer's bit 0 carries the target instruction set (ARM ARM A2.3.2), so it is
not part of the address and must not flow into CFG dedup. The short sample below is a raw
buffer (no container to name instruction sets) covering the three interesting transfers:

* ``entry_t`` (T32) reaches an A32 helper with ``blx`` - T32 -> A32,
* ``helper_a`` (A32) reaches a T32 leaf with ``blx <label>`` - A32 -> T32, which returns
  to the A32 caller through ``bx lr``,
* ``caller_ind`` (T32) loads a code pointer whose bit 0 wrongly names its A32 target as
  Thumb and calls through it with ``blx r3`` - the wrong-mode target.
"""

import json
import unittest

from smda.arm.ArmDisassembler import ArmDisassembler
from smda.arm.definitions import interworkPointer, interworkTarget, normalizeTarget
from smda.arm.FunctionCandidateManager import MODE_DECODED
from smda.common.BinaryInfo import BinaryInfo
from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

BASE = 0x10000

# entry_t    0x10000 (T32, 8):  push {r7, lr}; blx helper_a; pop {r7, pc}
# helper_a   0x10008 (A32, 12): push {r4, lr}; blx leaf_t; pop {r4, pc}
# leaf_t     0x10014 (T32, 8):  movs r0, #1; bx lr; nop; nop
# caller_ind 0x1001c (T32, 8):  ldr r3, [pc, #4]; blx r3; nop; nop
# pool       0x10024:          0x10009 = helper_a (0x10008) with the Thumb bit wrongly set
INTERWORK_SAMPLE = bytes.fromhex("80b500f002e880bd10402de9000000fa1080bde80120704700bf00bf014b984700bf00bf09000100")

ENTRY_T = 0x10000
HELPER_A = 0x10008
LEAF_T = 0x10014
CALLER_IND = 0x1001C
WRONG_POINTER = HELPER_A | 1


# A T32 function whose ``blx r3`` no constant-tracking pass can resolve: the target's
# instruction set is unprovable, so the report names the limitation instead of inventing an edge.
# push {r7, lr}; movs r0, #1; cmp r0, #0; beq .L; blx r3; .L: bx lr
UNRESOLVED_SAMPLE = bytes.fromhex("80b50120002800d098477047")


def _disassemble():
    return Disassembler(SmdaConfig()).disassembleBuffer(INTERWORK_SAMPLE, BASE, architecture="arm")


class InterworkIdentityTest(unittest.TestCase):
    def test_bit_zero_is_split_off_the_normalized_address(self):
        self.assertEqual(normalizeTarget(WRONG_POINTER), HELPER_A)
        self.assertEqual(interworkTarget(WRONG_POINTER), (HELPER_A, True))
        self.assertEqual(interworkTarget(HELPER_A), (HELPER_A, False))

    def test_the_pointer_is_reconstructed_with_its_bit(self):
        self.assertEqual(interworkPointer(HELPER_A, True), WRONG_POINTER)
        self.assertEqual(interworkPointer(HELPER_A, False), HELPER_A)
        self.assertEqual(interworkPointer(HELPER_A | 1, True), WRONG_POINTER)


class ArmUnprovableTargetTest(unittest.TestCase):
    def test_an_unresolved_register_branch_is_named_as_a_limitation(self):
        report = Disassembler(SmdaConfig()).disassembleBuffer(UNRESOLVED_SAMPLE, BASE, architecture="arm")
        function = report.getFunction(BASE)
        self.assertIsNotNone(function)
        unresolved = function.architecture_metadata["unresolved_interwork"]
        self.assertEqual(unresolved, [{"source": BASE + 8, "register": "r3"}])
        # no fabricated edge leaves the blx instruction
        self.assertNotIn(BASE + 8, function.outrefs)

    def test_the_limitation_survives_serialization(self):
        report = Disassembler(SmdaConfig()).disassembleBuffer(UNRESOLVED_SAMPLE, BASE, architecture="arm")
        restored = SmdaReport.fromDict(report.toDict())
        self.assertEqual(
            restored.getFunction(BASE).architecture_metadata["unresolved_interwork"],
            [{"source": BASE + 8, "register": "r3"}],
        )


class ArmInterworkingReportTest(unittest.TestCase):
    def setUp(self):
        self.report = _disassemble()

    def test_every_function_keeps_its_single_decoded_instruction_set(self):
        modes = {function.offset: function.architecture_metadata["thumb"] for function in self.report.getFunctions()}
        self.assertEqual(
            modes,
            {ENTRY_T: True, HELPER_A: False, LEAF_T: True, CALLER_IND: True},
        )

    def test_the_functions_are_decoded_in_the_actual_modes(self):
        entry = self.report.getFunction(ENTRY_T)
        self.assertEqual([ins.mnemonic for ins in entry.getInstructions()], ["push", "blx", "pop"])
        helper = self.report.getFunction(HELPER_A)
        self.assertEqual([ins.mnemonic for ins in helper.getInstructions()], ["push", "blx", "pop"])
        leaf = self.report.getFunction(LEAF_T)
        self.assertEqual([ins.mnemonic for ins in leaf.getInstructions()][:2], ["movs", "bx"])

    def test_the_t32_to_a32_call_edge_is_normalized_but_keeps_its_mode(self):
        entry = self.report.getFunction(ENTRY_T)
        self.assertEqual(entry.outrefs[ENTRY_T + 2], [HELPER_A])
        evidence = entry.architecture_metadata["interwork"][ENTRY_T + 2]
        self.assertEqual(evidence["target"], HELPER_A)
        self.assertFalse(evidence["thumb"])
        self.assertEqual(evidence["raw_pointer"], HELPER_A)
        self.assertTrue(evidence["switches"])

    def test_the_a32_to_t32_call_edge_carries_the_thumb_pointer(self):
        helper = self.report.getFunction(HELPER_A)
        self.assertEqual(helper.outrefs[HELPER_A + 4], [LEAF_T])
        evidence = helper.architecture_metadata["interwork"][HELPER_A + 4]
        self.assertEqual(evidence["target"], LEAF_T)
        self.assertTrue(evidence["thumb"])
        # the raw interworking pointer has bit 0 set even though the CFG edge is even
        self.assertEqual(evidence["raw_pointer"], LEAF_T | 1)
        self.assertTrue(evidence["switches"])

    def test_the_thumb_leaf_returns_through_bx_lr(self):
        leaf = self.report.getFunction(LEAF_T)
        self.assertEqual(leaf.num_returns, 1)
        self.assertEqual(list(leaf.getInstructions())[1].mnemonic, "bx")
        self.assertNotIn("interwork", leaf.architecture_metadata)

    def test_the_wrong_mode_pointer_keeps_its_raw_value_and_names_the_clash(self):
        caller = self.report.getFunction(CALLER_IND)
        evidence = caller.architecture_metadata["interwork"][CALLER_IND + 2]
        self.assertEqual(evidence["target"], HELPER_A)
        self.assertTrue(evidence["thumb"])
        self.assertEqual(evidence["raw_pointer"], WRONG_POINTER)
        # the CFG edge still uses the normalized, even address
        self.assertEqual(caller.outrefs[CALLER_IND + 2], [HELPER_A])
        conflicts = caller.architecture_metadata["mode_conflicts"]
        clash = next(entry for entry in conflicts if entry["address"] == HELPER_A)
        # the helper is decoded A32, the pointer requested Thumb: neither silently overwrites
        self.assertFalse(clash["decoded_thumb"])
        self.assertTrue(clash["requested_thumb"])
        self.assertIn(CALLER_IND, (clash["source"], CALLER_IND + 2))

    def test_mode_conflicts_do_not_change_the_decoded_function(self):
        helper = self.report.getFunction(HELPER_A)
        self.assertFalse(helper.architecture_metadata["thumb"])
        self.assertNotIn("mode_conflicts", helper.architecture_metadata)

    def test_thumb_markers_and_evidence_survive_serialization(self):
        restored = SmdaReport.fromDict(self.report.toDict())
        before = {f.offset: f.architecture_metadata for f in self.report.getFunctions()}
        after = {f.offset: f.architecture_metadata for f in restored.getFunctions()}
        self.assertEqual(after, before)
        helper = restored.getFunction(HELPER_A)
        self.assertFalse(helper.architecture_metadata["thumb"])
        evidence = helper.architecture_metadata["interwork"][HELPER_A + 4]
        self.assertEqual(evidence["raw_pointer"], LEAF_T | 1)
        caller = restored.getFunction(CALLER_IND)
        self.assertTrue(caller.architecture_metadata["mode_conflicts"])

    def test_thumb_markers_survive_a_json_round_trip(self):
        restored = SmdaReport.fromDict(json.loads(json.dumps(self.report.toDict())))
        # JSON turns the interwork dict's integer instruction keys into strings; the Thumb
        # marker and every evidence field must still be present and correct
        helper = restored.getFunction(HELPER_A)
        self.assertFalse(helper.architecture_metadata["thumb"])
        evidence = helper.architecture_metadata["interwork"][str(HELPER_A + 4)]
        self.assertTrue(evidence["thumb"])
        self.assertEqual(evidence["raw_pointer"], LEAF_T | 1)
        self.assertTrue(evidence["switches"])
        entry = restored.getFunction(ENTRY_T)
        self.assertTrue(entry.architecture_metadata["thumb"])
        entry_evidence = entry.architecture_metadata["interwork"][str(ENTRY_T + 2)]
        self.assertFalse(entry_evidence["thumb"])
        self.assertEqual(entry_evidence["raw_pointer"], HELPER_A)
        caller = restored.getFunction(CALLER_IND)
        self.assertTrue(caller.architecture_metadata["mode_conflicts"])
        self.assertTrue(restored.getFunction(LEAF_T).architecture_metadata["thumb"])


class ArmModeConflictLogTest(unittest.TestCase):
    """Same-address/different-mode evidence is logged, never silently overwritten."""

    def _manager(self):
        disassembler = ArmDisassembler(SmdaConfig())
        binary_info = BinaryInfo(INTERWORK_SAMPLE)
        binary_info.base_addr = BASE
        binary_info.bitness = 32
        disassembler.analyzeBuffer(binary_info)
        return disassembler.fc_manager

    def test_an_export_style_pointer_splits_address_and_thumb_bit(self):
        manager = self._manager()
        raw = 0x11001
        address = manager.noteMode(raw)
        self.assertEqual(address, 0x11000)
        self.assertTrue(manager.notedThumb(0x11000))

    def test_an_equal_strength_contradiction_is_logged_not_overwritten(self):
        manager = self._manager()
        address = 0x12000
        manager.noteMode(address, False, MODE_DECODED, source=0x12100)
        manager.noteMode(address, True, MODE_DECODED, source=0x12200)
        # the first statement stands
        self.assertFalse(manager.notedThumb(address))
        log = [entry for entry in manager.takeModeConflictLog() if entry["address"] == address]
        self.assertEqual(len(log), 1)
        self.assertFalse(log[0]["decoded_thumb"])
        self.assertTrue(log[0]["requested_thumb"])
        self.assertEqual(log[0]["source"], 0x12200)
        self.assertEqual(log[0]["reason"], "equal_strength_mode_clash")

    def test_identical_statements_do_not_spam_the_log(self):
        manager = self._manager()
        address = 0x13000
        manager.noteMode(address, True, MODE_DECODED, source=0x13100)
        manager.noteMode(address, True, MODE_DECODED, source=0x13100)
        self.assertFalse(any(entry["address"] == address for entry in manager.takeModeConflictLog()))


if __name__ == "__main__":
    unittest.main()
