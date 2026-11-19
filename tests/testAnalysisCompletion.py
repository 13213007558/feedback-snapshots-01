#!/usr/bin/python
"""Structured completion status for analyses a safeguard cut short.

A run that hits the analysis timeout or the candidate cap still returns a
report, and that report must not read as a complete analysis: it carries a
structured completion status naming each pipeline phase that did not finish
and why. These tests drive analyzeBuffer with controllable callbacks and a
tiny candidate cap - never a wall clock - so the partial reports are
deterministic, and check that the status survives a serialization round-trip
while a normal small-sample report is unambiguously complete.
"""

import json
import sys
import unittest

from smda.common.BinaryInfo import BinaryInfo
from smda.common.SmdaReport import SmdaReport
from smda.DisassemblyResult import DisassemblyResult
from smda.intel.IntelDisassembler import IntelDisassembler
from smda.SmdaConfig import SmdaConfig

BASE = 0x1000
# push ebp; mov ebp, esp; xor eax, eax; pop ebp; ret - a common-prologue function
FN1 = b"\x55\x8b\xec\x31\xc0\x5d\xc3"
# push ebp; mov ebp, esp; inc eax; pop ebp; ret - a second, distinct prologue function
FN2 = b"\x55\x8b\xec\x40\x5d\xc3"
# push ecx; pop ecx; ret - no known prologue, so only the gap search can find it
GAP_FN = b"\x51\x59\xc3"
PADDING = b"\xcc" * 8
# one prologue function with more than 256 basic blocks (the in-function budget
# poll interval): each `jnz $+2` ends a block and falls through to the next
BIG_FN = b"\x55\x8b\xec" + b"\x75\x00" * 300 + b"\x5d\xc3"


def _analyze(buffer, make_callback=None, config=None):
    """Run the intel backend and return (disassembler, disassembly, report).

    `make_callback` receives the disassembler, so the budget callback can trip on
    analysis state (phase, finished functions) rather than on wall-clock time.
    """
    config = config or SmdaConfig()
    disassembler = IntelDisassembler(config)
    binary_info = BinaryInfo(buffer)
    binary_info.base_addr = BASE
    binary_info.bitness = 32
    binary_info.architecture = "intel"
    callback = make_callback(disassembler) if make_callback is not None else None
    disassembly = disassembler.analyzeBuffer(binary_info, cbAnalysisTimeout=callback)
    return disassembler, disassembly, SmdaReport(disassembly, config=config)


def _trips_in_phase(phase):
    def make_callback(disassembler):
        return lambda: disassembler.disassembly.analysis_phase == phase

    return make_callback


def _roundtrip(report):
    return SmdaReport.fromDict(json.loads(json.dumps(report.toDict())))


class CompleteReportTestSuite(unittest.TestCase):
    def test_a_normal_small_sample_is_unambiguously_complete(self):
        _, _, report = _analyze(FN1 + PADDING + GAP_FN)

        self.assertEqual(report.status, "ok")
        self.assertEqual(report.message, "Analysis finished regularly.")
        self.assertEqual(report.completion["status"], "complete")
        self.assertEqual(report.completion["incomplete_phases"], {})
        self.assertEqual(report.completion["pending_phases"], [])
        self.assertNotIn("INCOMPLETE", str(report))
        # control for the abort tests below: both functions are found, the
        # prologue one by discovery and the prologue-less one by the gap search
        self.assertEqual([function.offset for function in report.getFunctions()], [BASE, BASE + 0xF])

    def test_completion_survives_a_serialization_roundtrip(self):
        _, _, report = _analyze(FN1 + PADDING + GAP_FN)

        self.assertEqual(_roundtrip(report).completion, report.completion)


class CandidateCapTestSuite(unittest.TestCase):
    def test_the_cap_marks_discovery_incomplete_without_a_timeout(self):
        config = SmdaConfig()
        config.MAX_FUNCTION_CANDIDATES = 1
        _, disassembly, report = _analyze(FN1 + PADDING + FN2 + PADDING + FN1, config=config)

        # the safeguard itself is untouched: the registry stays bounded
        self.assertLessEqual(len(disassembly.candidates), 1)
        self.assertFalse(disassembly.analysis_timeout)
        self.assertEqual(report.status, "ok")
        self.assertEqual(report.completion["status"], "incomplete")
        self.assertEqual(report.completion["incomplete_phases"]["candidate_discovery"], "candidate_cap")
        self.assertNotEqual(report.message, "Analysis finished regularly.")
        self.assertIn("candidate_cap", report.message)
        self.assertIn("INCOMPLETE", str(report))

    def test_the_cap_status_survives_a_serialization_roundtrip(self):
        config = SmdaConfig()
        config.MAX_FUNCTION_CANDIDATES = 1
        _, _, report = _analyze(FN1 + PADDING + FN2 + PADDING + FN1, config=config)

        self.assertEqual(_roundtrip(report).completion, report.completion)


class TimeoutAbortPointTestSuite(unittest.TestCase):
    def test_a_budget_spent_during_candidate_discovery(self):
        _, _, report = _analyze(FN1, lambda disassembler: lambda: True)

        self.assertEqual(report.status, "timeout")
        self.assertEqual(report.completion["status"], "incomplete")
        self.assertEqual(report.completion["incomplete_phases"]["candidate_discovery"], "timeout")
        self.assertEqual(report.num_functions, 0)
        self.assertEqual(_roundtrip(report).completion, report.completion)

    def test_a_budget_spent_mid_function_keeps_no_partial_cfg(self):
        def make_callback(disassembler):
            # trips only on the in-function budget poll, so the one big function
            # is cut mid-traversal rather than never started
            def callback():
                frame = sys._getframe(1)
                while frame is not None:
                    if frame.f_code.co_name == "analyzeFunction":
                        return True
                    frame = frame.f_back
                return False

            return callback

        _, disassembly, report = _analyze(BIG_FN, make_callback)

        self.assertEqual(report.status, "timeout")
        self.assertEqual(report.completion["incomplete_phases"]["function_traversal"], "timeout")
        # the partial function is not hung into the CFG as if it were complete
        self.assertEqual(report.num_functions, 0)
        self.assertNotIn(BASE, disassembly.functions)
        self.assertIn(BASE, disassembly.failed_analysis_addr)
        self.assertEqual(_roundtrip(report).completion, report.completion)

    def test_a_budget_spent_between_functions_keeps_the_finished_ones(self):
        def make_callback(disassembler):
            return lambda: len(disassembler.disassembly.functions) >= 1

        _, _, control = _analyze(FN1 + PADDING + FN2)
        _, _, report = _analyze(FN1 + PADDING + FN2, make_callback)

        self.assertEqual(report.status, "timeout")
        self.assertEqual(report.completion["incomplete_phases"]["function_traversal"], "timeout")
        # the function that finished before the budget ran out is kept, identical
        # to its shape in the uninterrupted run; the second one was never started
        self.assertEqual([function.offset for function in report.getFunctions()], [BASE])
        self.assertEqual(report.num_blocks, control.getFunction(BASE).num_blocks)
        self.assertEqual(_roundtrip(report).completion, report.completion)

    def test_a_budget_spent_during_the_gap_search(self):
        _, _, report = _analyze(FN1 + PADDING + GAP_FN, _trips_in_phase("gap_search"))

        self.assertEqual(report.status, "timeout")
        self.assertEqual(report.completion["incomplete_phases"]["gap_search"], "timeout")
        self.assertIn("function_traversal", report.completion["completed_phases"])
        # the prologue function from the primary pass is kept; the function only
        # the gap search can find is missing
        self.assertEqual([function.offset for function in report.getFunctions()], [BASE])
        self.assertEqual(_roundtrip(report).completion, report.completion)

    def test_a_budget_spent_during_symbol_completion(self):
        _, _, report = _analyze(FN1 + PADDING + GAP_FN, _trips_in_phase("symbol_completion"))

        self.assertEqual(report.status, "timeout")
        self.assertEqual(report.completion["incomplete_phases"]["symbol_completion"], "timeout")
        self.assertIn("gap_search", report.completion["completed_phases"])
        # everything up to the final pass was recovered
        self.assertEqual([function.offset for function in report.getFunctions()], [BASE, BASE + 0xF])
        self.assertEqual(_roundtrip(report).completion, report.completion)


class CompletionModelTestSuite(unittest.TestCase):
    def test_a_fresh_result_is_complete(self):
        completion = DisassemblyResult().getAnalysisCompletion()

        self.assertEqual(completion["status"], "complete")
        self.assertEqual(completion["incomplete_phases"], {})

    def test_the_first_reason_for_a_phase_wins(self):
        disassembly = DisassemblyResult()
        disassembly.setAnalysisPhase("candidate_discovery")
        disassembly.noteAnalysisIncomplete("candidate_cap")
        disassembly.noteAnalysisIncomplete("timeout")

        self.assertEqual(
            disassembly.getAnalysisCompletion()["incomplete_phases"],
            {"candidate_discovery": "candidate_cap"},
        )

    def test_a_phase_entered_with_a_spent_budget_is_incomplete(self):
        disassembly = DisassemblyResult()
        disassembly.analysis_timeout = True
        disassembly.setAnalysisPhase("gap_search")

        self.assertEqual(
            disassembly.getAnalysisCompletion()["incomplete_phases"],
            {"gap_search": "timeout"},
        )

    def test_a_bare_timeout_latch_still_reports_incomplete(self):
        # backends and exporters that only set the flag never name a phase; the
        # completion status must still not read as a finished analysis
        disassembly = DisassemblyResult()
        disassembly.analysis_timeout = True

        completion = disassembly.getAnalysisCompletion()

        self.assertEqual(completion["status"], "incomplete")
        self.assertIn("timeout", completion["incomplete_phases"].values())


class CompletionSerializationTestSuite(unittest.TestCase):
    def test_a_report_without_a_completion_field_reads_as_complete(self):
        _, _, report = _analyze(FN1)
        report_dict = report.toDict()
        del report_dict["completion"]

        self.assertEqual(SmdaReport.fromDict(report_dict).completion["status"], "complete")

    def test_a_malformed_completion_field_is_rejected(self):
        _, _, report = _analyze(FN1)
        for bad in ("incomplete", {"status": "maybe"}, {"status": "incomplete", "incomplete_phases": [1, 2]}):
            report_dict = report.toDict()
            report_dict["completion"] = bad
            with self.assertRaises(ValueError):
                SmdaReport.fromDict(report_dict)


if __name__ == "__main__":
    unittest.main()
