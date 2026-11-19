import datetime
import logging
import os
import struct
import tempfile
import unittest
from unittest import mock

from smda.common.RecursiveDisassembler import RecursiveDisassembler
from smda.Disassembler import Disassembler


class TestDisassemblerReuse(unittest.TestCase):
    X86 = bytes([0x55, 0x48, 0x89, 0xE5, 0x5D, 0xC3])  # push rbp; mov rbp, rsp; pop rbp; ret
    MIPS = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])

    def test_fresh_instance_rejects_unsupported_architecture(self):
        d = Disassembler()
        report = d.disassembleBuffer(self.MIPS, 0x400000, bitness=32, architecture="mips")
        self.assertEqual(report.status, "error")

    def test_reused_instance_rejects_unsupported_architecture(self):
        d = Disassembler()
        first = d.disassembleBuffer(self.X86, 0x400000, bitness=64, architecture="intel")
        self.assertEqual(first.status, "ok")
        self.assertEqual(first.architecture, "intel")

        second = d.disassembleBuffer(self.MIPS, 0x400000, bitness=32, architecture="mips")
        self.assertEqual(second.status, "error")


class TestAnalysisTimeoutIsAnnounced(unittest.TestCase):
    """A timed-out run returns a partial report that otherwise looks like a complete one, so the
    stop has to be announced once at default log level rather than only at debug level."""

    def setUp(self):
        # several test modules call logging.disable(CRITICAL) at import time, and that is
        # process-global, so assertLogs sees nothing in a full-suite run unless it is lifted
        previously_disabled = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, previously_disabled)

    def _expiredDisassembler(self):
        disassembler = Disassembler()
        disassembler._timeout = 10
        disassembler._start_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=30)
        return disassembler

    def test_the_stop_is_reported_once_however_often_the_callback_runs(self):
        disassembler = self._expiredDisassembler()

        with self.assertLogs("smda.Disassembler", level="WARNING") as logged:
            self.assertTrue(disassembler._callbackAnalysisTimeout())
            self.assertTrue(disassembler._callbackAnalysisTimeout())

        self.assertEqual(len(logged.output), 1)
        self.assertIn("incomplete", logged.output[0])

    def test_a_run_within_its_budget_reports_nothing(self):
        disassembler = Disassembler()
        disassembler._timeout = 300
        disassembler._start_time = datetime.datetime.now(datetime.timezone.utc)

        with self.assertNoLogs("smda.Disassembler", level="WARNING"):
            self.assertFalse(disassembler._callbackAnalysisTimeout())

    def test_a_reused_instance_reports_the_next_run_too(self):
        disassembler = self._expiredDisassembler()
        with self.assertLogs("smda.Disassembler", level="WARNING"):
            self.assertTrue(disassembler._callbackAnalysisTimeout())

        disassembler.disassembleBuffer(TestDisassemblerReuse.X86, 0x400000, bitness=64, architecture="intel")
        disassembler._timeout = 10
        disassembler._start_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=30)

        with self.assertLogs("smda.Disassembler", level="WARNING"):
            self.assertTrue(disassembler._callbackAnalysisTimeout())


FIXTURE_DIR = os.path.dirname(os.path.abspath(__file__))
X86_PE_WITH_PDB = os.path.join(FIXTURE_DIR, "rust_pe_msvc_i686_xored")
PDB_FOR_FIRST_PE = os.path.join(FIXTURE_DIR, "rust_pe_msvc_i686_pdb_xored")
X86_PE_OTHER = os.path.join(FIXTURE_DIR, "cutwail_xored")
ARM64_PE = os.path.join(FIXTURE_DIR, "arm64_pe_probe_xored")
SHARED_IMAGE_BASE = 0x400000
PDB_SYMBOL = "main::digest"


def decode_fixture(path):
    with open(path, "rb") as fin:
        return bytes(byte ^ (index % 256) for index, byte in enumerate(fin.read()))


def rebased_to_image_base(pe_data, image_base):
    data = bytearray(pe_data)
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[e_lfanew : e_lfanew + 4] == b"PE\0\0"
    struct.pack_into("<I", data, e_lfanew + 24 + 28, image_base)
    return bytes(data)


def report_signature(report):
    return (
        report.status,
        report.architecture,
        report.num_functions,
        report.num_instructions,
        sorted(function.offset for function in report.getFunctions()),
        {function.offset: function.function_name for function in report.getFunctions() if function.function_name},
    )


class CrossSampleResidueTestSuite(unittest.TestCase):
    """A Disassembler reused across samples must not let per-sample input (here: a PDB
    handed over via disassembleFile's pdb_path) bleed into the next sample's report,
    while application-level configuration (the shared SmdaConfig, the pinned backend)
    has to survive untouched. The two x86 PEs are rebased to the same image base so
    stale addresses from the first sample would land on real functions of the second."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.first_pe = self._write("first.exe", decode_fixture(X86_PE_WITH_PDB))
        self.first_pdb = self._write("first.pdb", decode_fixture(PDB_FOR_FIRST_PE))
        rebased = rebased_to_image_base(decode_fixture(X86_PE_OTHER), SHARED_IMAGE_BASE)
        self.second_pe = self._write("second.exe", rebased)
        self.arm64_pe = self._write("arm64.exe", decode_fixture(ARM64_PE))

    def _write(self, name, data):
        path = os.path.join(self.tempdir.name, name)
        with open(path, "wb") as fout:
            fout.write(data)
        return path

    def _independent_second_report(self, **kwargs):
        return Disassembler(**kwargs).disassembleFile(self.second_pe)

    def test_a_pdb_does_not_leak_into_the_next_sample(self):
        shared = Disassembler()
        named = shared.disassembleFile(self.first_pe, pdb_path=self.first_pdb)
        self.assertIn(PDB_SYMBOL, {f.function_name for f in named.getFunctions()})
        second = shared.disassembleFile(self.second_pe)
        self.assertEqual(report_signature(second), report_signature(self._independent_second_report()))

    def test_a_pdb_does_not_survive_an_architecture_switch_sequence(self):
        for kwargs in ({}, {"backend": "intel"}):
            with self.subTest(kwargs=kwargs):
                shared = Disassembler(**kwargs)
                shared.disassembleFile(self.first_pe, pdb_path=self.first_pdb)
                shared.disassembleFile(self.arm64_pe)
                second = shared.disassembleFile(self.second_pe)
                self.assertEqual(report_signature(second), report_signature(self._independent_second_report(**kwargs)))

    def test_a_failed_sample_does_not_leave_its_pdb_behind(self):
        shared = Disassembler(backend="intel")
        with mock.patch.object(
            RecursiveDisassembler, "_drainCandidateQueue", side_effect=RuntimeError("forced failure")
        ):
            failed = shared.disassembleFile(self.first_pe, pdb_path=self.first_pdb)
        self.assertEqual(failed.status, "error")
        second = shared.disassembleFile(self.second_pe)
        self.assertEqual(report_signature(second), report_signature(self._independent_second_report(backend="intel")))

    def test_a_pdb_supplied_with_each_call_still_applies(self):
        shared = Disassembler()
        for _ in range(2):
            report = shared.disassembleFile(self.first_pe, pdb_path=self.first_pdb)
            self.assertEqual(report.status, "ok")
            self.assertIn(PDB_SYMBOL, {f.function_name for f in report.getFunctions()})


if __name__ == "__main__":
    unittest.main()
