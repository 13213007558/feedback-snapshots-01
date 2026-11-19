import logging
import os
import struct
import tempfile
import unittest
from unittest import mock

from purepdb import Function, PdbInfo

from smda.common.BinaryInfo import BinaryInfo
from smda.common.labelprovider import PdbSymbolProvider as pdb_module
from smda.common.labelprovider.PdbSymbolProvider import (
    IDENTITY_MISMATCH,
    IDENTITY_NOT_LOADED,
    IDENTITY_UNVERIFIABLE,
    IDENTITY_VERIFIED,
    PDB_MAGIC,
    PdbSymbolProvider,
    _demangleSymbolName,
)
from smda.common.labelprovider.rust_demangler import demangle
from smda.common.labelprovider.rust_demangler.rust_legacy import UnableToLegacyDemangle
from smda.Disassembler import Disassembler
from smda.utility.PeDebugIdentity import PeSectionLayout

BASE_ADDR = 0x400000
FIXTURE_DIR = os.path.dirname(os.path.abspath(__file__))
PE_FIXTURE = os.path.join(FIXTURE_DIR, "rust_pe_msvc_i686_xored")
PDB_FIXTURE = os.path.join(FIXTURE_DIR, "rust_pe_msvc_i686_pdb_xored")
# entry point and code size of "main::digest" in the i686 fixture
DIGEST_RVA = 0x1000
DIGEST_CODE_SIZE = 299
TARGET_GUID = bytes(range(16))
FOREIGN_GUID = bytes(range(16, 32))
PDB_AGE = 1
# read out of real PDBs: the Rust names from a rust-lld/MSVC x64 image, the
# rest from sqlite3 x86/x64. The non-Rust names all begin with "_R", which is
# why the dispatch parses a name before it rewrites it
RUST_MAIN = "_RNvCs8JfRDQSkzJ8_15rust_pe_symbols4main"
RUST_MAIN_DEMANGLED = "rust_pe_symbols::main"
RUST_TRAIT_IMPL = "_RNvXs5_NtNtCslFVcyoAu48q_3std2io5errorNtB5_5ErrorNtNtCs55qC6OcLGgs_4core3fmt7Display3fmt"
RUST_TRAIT_IMPL_DEMANGLED = "<std::io::error::Error as core::fmt::Display>::fmt"
NOT_RUST = ("_RTC_Initialize", "_ReadFile@20", "_RoInitialize@4")
MSVC_PE_FIXTURE = os.path.join(FIXTURE_DIR, "msvc_cxx_pdb_pe_xored")
MSVC_PDB_FIXTURE = os.path.join(FIXTURE_DIR, "msvc_cxx_pdb_xored")
# the two translation units of the x64 fixture: one built with debug info, whose procedure
# records carry the name already undecorated, and one without, which contributes publics only
MSVC_PROC_NAME = "geometry::combine"
MSVC_PROC_RVA = 0x1000
MSVC_PUBLIC = "?measure@text@@YAHPEBDI@Z"
MSVC_PUBLIC_DEMANGLED = "int __cdecl text::measure(char const *, unsigned int)"
MSVC_PUBLIC_RVA = 0x1064
# shapes the demangler declines: a function-local name with no type, and a name truncated
# past its parameter list
MSVC_DECLINED = ("?x@?1??f@@YAHXZ@51", "?a2@@YAHX")
# a PDB carries one RTTI type descriptor per polymorphic class
MSVC_RTTI = "??_R0?AVexception@std@@@8"
MSVC_RTTI_DEMANGLED = "class std::exception `RTTI Type Descriptor'"
# a name scoped inside a function reads, which is what a PDB's statics and lambdas look like
MSVC_LOCAL_SCOPE = "?x@?1??f@@YAHXZ@4HA"
MSVC_LOCAL_SCOPE_DEMANGLED = "int `int __cdecl f(void)'::`2'::x"


def decode_fixture(path):
    with open(path, "rb") as fin:
        return bytes(byte ^ (index % 256) for index, byte in enumerate(fin.read()))


def strip_debug_directory(pe_data):
    """Zero the PE debug data-directory entry, producing a target that carries no
    CodeView identity while leaving its code and section layout untouched."""
    data = bytearray(pe_data)
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    optional_header = e_lfanew + 24
    magic = struct.unpack_from("<H", data, optional_header)[0]
    # IMAGE_DIRECTORY_ENTRY_DEBUG is data-directory index 6; directories start at
    # optional-header offset 96 (PE32) or 112 (PE32+)
    debug_entry = optional_header + (96 if magic == 0x10B else 112) + 6 * 8
    struct.pack_into("<II", data, debug_entry, 0, 0)
    return bytes(data)


class FakeDiagnostics:
    def __init__(self, warnings):
        self.warnings = warnings


class FakePdb:
    def __init__(self, functions, warnings=(), info=None, sections=None):
        self._functions = functions
        self._warnings = list(warnings)
        self._info = info or PdbInfo(version=20000404, signature=0, age=PDB_AGE, guid=TARGET_GUID)
        self._sections = sections if sections is not None else []

    def functions(self):
        return self._functions

    def info(self):
        return self._info

    @property
    def sections(self):
        return self._sections

    def diagnose(self):
        return FakeDiagnostics(self._warnings)


def make_function(name, rva, code_size=None, source="proc", module=None):
    return Function(
        name=name,
        segment=1,
        offset=rva,
        rva=rva,
        code_size=code_size,
        source=source,
        module=module,
    )


def make_section(name, rva, size, executable=True):
    section = mock.Mock()
    section.name = name
    section.virtual_address = rva
    section.virtual_size = size
    section.executable = executable
    return section


def make_binary_info(file_path, raw_data=b""):
    binary_info = BinaryInfo(b"")
    binary_info.raw_data = raw_data
    binary_info.file_path = file_path
    binary_info.base_addr = BASE_ADDR
    return binary_info


class FakeTarget:
    """A stand-in for the analyzed sample.

    ``identity`` is the CodeView record the target itself carries; None means the
    target has no identity evidence at all. ``sections`` are what its own headers say.
    """

    def __init__(self, identity=None, sections=None, file_path="sample.exe"):
        self.identity = identity
        self.sections = sections if sections is not None else [PeSectionLayout(".text", 0x1000, 0x1000, True)]
        self.file_path = file_path
        self.base_addr = BASE_ADDR

    def getLiefBinary(self):
        return object()


class PdbFragmentAttributionTestSuite(unittest.TestCase):
    def setUp(self):
        # several test modules call logging.disable() at import, which would make assertLogs
        # see no records depending on collection order; lift it for this class only
        previous_disable = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, previous_disable)

    def _providerWith(self, functions):
        provider = PdbSymbolProvider(None)
        provider._base_addr = BASE_ADDR
        # these tests exercise fragment attribution after a PDB has already been accepted,
        # so bind a target whose section spans every RVA the fixtures use
        provider.bindTargetBinary(FakeTarget(sections=[PeSectionLayout(".text", 0x1000, 0x2000, True)]))
        provider._parseSymbols(FakePdb(functions))
        return provider

    def test_an_undecorated_entry_point_is_reported_as_the_pdb_spells_it(self):
        provider = self._providerWith([make_function("_platform_seed", 0x1000, 0x40)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1000), "_platform_seed")
        self.assertEqual(provider.getFunctionSymbols(), {BASE_ADDR + 0x1000: "_platform_seed"})
        self.assertTrue(provider.is_active())

    def test_an_msvc_entry_point_is_reported_demangled(self):
        provider = self._providerWith([make_function(MSVC_PUBLIC, 0x1000, 0x40)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1000), MSVC_PUBLIC_DEMANGLED)

    def test_a_fragment_of_an_msvc_procedure_is_labelled_with_the_readable_name(self):
        provider = self._providerWith([make_function(MSVC_PUBLIC, 0x1000, 0x100)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1060), f"{MSVC_PUBLIC_DEMANGLED}$+0x60")

    def test_a_fragment_of_a_declined_msvc_procedure_keeps_the_decorated_parent(self):
        provider = self._providerWith([make_function("?a2@@YAHX", 0x1000, 0x100)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1060), "?a2@@YAHX$+0x60")

    def test_a_rust_entry_point_is_reported_demangled(self):
        provider = self._providerWith([make_function(RUST_MAIN, 0x1000, 0x40)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1000), RUST_MAIN_DEMANGLED)

    def test_a_fragment_of_a_rust_procedure_is_labelled_with_the_readable_name(self):
        provider = self._providerWith([make_function(RUST_MAIN, 0x1000, 0x100)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1060), f"{RUST_MAIN_DEMANGLED}$+0x60")

    def test_a_fragment_is_labelled_relative_to_its_containing_procedure(self):
        provider = self._providerWith([make_function("parent", 0x1000, 0x100)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1060), "parent$+0x60")

    def test_a_fragment_label_carries_no_virtual_address(self):
        provider = self._providerWith([make_function("parent", 0x1000, 0x100)])
        label = provider.getSymbol(BASE_ADDR + 0x1060)
        self.assertNotIn(f"{BASE_ADDR + 0x1060:x}", label)
        self.assertNotIn(f"{0x1060:x}", label)

    def test_a_fragment_label_is_independent_of_the_load_address(self):
        labels = []
        for base_addr in (0x400000, 0x10000000):
            provider = PdbSymbolProvider(None)
            provider._base_addr = base_addr
            provider._parseSymbols(FakePdb([make_function("parent", 0x1000, 0x100)]))
            labels.append(provider.getSymbol(base_addr + 0x1060))
        self.assertEqual(labels[0], labels[1])

    def test_an_address_beyond_every_procedure_stays_unnamed(self):
        provider = self._providerWith([make_function("parent", 0x1000, 0x100)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1100), "")

    def test_an_address_below_every_procedure_stays_unnamed(self):
        provider = self._providerWith([make_function("parent", 0x1000, 0x100)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x900), "")

    def test_a_fragment_is_attributed_to_the_nearest_enclosing_procedure(self):
        provider = self._providerWith([make_function("first", 0x1000, 0x100), make_function("second", 0x1100, 0x100)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1180), "second$+0x80")

    def test_an_import_thunk_never_becomes_a_fragment_parent(self):
        provider = self._providerWith(
            [
                make_function(
                    "_FlushFileBuffers@4",
                    0x1000,
                    0x100,
                    source="thunk",
                    module="Import:api-ms-win-core-file-l1-2-1.dll",
                )
            ]
        )
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1000), "_FlushFileBuffers@4")
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1060), "")

    def test_a_name_holding_a_control_character_is_skipped(self):
        provider = self._providerWith(
            [make_function("clean", 0x1000, 0x40), make_function("bell\x07name", 0x2000, 0x40)]
        )
        self.assertEqual(provider.getFunctionSymbols(), {BASE_ADDR + 0x1000: "clean"})
        # nor may it become a fragment parent, which would carry the byte into every label
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x2010), "")

    def test_a_non_ascii_name_is_kept(self):
        # a demangled Rust identifier is legitimately non-ASCII; only control bytes are refused
        provider = self._providerWith([make_function("hello::wörld", 0x1000, 0x40)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1000), "hello::wörld")

    def test_an_empty_name_is_skipped(self):
        provider = self._providerWith([make_function("", 0x1000, 0x40)])
        self.assertEqual(provider.getFunctionSymbols(), {})

    def test_a_procedure_without_a_resolvable_rva_is_skipped(self):
        unresolved = make_function("unresolved", 0x1000, 0x100)
        unresolved.rva = None
        provider = self._providerWith([unresolved])
        self.assertEqual(provider.getFunctionSymbols(), {})
        self.assertFalse(provider.is_active())

    def test_a_public_without_a_code_size_names_only_its_entry_point(self):
        provider = self._providerWith([make_function("stub", 0x1000, None, source="public")])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1000), "stub")
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1004), "")

    def _warnFor(self, functions, warnings=()):
        provider = PdbSymbolProvider(None)
        provider._base_addr = BASE_ADDR
        pdb = FakePdb(functions, warnings)
        provider._parseSymbols(pdb)
        with self.assertLogs("smda.common.labelprovider.PdbSymbolProvider", level=logging.WARNING) as logs:
            provider._warnAboutThinPdb("sample.pdb", pdb)
        return logs.output[0]

    def test_a_pdb_that_parses_but_resolves_no_address_warns(self):
        unresolved = make_function("unresolved", 0x1000, 0x100)
        unresolved.rva = None
        message = self._warnFor([unresolved], ["no section-header stream, every rva is None"])
        self.assertIn("no usable symbols", message)
        self.assertIn("no section-header stream", message)

    def test_a_pdb_without_procedure_records_warns_that_fragments_are_unavailable(self):
        message = self._warnFor([make_function("stub", 0x1000, None, source="public")])
        self.assertIn("no procedure records", message)

    def test_a_pdb_with_procedures_and_symbols_stays_quiet(self):
        provider = self._providerWith([make_function("parent", 0x1000, 0x100)])
        with self.assertNoLogs("smda.common.labelprovider.PdbSymbolProvider", level=logging.WARNING):
            provider._warnAboutThinPdb("sample.pdb", FakePdb([]))

    def test_the_provider_answers_symbols_but_not_apis(self):
        provider = PdbSymbolProvider(None)
        self.assertTrue(provider.isSymbolProvider())
        self.assertFalse(provider.isApiProvider())
        self.assertEqual(provider.getApi(0x1000), ("", ""))


class PdbUpdateTestSuite(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        # several test modules call logging.disable() at import, which would make assertLogs
        # see no records depending on collection order; lift it for this class only
        previous_disable = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, previous_disable)

    def _writeFixture(self, name, data):
        path = os.path.join(self.tempdir.name, name)
        with open(path, "wb") as fout:
            fout.write(data)
        return path

    def _targetInfo(self, pe_fixture=PE_FIXTURE):
        target_path = self._writeFixture("target.exe", decode_fixture(pe_fixture))
        target_info = make_binary_info(target_path)
        target_info.raw_data = decode_fixture(pe_fixture)
        return target_info

    def test_a_pdb_on_disk_is_parsed_into_symbols(self):
        pdb_path = self._writeFixture("sample.pdb", decode_fixture(PDB_FIXTURE))
        provider = PdbSymbolProvider(None)
        provider.bindTargetBinary(self._targetInfo())
        provider.update(make_binary_info(pdb_path))
        self.assertEqual(provider.identity_status, IDENTITY_VERIFIED)
        self.assertEqual(provider.getSymbol(BASE_ADDR + DIGEST_RVA), "main::digest")
        self.assertEqual(
            provider.getSymbol(BASE_ADDR + DIGEST_RVA + DIGEST_CODE_SIZE - 1),
            f"main::digest$+0x{DIGEST_CODE_SIZE - 1:x}",
        )
        self.assertEqual(provider.getSymbol(BASE_ADDR + DIGEST_RVA + DIGEST_CODE_SIZE), "")

    def test_a_pdb_already_in_memory_is_parsed_without_reading_the_file(self):
        provider = PdbSymbolProvider(None)
        provider.bindTargetBinary(self._targetInfo())
        provider.update(make_binary_info("sample.pdb", raw_data=decode_fixture(PDB_FIXTURE)))
        self.assertEqual(provider.identity_status, IDENTITY_VERIFIED)
        self.assertEqual(provider.getSymbol(BASE_ADDR + DIGEST_RVA), "main::digest")

    def test_a_target_without_a_file_path_yields_no_symbols(self):
        provider = PdbSymbolProvider(None)
        provider.update(make_binary_info(""))
        self.assertFalse(provider.is_active())

    def test_an_unreadable_file_path_yields_no_symbols(self):
        provider = PdbSymbolProvider(None)
        provider.update(make_binary_info(os.path.join(self.tempdir.name, "absent.pdb")))
        self.assertFalse(provider.is_active())

    def test_a_truncated_pdb_warns_instead_of_failing_silently(self):
        pdb_path = self._writeFixture("broken.pdb", decode_fixture(PDB_FIXTURE)[:512])
        provider = PdbSymbolProvider(None)
        with self.assertLogs("smda.common.labelprovider.PdbSymbolProvider", level=logging.WARNING) as logs:
            provider.update(make_binary_info(pdb_path))
        self.assertIn("Failed parsing PDB", logs.output[0])
        self.assertFalse(provider.is_active())

    def test_an_ignored_sidecar_pdb_warns_instead_of_failing_silently(self):
        self._writeFixture("sample.pdb", decode_fixture(PDB_FIXTURE))
        exe_path = self._writeFixture("sample.exe", decode_fixture(PE_FIXTURE))
        provider = PdbSymbolProvider(None)
        with self.assertLogs("smda.common.labelprovider.PdbSymbolProvider", level=logging.WARNING) as logs:
            provider.update(make_binary_info(exe_path))
        self.assertIn("sample.pdb", logs.output[0])

    def test_a_supplied_file_that_is_not_a_pdb_warns_instead_of_failing_silently(self):
        pdb_path = self._writeFixture("mistyped.pdb", b"MZ" + b"\x00" * 64)
        provider = PdbSymbolProvider(None)
        with self.assertLogs("smda.common.labelprovider.PdbSymbolProvider", level=logging.WARNING) as logs:
            provider.update(make_binary_info(pdb_path))
        self.assertIn("is not a PDB file", logs.output[0])

    def test_a_binary_without_a_sidecar_pdb_stays_quiet(self):
        exe_path = self._writeFixture("sample.exe", decode_fixture(PE_FIXTURE))
        provider = PdbSymbolProvider(None)
        with self.assertNoLogs("smda.common.labelprovider.PdbSymbolProvider", level=logging.WARNING):
            provider.update(make_binary_info(exe_path))

    def test_a_sidecar_pdb_that_was_supplied_explicitly_stays_quiet(self):
        pdb_path = self._writeFixture("sample.pdb", decode_fixture(PDB_FIXTURE))
        exe_path = self._writeFixture("sample.exe", decode_fixture(PE_FIXTURE))
        provider = PdbSymbolProvider(None)
        provider.bindTargetBinary(self._targetInfo())
        provider.update(make_binary_info(pdb_path))
        with self.assertNoLogs("smda.common.labelprovider.PdbSymbolProvider", level=logging.WARNING):
            provider.update(make_binary_info(exe_path))


class PdbReportIntegrationTestSuite(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.exe_path = os.path.join(self.tempdir.name, "sample.exe")
        self.pdb_path = os.path.join(self.tempdir.name, "sample.pdb")
        with open(self.exe_path, "wb") as fout:
            fout.write(decode_fixture(PE_FIXTURE))
        with open(self.pdb_path, "wb") as fout:
            fout.write(decode_fixture(PDB_FIXTURE))

    def _analyze(self, pdb_path):
        report = Disassembler(backend="intel").disassembleFile(self.exe_path, pdb_path=pdb_path)
        self.assertEqual(report.status, "ok")
        return {function.offset: function.function_name for function in report.getFunctions()}

    def test_a_supplied_pdb_names_the_functions_it_describes(self):
        named = {name for name in self._analyze(self.pdb_path).values() if name}
        self.assertIn("main::digest", named)
        self.assertIn("main::mainCRTStartup", named)

    def test_naming_is_reproducible_across_runs(self):
        self.assertEqual(self._analyze(self.pdb_path), self._analyze(self.pdb_path))

    def test_a_pe_analyzed_without_a_pdb_keeps_its_previous_naming(self):
        os.remove(self.pdb_path)
        named = {name for name in self._analyze("").values() if name}
        self.assertNotIn("main::digest", named)


class PdbIdentityGateTestSuite(unittest.TestCase):
    """Offline regression for the rule that a PDB may only label the sample whose own
    CodeView record asks for it. Everything here uses bundled fixtures or in-memory fakes,
    so no symbol server is contacted."""

    def setUp(self):
        previous_disable = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, previous_disable)

    def _provider(self, target, pdb, pdb_path="sample.pdb"):
        provider = PdbSymbolProvider(None)
        provider.bindTargetBinary(target)
        with (
            mock.patch.object(pdb_module, "extract_codeview_identity", side_effect=lambda bound: target.identity),
            mock.patch.object(pdb_module, "extract_section_layout", side_effect=lambda bound: target.sections),
            mock.patch.object(pdb_module.purepdb.PDB, "from_bytes", return_value=pdb),
        ):
            provider.update(make_binary_info(pdb_path, raw_data=PDB_MAGIC + b" rest"))
        return provider

    def test_a_matching_guid_and_age_verify_the_pairing(self):
        target = FakeTarget(
            identity=mock.Mock(guid=TARGET_GUID, age=PDB_AGE),
            sections=[PeSectionLayout(".text", 0x1000, 0x1000, True)],
        )
        pdb = FakePdb(
            [make_function("own_function", 0x1000, 0x40)],
            info=PdbInfo(20000404, 0, PDB_AGE, TARGET_GUID),
            sections=[make_section(".text", 0x1000, 0x1000)],
        )
        provider = self._provider(target, pdb)
        self.assertEqual(provider.identity_status, IDENTITY_VERIFIED)
        self.assertTrue(provider.is_active())
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1000), "own_function")

    def test_a_foreign_guid_is_rejected_however_readable_its_names_are(self):
        target = FakeTarget(
            identity=mock.Mock(guid=TARGET_GUID, age=PDB_AGE),
            sections=[PeSectionLayout(".text", 0x1000, 0x1000, True)],
        )
        pdb = FakePdb(
            [make_function("convincing_foreign_name", 0x1000, 0x40)],
            info=PdbInfo(20000404, 0, PDB_AGE, FOREIGN_GUID),
            sections=[make_section(".text", 0x1000, 0x1000)],
        )
        with self.assertLogs("smda.common.labelprovider.PdbSymbolProvider", level=logging.WARNING) as logs:
            provider = self._provider(target, pdb)
        self.assertEqual(provider.identity_status, IDENTITY_MISMATCH)
        self.assertFalse(provider.is_active())
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1000), "")
        self.assertIn("different PDB", logs.output[0])
        self.assertIn(FOREIGN_GUID.hex(), provider.identity_reason)

    def test_a_matching_guid_with_a_stale_age_is_rejected(self):
        target = FakeTarget(
            identity=mock.Mock(guid=TARGET_GUID, age=PDB_AGE),
            sections=[PeSectionLayout(".text", 0x1000, 0x1000, True)],
        )
        pdb = FakePdb(
            [make_function("stale_build", 0x1000, 0x40)],
            info=PdbInfo(20000404, 0, PDB_AGE + 1, TARGET_GUID),
            sections=[make_section(".text", 0x1000, 0x1000)],
        )
        provider = self._provider(target, pdb)
        self.assertEqual(provider.identity_status, IDENTITY_MISMATCH)
        self.assertFalse(provider.is_active())
        self.assertIn("age", provider.identity_reason)

    def test_a_target_without_identity_evidence_keeps_the_pdb_unverifiable(self):
        # the target cannot speak for itself: no CodeView record, only the caller's word
        target = FakeTarget(
            identity=None,
            sections=[PeSectionLayout(".text", 0x1000, 0x1000, True)],
        )
        pdb = FakePdb(
            [make_function("unverified_claim", 0x1000, 0x40)],
            info=PdbInfo(20000404, 0, PDB_AGE, TARGET_GUID),
            sections=[make_section(".text", 0x1000, 0x1000)],
        )
        with self.assertLogs("smda.common.labelprovider.PdbSymbolProvider", level=logging.WARNING) as logs:
            provider = self._provider(target, pdb)
        self.assertEqual(provider.identity_status, IDENTITY_UNVERIFIABLE)
        self.assertFalse(provider.is_active())
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1000), "")
        self.assertIn("no CodeView identity record", logs.output[0])

    def test_an_unbound_provider_never_treats_a_pdb_as_evidence(self):
        pdb = FakePdb([make_function("orphan", 0x1000, 0x40)])
        provider = PdbSymbolProvider(None)
        with (
            mock.patch.object(pdb_module.purepdb.PDB, "from_bytes", return_value=pdb),
            self.assertLogs("smda.common.labelprovider.PdbSymbolProvider", level=logging.WARNING) as logs,
        ):
            provider.update(make_binary_info("sample.pdb", raw_data=PDB_MAGIC + b" rest"))
        self.assertEqual(provider.identity_status, IDENTITY_UNVERIFIABLE)
        self.assertFalse(provider.is_active())
        self.assertIn("no target binary is bound", logs.output[0])

    def test_a_matching_pdb_file_name_is_only_a_claim_and_never_verifies(self):
        # the target's CodeView record names a path that happens to equal the supplied file,
        # but its GUID still belongs to another build: the readable name must not be accepted
        target = FakeTarget(
            identity=mock.Mock(guid=TARGET_GUID, age=PDB_AGE, pdb_path="sample.pdb"),
            sections=[PeSectionLayout(".text", 0x1000, 0x1000, True)],
        )
        pdb = FakePdb(
            [make_function("named_like_the_right_one", 0x1000, 0x40)],
            info=PdbInfo(20000404, 0, PDB_AGE, FOREIGN_GUID),
            sections=[make_section(".text", 0x1000, 0x1000)],
        )
        provider = self._provider(target, pdb, pdb_path="sample.pdb")
        self.assertEqual(provider.identity_status, IDENTITY_MISMATCH)
        self.assertFalse(provider.is_active())
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1000), "")

    def test_a_section_address_mismatch_rejects_an_otherwise_matching_pdb(self):
        target = FakeTarget(
            identity=mock.Mock(guid=TARGET_GUID, age=PDB_AGE),
            sections=[PeSectionLayout(".text", 0x2000, 0x1000, True)],
        )
        pdb = FakePdb(
            [make_function("mapped_elsewhere", 0x1000, 0x40)],
            info=PdbInfo(20000404, 0, PDB_AGE, TARGET_GUID),
            sections=[make_section(".text", 0x1000, 0x1000)],
        )
        with self.assertLogs("smda.common.labelprovider.PdbSymbolProvider", level=logging.WARNING) as logs:
            provider = self._provider(target, pdb)
        self.assertEqual(provider.identity_status, IDENTITY_MISMATCH)
        self.assertFalse(provider.is_active())
        self.assertIn("RVA", provider.identity_reason)
        self.assertIn("section", logs.output[0])

    def test_a_section_size_mismatch_is_reported_as_the_reason(self):
        target = FakeTarget(
            identity=mock.Mock(guid=TARGET_GUID, age=PDB_AGE),
            sections=[PeSectionLayout(".text", 0x1000, 0x800, True)],
        )
        pdb = FakePdb(
            [make_function("grown_function", 0x1000, 0x40)],
            info=PdbInfo(20000404, 0, PDB_AGE, TARGET_GUID),
            sections=[make_section(".text", 0x1000, 0x1000)],
        )
        provider = self._provider(target, pdb)
        self.assertEqual(provider.identity_status, IDENTITY_MISMATCH)
        self.assertIn("size", provider.identity_reason)

    def test_a_section_count_mismatch_keeps_the_pairing_pending(self):
        target = FakeTarget(
            identity=mock.Mock(guid=TARGET_GUID, age=PDB_AGE),
            sections=[
                PeSectionLayout(".text", 0x1000, 0x1000, True),
                PeSectionLayout(".rdata", 0x2000, 0x1000, False),
            ],
        )
        pdb = FakePdb(
            [make_function("one_section_build", 0x1000, 0x40)],
            info=PdbInfo(20000404, 0, PDB_AGE, TARGET_GUID),
            sections=[make_section(".text", 0x1000, 0x1000)],
        )
        provider = self._provider(target, pdb)
        self.assertEqual(provider.identity_status, IDENTITY_MISMATCH)
        self.assertIn("section count differs", provider.identity_reason)

    def test_a_symbol_outside_every_target_section_is_withheld(self):
        # identical section tables, so the PDB verifies; the symbol nonetheless lands at an RVA
        # no target section spans, which is the function-range/section evidence gap handled per symbol
        target = FakeTarget(
            identity=mock.Mock(guid=TARGET_GUID, age=PDB_AGE),
            sections=[
                PeSectionLayout(".text", 0x1000, 0x1000, True),
                PeSectionLayout(".data", 0x4000, 0x1000, False),
            ],
        )
        pdb = FakePdb(
            [
                make_function("inside", 0x1000, 0x40),
                make_function("beyond_image", 0x8000, 0x40),
            ],
            info=PdbInfo(20000404, 0, PDB_AGE, TARGET_GUID),
            sections=[
                make_section(".text", 0x1000, 0x1000),
                make_section(".data", 0x4000, 0x1000, executable=False),
            ],
        )
        with self.assertLogs("smda.common.labelprovider.PdbSymbolProvider", level=logging.WARNING) as logs:
            provider = self._provider(target, pdb)
        self.assertEqual(provider.identity_status, IDENTITY_VERIFIED)
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1000), "inside")
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x8000), "")
        self.assertTrue(any("outside the target" in line for line in logs.output))

    def test_relocation_to_a_different_base_keeps_rva_relative_labels(self):
        # changing the load address slides every VA by the same delta; RVA-relative PDB
        # resolution must follow it instead of reading the move as a mismatch
        target = FakeTarget(
            identity=mock.Mock(guid=TARGET_GUID, age=PDB_AGE),
            sections=[PeSectionLayout(".text", 0x1000, 0x1000, True)],
        )
        target.base_addr = 0x10000000
        pdb = FakePdb(
            [make_function("relocated", 0x1000, 0x100)],
            info=PdbInfo(20000404, 0, PDB_AGE, TARGET_GUID),
            sections=[make_section(".text", 0x1000, 0x1000)],
        )
        pdb_info = make_binary_info("sample.pdb", raw_data=PDB_MAGIC + b" rest")
        pdb_info.base_addr = target.base_addr
        provider = PdbSymbolProvider(None)
        provider.bindTargetBinary(target)
        with (
            mock.patch.object(pdb_module, "extract_codeview_identity", side_effect=lambda bound: target.identity),
            mock.patch.object(pdb_module, "extract_section_layout", side_effect=lambda bound: target.sections),
            mock.patch.object(pdb_module.purepdb.PDB, "from_bytes", return_value=pdb),
        ):
            provider.update(pdb_info)
        self.assertEqual(provider.identity_status, IDENTITY_VERIFIED)
        self.assertEqual(provider.getSymbol(0x10000000 + 0x1000), "relocated")
        self.assertEqual(provider.getSymbol(0x10000000 + 0x1060), "relocated$+0x60")

    def test_rejection_is_queryable_through_the_status_not_only_the_log(self):
        target = FakeTarget(identity=mock.Mock(guid=TARGET_GUID, age=PDB_AGE))
        pdb = FakePdb(
            [make_function("foreign", 0x1000)],
            info=PdbInfo(20000404, 0, PDB_AGE, FOREIGN_GUID),
            sections=[make_section(".text", 0x1000, 0x1000)],
        )
        provider = self._provider(target, pdb)
        self.assertEqual(provider.identity_status, IDENTITY_MISMATCH)
        self.assertTrue(provider.identity_reason)
        # a later, correct update must clear the stale rejection
        good_pdb = FakePdb(
            [make_function("own", 0x1000)],
            info=PdbInfo(20000404, 0, PDB_AGE, TARGET_GUID),
            sections=[make_section(".text", 0x1000, 0x1000)],
        )
        with (
            mock.patch.object(pdb_module, "extract_codeview_identity", side_effect=lambda bound: target.identity),
            mock.patch.object(pdb_module, "extract_section_layout", side_effect=lambda bound: target.sections),
            mock.patch.object(pdb_module.purepdb.PDB, "from_bytes", return_value=good_pdb),
        ):
            provider.update(make_binary_info("good.pdb", raw_data=PDB_MAGIC + b" rest"))
        self.assertEqual(provider.identity_status, IDENTITY_VERIFIED)
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1000), "own")

    def test_a_fresh_provider_starts_in_the_not_loaded_state(self):
        provider = PdbSymbolProvider(None)
        self.assertEqual(provider.identity_status, IDENTITY_NOT_LOADED)
        self.assertEqual(provider.identity_reason, "")
        self.assertFalse(provider.is_active())


class PdbRealFixtureIdentityTestSuite(unittest.TestCase):
    """The same PDB paired with its own build and with a foreign target, end to end."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        previous_disable = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, previous_disable)

    def _write(self, name, data):
        path = os.path.join(self.tempdir.name, name)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def _providerFor(self, pe_fixture, pdb_fixture):
        pe_data = decode_fixture(pe_fixture)
        pdb_data = decode_fixture(pdb_fixture)
        target_info = make_binary_info(self._write("target.exe", pe_data))
        target_info.raw_data = pe_data
        provider = PdbSymbolProvider(None)
        provider.bindTargetBinary(target_info)
        provider.update(make_binary_info(self._write("candidate.pdb", pdb_data)))
        return provider

    def test_each_bundled_pdb_verifies_against_its_own_pe(self):
        for pe_fixture, pdb_fixture in (
            (PE_FIXTURE, PDB_FIXTURE),
            (MSVC_PE_FIXTURE, MSVC_PDB_FIXTURE),
        ):
            with self.subTest(pair=os.path.basename(pdb_fixture)):
                provider = self._providerFor(pe_fixture, pdb_fixture)
                self.assertEqual(provider.identity_status, IDENTITY_VERIFIED)
                self.assertTrue(provider.is_active())

    def test_a_pdb_built_for_another_sample_is_rejected_for_this_target(self):
        with self.assertLogs("smda.common.labelprovider.PdbSymbolProvider", level=logging.WARNING):
            provider = self._providerFor(PE_FIXTURE, MSVC_PDB_FIXTURE)
        self.assertEqual(provider.identity_status, IDENTITY_MISMATCH)
        self.assertFalse(provider.is_active())
        self.assertEqual(provider.getFunctionSymbols(), {})

    def test_a_foreign_pdb_leaves_the_report_with_the_sample_own_labels(self):
        own_exe = self._write("sample.exe", decode_fixture(PE_FIXTURE))
        own_pdb = self._write("own.pdb", decode_fixture(PDB_FIXTURE))
        foreign_pdb = self._write("foreign.pdb", decode_fixture(MSVC_PDB_FIXTURE))
        labels_with_own = {
            function.offset: function.function_name
            for function in Disassembler(backend="intel").disassembleFile(own_exe, pdb_path=own_pdb).getFunctions()
        }
        labels_with_foreign = {
            function.offset: function.function_name
            for function in Disassembler(backend="intel").disassembleFile(own_exe, pdb_path=foreign_pdb).getFunctions()
        }
        labels_without_pdb = {
            function.offset: function.function_name
            for function in Disassembler(backend="intel").disassembleFile(own_exe, pdb_path="").getFunctions()
        }
        self.assertIn("main::digest", labels_with_own.values())
        # the foreign PDB contributes nothing: labels are exactly those the sample earns on its own
        self.assertNotIn("main::digest", labels_with_foreign.values())
        self.assertEqual(labels_with_foreign, labels_without_pdb)
        # and where both label an address, the foreign PDB's readable name never overrode the sample's
        for offset, sample_name in labels_without_pdb.items():
            if sample_name:
                self.assertEqual(labels_with_foreign.get(offset), sample_name)

    def test_a_target_without_codeview_evidence_keeps_a_matching_pdb_unapplied(self):
        # even a PDB that is the right one cannot be confirmed once the target's own evidence
        # is gone, so its readable names must still stay off the sample
        pe_data = strip_debug_directory(decode_fixture(PE_FIXTURE))
        exe_path = self._write("stripped.exe", pe_data)
        pdb_path = self._write("candidate.pdb", decode_fixture(PDB_FIXTURE))
        target_info = make_binary_info(exe_path)
        target_info.raw_data = pe_data
        provider = PdbSymbolProvider(None)
        provider.bindTargetBinary(target_info)
        with self.assertLogs("smda.common.labelprovider.PdbSymbolProvider", level=logging.WARNING) as logs:
            provider.update(make_binary_info(pdb_path))
        self.assertEqual(provider.identity_status, IDENTITY_UNVERIFIABLE)
        self.assertIn("no CodeView identity record", logs.output[0])
        self.assertFalse(provider.is_active())
        report = Disassembler(backend="intel").disassembleFile(exe_path, pdb_path=pdb_path)
        self.assertEqual(report.status, "ok")
        self.assertNotIn("main::digest", {function.function_name for function in report.getFunctions()})


class PdbSymbolDemanglingTestSuite(unittest.TestCase):
    def test_rust_v0_names_are_demangled(self):
        self.assertEqual(_demangleSymbolName(RUST_MAIN), RUST_MAIN_DEMANGLED)
        self.assertEqual(_demangleSymbolName(RUST_TRAIT_IMPL), RUST_TRAIT_IMPL_DEMANGLED)

    def test_names_that_only_look_rust_are_left_alone(self):
        for name in NOT_RUST:
            self.assertEqual(_demangleSymbolName(name), name)

    def test_a_cxx_itanium_name_without_a_rust_hash_is_not_claimed(self):
        self.assertEqual(_demangleSymbolName("_ZN4test4funcEv"), "_ZN4test4funcEv")

    def test_a_legacy_name_that_is_only_a_hash_keeps_its_original_spelling(self):
        # nothing is left to spell once the hash is dropped, so the name is refused
        name = "_ZN17h0000000000000000E"
        self.assertRaises(UnableToLegacyDemangle, demangle, name)
        self.assertEqual(_demangleSymbolName(name), name)

    def test_an_msvc_decorated_name_is_demangled(self):
        self.assertEqual(_demangleSymbolName(MSVC_PUBLIC), MSVC_PUBLIC_DEMANGLED)
        self.assertEqual(_demangleSymbolName("?mangled@@YAXXZ"), "void __cdecl mangled(void)")

    def test_an_msvc_name_the_demangler_declines_keeps_its_decorated_spelling(self):
        for name in MSVC_DECLINED:
            self.assertEqual(_demangleSymbolName(name), name)

    def test_an_rtti_type_descriptor_is_demangled(self):
        self.assertEqual(_demangleSymbolName(MSVC_RTTI), MSVC_RTTI_DEMANGLED)

    def test_a_name_scoped_inside_a_function_is_demangled(self):
        # a PDB carries these by the hundred: every function-local static and lambda
        self.assertEqual(_demangleSymbolName(MSVC_LOCAL_SCOPE), MSVC_LOCAL_SCOPE_DEMANGLED)

    def test_a_name_that_only_looks_msvc_is_left_alone(self):
        for name in ("?", "?????", "?not a symbol"):
            self.assertEqual(_demangleSymbolName(name), name)

    def test_an_unexpected_demangler_failure_keeps_the_original_name(self):
        with mock.patch.object(pdb_module, "is_rust_language_evidence", side_effect=RecursionError):
            self.assertEqual(_demangleSymbolName(RUST_MAIN), RUST_MAIN)

    def test_an_operational_exception_still_propagates(self):
        with mock.patch.object(pdb_module, "is_rust_language_evidence", side_effect=MemoryError):
            self.assertRaises(MemoryError, _demangleSymbolName, RUST_MAIN)

    def test_one_undemanglable_name_does_not_cost_the_other_symbols(self):
        provider = PdbSymbolProvider(None)
        provider._base_addr = BASE_ADDR
        functions = [make_function(RUST_MAIN, 0x1000, 0x40), make_function(RUST_MAIN, 0x2000, 0x40)]
        with mock.patch.object(pdb_module, "is_rust_language_evidence", side_effect=RecursionError):
            provider._parseSymbols(FakePdb(functions))
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1000), RUST_MAIN)
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x2000), RUST_MAIN)


class MsvcPdbFixtureTestSuite(unittest.TestCase):
    """The x64 fixture pair is a clang-cl/lld-link DLL built from two translation units, one
    compiled with /Z7 and one without, so the PDB carries both name shapes a real MSVC build
    produces: procedure records that already spell the name, and decorated publics."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.exe_path = os.path.join(self.tempdir.name, "sample.exe")
        self.pdb_path = os.path.join(self.tempdir.name, "sample.pdb")
        for path, fixture in ((self.exe_path, MSVC_PE_FIXTURE), (self.pdb_path, MSVC_PDB_FIXTURE)):
            with open(path, "wb") as fout:
                fout.write(decode_fixture(fixture))

    def _provider(self):
        provider = PdbSymbolProvider(None)
        target_info = make_binary_info(self.exe_path)
        target_info.raw_data = decode_fixture(MSVC_PE_FIXTURE)
        provider.bindTargetBinary(target_info)
        provider.update(make_binary_info(self.pdb_path))
        return provider

    def test_a_decorated_public_is_reported_as_a_signature(self):
        self.assertEqual(self._provider().getSymbol(BASE_ADDR + MSVC_PUBLIC_RVA), MSVC_PUBLIC_DEMANGLED)

    def test_a_procedure_record_name_is_reported_as_the_pdb_spells_it(self):
        self.assertEqual(self._provider().getSymbol(BASE_ADDR + MSVC_PROC_RVA), MSVC_PROC_NAME)

    def test_no_reported_name_stays_decorated(self):
        names = self._provider().getFunctionSymbols().values()
        self.assertTrue(names)
        self.assertEqual([name for name in names if name.startswith("?")], [])

    def test_a_supplied_pdb_names_the_functions_it_describes(self):
        report = Disassembler(backend="intel").disassembleFile(self.exe_path, pdb_path=self.pdb_path)
        self.assertEqual(report.status, "ok")
        named = {function.function_name for function in report.getFunctions()}
        self.assertIn(MSVC_PUBLIC_DEMANGLED, named)
        self.assertIn(MSVC_PROC_NAME, named)


if __name__ == "__main__":
    unittest.main()
