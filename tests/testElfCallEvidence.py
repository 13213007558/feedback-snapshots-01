"""Evidence and conflict handling for ELF external-call identities.

The fixture ``elf_same_symbol_two_versions_x64_xored`` is a self-contained ELF64 image
built with one PLT entry per case, no dynamic linker involved:

* ``0x1000`` calls a PLT entry whose GOT slot carries two relocations for the *same* base
  name at two different versions (``memcpy@GLIBC_2.2.5`` and ``memcpy@GLIBC_2.14``);
* ``0x1005`` calls an entry with exactly one versioned relocation;
* ``0x100a`` calls an entry whose relocation names ``puts`` while the slot still holds zero;
* ``0x100f`` calls an entry whose slot has no relocation at all.

The point is that a name alone cannot describe any of these: the version, the relocation and
the observed slot state are separate facts.
"""

import os
import unittest
from types import SimpleNamespace

from smda.common.labelprovider import import_parsers
from smda.common.labelprovider.ElfCallEvidence import (
    BINDING_BOUND,
    BINDING_LAZY,
    BINDING_UNBOUND,
    BINDING_UNOBSERVED,
    GOT_SLOT,
    HEURISTIC,
    RELOCATION,
    STATE_CONFIRMED,
    STATE_CONFLICTED,
    STATE_DECLARED,
    STATE_UNKNOWN,
    TARGET_PLT_STUB,
    TARGET_SLOT,
    ElfCallEvidence,
    ElfCallEvidenceTable,
    ElfCallSiteEvidence,
)
from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

FIXTURE = "elf_same_symbol_two_versions_x64_xored"

CONFLICT_CALL = 0x1000
SINGLE_VERSION_CALL = 0x1005
UNBOUND_SLOT_CALL = 0x100A
NO_RELOCATION_CALL = 0x100F

CONFLICT_SLOT = 0x1208
SINGLE_VERSION_SLOT = 0x1210
UNBOUND_SLOT = 0x1218


def _load_fixture():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), FIXTURE)
    with open(path, "rb") as handle:
        return bytes(byte ^ (index % 256) for index, byte in enumerate(handle.read()))


def _analysis():
    config = SmdaConfig()
    config.WITH_STRINGS = False
    return Disassembler(config).disassembleUnmappedBuffer(_load_fixture())


class TestCallEvidenceModel(unittest.TestCase):
    """The model keeps identities apart; nothing picks a winner."""

    def test_same_name_at_two_versions_is_a_conflict(self):
        old = ElfCallEvidence(RELOCATION, "memcpy", version="GLIBC_2.2.5", weak=False, slot=CONFLICT_SLOT)
        new = ElfCallEvidence(RELOCATION, "memcpy", version="GLIBC_2.14", weak=False, slot=CONFLICT_SLOT)
        site = ElfCallSiteEvidence(CONFLICT_CALL, slot=CONFLICT_SLOT, claims=[old, new])

        self.assertTrue(site.has_conflict())
        self.assertEqual(site.identity_state(), STATE_CONFLICTED)
        self.assertIsNone(site.display_name())
        self.assertFalse(site.is_confirmed())

    def test_merging_by_base_name_is_not_a_resolution(self):
        old = ElfCallEvidence(RELOCATION, "memcpy", version="GLIBC_2.2.5", weak=False)
        new = ElfCallEvidence(RELOCATION, "memcpy", version="GLIBC_2.14", weak=False)
        site = ElfCallSiteEvidence(1, claims=[old, new])

        # one base name, two identities: a consumer that compares names alone would call this
        # agreement, which is exactly the merge the versions exist to prevent
        self.assertEqual({claim.name for claim in site.claims}, {"memcpy"})
        self.assertEqual(len(site.identities()), 2)
        self.assertTrue(site.has_conflict())

    def test_a_bare_name_does_not_conflict_with_a_versioned_one(self):
        versioned = ElfCallEvidence(RELOCATION, "memcpy", version="GLIBC_2.14", weak=False)
        guess = ElfCallEvidence(HEURISTIC, "memcpy")
        site = ElfCallSiteEvidence(1, claims=[versioned, guess])

        self.assertFalse(site.has_conflict())
        # the heuristic claim carries no identity on its own, so the version is what is shown
        self.assertEqual(site.identity_state(), STATE_DECLARED)
        self.assertEqual(site.display_name(), "memcpy@GLIBC_2.14")

    def test_different_names_conflict_even_without_versions(self):
        site = ElfCallSiteEvidence(
            1,
            claims=[
                ElfCallEvidence(RELOCATION, "malloc", version="GLIBC_2.2.5", weak=False),
                ElfCallEvidence(RELOCATION, "calloc", version="GLIBC_2.2.5", weak=False),
            ],
        )
        self.assertTrue(site.has_conflict())
        self.assertIsNone(site.display_name())

    def test_weak_declaration_alone_is_not_a_resolution(self):
        weak = ElfCallEvidence(RELOCATION, "__cxa_finalize", version="GLIBC_2.2.5", weak=True)
        site = ElfCallSiteEvidence(1, slot=CONFLICT_SLOT, binding=BINDING_UNBOUND, claims=[weak])

        self.assertFalse(site.is_confirmed())
        self.assertEqual(site.identity_state(), STATE_UNKNOWN)
        self.assertIsNone(site.display_name())

    def test_strong_declaration_on_an_unbound_slot_stays_a_declaration(self):
        strong = ElfCallEvidence(RELOCATION, "puts", version="GLIBC_2.2.5", weak=False)
        for binding in (BINDING_UNBOUND, BINDING_LAZY):
            with self.subTest(binding=binding):
                site = ElfCallSiteEvidence(1, slot=1, binding=binding, claims=[strong])
                self.assertEqual(site.identity_state(), STATE_DECLARED)
                self.assertNotEqual(site.identity_state(), STATE_CONFIRMED)

    def test_a_bound_slot_confirms_the_declaration(self):
        strong = ElfCallEvidence(RELOCATION, "puts", version="GLIBC_2.2.5", weak=False)
        observed = ElfCallEvidence(GOT_SLOT, "puts", version="GLIBC_2.2.5", slot=1, binding=BINDING_BOUND)
        site = ElfCallSiteEvidence(1, slot=1, binding=BINDING_BOUND, claims=[strong, observed])

        self.assertEqual(site.identity_state(), STATE_CONFIRMED)
        self.assertTrue(site.is_confirmed())

    def test_an_unobserved_slot_yields_no_name(self):
        site = ElfCallSiteEvidence(1, slot=1, binding=BINDING_UNOBSERVED, claims=[])
        self.assertEqual(site.identity_state(), STATE_UNKNOWN)
        self.assertIsNone(site.display_name())

    def test_conflict_groups_name_the_claim_kinds(self):
        site = ElfCallSiteEvidence(
            1,
            claims=[
                ElfCallEvidence(RELOCATION, "memcpy", version="GLIBC_2.2.5", weak=False),
                ElfCallEvidence(RELOCATION, "memcpy", version="GLIBC_2.14", weak=False),
            ],
        )
        groups = site.conflict_identities()
        self.assertEqual(
            [(entry["version"], entry["evidence_kinds"]) for entry in groups],
            [("GLIBC_2.14", ["relocation"]), ("GLIBC_2.2.5", ["relocation"])],
        )


class TestApiResolverConflicts(unittest.TestCase):
    """The resolver must not answer for a slot whose own relocations disagree."""

    @classmethod
    def setUpClass(cls):
        import lief

        from smda.common.labelprovider.ElfApiResolver import ElfApiResolver

        cls.lief_binary = lief.parse(list(_load_fixture()))
        resolver = ElfApiResolver(None)
        resolver.update(SimpleNamespace(getLiefBinary=lambda: cls.lief_binary))
        cls.resolver = resolver

    def test_a_slot_with_two_versions_resolves_to_nothing(self):
        self.assertEqual(self.resolver.getApi(CONFLICT_SLOT), (None, None))

    def test_a_single_version_still_resolves(self):
        self.assertEqual(self.resolver.getApi(SINGLE_VERSION_SLOT), ("GLIBC_2.14", "memcpy"))

    def test_the_structured_claims_remain_available(self):
        claims = self.resolver.getRelocationEvidence(CONFLICT_SLOT)
        self.assertEqual({claim.version for claim in claims}, {"GLIBC_2.2.5", "GLIBC_2.14"})


class TestRelocationEvidenceParsing(unittest.TestCase):
    """The static parser keeps the version and the weakness beside the name."""

    @classmethod
    def setUpClass(cls):
        import lief

        cls.lief_binary = lief.parse(list(_load_fixture()))

    def test_claims_carry_the_version_out_of_the_version_need_table(self):
        evidence = import_parsers.parse_elf_relocation_evidence(self.lief_binary)
        versions = {(claim.name, claim.version) for claim in evidence[CONFLICT_SLOT]}
        self.assertEqual(
            versions,
            {("memcpy", "GLIBC_2.2.5"), ("memcpy", "GLIBC_2.14")},
        )

    def test_a_conflicted_slot_is_left_out_of_the_two_tuple_import_map(self):
        # the map can hold one (lib, name) per slot; writing either one down would be a pick
        imports = import_parsers.parse_elf_relocation_imports(self.lief_binary)
        self.assertNotIn(CONFLICT_SLOT, imports)
        self.assertEqual(imports[SINGLE_VERSION_SLOT], ("GLIBC_2.14", "memcpy"))

    def test_relocation_type_is_kept_as_detail(self):
        evidence = import_parsers.parse_elf_relocation_evidence(self.lief_binary)
        self.assertTrue(all("JUMP_SLOT" in claim.detail for claim in evidence[CONFLICT_SLOT]))


class TestReportedEvidence(unittest.TestCase):
    """A full analysis puts the evidence in the report and never resolves a conflict."""

    @classmethod
    def setUpClass(cls):
        cls.report = _analysis()
        cls.evidence = cls.report.xmetadata["external_call_evidence"]

    def _site(self, call_addr):
        return self.evidence[str(call_addr)]

    def test_both_versions_are_reported_for_the_disputed_call(self):
        site = self._site(CONFLICT_CALL)
        self.assertTrue(site["conflict"])
        self.assertEqual(site["identity_state"], STATE_CONFLICTED)
        self.assertEqual(
            {(claim["name"], claim["version"]) for claim in site["claims"]},
            {("memcpy", "GLIBC_2.2.5"), ("memcpy", "GLIBC_2.14")},
        )
        self.assertIsNone(site["resolved_name"])

    def test_the_call_records_the_stub_it_targeted_and_the_slot_it_read(self):
        site = self._site(CONFLICT_CALL)
        self.assertEqual(site["target_kind"], TARGET_PLT_STUB)
        self.assertEqual(site["target_addr"], 0x1100)
        self.assertEqual(site["slot"], CONFLICT_SLOT)
        self.assertEqual(site["evidence_kinds"], ["relocation"])

    def test_a_single_versioned_slot_is_declared_not_confirmed(self):
        site = self._site(SINGLE_VERSION_CALL)
        self.assertFalse(site["conflict"])
        self.assertEqual(site["identity_state"], STATE_DECLARED)
        self.assertEqual(site["resolved_name"], "memcpy@GLIBC_2.14")

    def test_an_unbound_got_slot_keeps_its_declaration_but_not_a_confirmation(self):
        site = self._site(UNBOUND_SLOT_CALL)
        self.assertEqual(site["slot"], UNBOUND_SLOT)
        self.assertEqual(site["binding"], BINDING_UNBOUND)
        self.assertEqual(site["identity_state"], STATE_DECLARED)
        self.assertEqual(site["evidence_kinds"], ["relocation"])

    def test_a_slot_without_any_relocation_stays_unknown(self):
        site = self._site(NO_RELOCATION_CALL)
        self.assertEqual(site["identity_state"], STATE_UNKNOWN)
        self.assertEqual(site["evidence_kinds"], [])
        self.assertIsNone(site["resolved_name"])

    def test_the_display_view_does_not_pick_between_versions(self):
        api_names = {name for function in self.report.getFunctions() for name in function.apirefs.values()}
        self.assertNotIn("memcpy@GLIBC_2.2.5", api_names)
        # the disputed call is simply absent from the display map
        conflicted_function = self.report.getFunction(CONFLICT_CALL)
        self.assertNotIn(CONFLICT_CALL, conflicted_function.apirefs)

    def test_conflicting_slot_is_absent_from_the_static_import_map(self):
        imported = self.report.xmetadata["imported_functions"] or {}
        self.assertNotIn(CONFLICT_SLOT, imported)
        self.assertEqual(imported[SINGLE_VERSION_SLOT], ("GLIBC_2.14", "memcpy"))

    def test_evidence_survives_report_round_trip(self):
        restored = SmdaReport.fromDict(self.report.toDict())
        self.assertEqual(restored.xmetadata["external_call_evidence"], self.evidence)
        site = restored.xmetadata["external_call_evidence"][str(CONFLICT_CALL)]
        self.assertTrue(site["conflict"])
        self.assertIsNone(site["resolved_name"])

    def test_round_trip_twice_is_byte_identical(self):
        once = SmdaReport.fromDict(self.report.toDict()).toDict()
        twice = SmdaReport.fromDict(once).toDict()
        self.assertEqual(once["xmetadata"]["external_call_evidence"], twice["xmetadata"]["external_call_evidence"])


class TestObservedSlotState(unittest.TestCase):
    """Real loaded ELF images: a lazy PLT slot is declared, not confirmed."""

    def _load(self, name):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
        with open(path, "rb") as handle:
            return bytes(byte ^ (index % 256) for index, byte in enumerate(handle.read()))

    def test_a_lazy_plt_slot_is_reported_as_declared(self):
        config = SmdaConfig()
        config.WITH_STRINGS = False
        report = Disassembler(config).disassembleUnmappedBuffer(self._load("elf_cet_landing_pads_x64_xored"))
        evidence = report.xmetadata["external_call_evidence"]
        printf_sites = [site for site in evidence.values() if any(c["name"] == "__printf_chk" for c in site["claims"])]
        self.assertTrue(printf_sites)
        for site in printf_sites:
            self.assertIn(site["binding"], (BINDING_LAZY, BINDING_UNBOUND))
            self.assertNotEqual(site["identity_state"], STATE_CONFIRMED)
            self.assertIn("relocation", site["evidence_kinds"])


class TestEvidenceTableSerialization(unittest.TestCase):
    def test_round_trip_preserves_conflicts(self):
        site = ElfCallSiteEvidence(
            0x10,
            target_addr=0x20,
            slot=0x30,
            target_kind=TARGET_SLOT,
            claims=[
                ElfCallEvidence(RELOCATION, "memcpy", version="GLIBC_2.2.5", weak=False, slot=0x30),
                ElfCallEvidence(RELOCATION, "memcpy", version="GLIBC_2.14", weak=False, slot=0x30),
            ],
        )
        table = ElfCallEvidenceTable([site])
        restored = ElfCallEvidenceTable.fromDict(table.toDict())
        restored_site = restored.get(0x10)
        self.assertIsNotNone(restored_site)
        self.assertTrue(restored_site.has_conflict())
        self.assertEqual(restored_site.toDict(), site.toDict())

    def test_tampered_call_address_is_rejected(self):
        payload = {"16": ElfCallSiteEvidence(0x99).toDict()}
        with self.assertRaises(ValueError):
            ElfCallEvidenceTable.fromDict(payload)


if __name__ == "__main__":
    unittest.main()
