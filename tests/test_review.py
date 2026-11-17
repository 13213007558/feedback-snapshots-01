# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

import struct

import pytest

from dncil.analysis import (
    Decision,
    FindingKind,
    MetadataError,
    UnresolvedKind,
    SyntheticMetadata,
    review_entry_point,
    review_entry_points,
)
from dncil.clr.token import Token
from tests.pe_builder import AssemblySpec, tiny, build_pe, method_token, member_ref_token
from dncil.analysis.metadata import method_def_token, method_ref_token, method_spec_token


def call(token: Token) -> bytes:
    return b"\x28" + int(token).to_bytes(4, "little")


def callvirt(token: Token) -> bytes:
    return b"\x6f" + int(token).to_bytes(4, "little")


def ldftn(token: Token) -> bytes:
    return b"\xfe\x06" + int(token).to_bytes(4, "little")


def calli(sig_token: int = 0x11000001) -> bytes:
    return b"\x29" + struct.pack("<I", sig_token)


def ret() -> bytes:
    return b"\x2a"


def body(*instructions: bytes) -> bytes:
    return tiny(b"".join(instructions))


# ---------------------------------------------------------------------------
# synthetic metadata: walk semantics
# ---------------------------------------------------------------------------


def test_entry_through_two_helpers_reaches_pinvoke():
    view = SyntheticMetadata()
    native = view.add_module_ref("kernel32.dll")
    view.add_member_ref("Beep", None, module=native)
    entry = view.add_method("Entry", "Fixture", body(call(method_def_token(2)), ret()))
    view.add_method("First", "Fixture", body(call(method_def_token(3)), ret()))
    view.add_method("Second", "Fixture", body(call(method_ref_token(1)), ret()))
    view.set_entry_point(entry)

    report = review_entry_points(view)
    assert report.decision is Decision.REJECT
    finding = report.entries[0].findings[0]
    assert finding.kind is FindingKind.PINVOKE
    assert finding.site.method.name == "Second"
    assert [edge.method.name for edge in finding.path] == ["Entry", "First"]
    assert int(finding.site.operand_token) == 0x0A000001


def test_unreferenced_dangerous_method_is_not_reported():
    view = SyntheticMetadata()
    native = view.add_module_ref("kernel32.dll")
    view.add_member_ref("Beep", None, module=native)
    entry = view.add_method("Entry", "Fixture", body(ret()))
    view.add_method("Unreferenced", "Fixture", body(call(method_ref_token(1)), ret()))
    view.set_entry_point(entry)

    report = review_entry_points(view)
    assert report.decision is Decision.NO_REACHABLE_FINDING
    assert report.entries[0].findings == []
    names = [reached.method.name for reached in report.entries[0].reachable]
    assert names == ["Entry"]


def test_callvirt_is_unresolved_not_followed():
    view = SyntheticMetadata()
    other = view.add_method("Target", "Fixture", body(call(method_ref_token(1)), ret()))
    view.add_member_ref("Beep", None, module=view.add_module_ref("native.dll"))
    entry = view.add_method("Entry", "Fixture", body(callvirt(other.token), ret()))
    view.set_entry_point(entry)

    entry_review = review_entry_point(view, entry.token)
    assert entry_review.decision is Decision.MANUAL_REVIEW
    assert [call.kind for call in entry_review.unresolved] == [UnresolvedKind.VIRTUAL_DISPATCH]
    assert entry_review.findings == []
    assert [reached.method.name for reached in entry_review.reachable] == ["Entry"]


def test_calli_and_function_pointer_are_unresolved():
    view = SyntheticMetadata()
    entry = view.add_method("Entry", "Fixture", body(calli(), ret()))
    view.add_method("Pointer", "Fixture", body(ldftn(method_def_token(3)), ret()))
    view.set_entry_point(entry)

    report = review_entry_point(view, entry.token)
    kinds = {call.kind for call in report.unresolved}
    assert UnresolvedKind.CALLI in kinds
    assert report.decision is Decision.MANUAL_REVIEW


def test_function_pointer_without_call_still_needs_review():
    view = SyntheticMetadata()
    entry = view.add_method("Entry", "Fixture", body(ldftn(method_def_token(2)), ret()))
    view.add_method("Target", "Fixture", body(ret()))
    view.set_entry_point(entry)

    report = review_entry_point(view, entry.token)
    assert report.decision is Decision.MANUAL_REVIEW
    assert report.unresolved[0].kind is UnresolvedKind.FUNCTION_POINTER
    assert len(report.reachable) == 1


def test_external_member_ref_is_recorded_not_followed():
    view = SyntheticMetadata()
    entry = view.add_method("Entry", "Fixture", body(call(method_ref_token(1)), ret()))
    view.add_member_ref("WriteLine", "System.Console")
    view.set_entry_point(entry)

    entry_review = review_entry_point(view, entry.token)
    assert entry_review.decision is Decision.NO_REACHABLE_FINDING
    assert entry_review.unresolved[0].kind is UnresolvedKind.EXTERNAL_TARGET
    assert entry_review.unresolved[0].blocking is False


def test_generic_method_spec_is_unresolved():
    view = SyntheticMetadata()
    entry = view.add_method("Entry", "Fixture", body(call(method_spec_token(1)), ret()))
    view.add_method_spec("Map", "Fixture")
    view.set_entry_point(entry)

    report = review_entry_point(view, entry.token)
    assert report.decision is Decision.MANUAL_REVIEW
    assert report.unresolved[0].kind is UnresolvedKind.GENERIC_TARGET


def test_unsafe_memory_instruction_is_a_finding():
    view = SyntheticMetadata()
    entry = view.add_method("Entry", "Fixture", body(b"\x46", b"\x2a"))  # ldind.i1
    view.set_entry_point(entry)

    report = review_entry_point(view, entry.token)
    assert report.decision is Decision.MANUAL_REVIEW
    assert report.findings[0].kind is FindingKind.UNSAFE_MEMORY
    assert report.findings[0].site.il_offset == 0


def test_branches_are_walked_and_conditional_fallthrough_kept():
    view = SyntheticMetadata()
    native = view.add_module_ref("kernel32.dll")
    view.add_member_ref("Beep", None, module=native)
    # brtrue.s +2 skips the call; both paths are still reviewed conservatively.
    code = b"\x2c\x02" + call(method_ref_token(1)) + ret()
    entry = view.add_method("Entry", "Fixture", body(code))
    view.set_entry_point(entry)

    report = review_entry_point(view, entry.token)
    assert report.decision is Decision.REJECT


def test_loop_terminates_and_is_walked_once():
    view = SyntheticMetadata()
    # br.s -2 loops forever; the walker must not hang.
    entry = view.add_method("Entry", "Fixture", tiny(b"\x2b\xfe"))
    view.set_entry_point(entry)

    report = review_entry_point(view, entry.token)
    assert report.decision is Decision.NO_REACHABLE_FINDING


def test_limits_are_reported_as_manual_review():
    view = SyntheticMetadata()
    entry = view.add_method("Entry", "Fixture", body(call(method_def_token(2)), ret()))
    view.add_method("Next", "Fixture", body(call(method_def_token(3)), ret()))
    view.add_method("Last", "Fixture", body(ret()))
    view.set_entry_point(entry)

    from dncil.analysis.review import ReviewLimits

    report = review_entry_point(view, entry.token, ReviewLimits(max_methods=2))
    assert report.decision is Decision.MANUAL_REVIEW
    assert report.truncated is True


def test_missing_entry_is_metadata_error():
    view = SyntheticMetadata()
    with pytest.raises(MetadataError):
        review_entry_point(view, Token(0x06000009))


def test_report_dict_reports_tokens_and_offsets():
    view = SyntheticMetadata()
    native = view.add_module_ref("kernel32.dll")
    view.add_member_ref("Beep", None, module=native)
    entry = view.add_method("Entry", "Fixture", body(call(method_ref_token(1)), ret()))
    view.set_entry_point(entry)

    payload = review_entry_points(view).to_dict()
    assert payload["decision"] == "reject"
    site = payload["entries"][0]["findings"][0]["site"]
    assert site["caller_token"] == "0x06000001"
    assert site["operand_token"] == "0x0A000001"
    assert site["offset"] == "0x00000001"
    assert "does not prove" in payload["scope"]


# ---------------------------------------------------------------------------
# dnfile adapter: end-to-end over a generated assembly
# ---------------------------------------------------------------------------


def _build(assembly: AssemblySpec):
    import dnfile

    from dncil.analysis.dnfile_adapter import DnfileMetadataView

    return DnfileMetadataView(dnfile.dnPE(data=build_pe(assembly)))


def test_dnfile_adapter_reads_generated_assembly():
    assembly = AssemblySpec()
    assembly.add_module_ref("native.dll")
    assembly.add_member_ref("Beep", assembly.module_refs[0])
    entry = assembly.add_method("Entry", tiny(ret()))
    assembly.add_method("Other", tiny(ret()))
    assembly.entry_point_rid = entry.rid

    view = _build(assembly)
    methods = list(view.methods())
    assert [method.name for method in methods] == ["Entry", "Other"]
    assert methods[0].token == Token(0x06000001)
    assert methods[0].declaring_type == "Fixture"
    assert view.entry_point().name == "Entry"
    assert view.method_body(methods[0]) == tiny(ret())


def test_dnfile_adapter_two_hop_chain_reports_each_token():
    assembly = AssemblySpec()
    assembly.add_module_ref("native.dll")
    assembly.add_member_ref("Beep", assembly.module_refs[0])

    entry = assembly.add_method("Entry", b"")
    first = assembly.add_method("First", b"")
    second = assembly.add_method("Second", b"")
    assembly.add_method("Unreferenced", tiny(call(member_ref_token(1)) + ret()))

    entry.body = tiny(call(method_token(first.rid)) + ret())
    first.body = tiny(call(method_token(second.rid)) + ret())
    second.body = tiny(call(member_ref_token(1)) + ret())
    assembly.entry_point_rid = entry.rid

    report = review_entry_points(_build(assembly))
    assert report.decision is Decision.REJECT

    finding = report.entries[0].findings[0]
    assert finding.site.method.name == "Second"
    assert finding.site.mnemonic == "call"
    assert int(finding.site.operand_token) == 0x0A000001
    assert [edge.method.name for edge in finding.path] == ["Entry", "First"]
    assert [int(edge.operand_token) for edge in finding.path] == [0x06000002, 0x06000003]
    assert finding.site.il_offset == 0
    assert finding.site.offset > 0

    text = report.format_text()
    assert "0x06000002" in text
    assert "0x06000003" in text
    assert "0x0A000001" in text
    assert "IL_0000" in text


def test_dnfile_adapter_direct_pinvoke_method_markup():
    assembly = AssemblySpec()
    assembly.add_module_ref("user32.dll")
    entry = assembly.add_method("Entry", b"")
    native = assembly.add_method("MessageBoxW", None, pinvoke_module="user32.dll", pinvoke_name="MessageBoxW")
    entry.body = tiny(call(method_token(native.rid)) + ret())
    assembly.entry_point_rid = entry.rid

    report = review_entry_points(_build(assembly))
    assert report.decision is Decision.REJECT
    assert report.entries[0].findings[0].kind is FindingKind.PINVOKE
    assert "user32.dll" in report.entries[0].findings[0].detail


def test_dnfile_adapter_abstract_and_virtual_targets_are_unresolved():
    assembly = AssemblySpec()
    entry = assembly.add_method("Entry", b"")
    abstract = assembly.add_method("Abstract", None, abstract=True, virtual=True)
    entry.body = tiny(call(method_token(abstract.rid)) + ret())
    assembly.entry_point_rid = entry.rid

    report = review_entry_points(_build(assembly))
    kinds = {call.kind for call in report.entries[0].unresolved}
    assert UnresolvedKind.ABSTRACT_TARGET in kinds
    assert report.decision is Decision.MANUAL_REVIEW


def test_dnfile_adapter_callvirt_and_calli():
    assembly = AssemblySpec()
    assembly.calli_signatures = 1
    entry = assembly.add_method("Entry", b"")
    target = assembly.add_method("Target", tiny(ret()))
    entry.body = tiny(callvirt(method_token(target.rid)) + calli() + ret())
    assembly.entry_point_rid = entry.rid

    report = review_entry_points(_build(assembly))
    kinds = {call.kind for call in report.entries[0].unresolved}
    assert kinds == {UnresolvedKind.VIRTUAL_DISPATCH, UnresolvedKind.CALLI}
    assert report.decision is Decision.MANUAL_REVIEW


def test_dnfile_adapter_generic_method():
    assembly = AssemblySpec()
    entry = assembly.add_method("Entry", b"")
    generic = assembly.add_method("Map", tiny(ret()), generic=True)
    assembly.generic_param_rids = [generic.rid]
    entry.body = tiny(call(method_token(generic.rid)) + ret())
    assembly.entry_point_rid = entry.rid

    report = review_entry_points(_build(assembly))
    assert report.entries[0].unresolved[0].kind is UnresolvedKind.GENERIC_TARGET
    assert report.decision is Decision.MANUAL_REVIEW


def test_dnfile_adapter_clean_assembly_reports_no_finding():
    assembly = AssemblySpec()
    entry = assembly.add_method("Entry", tiny(ret()))
    assembly.entry_point_rid = entry.rid

    report = review_entry_points(_build(assembly))
    assert report.decision is Decision.NO_REACHABLE_FINDING
    assert "not proof" in report.format_text()


def test_cli_exit_codes_and_json(tmp_path, monkeypatch):
    import sys
    import json
    import subprocess

    from tests.pe_builder import AssemblySpec, tiny, build_pe, member_ref_token

    def write_assembly(pinvoke: bool) -> str:
        assembly = AssemblySpec()
        entry = assembly.add_method("Entry", b"")
        if pinvoke:
            assembly.add_module_ref("native.dll")
            assembly.add_member_ref("Beep", assembly.module_refs[0])
            entry.body = tiny(call(Token(member_ref_token(1))) + ret())
        else:
            entry.body = tiny(ret())
        assembly.entry_point_rid = entry.rid
        path = tmp_path / ("reject.dll" if pinvoke else "clean.dll")
        path.write_bytes(build_pe(assembly))
        return str(path)

    script = "scripts/review_dotnet_entry.py"
    clean = subprocess.run([sys.executable, script, write_assembly(False)], capture_output=True, text=True)
    assert clean.returncode == 0
    assert "not proof" in clean.stdout

    rejected = subprocess.run([sys.executable, script, write_assembly(True), "--json"], capture_output=True, text=True)
    assert rejected.returncode == 2
    payload = json.loads(rejected.stdout)
    assert payload["decision"] == "reject"
    assert payload["entries"][0]["findings"][0]["site"]["operand_token"] == "0x0A000001"


def test_cli_requires_dnfile(monkeypatch):
    import scripts.review_dotnet_entry as cli

    monkeypatch.setattr(cli, "dnfile", None)
    assert cli.main(["plugin.dll"]) == 3
