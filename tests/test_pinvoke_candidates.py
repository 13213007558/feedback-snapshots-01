"""End-to-end tests for examples/pinvoke_candidates.py.

The sample assembly is generated on the fly by
examples/make_pinvoke_sample.py, so no binary fixtures are needed.
"""

import sys
from pathlib import Path

import pytest

EXAMPLES = Path(__file__).parent.parent / "examples"
sys.path.insert(0, str(EXAMPLES))

import make_pinvoke_sample  # noqa: E402
import pinvoke_candidates as pc  # noqa: E402


MANIFEST = pc.ExportManifest.from_dict({
    "platform": "windows",
    "modules": {
        "KERNEL32.dll": {
            "names": [
                "GetVersion", "GetVersionW",
                "ReadFile", "ReadFileA",
                "MessageBoxW",
                "SomeCdeclFunc",
            ],
            "ordinals": {"123": "OrdinalOnlyFunc"},
        },
    },
})


@pytest.fixture(scope="module")
def sample_assembly(tmp_path_factory):
    path = tmp_path_factory.mktemp("pinvoke") / "pinvoke-sample.exe"
    path.write_bytes(make_pinvoke_sample.build_pe())
    return path


@pytest.fixture(scope="module")
def results_windows(sample_assembly):
    return pc.analyze(sample_assembly, MANIFEST, "windows")


def by_method(results, name, occurrence=0):
    matches = [r for r in results if r.imported.method_name == name]
    return matches[occurrence]


def test_same_import_name_different_flags_give_different_candidates(results_windows):
    exact = by_method(results_windows, "GetVersionExact")
    mangled = by_method(results_windows, "GetVersion")
    # both declare ImportName 'GetVersion'
    assert exact.imported.import_name == mangled.imported.import_name == "GetVersion"
    # ExactSpelling: only the declared name
    assert exact.status == pc.STATUS_MATCHED
    assert [c.export_name for c in exact.candidates] == ["GetVersion"]
    assert exact.candidates[0].match_kind == "exact"
    # CharSet.Unicode: the W-suffixed variant enters the candidate set
    assert {c.export_name for c in mangled.candidates} == {"GetVersionW", "GetVersion"}
    assert {c.match_kind for c in mangled.candidates} == {"suffix-w", "exact"}


def test_multiple_matching_probes_are_not_forced(results_windows):
    mangled = by_method(results_windows, "GetVersion")
    assert mangled.status == pc.STATUS_AMBIGUOUS
    assert len(mangled.candidates) == 2


def test_same_name_overloads_keep_distinct_identities(results_windows):
    first = by_method(results_windows, "ReadFile", 0)
    second = by_method(results_windows, "ReadFile", 1)
    assert first.imported.method_token != second.imported.method_token
    assert first.imported.method_signature_hex != second.imported.method_signature_hex
    # both overloads share the declared import name and get the same candidates
    assert first.imported.import_name == second.imported.import_name == "ReadFile"
    assert first.status == second.status == pc.STATUS_AMBIGUOUS
    assert {c.export_name for c in first.candidates} == {"ReadFileA", "ReadFile"}


def test_missing_module_target(results_windows):
    missing = by_method(results_windows, "DeleteFile")
    assert missing.imported.module_name == "nonexistent.dll"
    assert missing.status == pc.STATUS_MODULE_NOT_PROVIDED
    assert missing.candidates == []


def test_ordinal_import(results_windows):
    ordinal = by_method(results_windows, "OrdinalOnly")
    assert ordinal.imported.import_name == "#123"
    assert ordinal.status == pc.STATUS_MATCHED
    assert ordinal.candidates[0].match_kind == "ordinal"
    assert ordinal.candidates[0].ordinal == 123
    assert ordinal.candidates[0].export_name == "OrdinalOnlyFunc"


def test_unsupported_calling_convention(results_windows):
    fastcall = by_method(results_windows, "FastCallBad")
    assert fastcall.status == pc.STATUS_UNSUPPORTED_CONVENTION
    assert fastcall.candidates == []


def test_charset_auto_requires_platform(sample_assembly):
    results = pc.analyze(sample_assembly, MANIFEST, "unknown")
    auto = by_method(results, "MessageBoxAuto")
    # unknown platform: no candidate may be forced
    assert auto.status == pc.STATUS_UNKNOWN
    assert auto.candidates == []
    # declared values are preserved verbatim
    assert auto.imported.import_name == "MessageBox"
    assert auto.imported.mapping_flags_raw == 0x0106

    resolved = by_method(pc.analyze(sample_assembly, MANIFEST, "windows"), "MessageBoxAuto")
    assert resolved.status == pc.STATUS_MATCHED
    assert [c.export_name for c in resolved.candidates] == ["MessageBoxW"]


def test_declared_values_preserved(results_windows):
    for result in results_windows:
        item = result.imported
        assert isinstance(item.import_name, str) and item.import_name
        assert isinstance(item.module_name, str) and item.module_name
        assert item.mapping_flags_raw == int(
            item.mapping_flags_raw
        )  # raw int, not decoded flags
    cdecl = by_method(results_windows, "CdeclExact")
    assert cdecl.imported.mapping_flags_raw == 0x0201
    assert "pmCallConvCdecl" in cdecl.imported.mapping_flags_decoded


def test_no_match_when_export_absent(sample_assembly):
    manifest = pc.ExportManifest.from_dict({
        "modules": {"KERNEL32.dll": {"names": ["SomethingElse"], "ordinals": {}}},
    })
    results = pc.analyze(sample_assembly, manifest, "windows")
    exact = by_method(results, "GetVersionExact")
    assert exact.status == pc.STATUS_NO_MATCH
    assert exact.candidates == []


def test_cli_json_output(sample_assembly, tmp_path, capsys):
    manifest_path = tmp_path / "exports.json"
    manifest_path.write_text(
        '{"platform": "windows", "modules": {"KERNEL32.dll": '
        '{"names": ["GetVersion"], "ordinals": {}}}}'
    )
    rc = pc.main([
        str(sample_assembly),
        "--exports", str(manifest_path),
        "--format", "json",
    ])
    assert rc == 0
    import json

    payload = json.loads(capsys.readouterr().out)
    assert payload["platform"] == "windows"
    assert len(payload["results"]) == 9
    for entry in payload["results"]:
        assert "disclaimer" in entry
        assert entry["declared_import_name"]
