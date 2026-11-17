import json

import report
import resolver


def _report(paths, policy):
    return report.build_report(
        str(paths["host"]),
        [str(paths["candidate_v1"]), str(paths["candidate_v2"])],
        policy,
    )


def test_report_has_three_explicit_layers(fixture_paths):
    built = _report(fixture_paths, "exact_identity")
    assert set(built["layer_legend"]) == {"declared", "static-policy", "runtime-observed"}
    assert built["runtime"]["configured"] is False
    assert built["runtime"]["claim"] == "none"


def test_conflicts_include_retargetable_and_signature_drift(fixture_paths):
    built = _report(fixture_paths, "name_only_highest_version")
    kinds = {finding["kind"] for finding in built["conflicts"]}
    assert "retargetable_assembly_ref" in kinds
    assert "member_ref_signature_mismatch" in kinds
    assert "same_simple_name_multiple_identities" in kinds


def test_every_caller_decision_has_a_question(fixture_paths):
    built = _report(fixture_paths, "name_only_highest_version")
    for finding in built["conflicts"]:
        if finding["severity"] == "caller_decision":
            assert finding["question"].strip()


def test_json_round_trip(fixture_paths):
    built = _report(fixture_paths, "exact_identity")
    assert json.loads(report.to_json(built))["schema"] == "dnfile-retarget-analysis/1"


def test_text_report_states_no_runtime_claim(fixture_paths):
    built = _report(fixture_paths, "exact_identity")
    text = report.to_text(built)
    assert "binding behaviour is unknown" in text
    assert "No statement about which candidate the CLR actually loads" in text


def test_runtime_configuration_is_observed_when_present(fixture_paths, tmp_path):
    import shutil

    import runtime_probe

    host = tmp_path / "Host.exe"
    shutil.copyfile(fixture_paths["host"], host)
    (tmp_path / "Host.deps.json").write_text(
        json.dumps(
            {
                "runtimeTarget": {"name": ".NETCoreApp,Version=v8.0"},
                "targets": {
                    ".NETCoreApp,Version=v8.0": {
                        "Contoso.Utils/1.0.0": {
                            "runtime": {"lib/net8.0/Contoso.Utils.dll": {}}
                        }
                    }
                },
                "libraries": {
                    "Contoso.Utils/1.0.0": {"type": "package", "serviceable": True}
                },
            }
        ),
        encoding="utf-8",
    )
    probed = runtime_probe.probe(str(host))
    assert probed["configured"] is True
    assert probed["claim"] == "observed-configuration-only"
    assert probed["sources"][0]["kind"] == "deps.json"
    assert "Contoso.Utils/1.0.0" in probed["sources"][0]["libraries"]
