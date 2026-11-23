# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Regression coverage for the offline ADC diagnostics scenarios.

These tests pin the discovery, project-resolution, and quota-application
boundaries the diagnostics document describes. Every scenario runs against
synthetic files and stubs; nothing touches a real ADC file, gcloud, or the
metadata service.
"""

import importlib.util
import os
import sys

import pytest  # type: ignore

_SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "scripts", "adc_diagnostics.py"
)


def _load_diagnostics():
    spec = importlib.util.spec_from_file_location("adc_diagnostics", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


diag = _load_diagnostics()


@pytest.fixture(scope="module")
def reports():
    return {report["scenario"]: report for report in diag.run_all()}


def _events(report, kind):
    return [event for event in report["events"] if event["event"] == kind]


def _probes(report, channel):
    return [probe for probe in report["probes"] if probe["channel"] == channel]


def test_scenarios_cover_distinct_failure_modes():
    names = set(diag._scenarios())
    assert {
        "explicit_distinct_missing",
        "explicit_same_sdk_missing",
        "explicit_same_sdk_user",
        "sdk_user_without_explicit_env",
        "sdk_path_malformed",
        "sdk_user_explicit_project",
        "sdk_user_quota_from_env",
        "managed_vm_same_project",
        "external_account_deferred",
        "external_account_no_scopes",
        "external_account_lookup_denied",
        "external_account_explicit_project",
        "external_account_quota_project",
    } <= names


def test_explicit_distinct_missing_is_terminal(reports):
    report = reports["explicit_distinct_missing"]

    assert report["result"]["status"] == "error"
    assert report["result"]["error_type"] == "DefaultCredentialsError"
    assert report["environment"]["explicit_path_equals_sdk_default"] is False

    # The read failure is the last thing that happens: no later stage runs.
    failed = _events(report, "file_read_failed")
    assert len(failed) == 1
    assert failed[0]["stage"] == "get_explicit_environ_credentials"
    assert _events(report, "stage_enter") == [
        event
        for event in _events(report, "stage_enter")
        if event["stage"] == "get_explicit_environ_credentials"
    ]
    assert report["probes"] == []


def test_explicit_same_sdk_path_missing_continues_to_metadata(reports):
    report = reports["explicit_same_sdk_missing"]

    assert report["result"]["status"] == "ok"
    assert report["result"]["credential_type"] == "VM credentials"
    assert report["result"]["project_id"] == diag.SHARED_PROJECT
    assert report["environment"]["explicit_path_equals_sdk_default"] is True

    stages = [event["stage"] for event in _events(report, "stage_enter")]
    assert stages == [
        "get_explicit_environ_credentials",
        "get_gcloud_sdk_credentials",
        "get_gcloud_sdk_credentials",
        "get_gae_credentials",
        "get_gce_credentials",
    ]
    assert _events(report, "file_read_failed") == []
    filesystem = _probes(report, "filesystem")
    assert [probe["result"] for probe in filesystem] == ["absent", "absent"]
    assert all(probe["explicit_path_matches"] is True for probe in filesystem)
    assert [probe["action"] for probe in _probes(report, "metadata")] == [
        "is_on_gce",
        "project/project-id",
    ]


def test_same_project_id_from_user_credentials(reports):
    report = reports["sdk_user_without_explicit_env"]

    assert report["result"]["status"] == "ok"
    assert report["result"]["credential_type"] == "user credentials"
    assert report["result"]["project_id"] == diag.SHARED_PROJECT
    assert report["result"]["project_lookup_available"] is False

    gcloud = _probes(report, "gcloud")
    assert [probe["action"] for probe in gcloud] == ["config get project"]
    assert gcloud[0]["result"] == diag.SHARED_PROJECT
    assert _probes(report, "metadata") == []


def test_same_project_id_from_managed_identity(reports):
    report = reports["managed_vm_same_project"]

    assert report["result"]["status"] == "ok"
    assert report["result"]["credential_type"] == "VM credentials"
    assert report["result"]["project_id"] == diag.SHARED_PROJECT
    assert report["result"]["credential_source"] == "metadata server"

    assert _probes(report, "gcloud") == []
    assert [probe["action"] for probe in _probes(report, "metadata")] == [
        "is_on_gce",
        "project/project-id",
    ]


def test_same_explicit_path_and_sdk_path_uses_sdk_project_lookup(reports):
    report = reports["explicit_same_sdk_user"]

    assert report["result"]["status"] == "ok"
    assert report["result"]["credential_type"] == "user credentials"
    assert report["result"]["project_id"] == diag.SHARED_PROJECT
    assert report["environment"]["explicit_path_equals_sdk_default"] is True
    assert [probe["action"] for probe in _probes(report, "gcloud")] == [
        "config get project"
    ]


def test_present_unparsable_file_stops_discovery(reports):
    report = reports["sdk_path_malformed"]

    assert report["result"]["status"] == "error"
    assert report["result"]["error_type"] == "DefaultCredentialsError"
    assert report["environment"]["explicit_path_equals_sdk_default"] is True

    failed = _events(report, "file_read_failed")
    assert len(failed) == 1
    assert "is not a valid json file" in failed[0]["error"]
    assert _probes(report, "metadata") == []
    assert _probes(report, "gcloud") == []


def test_external_account_defers_project_lookup_until_scopes(reports):
    report = reports["external_account_deferred"]

    assert report["result"]["status"] == "ok"
    assert report["result"]["project_id"] == diag.RESOLVED_PROJECT
    assert report["result"]["quota_project_id"] is None

    # Before scopes exist, the library returns None without any HTTP call.
    skipped = [
        probe
        for probe in _probes(report, "cloud-resource-manager")
        if probe["result"] == "skipped: no scopes"
    ]
    assert len(skipped) == 1

    scope_event = _events(report, "scope_attachment")[0]
    assert scope_event["requires_scopes"] is True

    # Scoping happens before the deferred project lookup.
    kinds = [
        event["event"]
        for event in report["events"]
        if event["event"] in ("scope_attachment", "project_lookup_attempt")
    ]
    assert kinds == ["scope_attachment", "project_lookup_attempt"]

    assert [probe["channel"] for probe in report["probes"]] == [
        "cloud-resource-manager",
        "synthetic-sts",
        "cloud-resource-manager",
    ]
    resolved = report["probes"][-1]
    assert resolved["action"] == "GET /v1/projects/{}".format(diag.PROJECT_NUMBER)
    assert resolved["result"] == "200"


def test_external_account_without_scopes_returns_no_project(reports):
    report = reports["external_account_no_scopes"]

    assert report["result"]["status"] == "ok"
    assert report["result"]["project_id"] is None
    assert report["result"]["credential_type"] == "external account credentials"
    assert [probe["result"] for probe in report["probes"]] == [
        "skipped: no scopes",
        "skipped: no scopes",
    ]
    assert _probes(report, "synthetic-sts") == []


def test_external_account_project_lookup_denied_returns_none(reports):
    report = reports["external_account_lookup_denied"]

    assert report["result"]["status"] == "ok"
    assert report["result"]["project_id"] is None
    assert [probe["result"] for probe in _probes(report, "cloud-resource-manager")] == [
        "skipped: no scopes",
        "403",
    ]


def test_external_account_explicit_project_skips_lookup(reports):
    report = reports["external_account_explicit_project"]

    assert report["result"]["status"] == "ok"
    assert report["result"]["project_id"] == diag.ENV_PINNED_PROJECT
    assert report["result"]["credential_type"] == "external account credentials"
    assert [probe["result"] for probe in report["probes"]] == ["skipped: no scopes"]
    assert _events(report, "project_lookup_attempt") == []


def test_quota_project_does_not_change_origin_evidence(reports):
    report = reports["external_account_quota_project"]

    assert report["result"]["status"] == "ok"
    assert report["result"]["project_id"] == diag.RESOLVED_PROJECT
    assert report["result"]["quota_project_id"] == diag.QUOTA_PROJECT
    assert report["result"]["credential_type"] == "external account credentials"
    assert report["result"]["credential_source"] == (
        "<synthetic>/external-account.json file via the "
        "GOOGLE_APPLICATION_CREDENTIALS environment variable"
    )

    quota_probe = _probes(report, "cloud-resource-manager")[-1]
    assert quota_probe["quota_project_header"] == diag.QUOTA_PROJECT


def test_quota_project_from_environment_is_recorded(reports):
    report = reports["sdk_user_quota_from_env"]

    assert report["result"]["status"] == "ok"
    assert report["result"]["project_id"] == diag.SHARED_PROJECT
    assert report["result"]["quota_project_id"] == diag.QUOTA_PROJECT

    quota_events = _events(report, "quota_application")
    assert any(
        event["environment_value"] == diag.QUOTA_PROJECT for event in quota_events
    )


def test_explicit_project_changes_only_returned_project(reports):
    report = reports["sdk_user_explicit_project"]

    assert report["result"]["status"] == "ok"
    assert report["result"]["project_id"] == diag.ENV_PINNED_PROJECT
    assert report["result"]["credential_type"] == "user credentials"
    assert _probes(report, "gcloud")[0]["result"] == diag.SHARED_PROJECT


def test_no_real_home_paths_in_reports(reports):
    import json

    rendered = json.dumps(reports)
    home = os.path.expanduser("~")
    if home and home != "~":
        assert home not in rendered

    # The synthetic client secret and refresh token never enter the report.
    assert "synthetic-client-secret" not in rendered
    assert "synthetic-refresh-token" not in rendered
    assert "synthetic-access-token" not in rendered
