#!/usr/bin/env python3
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

"""Offline diagnostics for Application Default Credentials provenance.

This script answers a support question that a project ID alone cannot answer:

    Which credential was actually selected, which layer supplied the project ID,
    and was a quota project applied?

It is deliberately offline. Every scenario runs against synthetic files in a
temporary directory, with gcloud and the Compute Engine metadata service
replaced by recording stubs. The script never reads the workstation's real ADC
file, never runs gcloud, and never contacts a metadata endpoint. Reports contain
only synthetic identifiers and the names of the stages that were consulted.

Usage::

    python scripts/adc_diagnostics.py
    python scripts/adc_diagnostics.py --format json
    python scripts/adc_diagnostics.py --scenario external_account_deferred

The scenarios are also importable so tests and support tooling can reuse the
runner.
"""
from __future__ import annotations

import argparse
import contextlib
import dataclasses
import json
import os
import sys
import tempfile
import warnings
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from google.auth import _cloud_sdk  # noqa: E402
from google.auth import _default  # noqa: E402
from google.auth import credentials as credentials_module  # noqa: E402
from google.auth import environment_vars  # noqa: E402
from google.auth import external_account  # noqa: E402
from google.auth.compute_engine import _metadata  # noqa: E402

# Synthetic values. They are intentionally boring and contain no real account.
SHARED_PROJECT = "shared-project-123456"
RESOLVED_PROJECT = "resolved-from-project-number"
ENV_PINNED_PROJECT = "pinned-by-environment"
QUOTA_PROJECT = "synthetic-quota-project"
PROJECT_NUMBER = "123456789012"
USER_PRINCIPAL = "synthetic-user@example.com"
CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

_MISSING_ADC_NAME = "application_default_credentials.json"
_HOME = os.path.expanduser("~")


def _authorized_user_info() -> Dict[str, str]:
    # The client ID is the public Cloud SDK client ID, so the library emits its
    # normal "end user credentials without a quota project" warning.
    return {
        "type": "authorized_user",
        "client_id": _cloud_sdk.CLOUD_SDK_CLIENT_ID,
        "client_secret": "synthetic-client-secret",
        "refresh_token": "synthetic-refresh-token",
        "account": USER_PRINCIPAL,
    }


def _external_account_info(subject_token_path: str) -> Dict[str, Any]:
    return {
        "type": "external_account",
        "audience": (
            "//iam.googleapis.com/projects/{}/locations/global/"
            "workloadIdentityPools/synthetic-pool/providers/synthetic-provider"
        ).format(PROJECT_NUMBER),
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "token_url": "https://sts.googleapis.com/v1/token",
        "credential_source": {"file": subject_token_path},
    }


@dataclasses.dataclass(frozen=True)
class Scenario:
    """A synthetic environment and the default() arguments to exercise."""

    name: str
    summary: str
    env: Mapping[str, str] = dataclasses.field(default_factory=dict)
    files: Mapping[str, Any] = dataclasses.field(default_factory=dict)
    metadata_available: bool = False
    metadata_project: Optional[str] = None
    gcloud_project: Optional[str] = None
    project_lookup_result: Optional[str] = None
    project_lookup_status: int = 200
    default_kwargs: Mapping[str, Any] = dataclasses.field(default_factory=dict)
    notes: Tuple[str, ...] = ()


def _scenarios() -> Dict[str, Scenario]:
    external_path = "{root}/external-account.json"
    subject_path = "{root}/subject-token.txt"
    scenarios = [
        Scenario(
            name="explicit_distinct_missing",
            summary=(
                "GOOGLE_APPLICATION_CREDENTIALS names a missing file that is "
                "not the Cloud SDK default path."
            ),
            env={environment_vars.CREDENTIALS: "{root}/missing-credentials.json"},
            metadata_available=True,
            metadata_project=SHARED_PROJECT,
            notes=(
                "The explicit read fails before any other stage runs.",
                "DefaultCredentialsError is terminal; no gcloud or metadata probe.",
            ),
        ),
        Scenario(
            name="explicit_same_sdk_missing",
            summary=(
                "GOOGLE_APPLICATION_CREDENTIALS equals the Cloud SDK default "
                "path, and that file does not exist."
            ),
            env={environment_vars.CREDENTIALS: "{root}/" + _MISSING_ADC_NAME},
            metadata_available=True,
            metadata_project=SHARED_PROJECT,
            notes=(
                "The explicit stage delegates to the Cloud SDK stage.",
                "A missing SDK-default file is a probe, not an error.",
                "Discovery continues to App Engine and then the metadata service.",
            ),
        ),
        Scenario(
            name="explicit_same_sdk_user",
            summary=(
                "The explicit path equals the SDK default path and a synthetic "
                "authorized_user file exists there."
            ),
            env={environment_vars.CREDENTIALS: "{root}/" + _MISSING_ADC_NAME},
            files={_MISSING_ADC_NAME: _authorized_user_info()},
            gcloud_project=SHARED_PROJECT,
            notes=(
                "The explicit stage delegates to the Cloud SDK stage.",
                "authorized_user files carry no project_id.",
                "The project comes from `gcloud config get project`, not the file.",
            ),
        ),
        Scenario(
            name="sdk_user_without_explicit_env",
            summary=(
                "No explicit path; a synthetic authorized_user ADC file exists "
                "at the Cloud SDK default path."
            ),
            files={_MISSING_ADC_NAME: _authorized_user_info()},
            gcloud_project=SHARED_PROJECT,
            notes=(
                "This is the ordinary developer-workstation shape.",
                "The project is the active gcloud configuration project.",
            ),
        ),
        Scenario(
            name="sdk_path_malformed",
            summary=(
                "The explicit path equals the SDK default path and a present "
                "file is not valid JSON."
            ),
            env={environment_vars.CREDENTIALS: "{root}/" + _MISSING_ADC_NAME},
            files={_MISSING_ADC_NAME: "not-json"},
            metadata_available=True,
            metadata_project=SHARED_PROJECT,
            notes=(
                "Once the file is present, a parse failure is terminal.",
                "The metadata service is not consulted as a fallback.",
            ),
        ),
        Scenario(
            name="sdk_user_explicit_project",
            summary=(
                "A synthetic authorized_user ADC file exists at the SDK default "
                "path, gcloud has a project, and GOOGLE_CLOUD_PROJECT is set."
            ),
            env={environment_vars.PROJECT: ENV_PINNED_PROJECT},
            files={_MISSING_ADC_NAME: _authorized_user_info()},
            gcloud_project=SHARED_PROJECT,
            notes=(
                "gcloud is still queried because the file carries no project.",
                "The environment value wins: the gcloud answer is not used.",
                "The credential class and source are unchanged.",
            ),
        ),
        Scenario(
            name="sdk_user_quota_from_env",
            summary=(
                "A synthetic authorized_user ADC file plus "
                "GOOGLE_CLOUD_QUOTA_PROJECT, with no quota argument."
            ),
            env={environment_vars.GOOGLE_CLOUD_QUOTA_PROJECT: QUOTA_PROJECT},
            files={_MISSING_ADC_NAME: _authorized_user_info()},
            gcloud_project=SHARED_PROJECT,
            notes=(
                "The returned project still comes from the gcloud configuration.",
                "Only the quota project and x-goog-user-project change.",
            ),
        ),
        Scenario(
            name="managed_vm_same_project",
            summary=(
                "No ADC file; the workload is treated as running on Compute "
                "Engine and the metadata service reports the same project."
            ),
            metadata_available=True,
            metadata_project=SHARED_PROJECT,
            notes=(
                "The credential is VM credentials sourced from the metadata server.",
                "A project ID equal to the developer value does not prove the source.",
            ),
        ),
        Scenario(
            name="external_account_deferred",
            summary=(
                "A synthetic workload identity config with scopes supplied to "
                "default(); the project is resolved after scoping."
            ),
            env={environment_vars.CREDENTIALS: external_path},
            files={
                "external-account.json": _external_account_info(subject_path),
                "subject-token.txt": "synthetic-subject-token",
            },
            project_lookup_result=RESOLVED_PROJECT,
            default_kwargs={"scopes": [CLOUD_PLATFORM_SCOPE]},
            notes=(
                "The first get_project_id call has no scopes and performs no HTTP.",
                "Scopes are attached, then get_project_id exchanges the subject token.",
                "The project ID is read from Cloud Resource Manager using the "
                "audience project number.",
            ),
        ),
        Scenario(
            name="external_account_no_scopes",
            summary=(
                "The same workload identity config, but default() is called "
                "without scopes."
            ),
            env={environment_vars.CREDENTIALS: external_path},
            files={
                "external-account.json": _external_account_info(subject_path),
                "subject-token.txt": "synthetic-subject-token",
            },
            project_lookup_result=RESOLVED_PROJECT,
            notes=(
                "Without scopes, get_project_id returns None without HTTP.",
                "A None project does not mean the identity is unconfigured.",
            ),
        ),
        Scenario(
            name="external_account_lookup_denied",
            summary=(
                "The workload identity config plus scopes, but the caller "
                "cannot read the project behind the audience project number."
            ),
            env={environment_vars.CREDENTIALS: external_path},
            files={
                "external-account.json": _external_account_info(subject_path),
                "subject-token.txt": "synthetic-subject-token",
            },
            project_lookup_status=403,
            default_kwargs={"scopes": [CLOUD_PLATFORM_SCOPE]},
            notes=(
                "Scopes were available, so the lookup was attempted and denied.",
                "A None project here means 'not readable', not 'no identity'.",
            ),
        ),
        Scenario(
            name="external_account_explicit_project",
            summary=(
                "The workload identity config plus GOOGLE_CLOUD_PROJECT; the "
                "environment value short-circuits project resolution."
            ),
            env={
                environment_vars.CREDENTIALS: external_path,
                environment_vars.PROJECT: ENV_PINNED_PROJECT,
            },
            files={
                "external-account.json": _external_account_info(subject_path),
                "subject-token.txt": "synthetic-subject-token",
            },
            project_lookup_result=RESOLVED_PROJECT,
            default_kwargs={"scopes": [CLOUD_PLATFORM_SCOPE]},
            notes=(
                "The returned project is the environment value.",
                "The deferred Cloud Resource Manager lookup is skipped.",
                "The credential class and source are unchanged.",
            ),
        ),
        Scenario(
            name="external_account_quota_project",
            summary=(
                "The workload identity config plus an explicit quota project; "
                "project resolution still happens and gains a quota header."
            ),
            env={environment_vars.CREDENTIALS: external_path},
            files={
                "external-account.json": _external_account_info(subject_path),
                "subject-token.txt": "synthetic-subject-token",
            },
            project_lookup_result=RESOLVED_PROJECT,
            default_kwargs={
                "scopes": [CLOUD_PLATFORM_SCOPE],
                "quota_project_id": QUOTA_PROJECT,
            },
            notes=(
                "The returned project still comes from Cloud Resource Manager.",
                "The quota project is visible as x-goog-user-project.",
                "The credential class and source are unchanged.",
            ),
        ),
    ]
    return {scenario.name: scenario for scenario in scenarios}


class _Trace:
    """Ordered, sanitized record of discovery stages and probe calls."""

    def __init__(self, root: str):
        self.root = root
        self._stages: List[str] = []
        self.events: List[Dict[str, Any]] = []
        self.probes: List[Dict[str, Any]] = []

    @property
    def stage(self) -> str:
        return self._stages[-1] if self._stages else "default()"

    def sanitize(self, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        value = value.replace(self.root, "<synthetic>")
        if _HOME and _HOME != "~":
            value = value.replace(_HOME, "~")
        return value

    def push_stage(self, name: str) -> None:
        self._stages.append(name)
        self.event("stage_enter", stage=name)

    def pop_stage(self) -> None:
        name = self._stages.pop()
        self.event("stage_exit", stage=name)

    def event(self, kind: str, **details: Any) -> None:
        entry = {"seq": len(self.events) + 1, "stage": self.stage, "event": kind}
        entry.update({key: self.sanitize(value) for key, value in details.items()})
        self.events.append(entry)

    def probe(self, channel: str, action: str, result: str, **details: Any) -> None:
        entry = {
            "seq": len(self.probes) + 1,
            "stage": self.stage,
            "channel": channel,
            "action": action,
            "result": result,
        }
        entry.update({key: self.sanitize(value) for key, value in details.items()})
        self.probes.append(entry)

    def report(self) -> Dict[str, Any]:
        return {
            "events": list(self.events),
            "probes": list(self.probes),
        }


class _Response:
    def __init__(self, status: int, body: Mapping[str, Any]):
        self.status = status
        self.data = json.dumps(body).encode("utf-8")
        self.headers = {"content-type": "application/json"}


class _SyntheticTransport:
    """Answers only the two endpoints used by external account credentials."""

    def __init__(
        self, trace: _Trace, project_id: Optional[str], project_status: int = 200
    ):
        self._trace = trace
        self._project_id = project_id
        self._project_status = project_status
        self.calls = 0

    def __call__(self, url=None, method=None, body=None, headers=None, **kwargs):
        self.calls += 1
        parsed = urlsplit(url or "")
        request_headers = dict(headers or {})
        quota_header = request_headers.get("x-goog-user-project")
        has_authorization = "authorization" in {
            key.lower() for key in request_headers
        }

        if parsed.netloc == "sts.googleapis.com":
            self._trace.probe(
                "synthetic-sts",
                "POST /v1/token",
                "200",
                request_has_authorization=has_authorization,
            )
            return _Response(
                200,
                {
                    "access_token": "synthetic-access-token",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                },
            )

        if parsed.netloc == "cloudresourcemanager.googleapis.com":
            status = self._project_status
            self._trace.probe(
                "cloud-resource-manager",
                "GET " + parsed.path,
                str(status),
                request_has_authorization=has_authorization,
                quota_project_header=quota_header,
            )
            if status != 200:
                return _Response(status, {"error": {"code": status}})
            return _Response(
                200,
                {
                    "projectId": self._project_id,
                    "projectNumber": PROJECT_NUMBER,
                },
            )

        self._trace.probe("unexpected", url or "<none>", "blocked")
        raise AssertionError(
            "Synthetic transport refused an unexpected endpoint: {}".format(url)
        )


def _stage_wrapper(trace: _Trace, name: str, function):
    def wrapper(*args, **kwargs):
        trace.push_stage(name)
        try:
            result = function(*args, **kwargs)
            if isinstance(result, tuple) and len(result) == 2:
                credentials, project = result
                trace.event(
                    "stage_result",
                    credential_class=(
                        type(credentials).__module__
                        + "."
                        + type(credentials).__qualname__
                        if credentials is not None
                        else None
                    ),
                    project_id=project,
                )
            return result
        except BaseException as exc:  # noqa: BLE001 - recorded, then re-raised
            trace.event("stage_error", error_type=type(exc).__name__)
            raise
        finally:
            trace.pop_stage()

    return wrapper


def _install_patches(
    stack: contextlib.ExitStack,
    trace: _Trace,
    scenario: Scenario,
) -> None:
    original_load = _default.load_credentials_from_file
    original_scopes = credentials_module.with_scopes_if_required
    original_quota = _default._apply_quota_project_id

    def load(filename, *args, **kwargs):
        trace.event("file_read_attempt", path=filename)
        try:
            result = original_load(filename, *args, **kwargs)
        except BaseException as exc:  # noqa: BLE001 - recorded, then re-raised
            trace.event(
                "file_read_failed",
                path=filename,
                error_type=type(exc).__name__,
                error=str(exc),
            )
            raise
        trace.event("file_loaded", path=filename)
        return result

    def scopes(credentials, scopes_arg, default_scopes=None):
        requires = bool(getattr(credentials, "requires_scopes", False))
        trace.event(
            "scope_attachment",
            requires_scopes=requires,
            scopes=list(scopes_arg) if scopes_arg else None,
            default_scopes=list(default_scopes) if default_scopes else None,
        )
        return original_scopes(credentials, scopes_arg, default_scopes=default_scopes)

    def quota(credentials, quota_project_id):
        trace.event(
            "quota_application",
            requested=quota_project_id,
            environment_value=os.environ.get(
                environment_vars.GOOGLE_CLOUD_QUOTA_PROJECT
            ),
        )
        return original_quota(credentials, quota_project_id)

    def gcloud_project():
        trace.probe(
            "gcloud",
            "config get project",
            scenario.gcloud_project or "no project configured",
        )
        return scenario.gcloud_project

    def is_on_gce(request=None):
        trace.probe(
            "metadata",
            "is_on_gce",
            "available" if scenario.metadata_available else "unavailable",
        )
        return scenario.metadata_available

    def metadata_project(request=None):
        trace.probe(
            "metadata", "project/project-id", scenario.metadata_project or "none"
        )
        return scenario.metadata_project

    stack.enter_context(_patch_object(_default, "load_credentials_from_file", load))
    stack.enter_context(
        _patch_object(credentials_module, "with_scopes_if_required", scopes)
    )
    stack.enter_context(_patch_object(_default, "_apply_quota_project_id", quota))
    stack.enter_context(_patch_object(_cloud_sdk, "get_project_id", gcloud_project))
    stack.enter_context(_patch_object(_metadata, "is_on_gce", is_on_gce))
    stack.enter_context(_patch_object(_metadata, "get_project_id", metadata_project))

    original_get_project_id = external_account.Credentials.get_project_id

    def get_project_id(credentials, request):
        scopes = credentials.scopes or credentials.default_scopes
        project_number = getattr(credentials, "project_number", None)
        if not scopes:
            # library get_project_id() silently returns None before any HTTP.
            trace.probe(
                "cloud-resource-manager",
                "GET /v1/projects/{}".format(project_number or "<unknown>"),
                "skipped: no scopes",
                request_has_authorization=False,
                quota_project_header=None,
            )
            return None
        trace.event(
            "project_lookup_attempt",
            audience=getattr(credentials, "_audience", None),
        )
        result = original_get_project_id(credentials, request)
        trace.event("project_lookup_result", project_id=result)
        return result

    stack.enter_context(
        _patch_object(external_account.Credentials, "get_project_id", get_project_id)
    )

    for name, function in (
        (
            "_get_explicit_environ_credentials",
            _stage_wrapper(
                trace,
                "get_explicit_environ_credentials",
                _default._get_explicit_environ_credentials,
            ),
        ),
        ("_get_gcloud_sdk_credentials", _sdk_stage(trace)),
        (
            "_get_gae_credentials",
            _stage_wrapper(trace, "get_gae_credentials", _default._get_gae_credentials),
        ),
        (
            "_get_gce_credentials",
            _stage_wrapper(trace, "get_gce_credentials", _default._get_gce_credentials),
        ),
    ):
        stack.enter_context(
            _patch_object(_default, name, function)
        )


def _sdk_stage(trace: _Trace):
    """Wrap the Cloud SDK stage and record whether its file exists."""

    original = _default._get_gcloud_sdk_credentials

    def stage(quota_project_id=None):
        trace.push_stage("get_gcloud_sdk_credentials")
        try:
            path = _cloud_sdk.get_application_default_credentials_path()
            present = os.path.isfile(path)
            explicit = os.environ.get(environment_vars.CREDENTIALS, "")
            trace.probe(
                "filesystem",
                "isfile {}".format(_MISSING_ADC_NAME),
                "present" if present else "absent",
                path=path,
                explicit_path_matches=explicit == path,
            )
            result = original(quota_project_id=quota_project_id)
            credentials, project = result
            trace.event(
                "stage_result",
                credential_class=(
                    type(credentials).__module__
                    + "."
                    + type(credentials).__qualname__
                    if credentials is not None
                    else None
                ),
                project_id=project,
            )
            return result
        except BaseException as exc:
            trace.event("stage_error", error_type=type(exc).__name__)
            raise
        finally:
            trace.pop_stage()

    return stage


def _patch_object(target, attribute, replacement):
    from unittest import mock

    return mock.patch.object(target, attribute, replacement)


def _credential_provenance(
    credentials, project_id: Optional[str], trace: _Trace
) -> Dict[str, Any]:
    """Return only non-secret provenance fields for a credential."""

    info = None
    get_info = getattr(credentials, "get_cred_info", None)
    if callable(get_info):
        try:
            info = get_info()
        except Exception:  # pragma: NO COVER - diagnostic must not fail here
            info = None
    info = info or {}
    return {
        "credential_class": type(credentials).__module__
        + "."
        + type(credentials).__qualname__,
        "credential_type": info.get("credential_type"),
        "credential_source": trace.sanitize(info.get("credential_source")),
        "principal": trace.sanitize(info.get("principal")),
        "project_id": project_id,
        "quota_project_id": getattr(credentials, "quota_project_id", None),
        "project_lookup_available": callable(
            getattr(credentials, "get_project_id", None)
        ),
        "is_user": getattr(credentials, "is_user", None),
        "is_workforce_pool": getattr(credentials, "is_workforce_pool", None),
        "requires_scopes": getattr(credentials, "requires_scopes", None),
    }


def _write_files(directory: str, files: Mapping[str, Any]) -> None:
    for relative, content in files.items():
        path = os.path.join(directory, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if isinstance(content, (dict, list)):
            content = json.dumps(content)
        content = content.replace("{root}", directory)
        with open(path, "w", encoding="utf-8") as file_obj:
            file_obj.write(content)


def run_scenario(scenario: Scenario, root: str) -> Dict[str, Any]:
    """Run one scenario entirely against synthetic files and stubs."""

    directory = os.path.join(root, scenario.name)
    os.makedirs(directory, exist_ok=True)
    _write_files(directory, scenario.files)

    resolved_env = {
        key: value.replace("{root}", directory)
        for key, value in scenario.env.items()
    }
    resolved_env.setdefault("CLOUDSDK_CONFIG", directory)

    trace = _Trace(directory)
    transport = _SyntheticTransport(
        trace,
        scenario.project_lookup_result,
        project_status=scenario.project_lookup_status,
    )

    report: Dict[str, Any] = {
        "scenario": scenario.name,
        "summary": scenario.summary,
        "environment": {
            "explicit_credentials_path": trace.sanitize(
                resolved_env.get(environment_vars.CREDENTIALS)
            ),
            "explicit_path_equals_sdk_default": None,
            "project_env": resolved_env.get(environment_vars.PROJECT),
            "legacy_project_env": resolved_env.get(environment_vars.LEGACY_PROJECT),
            "quota_project_env": resolved_env.get(
                environment_vars.GOOGLE_CLOUD_QUOTA_PROJECT
            ),
            "metadata_available": scenario.metadata_available,
            "gcloud_config_project": scenario.gcloud_project,
        },
        "notes": list(scenario.notes),
    }

    with contextlib.ExitStack() as stack:
        from unittest import mock

        stack.enter_context(mock.patch.dict(os.environ, resolved_env, clear=True))
        sdk_path = os.path.join(directory, _MISSING_ADC_NAME)
        report["environment"]["explicit_path_equals_sdk_default"] = (
            resolved_env.get(environment_vars.CREDENTIALS) == sdk_path
        )
        _install_patches(stack, trace, scenario)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            try:
                credentials, project_id = _default.default(
                    request=transport, **scenario.default_kwargs
                )
            except BaseException as exc:  # noqa: BLE001 - reported, not swallowed
                report["result"] = {
                    "status": "error",
                    "error_type": type(exc).__name__,
                    "error": trace.sanitize(str(exc)),
                }
            else:
                report["result"] = {
                    "status": "ok",
                    "project_id": project_id,
                    **_credential_provenance(credentials, project_id, trace),
                }

        report["warnings"] = [
            {
                "category": warning.category.__name__,
                "message": trace.sanitize(str(warning.message)),
            }
            for warning in caught
        ]

    report.update(trace.report())
    return report


def run_all(scenarios: Optional[Iterable[str]] = None) -> List[Dict[str, Any]]:
    available = _scenarios()
    selected = list(scenarios) if scenarios else list(available)
    unknown = [name for name in selected if name not in available]
    if unknown:
        raise ValueError("Unknown scenario(s): {}".format(", ".join(unknown)))

    with tempfile.TemporaryDirectory(prefix="adc-diagnostics-") as root:
        return [run_scenario(available[name], root) for name in selected]


def _format_markdown(reports: Iterable[Dict[str, Any]]) -> str:
    lines = [
        "# ADC provenance diagnostics",
        "",
        "All results below were produced from synthetic files and stubs. No real "
        "ADC file, gcloud configuration, or metadata endpoint was read.",
        "",
    ]
    for report in reports:
        lines.append("## {}".format(report["scenario"]))
        lines.append("")
        lines.append(report["summary"])
        lines.append("")
        result = report["result"]
        if result["status"] == "ok":
            lines.append("- Result: credentials returned")
            lines.append("- Credential class: `{}`".format(result["credential_class"]))
            lines.append("- Credential type: `{}`".format(result["credential_type"]))
            lines.append("- Source evidence: `{}`".format(result["credential_source"]))
            lines.append("- Principal: `{}`".format(result["principal"]))
            lines.append("- Returned project: `{}`".format(result["project_id"]))
            lines.append("- Quota project: `{}`".format(result["quota_project_id"]))
        else:
            lines.append("- Result: `{}`".format(result["error_type"]))
            lines.append("- Error: `{}`".format(result["error"]))
        lines.append("")
        if report["probes"]:
            lines.append("Probe calls, in order:")
            lines.append("")
            lines.append("| # | Stage | Channel | Call | Result |")
            lines.append("|---|-------|---------|------|--------|")
            for probe in report["probes"]:
                lines.append(
                    "| {seq} | {stage} | {channel} | {action} | {result} |".format(
                        **probe
                    )
                )
            matches = {
                probe.get("explicit_path_matches")
                for probe in report["probes"]
                if "explicit_path_matches" in probe
            }
            lines.append("")
            if matches and report["environment"]["explicit_credentials_path"]:
                lines.append(
                    "The explicit path equals the SDK default path: `{}`.".format(
                        matches.pop()
                    )
                )
                lines.append("")
        if report["events"]:
            lines.append("Ordered events:")
            lines.append("")
            for event in report["events"]:
                detail = ", ".join(
                    "{}={!r}".format(key, value)
                    for key, value in event.items()
                    if key not in ("seq", "stage", "event")
                )
                lines.append(
                    "{seq}. [{stage}] {event}{detail}".format(
                        detail=(" ({})".format(detail) if detail else ""),
                        **event,
                    )
                )
            lines.append("")
        if report["warnings"]:
            lines.append("Warnings:")
            lines.append("")
            for warning in report["warnings"]:
                lines.append(
                    "- {}: {}".format(warning["category"], warning["message"])
                )
            lines.append("")
        lines.append("Interpretation:")
        lines.append("")
        for note in report["notes"]:
            lines.append("- {}".format(note))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario",
        action="append",
        choices=sorted(_scenarios()),
        help="Run only this scenario. May be repeated.",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Output format (default: markdown).",
    )
    args = parser.parse_args(argv)

    reports = run_all(args.scenario)
    if args.format == "json":
        print(json.dumps(reports, indent=2, sort_keys=True))
    else:
        print(_format_markdown(reports), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
