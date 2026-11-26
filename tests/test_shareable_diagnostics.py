# Copyright 2021-2025 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

import json
import logging

import grpc
import httpx
import pytest
from google.protobuf import struct_pb2

from cerbos.effect.v1.effect_pb2 import EFFECT_ALLOW, EFFECT_DENY
from cerbos.engine.v1 import engine_pb2
from cerbos.request.v1 import request_pb2
from cerbos.response.v1 import response_pb2
from cerbos.sdk._sync._grpc import CerbosClient as GrpcCerbosClient
from cerbos.sdk._sync._http import CerbosClient as HttpCerbosClient
from cerbos.sdk.diagnostics import (
    DiagnosticStatus,
    PublicScope,
    SecretRedactionFilter,
    build_diagnostic_report,
    diagnostic_view,
    log_diagnostics,
)
from cerbos.sdk.grpc.utils import get_resource, is_allowed
from cerbos.sdk.model import (
    CheckResourcesRequest,
    CheckResourcesResponse,
    CheckResourcesResult,
    Effect,
    Principal,
    Resource,
    ResourceList,
)

PARTIAL_MARKER = "SYNTHETIC-PRIVATE-MARKER-PARTIAL-7F3A9C21"
ERROR_MARKER = "SYNTHETIC-PRIVATE-MARKER-ERROR-2D84E6B0"
PARTIAL_CORRELATION = "corr-partial-7558"
ERROR_CORRELATION = "corr-error-7558"
POLICY_VERSION = "2026-11-support"
RESOURCE_ID = "ticket-7558"
RESOURCE_KIND = "support_ticket"
ACTIONS = ("view", "resolve", "export_diagnostic", "missing_action")


class LocalHttpEngine:
    """Small local engine double which records raw requests and engine logs."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.engine_logs: list[str] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.requests.append(body)
        marker = body["principal"]["attr"]["private_marker"]
        correlation = body["requestId"]

        if body["principal"]["id"] == "principal-error":
            message = f"policy compiler failure near private fragment {marker}"
            self.engine_logs.append(message)
            return httpx.Response(
                500,
                json={"code": 13, "message": message},
            )

        leak = f"output evaluator echoed {marker}"
        self.engine_logs.append(leak)
        return httpx.Response(
            200,
            json={
                "requestId": correlation,
                "cerbosCallId": "call-http-partial-7558",
                "results": [
                    {
                        "resource": {
                            "id": RESOURCE_ID,
                            "kind": RESOURCE_KIND,
                            "policyVersion": POLICY_VERSION,
                        },
                        "actions": {
                            "view": "EFFECT_ALLOW",
                            "resolve": "EFFECT_DENY",
                            "export_diagnostic": "EFFECT_ALLOW",
                        },
                        "meta": {
                            "actions": {
                                "view": {
                                    "matchedPolicy": "support.ticket.view.v202611",
                                    "matchedScope": "acme.support",
                                },
                                "resolve": {
                                    "matchedPolicy": "support.ticket.resolve.v202611",
                                    "matchedScope": "acme.support",
                                },
                                "export_diagnostic": {
                                    "matchedPolicy": "support.ticket.export.v202611",
                                    "matchedScope": "acme.support",
                                },
                            }
                        },
                        "outputs": [
                            {
                                "src": "support.ticket.export.v202611#redacted-export",
                                "action": "export_diagnostic",
                                "error": leak,
                                "val": None,
                            }
                        ],
                    }
                ],
            },
        )


class FakeGrpcError(grpc.RpcError):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self._message = message

    def code(self):
        return grpc.StatusCode.FAILED_PRECONDITION

    def details(self) -> str:
        return self._message


class LocalGrpcEngine:
    def __init__(self) -> None:
        self.requests: list[request_pb2.CheckResourcesRequest] = []

    def CheckResources(
        self, request: request_pb2.CheckResourcesRequest
    ) -> response_pb2.CheckResourcesResponse:
        self.requests.append(request)
        marker = request.principal.attr["private_marker"].string_value
        if request.principal.id == "principal-error":
            raise FakeGrpcError(f"gRPC compiler failure {marker}")

        meta = response_pb2.CheckResourcesResponse.ResultEntry.Meta(
            actions={
                "view": response_pb2.CheckResourcesResponse.ResultEntry.Meta.EffectMeta(
                    matched_policy="support.ticket.view.v202611",
                    matched_scope="acme.support",
                ),
                "resolve": response_pb2.CheckResourcesResponse.ResultEntry.Meta.EffectMeta(
                    matched_policy="support.ticket.resolve.v202611",
                    matched_scope="acme.support",
                ),
                "export_diagnostic": response_pb2.CheckResourcesResponse.ResultEntry.Meta.EffectMeta(
                    matched_policy="support.ticket.export.v202611",
                    matched_scope="acme.support",
                ),
            }
        )
        return response_pb2.CheckResourcesResponse(
            request_id=request.request_id,
            cerbos_call_id="call-grpc-partial-7558",
            results=[
                response_pb2.CheckResourcesResponse.ResultEntry(
                    resource=response_pb2.CheckResourcesResponse.ResultEntry.Resource(
                        id=RESOURCE_ID,
                        kind=RESOURCE_KIND,
                        policy_version=POLICY_VERSION,
                    ),
                    actions={
                        "view": EFFECT_ALLOW,
                        "resolve": EFFECT_DENY,
                        "export_diagnostic": EFFECT_ALLOW,
                    },
                    meta=meta,
                    outputs=[
                        engine_pb2.OutputEntry(
                            src="support.ticket.export.v202611#redacted-export",
                            action="export_diagnostic",
                            error=f"gRPC output leak {marker}",
                        )
                    ],
                )
            ],
        )


def partial_principal() -> Principal:
    return Principal(
        id="principal-partial",
        roles={"support_agent"},
        policy_version=POLICY_VERSION,
        attr={"private_marker": PARTIAL_MARKER, "team": "support"},
    )


def error_principal() -> Principal:
    return Principal(
        id="principal-error",
        roles={"support_agent"},
        policy_version=POLICY_VERSION,
        attr={"private_marker": ERROR_MARKER, "team": "support"},
    )


def resource() -> Resource:
    return Resource(
        id=RESOURCE_ID,
        kind=RESOURCE_KIND,
        policy_version=POLICY_VERSION,
        attr={
            "case_id": "CASE-7558",
            "geography": "GB",
            "private_resource_marker": PARTIAL_MARKER,
        },
    )


def resource_list() -> ResourceList:
    return ResourceList().add(resource(), set(ACTIONS))


def public_support_scope() -> PublicScope:
    return PublicScope(
        allowed_fields={
            "schema_version",
            "correlation_id",
            "request_id",
            "cerbos_call_id",
            "status",
            "partial",
            "failed",
            "summary",
            "items.action",
            "items.status",
            "items.decision",
            "items.allowed",
            "items.found",
            "items.resource_found",
            "items.result_present",
            "items.failed",
            "items.policy",
            "items.matched_policy",
            "items.version",
            "items.policy_version",
            "items.correlation_id",
            "items.resource_id",
            "items.error.type",
            "items.error.code",
            "error.type",
            "error.code",
        }
    )


def test_http_raw_request_response_public_report_and_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    engine = LocalHttpEngine()
    transport = httpx.MockTransport(engine.handle)
    logger = logging.getLogger("test.diagnostics.http")

    with HttpCerbosClient(
        "http://local-engine", transport=transport, logger=logger
    ) as client:
        response = client.check_resources(
            partial_principal(),
            resource_list(),
            request_id=PARTIAL_CORRELATION,
            include_meta=True,
        )

    # The engine still receives the original private value unchanged.
    raw_request = engine.requests[-1]
    assert raw_request["principal"]["attr"]["private_marker"] == PARTIAL_MARKER
    assert raw_request["includeMeta"] is True
    assert any(PARTIAL_MARKER in line for line in engine.engine_logs)

    # The existing in-app authorization contract is unchanged.
    assert not response.failed()
    result = response.get_resource(RESOURCE_ID)
    assert result is not None
    assert result.is_allowed("view") is True
    assert result.is_allowed("resolve") is False
    assert result.is_allowed("missing_action") is False
    assert response.results[0].outputs[0].error.endswith(PARTIAL_MARKER)

    report = build_diagnostic_report(response, secret_values=[PARTIAL_MARKER])
    view = report.public_view(public_support_scope())
    payload = view.to_json(sort_keys=True)

    assert view["status"] == "partial"
    assert view["partial"] is True
    assert view["failed"] is False
    by_action = {item["action"]: item for item in view.entries}
    assert set(by_action) == set(ACTIONS)

    assert by_action["view"]["status"] == DiagnosticStatus.ALLOWED.value
    assert by_action["view"]["policy"] == "support.ticket.view.v202611"
    assert by_action["resolve"]["status"] == DiagnosticStatus.DENIED.value
    assert by_action["resolve"]["policy"] == "support.ticket.resolve.v202611"
    assert by_action["export_diagnostic"]["status"] == DiagnosticStatus.ERROR.value
    assert by_action["missing_action"]["status"] == DiagnosticStatus.MISSING.value
    assert by_action["missing_action"]["found"] is False
    assert by_action["missing_action"]["resource_found"] is True
    assert by_action["missing_action"]["result_present"] is False

    for item in view.entries:
        assert item["version"] == POLICY_VERSION
        assert item["correlation_id"] == PARTIAL_CORRELATION
        assert item["action"] in ACTIONS

    assert PARTIAL_MARKER not in payload
    assert "SYNTHETIC-PRIVATE" not in payload
    assert "case_id" not in payload
    assert "team" not in payload

    with caplog.at_level(logging.INFO, logger=logger.name):
        logged_view = log_diagnostics(view, logger=logger)
    assert logged_view is view
    assert PARTIAL_MARKER not in caplog.text
    assert "missing_action" in caplog.text
    assert "support.ticket.resolve.v202611" in caplog.text

    # An app can deliberately expose messages, but known private values are
    # still scrubbed by the shared redactor.
    verbose = report.public_view(
        PublicScope(
            allowed_fields="all",
            secret_values=[PARTIAL_MARKER],
            expose_error_messages=True,
        )
    )
    assert PARTIAL_MARKER not in verbose.to_json()
    assert "[REDACTED]" in verbose.to_json()


def test_http_entire_request_failure_lists_every_action(
    caplog: pytest.LogCaptureFixture,
) -> None:
    engine = LocalHttpEngine()
    with HttpCerbosClient(
        "http://local-engine", transport=httpx.MockTransport(engine.handle)
    ) as client:
        response = client.check_resources(
            error_principal(),
            resource_list(),
            request_id=ERROR_CORRELATION,
        )

    assert response.failed()
    assert response.status_msg is not None
    assert ERROR_MARKER in response.status_msg.message
    assert any(ERROR_MARKER in line for line in engine.engine_logs)

    view = diagnostic_view(
        response,
        secret_values=[ERROR_MARKER],
        public_scope=PublicScope(allowed_fields="all", expose_error_messages=True),
    )
    assert view["status"] == "failed"
    assert view["failed"] is True
    assert view["partial"] is False
    assert {item["action"] for item in view.entries} == set(ACTIONS)
    for item in view.entries:
        assert item["status"] == "failed"
        assert item["result_present"] is False
        assert item["correlation_id"] == ERROR_CORRELATION
        assert item["version"] == POLICY_VERSION

    with caplog.at_level(logging.ERROR):
        logger = logging.getLogger("test.diagnostics.http.error")
        logger.error(view.to_json())
    assert ERROR_MARKER not in caplog.text


def test_grpc_diagnostics_match_http_fields() -> None:
    engine = LocalGrpcEngine()
    client = GrpcCerbosClient.__new__(GrpcCerbosClient)
    client._client = engine

    principal = engine_pb2.Principal(
        id="principal-partial",
        roles=["support_agent"],
        policy_version=POLICY_VERSION,
        attr={"private_marker": struct_pb2.Value(string_value=PARTIAL_MARKER)},
    )
    grpc_resource = engine_pb2.Resource(
        id=RESOURCE_ID, kind=RESOURCE_KIND, policy_version=POLICY_VERSION
    )
    entries = [
        request_pb2.CheckResourcesRequest.ResourceEntry(
            actions=list(ACTIONS), resource=grpc_resource
        )
    ]

    response = client.check_resources(
        principal, entries, request_id=PARTIAL_CORRELATION, include_meta=True
    )
    raw_request = engine.requests[-1]
    assert raw_request.principal.attr["private_marker"].string_value == PARTIAL_MARKER
    assert raw_request.include_meta is True
    result = get_resource(response, RESOURCE_ID)
    assert result is not None
    assert is_allowed(result, "view") is True
    assert is_allowed(result, "resolve") is False

    view = diagnostic_view(
        response,
        request=raw_request,
        public_scope=public_support_scope(),
        secret_values=[PARTIAL_MARKER],
    )
    assert view["status"] == "partial"
    grpc_fields = sorted(
        (
            item["action"],
            item["status"],
            item["policy"],
            item["version"],
            item["correlation_id"],
        )
        for item in view.entries
    )

    http_engine = LocalHttpEngine()
    http_request = CheckResourcesRequest(
        request_id=PARTIAL_CORRELATION,
        principal=partial_principal(),
        resources=resource_list(),
    )
    http_response = CheckResourcesResponse.from_dict(
        http_engine.handle(
            httpx.Request(
                "POST",
                "http://local/api/check/resources",
                content=json.dumps(
                    {
                        "requestId": PARTIAL_CORRELATION,
                        "principal": partial_principal().to_dict(),
                        "resources": [
                            {
                                "resource": resource().to_dict(),
                                "actions": list(ACTIONS),
                            }
                        ],
                    }
                ).encode(),
            )
        ).json()
    )
    http_view = diagnostic_view(
        http_response,
        request=http_request,
        public_scope=public_support_scope(),
        secret_values=[PARTIAL_MARKER],
    )
    http_fields = sorted(
        (
            item["action"],
            item["status"],
            item["policy"],
            item["version"],
            item["correlation_id"],
        )
        for item in http_view.entries
    )
    assert grpc_fields == http_fields
    assert PARTIAL_MARKER not in view.to_json()

    error_view = client.diagnose_check_resources(
        engine_pb2.Principal(
            id="principal-error",
            roles=["support_agent"],
            policy_version=POLICY_VERSION,
            attr={"private_marker": struct_pb2.Value(string_value=ERROR_MARKER)},
        ),
        entries,
        request_id=ERROR_CORRELATION,
        public_scope=PublicScope(allowed_fields="all", expose_error_messages=True),
    )
    assert error_view["status"] == "failed"
    assert {item["action"] for item in error_view.entries} == set(ACTIONS)
    assert all(item["status"] == "failed" for item in error_view.entries)
    assert ERROR_MARKER not in error_view.to_json()


def test_secret_log_filter_scrubs_engine_fragments() -> None:
    log_filter = SecretRedactionFilter([PARTIAL_MARKER])
    record = logging.LogRecord(
        name="engine",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="diagnostic from engine: %s",
        args=(f"prefix {PARTIAL_MARKER} suffix",),
        exc_info=None,
    )
    assert log_filter.filter(record) is True
    assert PARTIAL_MARKER not in record.getMessage()
    assert "[REDACTED]" in record.getMessage()


def test_application_attribute_allowlist_is_the_only_attribute_output() -> None:
    principal = partial_principal()
    checked_resource = resource()
    request = CheckResourcesRequest(
        request_id=PARTIAL_CORRELATION,
        principal=principal,
        resources=ResourceList().add(checked_resource, {"view"}),
    )
    response = CheckResourcesResponse(
        request_id=PARTIAL_CORRELATION,
        results=[
            CheckResourcesResult(
                resource=checked_resource,
                actions={"view": Effect.ALLOW},
            )
        ],
    )

    view = diagnostic_view(
        response,
        request=request,
        public_scope=PublicScope(
            allowed_fields="all",
            public_attributes={
                "principal": ["team"],
                "resource": ["geography"],
            },
        ),
    )

    assert view["principal_attributes"] == {"team": "support"}
    assert view.entries[0]["attributes"] == {"geography": "GB"}
    assert PARTIAL_MARKER not in view.to_json()
    assert "private_resource_marker" not in view.to_json()
