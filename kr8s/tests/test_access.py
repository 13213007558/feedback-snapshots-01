# SPDX-FileCopyrightText: Copyright (c) 2023-2026, Kr8s Developers (See LICENSE for list)
# SPDX-License-Identifier: BSD 3-Clause License
"""Tests for per-resource-version discovery and request authorization.

These tests use a local HTTP transport, so they do not require a Kubernetes
cluster. The transport records every request that is actually sent, which is
how the "preflight rejects before sending" behaviour is verified.
"""

from __future__ import annotations

from urllib.parse import parse_qs

import httpx
import pytest

import kr8s
from kr8s._api import Api
from kr8s._async_utils import anext

GROUP = "example.com"
# Same resource name, two local version definitions:
#   v1alpha is approved for read (get) requests only.
#   v1beta1 is approved for list requests only.
VERSION_READ = "v1alpha"
VERSION_LIST = "v1beta1"
RESOURCE = "widgets"


def _discovery_payloads(versions: dict[str, dict]) -> dict[str, dict]:
    group_versions = [
        {"groupVersion": f"{GROUP}/{version}", "version": version}
        for version in versions
    ]
    payloads: dict[str, dict] = {
        "/api": {"versions": ["v1"]},
        "/api/v1": {"resources": []},
        "/apis": {"groups": [{"name": GROUP, "versions": group_versions}]},
    }
    for version, resource in versions.items():
        payloads[f"/apis/{GROUP}/{version}"] = {"resources": [resource]}
    return payloads


def widget_resource(version: str, verbs: list[str]) -> dict:
    return {
        "name": RESOURCE,
        "singularName": "widget",
        "namespaced": True,
        "kind": "Widget",
        "verbs": verbs,
    }


class Recorder:
    """Local HTTP transport that serves discovery and records real requests."""

    def __init__(self, versions: dict[str, dict]) -> None:
        self.versions = versions
        self.requests: list[dict] = []

    def set_versions(self, versions: dict[str, dict]) -> None:
        self.versions = versions

    def discovery(self) -> dict[str, dict]:
        return _discovery_payloads(self.versions)

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if len(path) > 1:
            path = path.rstrip("/")
        self.requests.append(
            {
                "method": request.method,
                "path": path,
                "query": parse_qs(request.url.query.decode()),
                "body": request.content.decode() if request.content else "",
            }
        )
        discovery = self.discovery()
        if path in discovery:
            return httpx.Response(200, json=discovery[path])
        if path.startswith(f"/apis/{GROUP}/"):
            if request.method == "GET":
                if path.count("/") > 3 and not path.endswith(RESOURCE):
                    # A single named object.
                    return httpx.Response(
                        200, json={"kind": "Widget", "metadata": {"name": "w"}}
                    )
                items = []
                field_selector = parse_qs(request.url.query.decode()).get(
                    "fieldSelector", [""]
                )[0]
                if "metadata.name=w" in field_selector:
                    items.append({"kind": "Widget", "metadata": {"name": "w"}})
                return httpx.Response(200, json={"items": items, "metadata": {}})
            return httpx.Response(
                201, json={"kind": "Widget", "metadata": {"name": "w"}}
            )
        return httpx.Response(404, json={"message": f"unexpected path {path}"})

    def resource_requests(self) -> list[dict]:
        """Requests that target the resource itself (not discovery)."""
        return [
            r
            for r in self.requests
            if r["path"].startswith(f"/apis/{GROUP}/") and r["path"].count("/") > 3
        ]


def make_api(recorder: Recorder) -> Api:
    api = Api(bypass_factory=True, url="https://example.invalid")
    api.auth.server = "https://example.invalid"

    async def create_session(self) -> None:
        self._session = httpx.AsyncClient(
            base_url="https://example.invalid",
            transport=httpx.MockTransport(recorder.handler),
        )

    api._create_session = create_session.__get__(api, Api)  # type: ignore[method-assign]
    return api


async def _close(api: Api) -> None:
    if api._session:
        await api._session.aclose()


def _two_versions() -> dict[str, dict]:
    return {
        VERSION_READ: widget_resource(VERSION_READ, ["get", "watch"]),
        VERSION_LIST: widget_resource(VERSION_LIST, ["list"]),
    }


def _policy() -> kr8s.AccessPolicy:
    policy = kr8s.AccessPolicy()
    # Same resource name, two versions, two different approvals. Both are
    # allowed to appear in the catalog.
    policy.allow(RESOURCE, group=GROUP, version=VERSION_READ, verbs=["get", "watch"])
    policy.allow(RESOURCE, group=GROUP, version=VERSION_LIST, verbs=["list"])
    return policy


async def test_catalog_shows_both_versions_with_their_own_verbs() -> None:
    recorder = Recorder(_two_versions())
    api = make_api(recorder)
    api.access_policy = _policy()
    try:
        resources = await api.async_api_resources()
        versions = {r["version"]: r for r in resources if r["name"] == RESOURCE}
        assert set(versions) == {f"{GROUP}/{VERSION_READ}", f"{GROUP}/{VERSION_LIST}"}
        assert versions[f"{GROUP}/{VERSION_READ}"]["kr8sApprovedVerbs"] == [
            "get",
            "watch",
        ]
        assert versions[f"{GROUP}/{VERSION_LIST}"]["kr8sApprovedVerbs"] == ["list"]
    finally:
        await _close(api)


async def test_lookup_selects_version_for_the_real_verb() -> None:
    recorder = Recorder(_two_versions())
    api = make_api(recorder)
    api.access_policy = _policy()
    try:
        kind_for_get, plural, namespaced = await api.async_lookup_kind(
            RESOURCE, verb="get"
        )
        assert kind_for_get == f"widget.{GROUP}/{VERSION_READ}"
        assert plural == RESOURCE
        assert namespaced is True

        kind_for_list, _, _ = await api.async_lookup_kind(RESOURCE, verb="list")
        assert kind_for_list == f"widget.{GROUP}/{VERSION_LIST}"
    finally:
        await _close(api)


async def test_real_queries_go_to_the_approved_version() -> None:
    recorder = Recorder(_two_versions())
    api = make_api(recorder)
    api.access_policy = _policy()
    try:
        # A list request resolves to the list-approved version.
        widgets = [w async for w in api.get(RESOURCE, namespace="ns")]
        assert widgets == []
        assert recorder.resource_requests()[-1] == {
            "method": "GET",
            "path": f"/apis/{GROUP}/{VERSION_LIST}/namespaces/ns/widgets",
            "query": {"limit": ["100"]},
            "body": "",
        }

        # A direct read of one object uses the read-approved version.
        async with api.call_api(
            "GET",
            version=f"{GROUP}/{VERSION_READ}",
            url=f"{RESOURCE}/w",
            namespace="ns",
        ) as response:
            await response.aread()
        assert recorder.resource_requests()[-1]["path"] == (
            f"/apis/{GROUP}/{VERSION_READ}/namespaces/ns/widgets/w"
        )

        # The list-only version may list, but a get or a watch against it is
        # rejected before it leaves the client, even though the same resource
        # name is approved for reads at another version.
        async with api.call_api(
            "GET",
            version=f"{GROUP}/{VERSION_LIST}",
            url=RESOURCE,
            namespace="ns",
        ) as response:
            await response.aread()
        assert recorder.resource_requests()[-1]["path"] == (
            f"/apis/{GROUP}/{VERSION_LIST}/namespaces/ns/widgets"
        )

        with pytest.raises(kr8s.AccessDeniedError, match="not approved for 'get'"):
            async with api.call_api(
                "GET",
                version=f"{GROUP}/{VERSION_LIST}",
                url=f"{RESOURCE}/w",
                namespace="ns",
            ):
                pass
        with pytest.raises(kr8s.AccessDeniedError, match="not approved for 'watch'"):
            async with api.call_api(
                "GET",
                version=f"{GROUP}/{VERSION_LIST}",
                url=RESOURCE,
                namespace="ns",
                params={"watch": "true"},
            ):
                pass

        # Only the approved queries above reached the server.
        assert [
            r["method"] + " " + r["path"] for r in recorder.resource_requests()
        ] == [
            f"GET /apis/{GROUP}/{VERSION_LIST}/namespaces/ns/widgets",
            f"GET /apis/{GROUP}/{VERSION_READ}/namespaces/ns/widgets/w",
            f"GET /apis/{GROUP}/{VERSION_LIST}/namespaces/ns/widgets",
        ]
    finally:
        await _close(api)


async def test_named_get_uses_the_real_list_request() -> None:
    recorder = Recorder(_two_versions())
    api = make_api(recorder)
    api.access_policy = _policy()
    try:
        widget = await anext(api.get(RESOURCE, "w", namespace="ns"))
        assert widget.name == "w"
        # kr8s resolves a named read with a list request carrying a field
        # selector. That is a 'list' verb, so it targets the list-approved
        # version even though a get-approved version exists for the same name.
        request = recorder.resource_requests()[0]
        assert request["path"] == f"/apis/{GROUP}/{VERSION_LIST}/namespaces/ns/widgets"
        assert request["query"]["fieldSelector"] == ["metadata.name=w,"]
    finally:
        await _close(api)


async def test_write_preflight_rejects_both_versions_without_sending() -> None:
    recorder = Recorder(_two_versions())
    api = make_api(recorder)
    api.access_policy = _policy()
    try:
        for version in (VERSION_READ, VERSION_LIST):
            payload = {
                "apiVersion": f"{GROUP}/{version}",
                "kind": "Widget",
                "metadata": {"name": "w", "namespace": "ns"},
            }
            widget = kr8s.objects.new_class("Widget", f"{GROUP}/{version}")(
                payload, api=api
            )

            with pytest.raises(kr8s.AccessDeniedError) as excinfo:
                await widget.async_create()
            assert excinfo.value.decision is not None
            assert excinfo.value.decision.verb == "create"
            assert excinfo.value.decision.version == version
            assert excinfo.value.decision.allowed is False
            assert "not approved for 'create'" in str(excinfo.value)

            with pytest.raises(kr8s.AccessDeniedError):
                await widget.async_delete()
            with pytest.raises(kr8s.AccessDeniedError):
                await widget.async_patch({"metadata": {"labels": {"a": "b"}}})

        # The write preflight ran entirely on the client.
        assert recorder.resource_requests() == []
    finally:
        await _close(api)


async def test_new_version_does_not_inherit_approval_after_refresh() -> None:
    recorder = Recorder(_two_versions())
    api = make_api(recorder)
    api.access_policy = _policy()
    try:
        await api.async_api_resources()
        assert len(recorder.requests) == 5  # /api, /api/v1, /apis, two group versions

        # Discovery is cached. A second catalog read must not refetch.
        await api.async_api_resources()
        assert len(recorder.requests) == 5

        # The server now serves a stable version under the same resource name.
        # Refreshing discovery must not grant it the old approvals.
        new_versions = _two_versions()
        new_versions["v1"] = widget_resource("v1", ["get", "list", "watch", "create"])
        recorder.set_versions(new_versions)
        resources = await api.async_refresh_api_resources()
        assert f"{GROUP}/v1" not in {r["version"] for r in resources}

        decisions = {
            (d.group, d.version): d
            for d in await api.async_api_resource_access()
            if d.resource == RESOURCE
        }
        assert decisions[(GROUP, "v1")].visible is False
        assert decisions[(GROUP, "v1")].allowed is False
        assert decisions[(GROUP, VERSION_READ)].visible is True
        assert decisions[(GROUP, VERSION_LIST)].visible is True
        assert "not visible in discovery" in decisions[(GROUP, "v1")].explain()

        # The new version cannot be looked up or requested, and the error says
        # exactly why.
        with pytest.raises(kr8s.AccessDeniedError) as excinfo:
            await api.async_lookup_kind(f"{RESOURCE}.{GROUP}/v1", verb="get")
        assert "discovered at" in str(excinfo.value)
        assert "has not been approved" in str(excinfo.value)

        with pytest.raises(kr8s.AccessDeniedError):
            async with api.call_api(
                "GET",
                version=f"{GROUP}/v1",
                url=RESOURCE,
                namespace="ns",
            ):
                pass

        # No request was sent for the unapproved version.
        assert all("/v1/" not in r["path"] for r in recorder.resource_requests())
    finally:
        await _close(api)


async def test_policy_changes_apply_to_cached_discovery() -> None:
    recorder = Recorder(_two_versions())
    api = make_api(recorder)
    api.access_policy = _policy()
    try:
        await api.async_api_resources()
        assert len(recorder.requests) == 5

        # Approving the list version for get is visible immediately, without a
        # new discovery round trip.
        api.access_policy.allow(
            RESOURCE, group=GROUP, version=VERSION_LIST, verbs=["list", "get"]
        )
        resources = await api.async_api_resources()
        assert len(recorder.requests) == 5
        entry = [r for r in resources if r["version"] == f"{GROUP}/{VERSION_LIST}"][0]
        assert entry["kr8sApprovedVerbs"] == ["get", "list"]

        # Removing the read approval hides that version from the catalog
        # without refetching.
        api.access_policy.deny(RESOURCE, group=GROUP, version=VERSION_READ)
        resources = await api.async_api_resources()
        assert len(recorder.requests) == 5
        assert f"{GROUP}/{VERSION_READ}" not in {r["version"] for r in resources}
    finally:
        await _close(api)


async def test_websocket_preflight_uses_create_and_skips_connection() -> None:
    recorder = Recorder(_two_versions())
    api = make_api(recorder)
    api.access_policy = _policy()
    try:
        # exec/attach/portforward are authorized with the create verb, so a
        # read-approved version must not open a websocket for them.
        with pytest.raises(kr8s.AccessDeniedError) as excinfo:
            async with api.open_websocket(
                version=f"{GROUP}/{VERSION_READ}",
                url=f"{RESOURCE}/w/exec",
                namespace="ns",
            ):
                pass
        assert excinfo.value.decision is not None
        assert excinfo.value.decision.verb == "create"
        assert recorder.requests == []
    finally:
        await _close(api)


async def test_request_verb_resolution() -> None:
    from kr8s._api import _parse_resource_path, _request_verb

    assert _request_verb("GET", False, None, None) == "list"
    assert _request_verb("GET", True, None, None) == "get"
    assert _request_verb("GET", False, None, {"watch": "true"}) == "watch"
    assert _request_verb("POST", False, None, None) == "create"
    assert _request_verb("PUT", True, None, None) == "update"
    assert _request_verb("PATCH", True, None, None) == "patch"
    assert _request_verb("DELETE", True, None, None) == "delete"
    assert _request_verb("DELETE", False, None, None) == "deletecollection"
    assert _request_verb("GET", True, "exec", None) == "create"

    assert _parse_resource_path("/api") is None
    assert _parse_resource_path("/apis") is None
    assert _parse_resource_path("/version") is None
    assert _parse_resource_path("/apis/apps/v1") is None
    assert _parse_resource_path("/api/v1/pods") == ("", "v1", "pods", False, None)
    assert _parse_resource_path("/api/v1/namespaces/ns/pods/p1") == (
        "",
        "v1",
        "pods",
        True,
        None,
    )
    assert _parse_resource_path("/apis/apps/v1/deployments/d1/scale") == (
        "apps",
        "v1",
        "deployments",
        True,
        "scale",
    )
