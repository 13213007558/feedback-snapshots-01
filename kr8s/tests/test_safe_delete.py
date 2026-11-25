# SPDX-FileCopyrightText: Copyright (c) 2023-2026, Kr8s Developers (See LICENSE for list)
# SPDX-License-Identifier: BSD 3-Clause License
"""Tests for identity-pinned safe deletion.

These tests never talk to a cluster. ``FakeApi`` is an in-memory stand-in for
:class:`kr8s._api.Api` that understands DELETE preconditions and can inject
connection failures at specific points.
"""

import json
from contextlib import asynccontextmanager

import httpx
import pytest

from kr8s._exceptions import ServerError
from kr8s.asyncio.objects import DeleteResult, Pod


class FakeResponse:
    """Minimal stand-in for an httpx response."""

    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class FakeApi:
    """In-memory Kubernetes API double keyed by object name and uid.

    It enforces DELETE ``preconditions`` the way the API server does:

    * a precondition uid that no longer matches yields HTTP 409;
    * deleting a missing name yields HTTP 404.

    Connection failures can be scheduled per DELETE attempt. Failures raised
    *before* the store is mutated model a request lost before the server
    received it; failures raised *after* mutation model a response lost after
    the server confirmed the object was gone.
    """

    def __init__(self, objects):
        self._objects = {obj["metadata"]["name"]: obj for obj in objects}
        self.namespace = "default"
        self.requests = []
        self.before_server_failures = []
        self.after_server_failures = []
        self.get_failures = []

    @asynccontextmanager
    async def call_api(self, method, version, url, namespace=None, content=None, **_):
        name = url.rsplit("/", 1)[-1]
        if method == "GET":
            get_attempt = len([r for r in self.requests if r[0] == "GET"]) + 1
            self.requests.append(("GET", name, None))
            if get_attempt in self.get_failures:
                raise httpx.ConnectError("connection refused during reconciliation")
            current = self._objects.get(name)
            if current is None:
                yield FakeResponse(404, {})
            else:
                yield FakeResponse(200, current)
            return

        body = json.loads(content)
        preconditions = body.get("preconditions", {})
        self.requests.append(("DELETE", name, body))
        attempt = len([r for r in self.requests if r[0] == "DELETE"])

        if attempt in self.before_server_failures:
            raise httpx.ConnectError("connection refused before server receipt")

        current = self._objects.get(name)
        if current is None:
            raise ServerError(
                "not found",
                status={"code": 404},
                response=FakeResponse(404, {"code": 404}),
            )
        current_uid = current["metadata"]["uid"]
        if "uid" in preconditions and preconditions["uid"] != current_uid:
            raise ServerError(
                "precondition failed: uid conflict",
                status={"code": 409},
                response=FakeResponse(409, {"code": 409}),
            )
        if (
            "resourceVersion" in preconditions
            and preconditions["resourceVersion"]
            != current["metadata"]["resourceVersion"]
        ):
            raise ServerError(
                "precondition failed: resourceVersion conflict",
                status={"code": 409},
                response=FakeResponse(409, {"code": 409}),
            )

        removed = self._objects.pop(name)
        if attempt in self.after_server_failures:
            raise httpx.ReadError("connection reset after server delete")
        yield FakeResponse(200, removed)

    def put(self, obj):
        self._objects[obj["metadata"]["name"]] = obj

    def uid_of(self, name):
        current = self._objects.get(name)
        return None if current is None else current["metadata"]["uid"]


def make_pod(api, name="demo", uid="uid-original", resource_version="100"):
    return Pod(
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": name,
                "namespace": "default",
                "uid": uid,
                "resourceVersion": resource_version,
            },
        },
        api=api,
    )


def replacement_object(name="demo", uid="uid-replacement"):
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": "default",
            "uid": uid,
            "resourceVersion": "200",
        },
    }


def delete_preconditions(api):
    return [
        body["preconditions"] for method, _, body in api.requests if method == "DELETE"
    ]


async def test_safe_delete_sends_identity_preconditions_and_succeeds():
    api = FakeApi([make_pod(api=None).raw])
    pod = make_pod(api)

    result = await pod.async_safe_delete()

    assert isinstance(result, DeleteResult)
    assert result.status == "deleted"
    assert result.deleted is True
    assert result.certain is True
    assert result.delete_attempts == 1
    assert result.preconditions == {"uid": "uid-original", "resourceVersion": "100"}
    assert delete_preconditions(api) == [
        {"uid": "uid-original", "resourceVersion": "100"}
    ]
    assert api.uid_of("demo") is None
    assert result.next_actions


async def test_interruption_before_server_retry_uses_same_identity():
    # First DELETE is lost before the server receives anything; the object
    # survives and the retry must carry the exact same preconditions.
    api = FakeApi([make_pod(api=None).raw])
    api.before_server_failures = [1]
    pod = make_pod(api)

    result = await pod.async_safe_delete(max_retries=3)

    assert result.status == "deleted"
    assert result.delete_attempts == 2
    preconditions = delete_preconditions(api)
    assert len(preconditions) == 2
    assert preconditions[0] == preconditions[1] == result.preconditions
    assert preconditions[0]["uid"] == "uid-original"
    assert api.uid_of("demo") is None


async def test_interruption_before_server_with_replacement_preserves_new_object():
    # Lost request, then a brand-new object reuses the name before the retry.
    api = FakeApi([make_pod(api=None).raw])
    api.before_server_failures = [1]
    pod = make_pod(api)

    @asynccontextmanager
    async def replace_on_retry(*args, **kwargs):
        api.put(replacement_object())
        async with original_call(*args, **kwargs) as response:
            yield response

    original_call = api.call_api
    api.call_api = replace_on_retry

    result = await pod.async_safe_delete(max_retries=3)

    assert result.status == "replaced"
    assert result.observed_uid == "uid-replacement"
    assert result.uid == "uid-original"
    # The retry still targeted the original uid, so the new object is intact.
    assert api.uid_of("demo") == "uid-replacement"
    assert all(p["uid"] == "uid-original" for p in delete_preconditions(api))
    assert result.next_actions


async def test_interruption_after_server_confirmed_delete():
    # The server deletes the object but the response is lost. Reconciliation by
    # uid (not name) must still report a definite outcome.
    api = FakeApi([make_pod(api=None).raw])
    api.after_server_failures = [1]
    pod = make_pod(api)

    result = await pod.async_safe_delete(max_retries=3)

    assert result.status == "deleted"
    assert result.delete_attempts == 1
    assert api.uid_of("demo") is None
    assert result.certain is True


async def test_interruption_after_server_with_replacement_preserves_new_object():
    # After the confirmed delete a new object takes the name; reconciliation can
    # only match the previous approval by uid, never infer from the current name.
    api = FakeApi([make_pod(api=None).raw])
    api.after_server_failures = [1]
    pod = make_pod(api)

    @asynccontextmanager
    async def replace_on_get(*args, **kwargs):
        if kwargs.get("method") == "GET" or args[0] == "GET":
            api.put(replacement_object())
        async with original_call(*args, **kwargs) as response:
            yield response

    original_call = api.call_api
    api.call_api = replace_on_get

    result = await pod.async_safe_delete(max_retries=3)

    assert result.status == "replaced"
    assert result.uid == "uid-original"
    assert result.observed_uid == "uid-replacement"
    assert api.uid_of("demo") == "uid-replacement"
    assert all(p["uid"] == "uid-original" for p in delete_preconditions(api))
    assert result.next_actions


async def test_retries_exhausted_while_original_survives_is_unknown():
    # Every request is lost before the server receives it and the original uid
    # is still present: the conservative answer is "unknown", not "deleted".
    api = FakeApi([make_pod(api=None).raw])
    api.before_server_failures = [1, 2]
    pod = make_pod(api)

    result = await pod.async_safe_delete(max_retries=2)

    assert result.status == "unknown"
    assert result.deleted is False
    assert result.certain is False
    assert result.observed_uid == "uid-original"
    assert result.delete_attempts == 2
    assert all(p["uid"] == "uid-original" for p in delete_preconditions(api))
    assert api.uid_of("demo") == "uid-original"
    assert "retry" in " ".join(result.next_actions).lower()


async def test_server_409_with_replacement_reports_replaced():
    api = FakeApi([replacement_object()])
    pod = make_pod(api)

    result = await pod.async_safe_delete()

    assert result.status == "replaced"
    assert result.observed_uid == "uid-replacement"
    assert api.uid_of("demo") == "uid-replacement"
    assert result.next_actions


async def test_server_404_then_name_reused_reports_replaced():
    # The server first answers 404, but by reconciliation time a same-name
    # object with a different uid exists: the name alone must not be read as
    # "my object was deleted".
    api = FakeApi([])
    pod = make_pod(api)
    original_call = api.call_api

    @asynccontextmanager
    async def insert_replacement_before_get(*args, **kwargs):
        if (args[0] if args else kwargs.get("method")) == "GET":
            api.put(replacement_object())
        async with original_call(*args, **kwargs) as response:
            yield response

    api.call_api = insert_replacement_before_get

    result = await pod.async_safe_delete()

    assert result.status == "replaced"
    assert result.uid == "uid-original"
    assert result.observed_uid == "uid-replacement"
    assert api.uid_of("demo") == "uid-replacement"


async def test_server_404_when_absent_reports_already_absent():
    api = FakeApi([])
    pod = make_pod(api)

    result = await pod.async_safe_delete()

    assert result.status == "already_absent"
    assert result.observed_uid is None
    assert result.next_actions


async def test_safe_delete_without_uid_raises():
    api = FakeApi([])
    pod = Pod({"metadata": {"name": "demo", "namespace": "default"}}, api=api)

    with pytest.raises(ValueError):
        await pod.async_safe_delete()


async def test_force_and_grace_period_are_mutually_exclusive():
    api = FakeApi([make_pod(api=None).raw])
    pod = make_pod(api)

    with pytest.raises(ValueError):
        await pod.async_safe_delete(grace_period=5, force=True)


async def test_force_delete_sets_zero_grace_period_alongside_preconditions():
    api = FakeApi([make_pod(api=None).raw])
    pod = make_pod(api)

    result = await pod.async_safe_delete(force=True)

    assert result.status == "deleted"
    delete_body = next(body for method, _, body in api.requests if method == "DELETE")
    assert delete_body["gracePeriodSeconds"] == 0
    assert delete_body["preconditions"] == {
        "uid": "uid-original",
        "resourceVersion": "100",
    }


async def test_explicit_uid_overrides_object_metadata():
    pod_spec = make_pod(api=None, uid="uid-explicit").raw
    pod_spec["metadata"].pop("resourceVersion")
    api = FakeApi([pod_spec])
    pod = Pod(pod_spec, api=api)
    pod.metadata["uid"] = "uid-stale"

    result = await pod.async_safe_delete(uid="uid-explicit")

    assert result.status == "deleted"
    assert result.uid == "uid-explicit"
    assert result.preconditions == {"uid": "uid-explicit"}


async def test_reconciliation_failure_is_never_reported_as_deleted():
    # Both the DELETE and every reconciliation GET fail: the answer must stay
    # conservative ("unknown") even though the object is still in the store.
    api = FakeApi([make_pod(api=None).raw])
    api.before_server_failures = [1, 2]
    api.get_failures = [1, 2]
    pod = make_pod(api)

    result = await pod.async_safe_delete(max_retries=2)

    assert result.status == "unknown"
    assert result.deleted is False
    assert result.certain is False
    assert result.observed_uid is None
    assert result.delete_attempts == 2
    assert api.uid_of("demo") == "uid-original"
    assert all(p["uid"] == "uid-original" for p in delete_preconditions(api))
    assert result.next_actions


async def test_observation_recovers_on_later_retry_with_same_identity():
    # First DELETE and its reconciliation GET fail; the second attempt succeeds
    # and must still be bounded to the original captured identity.
    api = FakeApi([make_pod(api=None).raw])
    api.before_server_failures = [1]
    api.get_failures = [1]
    pod = make_pod(api)

    result = await pod.async_safe_delete(max_retries=3)

    assert result.status == "deleted"
    assert result.delete_attempts == 2
    preconditions = delete_preconditions(api)
    assert len(preconditions) == 2
    assert all(p["uid"] == "uid-original" for p in preconditions)
    assert api.uid_of("demo") is None


async def test_reconciliation_failure_after_404_stays_unknown():
    # A 404 followed by a failed reconciliation must not be claimed as a
    # definite delete; the caller can only retry with the same uid.
    api = FakeApi([])
    api.get_failures = [1]
    pod = make_pod(api)

    result = await pod.async_safe_delete()

    assert result.status == "unknown"
    assert result.certain is False
    assert result.uid == "uid-original"
    assert result.next_actions
