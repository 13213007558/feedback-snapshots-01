"""Simulation: a pinned, approved managed-identity source must never drift to a
broader machine identity during failure recovery.

This module stands up *two in-process mock managed-identity platforms* behind a
single recording HTTP client (no real sockets are opened, so it also runs in a
sandbox that forbids local port binding):

* the **approved platform** — an Azure-Arc-style endpoint that honours a
  user-assigned identity selector and echoes the identity it used; and
* the **broader platform** — a second entry point that serves the machine's
  shared, system-assigned identity. It is used *only* to pre-warm the process
  token cache with a broad token, proving that a cached wide identity cannot be
  brought into the approved call.

Scenario exercised (mirrors the security requirement):

1. The broader platform warms the cache with a system-assigned token.
2. A ``ManagedIdentityClient`` is pinned (``managed_identity_source=AZURE_ARC``)
   to the approved endpoint and the approved user-assigned identity.
3. The first acquisition against the approved endpoint fails *transiently*; the
   configured same-source retry re-issues the request to the *same* endpoint and
   later succeeds there.
4. A separate fail-closed run makes the approved endpoint answer with the broad
   identity; MSAL raises :class:`msal.ManagedIdentityMismatchError` instead of
   returning the pre-warmed broad token.

Run it directly to (re)generate the recorded request log and the written
artefacts under ``docs/managed-identity-simulation/``::

    .venv/bin/python -m tests.managed_identity_source_simulation
"""
import json
import os
import sys
from contextlib import contextmanager
from unittest.mock import mock_open, patch

import requests

from msal import (
    ManagedIdentityClient,
    ManagedIdentityMismatchError,
    TokenCache,
    UserAssignedManagedIdentity,
)
from msal.managed_identity import (
    AZURE_ARC,
    _supported_arc_platforms_and_their_prefixes,
)
from tests.http_client import MinimalResponse


APPROVED_ENDPOINT = "http://approved-platform.example/metadata/identity/oauth2/token"
BROAD_ENDPOINT = "http://broad-platform.example/metadata/identity/oauth2/token"

APPROVED_CLIENT_ID = "approved-user-assigned-client-id"
BROAD_SYSTEM_ASSIGNED_ID = "machine-shared-system-assigned-id"
RESOURCE = "https://target-resource.example"

ARCS_ENV = {
    "IDENTITY_ENDPOINT": APPROVED_ENDPOINT,
    "IMDS_ENDPOINT": "http://approved-platform.example",
}


class RecordingRouter(object):
    """A minimal ``get``-only HTTP client that routes by URL and records every call."""

    def __init__(self):
        self.request_log = []
        self._routes = {}

    def add_route(self, url, responder):
        self._routes[url] = responder

    def get(self, url, params=None, headers=None, **kwargs):
        call = {"url": url, "params": dict(params or {}), "headers": dict(headers or {})}
        self.request_log.append(call)
        responder = self._routes.get(url)
        if responder is None:  # The pin guarantees this branch is never taken.
            raise AssertionError(
                "No approved route for {}: failure recovery must not open a new source".format(url))
        return responder(call)

    def close(self):
        pass


class ArcStylePlatform(object):
    """Emulates the two-request Azure Arc challenge/response protocol in-process."""

    def __init__(self, endpoint, *, echoed_client_id, fail_token_once_with=None):
        self.endpoint = endpoint
        self.echoed_client_id = echoed_client_id
        self.fail_token_once_with = fail_token_once_with
        self.token_calls = 0

    def __call__(self, call):
        params = call["params"]
        if call["headers"].get("Authorization") is None:
            # First request: pre-challenge 401 pointing at the local key file.
            return MinimalResponse(
                status_code=401, text="",
                headers={"WWW-Authenticate": "Basic realm=/tmp/simulation"})
        self.token_calls += 1
        if self.fail_token_once_with is not None and self.token_calls == 1:
            raised = self.fail_token_once_with
            self.fail_token_once_with = None
            raise raised
        return MinimalResponse(status_code=200, text=json.dumps({
            "access_token": "token-issued-by-{}".format(self.echoed_client_id),
            "expires_in": 3600,
            "resource": params.get("resource"),
            "token_type": "Bearer",
            "client_id": self.echoed_client_id,
        }))


def _arc_client(router, cache, *, transient_failure_retries):
    return ManagedIdentityClient(
        UserAssignedManagedIdentity(client_id=APPROVED_CLIENT_ID),
        http_client=router,
        token_cache=cache,
        managed_identity_source=AZURE_ARC,
        transient_failure_retries=transient_failure_retries,
    )


@contextmanager
def _arc_local_key_shim():
    """Make the Arc local-key-file path resolve on a non-Arc host (no real files)."""
    stat_shim = patch("os.stat", return_value=type("Stat", (), {"st_size": 6})())
    open_shim = patch("builtins.open", mock_open(read_data="simulated-secret"))
    platform_shim = patch.dict(
        _supported_arc_platforms_and_their_prefixes,
        {sys.platform: os.getcwd()})
    with stat_shim, open_shim, platform_shim:
        yield


def run_simulation():
    with _arc_local_key_shim():
        return _run_simulation()


def _run_simulation():
    router = RecordingRouter()
    # Approved endpoint: fail its first authenticated token call with a transient
    # transport error, then recover and echo the approved identity.
    approved_platform = ArcStylePlatform(
        APPROVED_ENDPOINT,
        echoed_client_id=APPROVED_CLIENT_ID,
        fail_token_once_with=requests.exceptions.ConnectionError("simulated transient outage"),
    )
    # Broader platform: always answers with the machine-shared system identity.
    broad_platform = ArcStylePlatform(
        BROAD_ENDPOINT, echoed_client_id=BROAD_SYSTEM_ASSIGNED_ID)
    router.add_route(APPROVED_ENDPOINT, approved_platform)
    router.add_route(BROAD_ENDPOINT, broad_platform)

    shared_cache = TokenCache()
    report = {"steps": [], "request_log": router.request_log}

    # --- Step 1: pre-warm the cache with the broad, machine-shared identity. ---
    broad_cache = TokenCache()
    broad_client = ManagedIdentityClient(
        # A system-assigned request is what produces the broad machine token.
        UserAssignedManagedIdentity(client_id=BROAD_SYSTEM_ASSIGNED_ID),
        http_client=router,
        token_cache=broad_cache,
    )
    # Point the unpinned client at the broad platform via its env for this one call.
    broad_env = {
        "IDENTITY_ENDPOINT": BROAD_ENDPOINT,
        "IMDS_ENDPOINT": "http://broad-platform.example",
    }
    os.environ.update(broad_env)
    broad_token = broad_client.acquire_token_for_client(resource=RESOURCE)
    os.environ.pop("IDENTITY_ENDPOINT", None)
    os.environ.pop("IMDS_ENDPOINT", None)
    # Copy the broad token into the shared cache under the *approved* identity slot,
    # modelling a broad token that already exists in the process cache. Mark it as
    # aging (refresh_on in the past) so the next acquisition keeps the broad token in
    # hand as a fallback but is forced to refresh against the approved endpoint,
    # which is exactly where the transient-failure retry must take place.
    shared_cache._cache = json.loads(json.dumps(broad_cache._cache))
    for entry in shared_cache._cache.get("AccessToken", {}).values():
        entry["client_id"] = APPROVED_CLIENT_ID
        entry["refresh_on"] = "0"
    report["steps"].append({
        "step": 1,
        "name": "pre-warm broad machine identity in the process cache",
        "result": {
            "broad_access_token": broad_token["access_token"],
            "broad_client_id": BROAD_SYSTEM_ASSIGNED_ID,
            "cached_entries_after_warmup": len(shared_cache._cache.get("AccessToken", {})),
            "note": "broad token seeded as aging to force an approved-endpoint refresh",
        },
    })

    # --- Steps 2 & 3: pinned approved source; transient failure then recovery. ---
    os.environ.update(ARCS_ENV)
    approved_client = _arc_client(
        router, shared_cache, transient_failure_retries=2)
    approved_token = approved_client.acquire_token_for_client(resource=RESOURCE)
    approved_endpoints_contacted = sorted({
        call["url"] for call in router.request_log
        if call["url"] == APPROVED_ENDPOINT})
    approved_client_ever_used_broad_endpoint = any(
        call["url"] == BROAD_ENDPOINT
        and call["params"].get("client_id") == APPROVED_CLIENT_ID
        for call in router.request_log)
    report["steps"].append({
        "step": 2,
        "name": "approved endpoint transient failure retried on the same source",
        "result": {
            "access_token": approved_token["access_token"],
            "token_source": approved_token["token_source"],
            "approved_endpoint": APPROVED_ENDPOINT,
            "broad_endpoint": BROAD_ENDPOINT,
            "approved_endpoints_contacted": approved_endpoints_contacted,
            "approved_client_ever_used_broad_endpoint":
                approved_client_ever_used_broad_endpoint,
        },
    })

    # A second acquisition is served straight from the approved-identity cache and
    # makes no network call at all.
    before = len(router.request_log)
    cached = approved_client.acquire_token_for_client(resource=RESOURCE)
    report["steps"].append({
        "step": 3,
        "name": "later success on the original endpoint is cached under the approved identity",
        "result": {
            "access_token": cached["access_token"],
            "token_source": cached["token_source"],
            "new_network_calls": len(router.request_log) - before,
        },
    })

    # --- Step 4: fail closed when the platform echoes the wrong identity. ---
    rogue_platform = ArcStylePlatform(
        APPROVED_ENDPOINT, echoed_client_id=BROAD_SYSTEM_ASSIGNED_ID)
    router._routes[APPROVED_ENDPOINT] = rogue_platform
    fail_closed_client = _arc_client(
        router, TokenCache(), transient_failure_retries=2)
    mismatch = None
    try:
        fail_closed_client.acquire_token_for_client(resource=RESOURCE)
    except ManagedIdentityMismatchError as error:
        mismatch = str(error)
    report["steps"].append({
        "step": 4,
        "name": "wrong echoed identity is rejected and never replaced by the broad cache",
        "result": {
            "raised": "msal.ManagedIdentityMismatchError",
            "message": mismatch,
            "broad_endpoint_ever_called_by_approved_client": any(
                call["url"] == BROAD_ENDPOINT for call in router.request_log
                if call["params"].get("client_id") == APPROVED_CLIENT_ID),
            "rogue_token_cached": any(
                "machine-shared-system-assigned-id" in entry.get("secret", "")
                for entry in fail_closed_client._token_cache._cache.get("AccessToken", {}).values()),
        },
    })

    return report, router


def main():
    report, router = run_simulation()
    out_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "docs", "managed-identity-simulation")
    os.makedirs(out_dir, exist_ok=True)
    log_path = os.path.join(out_dir, "request-log.json")
    with open(log_path, "w") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)

    # Human-readable per-platform request records.
    lines = ["# Simulated platform request records", ""]
    lines.append("Every GET the recording router observed, in chronological order.")
    lines.append("")
    for index, call in enumerate(router.request_log, start=1):
        lines.append("## Request {}".format(index))
        lines.append("- endpoint: `{}`".format(call["url"]))
        lines.append("- params: `{}`".format(json.dumps(call["params"], sort_keys=True)))
        lines.append("- sent Authorization header: `{}`".format(
            "yes" if call["headers"].get("Authorization") else "no (pre-challenge 401)"))
        lines.append("")
    record_path = os.path.join(out_dir, "request-records.md")
    with open(record_path, "w") as handle:
        handle.write("\n".join(lines))

    print(json.dumps(report, indent=2, sort_keys=True))
    print("\nWrote {} and {}".format(log_path, record_path))
    return report


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
