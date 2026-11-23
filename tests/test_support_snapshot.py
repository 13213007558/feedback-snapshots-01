"""Tests for the support snapshot feature of SerializableTokenCache.

A support snapshot is a diagnostic, secret-free export of the token cache:
it preserves the per-tenant account view (so support can tell the same
person apart across tenants) but carries no material usable for silent
token acquisition. The normal serialize()/deserialize() pair remains the
restart-recovery mechanism and is intentionally kept type-incompatible
with snapshots.
"""
import json
import logging

from unittest.mock import patch, Mock

import msal
from msal.token_cache import TokenCache, SerializableTokenCache
from tests import unittest
from tests.test_token_cache import build_id_token, build_response


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

_OIDC_DISCOVERY_MOCK = Mock(return_value={
    "authorization_endpoint": "https://login.example.com/tenant-a/oauth2/v2.0/authorize",
    "token_endpoint": "https://login.example.com/tenant-a/oauth2/v2.0/token",
    "issuer": "https://login.example.com/tenant-a/v2.0",
})

ENVIRONMENT = "login.example.com"
TENANTS = ("tenant-a", "tenant-b")
CLIENTS = ("client-1", "client-2")
UID = "user-uid"
UTID = "home-tenant-id"
HOME_ACCOUNT_ID = "{}.{}".format(UID, UTID)
USERNAME = "jane@example.com"
SCOPES = ["scope1"]


def _tag(kind, tenant, client):
    return "FAKE-{}-{}-{}".format(kind, tenant, client)


def build_populated_cache():
    """A cache with one user signed in via 2 clients across 2 tenants,
    all filled with tagged fake credentials."""
    cache = SerializableTokenCache()
    for tenant in TENANTS:
        for client in CLIENTS:
            cache.add({
                "client_id": client,
                "scope": SCOPES,
                "grant_type": "authorization_code",
                "token_endpoint": "https://{}/{}/oauth2/v2.0/token".format(
                    ENVIRONMENT, tenant),
                "response": build_response(
                    uid=UID, utid=UTID,
                    access_token=_tag("AT", tenant, client),
                    refresh_token=_tag("RT", tenant, client),
                    id_token=build_id_token(
                        sub="sub-" + tenant, oid="oid-" + tenant,
                        preferred_username=USERNAME),
                    expires_in=3600),
                })
    return cache


class _NoNetworkHttpClient(object):
    """An http_client double that fails the test on any outbound call."""

    def __init__(self, test_case):
        self._test_case = test_case
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url))
        raise AssertionError("Unexpected outbound GET {}".format(url))

    def post(self, url, **kwargs):
        self.calls.append(("POST", url))
        raise AssertionError("Unexpected outbound POST {}".format(url))

    def close(self):
        pass


class SupportSnapshotCacheTestCase(unittest.TestCase):

    def setUp(self):
        self.cache = build_populated_cache()
        self.snapshot = self.cache.serialize_support_snapshot()
        self.payload = json.loads(self.snapshot)

    def test_snapshot_distinguishes_same_user_across_tenants(self):
        accounts = self.payload["Account"]
        self.assertEqual(len(TENANTS), len(accounts))
        self.assertEqual(
            set(TENANTS), {a["realm"] for a in accounts.values()})
        for account in accounts.values():
            self.assertEqual(HOME_ACCOUNT_ID, account["home_account_id"])
            self.assertEqual(USERNAME, account["username"])
            self.assertEqual(ENVIRONMENT, account["environment"])
            self.assertEqual(
                TokenCache.AuthorityType.MSSTS, account["authority_type"])
            self.assertIn("local_account_id", account)
        # Same person, different tenants -> different tenant-specific ids
        self.assertEqual(
            set("oid-" + t for t in TENANTS),
            {a["local_account_id"] for a in accounts.values()})

    def test_snapshot_contains_no_token_material(self):
        for tenant in TENANTS:
            for client in CLIENTS:
                for kind in ("AT", "RT"):
                    self.assertNotIn(_tag(kind, tenant, client), self.snapshot)
        for section in ("AccessToken", "RefreshToken", "IdToken"):
            self.assertNotIn(section, self.payload)
        self.assertNotIn("secret", json.dumps(self.payload))
        # Only approved fields survive on each account entry
        approved = SerializableTokenCache._SUPPORT_SNAPSHOT_SCHEMA["Account"]
        for account in self.payload["Account"].values():
            self.assertEqual(set(), set(account.keys()) - approved)

    def test_snapshot_is_marked_and_detectable(self):
        marker = self.payload[SerializableTokenCache.SUPPORT_SNAPSHOT_MARKER]
        self.assertEqual(
            SerializableTokenCache.SUPPORT_SNAPSHOT_VERSION, marker["version"])
        self.assertTrue(SerializableTokenCache.is_support_snapshot(self.snapshot))
        self.assertFalse(
            SerializableTokenCache.is_support_snapshot(self.cache.serialize()))
        self.assertFalse(SerializableTokenCache.is_support_snapshot("not json"))

    def test_deserialize_rejects_snapshot_to_keep_type_boundary(self):
        with self.assertRaises(ValueError):
            SerializableTokenCache().deserialize(self.snapshot)

    def test_import_snapshot_restores_minimal_account_view(self):
        imported = SerializableTokenCache()
        imported.deserialize_support_snapshot(self.snapshot)
        accounts = list(imported.search(TokenCache.CredentialType.ACCOUNT))
        self.assertEqual(len(TENANTS), len(accounts))
        self.assertEqual(set(TENANTS), {a["realm"] for a in accounts})
        self.assertFalse(list(search_credentials(imported)))

    def test_import_ignores_smuggled_credentials(self):
        tampered = dict(self.payload)
        tampered["RefreshToken"] = {"evil": {
            "credential_type": "RefreshToken", "secret": "stolen-rt",
            "home_account_id": HOME_ACCOUNT_ID, "environment": ENVIRONMENT,
            "client_id": CLIENTS[0]}}
        tampered["Account"] = {k: dict(v, secret="smuggled")
            for k, v in self.payload["Account"].items()}
        imported = SerializableTokenCache()
        imported.deserialize_support_snapshot(json.dumps(tampered))
        self.assertFalse(list(search_credentials(imported)))
        for account in imported.search(TokenCache.CredentialType.ACCOUNT):
            self.assertNotIn("secret", account)

    def test_import_requires_snapshot_document(self):
        with self.assertRaises(ValueError):
            SerializableTokenCache().deserialize_support_snapshot(
                self.cache.serialize())

    def test_merge_then_reserialize_keeps_type_boundary(self):
        archive = self.cache.serialize()
        # Merge the snapshot into a live, fully-populated cache
        merged = SerializableTokenCache()
        merged.deserialize(archive)
        merged.deserialize_support_snapshot(self.snapshot)
        # Re-serialized snapshot is still secret-free
        resnapshot = merged.serialize_support_snapshot()
        for tenant in TENANTS:
            for client in CLIENTS:
                self.assertNotIn(_tag("RT", tenant, client), resnapshot)
                self.assertNotIn(_tag("AT", tenant, client), resnapshot)
        self.assertNotIn("RefreshToken", json.loads(resnapshot))
        # Re-serialized full state is still a normal cache (no marker),
        # round-trips through deserialize(), and keeps its credentials
        rearchive = merged.serialize()
        self.assertNotIn(SerializableTokenCache.SUPPORT_SNAPSHOT_MARKER,
            json.loads(rearchive))
        restored = SerializableTokenCache()
        restored.deserialize(rearchive)
        rts = list(restored.search(TokenCache.CredentialType.REFRESH_TOKEN))
        self.assertTrue(rts)
        self.assertTrue(all(rt["secret"].startswith("FAKE-RT-") for rt in rts))


def search_credentials(cache):
    for section in ("AccessToken", "RefreshToken", "IdToken"):
        for entry in cache.search(section):
            yield entry


@patch("msal.authority.tenant_discovery", new=_OIDC_DISCOVERY_MOCK)
class SupportSnapshotEndToEndTestCase(unittest.TestCase):
    """The acceptance scenario: 2 tenants x 2 clients with tagged fake
    credentials; support export and normal archive go their separate ways."""

    def setUp(self):
        self.cache = build_populated_cache()
        self.snapshot = self.cache.serialize_support_snapshot()
        self.archive = self.cache.serialize()

    def _build_app(self, cache):
        http_client = _NoNetworkHttpClient(self)
        app = msal.PublicClientApplication(
            CLIENTS[0],
            authority="https://{}/{}".format(ENVIRONMENT, TENANTS[0]),
            token_cache=cache,
            instance_discovery=False,  # So this test needs no metadata traffic
            http_client=http_client)
        return app, http_client

    def test_support_snapshot_into_empty_cache(self):
        imported = SerializableTokenCache()
        imported.deserialize_support_snapshot(self.snapshot)
        app, http_client = self._build_app(imported)

        # The minimal account view shows the approved fields
        accounts = app.get_accounts()
        self.assertEqual(1, len(accounts))  # Same person, grouped by home id
        account = accounts[0]
        self.assertEqual(USERNAME, account["username"])
        self.assertEqual(HOME_ACCOUNT_ID, account["home_account_id"])
        self.assertEqual(ENVIRONMENT, account["environment"])
        self.assertEqual(
            TokenCache.AuthorityType.MSSTS, account["authority_type"])
        self.assertIn(account["realm"], TENANTS)  # Tenant-specific state
        # ... and both tenants remain distinguishable at cache level
        self.assertEqual(
            set(TENANTS),
            {a["realm"] for a in imported.search(
                TokenCache.CredentialType.ACCOUNT)})

        # A silent call must not attempt authorized refresh:
        # it returns None and emits no outbound request.
        result = app.acquire_token_silent(SCOPES, account)
        self.assertIsNone(result)
        self.assertEqual([], http_client.calls)

    def test_normal_archive_still_supports_restart_recovery(self):
        recovered = SerializableTokenCache()
        recovered.deserialize(self.archive)
        app, http_client = self._build_app(recovered)

        accounts = app.get_accounts()
        self.assertEqual(1, len(accounts))
        result = app.acquire_token_silent(SCOPES, accounts[0])
        self.assertIsNotNone(result)
        self.assertEqual(
            _tag("AT", TENANTS[0], CLIENTS[0]), result["access_token"])
        # Served from the recovered cache; no network was needed either
        self.assertEqual([], http_client.calls)


if __name__ == "__main__":
    unittest.main()
