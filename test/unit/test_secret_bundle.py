# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""
Unit tests for coordinated release-manifest bundle reads.
"""
import unittest

import botocore
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from aws_secretsmanager_caching import (
    ComponentStatus,
    SecretBundleUnavailableError,
    SecretCache,
    SecretComponent,
    SecretRelease,
    SecretReleaseManifest,
)
from aws_secretsmanager_caching.config import SecretCacheConfig

USERNAME_SECRET = "db/username"
PASSWORD_SECRET = "db/password"

USERNAME_OLD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
USERNAME_NEW = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
PASSWORD_OLD = "cccccccccccccccccccccccccccccccc"
PASSWORD_NEW = "dddddddddddddddddddddddddddddddd"


def _client_error(operation="GetSecretValue"):
    return ClientError(
        {"Error": {"Code": "ResourceNotFoundException", "Message": "version not yet available"}},
        operation,
    )


class FakeSecretsManagerClient:
    """In-memory secretsmanager client supporting stage-based and version-id reads.

    A version can be marked unavailable to emulate the two entries updating at
    different speeds: until it becomes available, get_secret_value raises the
    same ClientError the real service would.
    """

    def __init__(self):
        # secret_id -> version_id -> {"SecretString": value, "available": bool}
        self._versions = {}
        # secret_id -> stage -> version_id
        self._stages = {}

    def put_version(self, secret_id, version_id, secret_string, available=True, stages=None):
        self._versions.setdefault(secret_id, {})[version_id] = {
            "SecretString": secret_string,
            "available": available,
        }
        for stage in stages or []:
            self._stages.setdefault(secret_id, {})[stage] = version_id

    def make_available(self, secret_id, version_id):
        self._versions[secret_id][version_id]["available"] = True

    def get_secret_value(self, SecretId=None, VersionId=None, VersionStage=None):
        if VersionId is None and VersionStage is not None:
            VersionId = self._stages.get(SecretId, {}).get(VersionStage)
        record = self._versions.get(SecretId, {}).get(VersionId)
        if record is None or not record["available"]:
            raise _client_error()
        return {"Name": SecretId, "VersionId": VersionId, "SecretString": record["SecretString"]}

    def describe_secret(self, SecretId=None):
        version_ids_to_stages = {}
        for stage, version_id in self._stages.get(SecretId, {}).items():
            version_ids_to_stages.setdefault(version_id, []).append(stage)
        return {"Name": SecretId, "VersionIdsToStages": version_ids_to_stages}


def _build_manifest():
    old_release = SecretRelease(
        release_id="release-1",
        components=[
            SecretComponent(name="username", secret_id=USERNAME_SECRET, version_id=USERNAME_OLD),
            SecretComponent(name="password", secret_id=PASSWORD_SECRET, version_id=PASSWORD_OLD),
        ],
    )
    new_release = SecretRelease(
        release_id="release-2",
        components=[
            SecretComponent(name="username", secret_id=USERNAME_SECRET, version_id=USERNAME_NEW),
            SecretComponent(name="password", secret_id=PASSWORD_SECRET, version_id=PASSWORD_NEW),
        ],
    )
    manifest = SecretReleaseManifest(name="db-credentials")
    manifest.add_release(old_release)
    manifest.add_release(new_release)
    return manifest, old_release, new_release


def _build_client():
    client = FakeSecretsManagerClient()
    # Old release: both entries present and available.
    client.put_version(USERNAME_SECRET, USERNAME_OLD, "user-old", stages=["AWSPREVIOUS"])
    client.put_version(PASSWORD_SECRET, PASSWORD_OLD, "pass-old", stages=["AWSCURRENT"])
    # New release: username has rolled out, password version is not yet available.
    client.put_version(
        USERNAME_SECRET, USERNAME_NEW, "user-new", available=True, stages=["AWSCURRENT"]
    )
    client.put_version(PASSWORD_SECRET, PASSWORD_NEW, "pass-new", available=False)
    return client


class TestSecretBundle(unittest.TestCase):
    def _cache(self, client):
        # No retry backoff so an unavailable version fails immediately and
        # stays retriable once it becomes available.
        config = SecretCacheConfig(exception_retry_delay_base=0, exception_retry_delay_max=0)
        return SecretCache(config=config, client=client)

    def test_rollout_falls_back_then_unavailable_then_new_release(self):
        client = _build_client()
        manifest, old_release, new_release = _build_manifest()
        cache = self._cache(client)

        # 1) New release is incomplete (password version not available), so the
        #    complete previous release is returned.
        bundle = cache.get_secret_bundle(manifest)
        self.assertEqual(bundle.release_id, old_release.release_id)
        self.assertEqual(bundle.get("username"), "user-old")
        self.assertEqual(bundle.get("password"), "pass-old")
        self.assertEqual(
            bundle.statuses,
            {"username": ComponentStatus.AVAILABLE, "password": ComponentStatus.AVAILABLE},
        )

        # Single-key reads keep their stage semantics and are independent of the
        # bundle: username already moved to AWSCURRENT, password lags behind.
        self.assertEqual(cache.get_secret_string(USERNAME_SECRET), "user-new")
        self.assertEqual(cache.get_secret_string(PASSWORD_SECRET), "pass-old")

        # 2) Revoke the old manifest while the new password is still missing.
        #    No approved release is complete -> explicit unavailability, not a
        #    partial or cached-as-success result.
        manifest.revoke_release(old_release.release_id)
        with self.assertRaises(SecretBundleUnavailableError):
            cache.get_secret_bundle(manifest)

        # The failed new-release attempt must not have cached a success: the
        # pinned password version still carries an exception and no result.
        password_version = cache._bundle_reader._versions.get((PASSWORD_SECRET, PASSWORD_NEW))
        self.assertIsNotNone(password_version)
        self.assertIsNotNone(password_version._exception)
        self.assertIsNone(password_version._get_result())

        # 3) The password version finishes rolling out; the complete new
        #    release is now served.
        client.make_available(PASSWORD_SECRET, PASSWORD_NEW)
        bundle = cache.get_secret_bundle(manifest)
        self.assertEqual(bundle.release_id, new_release.release_id)
        self.assertEqual(bundle.get("username"), "user-new")
        self.assertEqual(bundle.get("password"), "pass-new")

    def test_null_component_skips_release_and_falls_back(self):
        client = FakeSecretsManagerClient()
        client.put_version(USERNAME_SECRET, USERNAME_OLD, "user-old")
        client.put_version(PASSWORD_SECRET, PASSWORD_OLD, "pass-old")
        client.put_version(USERNAME_SECRET, USERNAME_NEW, "user-new")
        # An empty SecretString is a null value, not a usable credential.
        client.put_version(PASSWORD_SECRET, PASSWORD_NEW, "", available=True)

        manifest, _old, new_release = _build_manifest()
        cache = self._cache(client)

        bundle = cache.get_secret_bundle(manifest)
        self.assertEqual(bundle.release_id, "release-1")
        self.assertEqual(bundle.values, {"username": "user-old", "password": "pass-old"})

        # The incomplete new release reports NULL for the empty password value.
        value, status = cache._bundle_reader._resolve_component(
            new_release.component("password")
        )
        self.assertEqual(value, "")
        self.assertEqual(status, ComponentStatus.NULL)
        self.assertIsNone(cache._bundle_reader._try_release(new_release))

    def test_all_releases_incomplete_raises_and_does_not_cache_success(self):
        client = FakeSecretsManagerClient()
        client.put_version(USERNAME_SECRET, USERNAME_NEW, "user-new")
        client.put_version(PASSWORD_SECRET, PASSWORD_NEW, "pass-new", available=False)

        manifest = SecretReleaseManifest(name="only-new")
        manifest.add_release(
            SecretRelease(
                release_id="release-2",
                components=[
                    SecretComponent("username", USERNAME_SECRET, USERNAME_NEW),
                    SecretComponent("password", PASSWORD_SECRET, PASSWORD_NEW),
                ],
            )
        )
        cache = self._cache(client)

        with self.assertRaises(SecretBundleUnavailableError):
            cache.get_secret_bundle(manifest)

        # Once the missing component appears, the same cache serves the bundle;
        # the earlier failure left no bogus success cached.
        client.make_available(PASSWORD_SECRET, PASSWORD_NEW)
        bundle = cache.get_secret_bundle(manifest)
        self.assertEqual(bundle.get("username"), "user-new")
        self.assertEqual(bundle.get("password"), "pass-new")

    def test_empty_manifest_is_unavailable(self):
        cache = self._cache(FakeSecretsManagerClient())
        with self.assertRaises(SecretBundleUnavailableError):
            cache.get_secret_bundle(SecretReleaseManifest(name="empty"))

    def test_revoke_unknown_release_raises(self):
        manifest, _old, _new = _build_manifest()
        with self.assertRaises(KeyError):
            manifest.revoke_release("does-not-exist")

    def test_revoked_release_is_skipped(self):
        client = _build_client()
        manifest, old_release, _new = _build_manifest()
        manifest.revoke_release(old_release.release_id)
        cache = self._cache(client)
        with self.assertRaises(SecretBundleUnavailableError):
            cache.get_secret_bundle(manifest)

    def test_pinned_version_id_is_sent_to_service(self):
        client = botocore.session.get_session().create_client(
            "secretsmanager", region_name="us-west-2"
        )
        stubber = Stubber(client)
        stubber.add_response(
            "get_secret_value",
            {"Name": USERNAME_SECRET, "VersionId": USERNAME_OLD, "SecretString": "user-old"},
            {"SecretId": USERNAME_SECRET, "VersionId": USERNAME_OLD},
        )
        stubber.add_response(
            "get_secret_value",
            {"Name": PASSWORD_SECRET, "VersionId": PASSWORD_OLD, "SecretString": "pass-old"},
            {"SecretId": PASSWORD_SECRET, "VersionId": PASSWORD_OLD},
        )
        stubber.activate()

        manifest = SecretReleaseManifest(name="db-credentials")
        manifest.add_release(
            SecretRelease(
                release_id="release-1",
                components=[
                    SecretComponent("username", USERNAME_SECRET, USERNAME_OLD),
                    SecretComponent("password", PASSWORD_SECRET, PASSWORD_OLD),
                ],
            )
        )
        cache = self._cache(client)
        bundle = cache.get_secret_bundle(manifest)
        self.assertEqual(bundle.values, {"username": "user-old", "password": "pass-old"})
        stubber.assert_no_pending_responses()

    def test_single_key_reads_keep_stage_semantics(self):
        client = _build_client()
        cache = self._cache(client)
        # Stage-based reads reflect the uneven rollout directly.
        self.assertEqual(cache.get_secret_string(USERNAME_SECRET), "user-new")
        self.assertEqual(cache.get_secret_string(PASSWORD_SECRET), "pass-old")
        self.assertIsNone(cache.get_secret_binary(USERNAME_SECRET))
