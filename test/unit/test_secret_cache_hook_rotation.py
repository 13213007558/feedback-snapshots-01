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
# ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
"""Unit tests for rotating envelope hooks and per-entry migration."""
from datetime import datetime, timezone
import unittest
from unittest.mock import patch

from aws_secretsmanager_caching.cache.secret_cache_hook import (
    RotatingSecretCacheHook,
    SecretCacheEnvelope,
    SecretCacheEnvelopeFormatError,
    SecretCacheEnvelopeIntegrityError,
    SecretCacheKeyUnavailableError,
)
from aws_secretsmanager_caching.config import SecretCacheConfig
from aws_secretsmanager_caching.secret_cache import SecretCache

OLD_KEY = b"old-envelope-key"
NEW_KEY = b"new-envelope-key"
THIRD_KEY = b"third-envelope-key"


class FakeSecretsManager:
    """Minimal Secrets Manager client backed by an in-memory map."""

    def __init__(self):
        self.values = {}
        self.calls = []

    def add_secret(self, secret_id, version_id, value, stage="AWSCURRENT"):
        self.values.setdefault(secret_id, {"versions": {}, "stages": {}})
        self.values[secret_id]["versions"][version_id] = value
        self.values[secret_id]["stages"][version_id] = [stage]

    def rotate_secret(self, secret_id, version_id, value):
        self.add_secret(secret_id, version_id, value)
        for existing in self.values[secret_id]["versions"]:
            if existing != version_id:
                self.values[secret_id]["stages"][existing] = ["AWSPREVIOUS"]

    def describe_secret(self, SecretId):  # noqa: N803 - botocore parameter name
        self.calls.append(("describe_secret", SecretId))
        secret = self.values[SecretId]
        return {
            "Name": SecretId,
            "VersionIdsToStages": {
                version_id: list(stages) for version_id, stages in secret["stages"].items()
            },
        }

    def get_secret_value(self, SecretId, VersionId):  # noqa: N803
        self.calls.append(("get_secret_value", SecretId, VersionId))
        value = dict(self.values[SecretId]["versions"][VersionId])
        value["VersionId"] = VersionId
        return value


class TestRotatingSecretCacheHook(unittest.TestCase):

    def test_round_trip_string_and_binary(self):
        hook = RotatingSecretCacheHook(OLD_KEY)
        envelope = hook.put({"SecretString": "mysecret", "SecretBinary": b"\x00\x01"})
        self.assertIsInstance(envelope, SecretCacheEnvelope)
        self.assertEqual(
            hook.get(envelope),
            {"SecretString": "mysecret", "SecretBinary": b"\x00\x01"},
        )

    def test_round_trip_nested_and_datetime(self):
        hook = RotatingSecretCacheHook(OLD_KEY)
        created = datetime(2026, 11, 23, tzinfo=timezone.utc)
        value = {"Tags": [{"Key": "a", "Value": "b"}], "CreatedDate": created}
        self.assertEqual(hook.get(hook.put(value)), value)

    def test_round_trip_reserved_tag_shaped_dict(self):
        hook = RotatingSecretCacheHook(OLD_KEY)
        value = {"SecretString": {"__aws_secretsmanager_caching_bytes__": "not-bytes"}}
        self.assertEqual(hook.get(hook.put(value)), value)

    def test_key_id_is_derived_and_stable(self):
        first = RotatingSecretCacheHook(OLD_KEY)
        second = RotatingSecretCacheHook(OLD_KEY)
        self.assertEqual(first.primary_key_id, second.primary_key_id)
        self.assertNotEqual(first.primary_key_id, RotatingSecretCacheHook(NEW_KEY).primary_key_id)

    def test_rotate_retains_previous_key_for_reads(self):
        hook = RotatingSecretCacheHook(OLD_KEY)
        legacy = hook.put({"SecretString": "old"})
        hook.rotate(NEW_KEY)

        self.assertTrue(hook.needs_rewrap(legacy))
        self.assertEqual(hook.get(legacy), {"SecretString": "old"})
        current = hook.put({"SecretString": "new"})
        self.assertFalse(hook.needs_rewrap(current))

    def test_rotate_without_retaining_previous_key(self):
        hook = RotatingSecretCacheHook(OLD_KEY)
        legacy = hook.put({"SecretString": "old"})
        hook.rotate(NEW_KEY, retain_previous=False)

        with self.assertRaises(SecretCacheKeyUnavailableError):
            hook.get(legacy)

    def test_retire_legacy_keys_rejects_unmigrated_envelope(self):
        hook = RotatingSecretCacheHook(OLD_KEY)
        legacy = hook.put({"SecretString": "old"})
        hook.rotate(NEW_KEY, retain_previous=True)
        hook.retire_legacy_keys()

        with self.assertRaises(SecretCacheKeyUnavailableError):
            hook.get(legacy)
        self.assertEqual(hook.get(hook.put({"SecretString": "new"})), {"SecretString": "new"})

    def test_retire_specific_key(self):
        hook = RotatingSecretCacheHook(OLD_KEY)
        old_key_id = hook.primary_key_id
        legacy = hook.put({"SecretString": "old"})
        hook.rotate(NEW_KEY, retain_previous=True)

        self.assertTrue(hook.retire_key(old_key_id))
        self.assertFalse(hook.retire_key(old_key_id))
        with self.assertRaises(SecretCacheKeyUnavailableError):
            hook.get(legacy)
        with self.assertRaises(ValueError):
            hook.retire_key(hook.primary_key_id)

    def test_rejects_non_envelope_and_tampering(self):
        hook = RotatingSecretCacheHook(OLD_KEY)
        with self.assertRaises(SecretCacheEnvelopeFormatError):
            hook.get({"SecretString": "plaintext"})

        envelope = hook.put({"SecretString": "mysecret"})
        tampered = SecretCacheEnvelope(
            envelope.key_id,
            envelope.nonce,
            envelope.ciphertext[:-1] + bytes([envelope.ciphertext[-1] ^ 1]),
            envelope.tag,
        )
        with self.assertRaises(SecretCacheEnvelopeIntegrityError):
            hook.get(tampered)

        wrong_version = SecretCacheEnvelope(
            envelope.key_id, envelope.nonce, envelope.ciphertext, envelope.tag, format_version=2
        )
        with self.assertRaises(SecretCacheEnvelopeFormatError):
            hook.get(wrong_version)

    def test_cache_config_copy_observes_live_rotation(self):
        hook = RotatingSecretCacheHook(OLD_KEY)
        config = SecretCacheConfig(secret_cache_hook=hook)
        client = FakeSecretsManager()
        client.add_secret("one", "v1", {"SecretString": "one-v1"})
        cache = SecretCache(config=config, client=client)

        self.assertEqual(cache.get_secret_string("one"), "one-v1")
        legacy = cache._get_cached_secret("one")._versions.get("v1")._result
        self.assertEqual(legacy.key_id, hook.primary_key_id)

        hook.rotate(NEW_KEY)
        self.assertIs(cache._config.secret_cache_hook, hook)
        self.assertTrue(cache._config.secret_cache_hook.needs_rewrap(legacy))


class TestPerEntryMigration(unittest.TestCase):

    def setUp(self):
        self.hook = RotatingSecretCacheHook(OLD_KEY)
        self.client = FakeSecretsManager()
        self.client.add_secret("one", "v1", {"SecretString": "one-v1"})
        self.client.add_secret("two", "v1", {"SecretString": "two-v1"})
        self.cache = SecretCache(
            config=SecretCacheConfig(secret_cache_hook=self.hook), client=self.client
        )

    def _item(self, secret_id):
        return self.cache._get_cached_secret(secret_id)

    def _version(self, secret_id, version_id):
        return self._item(secret_id)._versions.get(version_id)

    def _force_describe_refresh(self, secret_id):
        self._item(secret_id)._refresh_needed = True

    def test_migration_scenario(self):
        # Both secrets are cached under the old key.
        self.assertEqual(self.cache.get_secret_string("one"), "one-v1")
        self.assertEqual(self.cache.get_secret_string("two"), "two-v1")
        self.assertEqual(self._version("one", "v1")._result.key_id, self.hook.primary_key_id)

        # Rotate: old key stays readable during the upgrade window.
        self.hook.rotate(NEW_KEY, retain_previous=True)
        legacy_describe = self._item("one")._result
        legacy_version = self._version("one", "v1")._result
        self.assertNotEqual(legacy_describe.key_id, self.hook.primary_key_id)
        self.assertNotEqual(legacy_version.key_id, self.hook.primary_key_id)

        # Make the first re-wrap of this exact version fail. The describe
        # envelope migrates first, then the version migration fails once.
        original_put = self.hook.put
        attempts = []
        put_events = []

        def flaky_put(obj):
            if "Name" in obj:
                put_events.append(("describe", obj["Name"]))
            if "SecretString" in obj:
                put_events.append(("version", obj["SecretString"]))
            if obj.get("SecretString") == "one-v1":
                attempts.append(obj)
                if len(attempts) == 1:
                    raise RuntimeError("temporary re-wrap failure")
            return original_put(obj)

        get_calls_before = len(self.client.calls)
        with patch.object(self.hook, "put", side_effect=flaky_put):
            self.assertEqual(self.cache.get_secret_string("one"), "one-v1")

            # Describe migrated before the version was attempted.
            self.assertEqual(put_events[0], ("describe", "one"))
            self.assertEqual(self._item("one")._result.key_id, self.hook.primary_key_id)

            # Failed migration does not fall back to plaintext in storage.
            failed_result = self._version("one", "v1")._result
            self.assertIsInstance(failed_result, SecretCacheEnvelope)
            self.assertEqual(failed_result.key_id, legacy_version.key_id)
            self.assertNotIn("one-v1", str(failed_result))

            # The failure was not treated as a backend refresh failure.
            self.assertIsNone(self._version("one", "v1")._exception)
            self.assertIsNone(self._item("one")._exception)

            # The same version retries and completes the migration.
            self.assertEqual(self.cache.get_secret_string("one"), "one-v1")
            migrated = self._version("one", "v1")._result
            self.assertEqual(migrated.key_id, self.hook.primary_key_id)

        # No extra backend reads were needed for the migration retries.
        after_migration_calls = self.client.calls[get_calls_before:]
        self.assertEqual(sum(1 for call in after_migration_calls if call[0] == "get_secret_value"), 0)
        self.assertEqual(sum(1 for call in after_migration_calls if call[0] == "describe_secret"), 0)
        self.assertEqual(len(attempts), 2)

        # A secret written after rotation only ever uses the new key.
        self.client.add_secret("three", "v1", {"SecretString": "three-v1"})
        self.assertEqual(self.cache.get_secret_string("three"), "three-v1")
        self.assertEqual(self._version("three", "v1")._result.key_id, self.hook.primary_key_id)

        # Retiring the old key only breaks entries that never migrated.
        self.hook.retire_legacy_keys()
        self.assertEqual(self.cache.get_secret_string("one"), "one-v1")
        self.assertEqual(self.cache.get_secret_string("three"), "three-v1")
        with self.assertRaises(SecretCacheKeyUnavailableError):
            self.cache.get_secret_string("two")

    def test_describe_envelope_migration_failure_is_retried(self):
        self.assertEqual(self.cache.get_secret_string("one"), "one-v1")
        self.hook.rotate(NEW_KEY, retain_previous=True)
        legacy_describe = self._item("one")._result
        self.assertNotEqual(legacy_describe.key_id, self.hook.primary_key_id)

        original_put = self.hook.put
        attempts = []

        def flaky_put(obj):
            if obj.get("Name") == "one":
                attempts.append(obj)
                if len(attempts) == 1:
                    raise RuntimeError("temporary describe re-wrap failure")
            return original_put(obj)

        with patch.object(self.hook, "put", side_effect=flaky_put):
            self.assertEqual(self.cache.get_secret_string("one"), "one-v1")
            self.assertEqual(self._item("one")._result.key_id, legacy_describe.key_id)
            self.assertEqual(self.cache.get_secret_string("one"), "one-v1")
            self.assertEqual(self._item("one")._result.key_id, self.hook.primary_key_id)

        self.assertEqual(len(attempts), 2)

    def test_retired_key_does_not_block_other_secrets(self):
        self.assertEqual(self.cache.get_secret_string("one"), "one-v1")
        self.assertEqual(self.cache.get_secret_string("two"), "two-v1")
        self.hook.rotate(NEW_KEY, retain_previous=True)

        # Read "one" so it migrates, leave "two" on the old envelope.
        self.assertEqual(self.cache.get_secret_string("one"), "one-v1")
        self.hook.retire_key(self.hook.legacy_key_ids[0])

        self.assertEqual(self.cache.get_secret_string("one"), "one-v1")
        with self.assertRaises(SecretCacheKeyUnavailableError):
            self.cache.get_secret_string("two")
