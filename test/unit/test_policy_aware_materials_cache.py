# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the policy-aware shared materials cache example.

These tests exercise the security requirement directly: a shared in-memory
cache keeps each project's effective authorization scope and write-policy
version distinct, so rotating a project's write key stops reuse of the retired
write material while historical reads and the other project's cache hits are
preserved.
"""
import pytest

from aws_encryption_sdk import CommitmentPolicy, EncryptionSDKClient, LocalCryptoMaterialsCache

from examples.src.legacy.policy_aware_materials_cache import (
    WriteKeyPolicy,
    build_project_cmm,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

ENCRYPTION_CONTEXT = {"archive": "materials"}
PLAINTEXT = b"archived material"


def _encrypt(client, cmm):
    ciphertext, _ = client.encrypt(
        source=PLAINTEXT, materials_manager=cmm, encryption_context=dict(ENCRYPTION_CONTEXT)
    )
    return ciphertext


def _decrypt(client, cmm, ciphertext):
    plaintext, _ = client.decrypt(source=ciphertext, materials_manager=cmm)
    return plaintext


def test_policy_rotation_and_shared_cache():
    client = EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
    shared_cache = LocalCryptoMaterialsCache(capacity=100)

    project_a_policy = WriteKeyPolicy(provider_id="project-a")
    project_a_policy.rotate("a-write-key-v1")
    provider_a, cmm_a = build_project_cmm(shared_cache, project_a_policy)

    project_b_policy = WriteKeyPolicy(provider_id="project-b")
    project_b_policy.rotate("b-write-key-v1")
    provider_b, cmm_b = build_project_cmm(shared_cache, project_b_policy)

    # First write in each project misses the cache and reaches the key provider.
    ciphertext_a_v1 = _encrypt(client, cmm_a)
    ciphertext_b = _encrypt(client, cmm_b)
    assert provider_a.calls["generate"] == 1
    assert provider_b.calls["generate"] == 1

    # A repeated write is a normal hit: no additional key-provider fetch.
    _encrypt(client, cmm_a)
    assert provider_a.calls["generate"] == 1

    # A historical read under the original write key works and caches the
    # decryption materials on first use, then reuses them on a second read.
    assert _decrypt(client, cmm_a, ciphertext_a_v1) == PLAINTEXT
    assert provider_a.calls["decrypt"] == 1
    assert _decrypt(client, cmm_a, ciphertext_a_v1) == PLAINTEXT
    assert provider_a.calls["decrypt"] == 1

    # Project A rotates its write key. Its CMM is rebuilt against the same shared
    # cache so new writes are authorized under the new policy version.
    project_a_policy.rotate("a-write-key-v2")
    provider_a, cmm_a = build_project_cmm(shared_cache, project_a_policy)

    # New write after rotation must miss the version-scoped cache and fetch fresh
    # materials instead of reusing the retired v1 write material.
    ciphertext_a_v2 = _encrypt(client, cmm_a)
    assert provider_a.calls["generate"] == 1
    assert ciphertext_a_v2 != ciphertext_a_v1

    # The shared cache now holds both the v1 and v2 write entries under distinct
    # keys, proving the retired write material is no longer on the active path.
    write_entries = [key for key in shared_cache._cache if key.startswith(b"write\x1fproject=project-a")]
    assert len(write_entries) == 2

    # The retired key is still trusted, so reading the historical v1 message
    # succeeds. Its decryption materials were cached before the rotation and are
    # keyed by project scope only, so no new provider call is needed.
    assert _decrypt(client, cmm_a, ciphertext_a_v1) == PLAINTEXT
    assert provider_a.calls["decrypt"] == 0

    # The new v2 message is a first read for this key, so it fetches once, then
    # reuses the cached decryption materials on the next read.
    assert _decrypt(client, cmm_a, ciphertext_a_v2) == PLAINTEXT
    assert provider_a.calls["decrypt"] == 1
    assert _decrypt(client, cmm_a, ciphertext_a_v2) == PLAINTEXT
    assert provider_a.calls["decrypt"] == 1

    # Project B's write entry is scoped independently: its repeated write still
    # hits the shared cache and never invokes its key provider again.
    generate_before = provider_b.calls["generate"]
    _encrypt(client, cmm_b)
    assert provider_b.calls["generate"] == generate_before


def test_write_cache_keys_change_with_policy_version():
    from examples.src.legacy.policy_aware_materials_cache import PolicyAwareMaterialsCache

    version = {"value": 1}
    scoped = PolicyAwareMaterialsCache(
        wrapped=LocalCryptoMaterialsCache(capacity=10),
        project_id="project-x",
        policy_version_provider=lambda: version["value"],
    )

    request_key = b"same-request-key"
    original_key = scoped._write_cache_key(request_key)

    # Bumping the policy version must produce a distinct write key for an
    # otherwise identical request, forcing a fresh fetch after rotation.
    version["value"] += 1
    rotated_key = scoped._write_cache_key(request_key)
    assert rotated_key != original_key

    # Read keys deliberately ignore the policy version so historical reads stay
    # cacheable across rotations.
    read_key_before = scoped._read_cache_key(b"read-request")
    version["value"] += 1
    read_key_after = scoped._read_cache_key(b"read-request")
    assert read_key_after == read_key_before
