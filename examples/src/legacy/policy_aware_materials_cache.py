# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Policy-aware sharing of one cryptographic materials cache across archive projects.

Two archive projects share a single in-memory materials cache.  Each project is
free to rotate its own write-key policy at any time, so the cache must keep two
authorization concepts distinct when it decides whether a stored entry is still
usable:

* **Effective authorization scope** - which project (and, for write materials,
  which concrete write key) an entry actually belongs to.
* **Policy version** - the generation of the write-key policy that produced the
  entry.

Write materials are keyed by *both* values.  Rotating a project's write key
bumps its policy version, so the next write misses the cache and forces a fresh
material fetch instead of silently continuing to encrypt under a key that has
left the write policy.  Read materials are keyed only by project scope: the
encryption context and the encrypted data keys already identify the wrapping key,
so materials produced by an older, still-trusted write key remain readable and
stay cached.

The same cache instance backs every project; normal cache hits therefore still
avoid repeated calls to the underlying key provider.
"""
import attr
import six

from aws_encryption_sdk.caches.base import CryptoMaterialsCache
from aws_encryption_sdk.identifiers import EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.internal.str_ops import to_bytes
from aws_encryption_sdk.key_providers.base import MasterKeyProviderConfig
from aws_encryption_sdk.key_providers.raw import RawMasterKey, RawMasterKeyConfig, RawMasterKeyProvider

_WRAPPING_ALGORITHM = WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING


class PolicyAwareMaterialsCache(CryptoMaterialsCache):
    """Cache decorator that separates entries by authorization scope and policy version.

    This wraps any :class:`CryptoMaterialsCache` (for example, a shared
    :class:`LocalCryptoMaterialsCache`) and rewrites each cache key before the
    wrapped cache sees it.  The wrapping material manager keeps working unchanged
    because every entry it stores is later looked up through the same rewrite.

    Write and read paths use deliberately different namespaces:

    * Encryption entries include the current write-policy version, so a key
      rotation changes the key and stops reuse of the retired write material.
    * Decryption entries are scoped to the project only, so historical materials
      encrypted under a previous write key stay readable and cacheable.

    :param wrapped: The shared cache that actually stores the entries.
    :type wrapped: aws_encryption_sdk.caches.base.CryptoMaterialsCache
    :param str project_id: Stable identifier of the project that owns this view.
    :param callable policy_version_provider: Zero-argument callable returning the
        write-policy version currently in effect for this project.
    """

    def __init__(self, wrapped, project_id, policy_version_provider):
        self._wrapped = wrapped
        self._project_scope = b"project=" + to_bytes(project_id)
        self._policy_version_provider = policy_version_provider

    def _write_cache_key(self, cache_key):
        policy_version = to_bytes(str(self._policy_version_provider()))
        return b"write\x1f" + self._project_scope + b"\x1fpolicy=" + policy_version + b"\x1f" + cache_key

    def _read_cache_key(self, cache_key):
        return b"read\x1f" + self._project_scope + b"\x1f" + cache_key

    def put_encryption_materials(self, cache_key, encryption_materials, plaintext_length, entry_hints=None):
        return self._wrapped.put_encryption_materials(
            cache_key=self._write_cache_key(cache_key),
            encryption_materials=encryption_materials,
            plaintext_length=plaintext_length,
            entry_hints=entry_hints,
        )

    def get_encryption_materials(self, cache_key, plaintext_length):
        return self._wrapped.get_encryption_materials(
            cache_key=self._write_cache_key(cache_key), plaintext_length=plaintext_length
        )

    def put_decryption_materials(self, cache_key, decryption_materials):
        return self._wrapped.put_decryption_materials(
            cache_key=self._read_cache_key(cache_key), decryption_materials=decryption_materials
        )

    def get_decryption_materials(self, cache_key):
        return self._wrapped.get_decryption_materials(cache_key=self._read_cache_key(cache_key))

    def remove(self, value):
        self._wrapped.remove(value)


@attr.s
class WriteKeyPolicy(object):
    """In-memory write-key policy for one project.

    The policy keeps every write key it has ever trusted so historical messages
    stay decryptable, while exposing only the current write key for new writes.
    Each rotation appends a new key and bumps the version.

    :param str provider_id: Provider ID advertised by this project's keys.
    """

    provider_id = attr.ib(validator=attr.validators.instance_of(six.string_types))
    _write_key_ids = attr.ib(default=attr.Factory(list), init=False)
    _wrapping_material = attr.ib(default=attr.Factory(dict), init=False)
    _version = attr.ib(default=0, init=False)

    def rotate(self, key_id):
        """Adds a new write key and makes it the effective write key.

        :param str key_id: Identifier for the new write key.
        """
        key_id = to_bytes(key_id)
        if key_id in self._write_key_ids:
            raise ValueError("write key {!r} is already part of this policy".format(key_id))
        self._write_key_ids.append(key_id)
        # Deterministically derive a distinct 32-byte AES wrapping key per key ID.
        wrapping_material = (key_id + b"\x00" * 32)[:32]
        self._wrapping_material[key_id] = WrappingKey(
            wrapping_algorithm=_WRAPPING_ALGORITHM,
            wrapping_key=wrapping_material,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC,
        )
        self._version += 1

    @property
    def version(self):
        """Version of the write policy currently in effect."""
        return self._version

    @property
    def current_write_key_id(self):
        """Key ID that new writes must use."""
        return self._write_key_ids[-1]

    @property
    def trusted_key_ids(self):
        """Every key ID still trusted for reads, including retired write keys."""
        return tuple(self._write_key_ids)

    def wrapping_key(self, key_id):
        """Returns the wrapping key registered for ``key_id``."""
        return self._wrapping_material[to_bytes(key_id)]


@attr.s
class RecordingRawMasterKeyProviderConfig(MasterKeyProviderConfig):
    """Configuration carrying the write-key policy and the fetch counters."""

    policy = attr.ib()
    calls = attr.ib(default=attr.Factory(lambda: {"generate": 0, "decrypt": 0}))


class RecordingRawMasterKey(RawMasterKey):
    """Raw master key that reports each data-key fetch back to its provider."""

    def __new__(cls, on_generate=None, on_decrypt=None, **kwargs):
        instance = super(RecordingRawMasterKey, cls).__new__(cls, **kwargs)
        instance._on_generate = on_generate or (lambda: None)
        instance._on_decrypt = on_decrypt or (lambda: None)
        return instance

    def generate_data_key(self, algorithm, encryption_context):
        self._on_generate()
        return super(RecordingRawMasterKey, self).generate_data_key(algorithm, encryption_context)

    def decrypt_data_key(self, encrypted_data_key, algorithm, encryption_context):
        self._on_decrypt()
        return super(RecordingRawMasterKey, self).decrypt_data_key(
            encrypted_data_key, algorithm, encryption_context
        )


class RecordingRawMasterKeyProvider(RawMasterKeyProvider):
    """Raw key provider that records every material fetch against a write-key policy.

    The recorded counters are what let the demonstration prove cache behaviour:
    a cache hit must not reach this provider, while a miss (including the first
    request after a rotation) must.
    """

    _config_class = RecordingRawMasterKeyProviderConfig
    _master_key_class = RecordingRawMasterKey

    @property
    def provider_id(self):
        return self.config.policy.provider_id

    @property
    def policy(self):
        return self.config.policy

    @property
    def calls(self):
        return self.config.calls

    def _record_generate(self):
        self.config.calls["generate"] += 1

    def _record_decrypt(self):
        self.config.calls["decrypt"] += 1

    def _new_master_key(self, key_id):
        wrapping_key = self._get_raw_key(key_id)
        return self._master_key_class(
            on_generate=self._record_generate,
            on_decrypt=self._record_decrypt,
            config=RawMasterKeyConfig(key_id=key_id, provider_id=self.provider_id, wrapping_key=wrapping_key),
        )

    def _get_raw_key(self, key_id):
        return self.config.policy.wrapping_key(key_id)


def build_project_cmm(shared_cache, policy, max_age=600.0, max_messages_encrypted=100):
    """Builds the recording provider and caching CMM for one project.

    The project's view of the shared cache is bound to its policy so that write
    entries carry the effective policy version and read entries carry only the
    project scope.

    :param shared_cache: The cache instance shared between projects.
    :param policy: Write-key policy for this project.
    :param float max_age: Maximum age of a cached entry in seconds.
    :param int max_messages_encrypted: Maximum messages per cached write entry.
    :returns: Tuple of the recording provider and its caching material manager.
    :rtype: tuple
    """
    # Imported here to keep the public example imports free of internal module paths.
    from aws_encryption_sdk.materials_managers.caching import CachingCryptoMaterialsManager

    key_provider = RecordingRawMasterKeyProvider(policy=policy)
    key_provider.add_master_key(policy.current_write_key_id)

    scoped_cache = PolicyAwareMaterialsCache(
        wrapped=shared_cache, project_id=policy.provider_id, policy_version_provider=lambda: policy.version
    )
    caching_cmm = CachingCryptoMaterialsManager(
        master_key_provider=key_provider,
        cache=scoped_cache,
        max_age=max_age,
        max_messages_encrypted=max_messages_encrypted,
        partition_name=b"archive-" + to_bytes(policy.provider_id),
    )
    return key_provider, caching_cmm


def run_demo():
    """Runs the end-to-end scenario and prints the key-provider call counts."""
    import aws_encryption_sdk

    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=aws_encryption_sdk.CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )
    shared_cache = aws_encryption_sdk.LocalCryptoMaterialsCache(capacity=100)

    project_a = WriteKeyPolicy(provider_id="project-a")
    project_a.rotate("a-write-key-v1")
    provider_a, cmm_a = build_project_cmm(shared_cache, project_a)

    project_b = WriteKeyPolicy(provider_id="project-b")
    project_b.rotate("b-write-key-v1")
    provider_b, cmm_b = build_project_cmm(shared_cache, project_b)

    def write(project_cmm, plaintext):
        ciphertext, _ = client.encrypt(
            source=plaintext, materials_manager=project_cmm, encryption_context={"archive": "demo"}
        )
        return ciphertext

    def read(project_cmm, ciphertext):
        plaintext, _ = client.decrypt(source=ciphertext, materials_manager=project_cmm)
        return plaintext

    historical = write(cmm_a, b"first archived record")
    write(cmm_b, b"project b record")
    write(cmm_a, b"second archived record")  # normal hit: no new fetch

    read(cmm_a, historical)
    read(cmm_a, historical)  # decryption-materials hit: no new fetch
    print("before rotation  project-a calls:", provider_a.calls, " project-b calls:", provider_b.calls)

    project_a.rotate("a-write-key-v2")
    provider_a, cmm_a = build_project_cmm(shared_cache, project_a)
    new_record = write(cmm_a, b"record under the rotated write key")
    print("after rotation   project-a write fetch:", provider_a.calls["generate"])

    assert read(cmm_a, historical) == b"first archived record"  # allowed historical read
    assert read(cmm_a, new_record) == b"record under the rotated write key"
    print("historical reads still allowed; project-a decrypt fetches:", provider_a.calls["decrypt"])

    write(cmm_b, b"another project b record")  # project B still hits its own entry
    print("project-b write fetch unchanged at:", provider_b.calls["generate"])


if __name__ == "__main__":
    run_demo()
