# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Offline contract tests for AWS KMS multi-Region key (MRK) selection.

These tests exercise the archive service's decrypt-time key selection without any
network access. A fake regional KMS client is registered per region and every KMS
operation it receives is recorded together with the region that owns the client,
so each assertion can verify both the operation that was actually sent to KMS and
which client (region/attribution) it was sent to.
"""
import botocore.client
import pytest
from mock import MagicMock, patch

from aws_encryption_sdk.exceptions import (
    ConfigMismatchError,
    DecryptKeyError,
    MasterKeyProviderError,
)
from aws_encryption_sdk.identifiers import AlgorithmSuite
from aws_encryption_sdk.key_providers.kms import (
    DiscoveryFilter,
    MRKAwareDiscoveryAwsKmsMasterKeyProvider,
    MRKAwareStrictAwsKmsMasterKeyProvider,
    StrictAwsKmsMasterKeyProvider,
)
from aws_encryption_sdk.structures import EncryptedDataKey, MasterKeyInfo

pytestmark = [pytest.mark.functional, pytest.mark.local]

# The archive service owns account TRUSTED_ACCOUNT and runs its discovery client in
# DISCOVERY_REGION. Its multi-Region key group is replicated into PRIMARY_REGION and
# REPLICA_REGION; the other-account key and the single-Region key are unrelated.
TRUSTED_ACCOUNT = "111111111111"
OTHER_ACCOUNT = "222222222222"
PARTITION = "aws"
PRIMARY_REGION = "us-east-1"
REPLICA_REGION = "us-west-2"
DISCOVERY_REGION = PRIMARY_REGION
MRK_RESOURCE_ID = "mrk-12345678-1234-1234-1234-123456789012"
OTHER_MRK_RESOURCE_ID = "mrk-99999999-1234-1234-1234-123456789012"
SRK_RESOURCE_ID = "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"

MRK_PRIMARY_ARN = "arn:aws:kms:{region}:{account}:key/{resource}"

MRK_PRIMARY = MRK_PRIMARY_ARN.format(
    region=PRIMARY_REGION, account=TRUSTED_ACCOUNT, resource=MRK_RESOURCE_ID
)
MRK_REPLICA = MRK_PRIMARY_ARN.format(
    region=REPLICA_REGION, account=TRUSTED_ACCOUNT, resource=MRK_RESOURCE_ID
)
OTHER_ACCOUNT_MRK = MRK_PRIMARY_ARN.format(
    region=REPLICA_REGION, account=OTHER_ACCOUNT, resource=OTHER_MRK_RESOURCE_ID
)
SINGLE_REGION_KEY = MRK_PRIMARY_ARN.format(
    region=REPLICA_REGION, account=TRUSTED_ACCOUNT, resource=SRK_RESOURCE_ID
)

ENCRYPTED_DATA_KEY_BYTES = b"archive-wrapped-data-key"
ENCRYPTION_CONTEXT = {"archive-service": "cold-storage"}
ALGORITHM = AlgorithmSuite.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
PLAINTEXT_DATA_KEY = b"\x00" * ALGORITHM.data_key_len


def _edk(key_arn):
    """Builds an encrypted data key whose provider info claims the given KMS key ARN."""
    return EncryptedDataKey(
        key_provider=MasterKeyInfo(provider_id="aws-kms", key_info=key_arn),
        encrypted_data_key=ENCRYPTED_DATA_KEY_BYTES,
    )


class FakeRegionalKMS(object):
    """Replacement for ``boto3.session.Session`` that hands out one recorded client per region.

    Every returned client records each KMS operation as a tuple of
    ``(region, operation_name, request_kwargs)`` on the shared ``calls`` list, giving
    the tests a single place to assert both the operation and the client that owns it.
    """

    def __init__(self):
        self.calls = []
        self.clients_by_region = {}

    def __call__(self, *args, **kwargs):
        session = MagicMock()
        session.client.side_effect = self._client
        return session

    def _client(self, service_name, region_name=None, **kwargs):
        existing = self.clients_by_region.get(region_name)
        if existing is not None:
            return existing

        client = MagicMock()
        # The KMS master key config validator requires a botocore client instance.
        client.__class__ = botocore.client.BaseClient
        client.meta.region_name = region_name

        def _record(operation_name):
            def _handler(**request):
                self.calls.append((region_name, operation_name, dict(request)))
                if operation_name == "Decrypt":
                    return {"KeyId": request["KeyId"], "Plaintext": PLAINTEXT_DATA_KEY}
                raise AssertionError("unexpected KMS operation {} in these contract tests".format(operation_name))

            return _handler

        client.decrypt.side_effect = _record("Decrypt")
        self.clients_by_region[region_name] = client
        return client

    def regions_contacted(self):
        return sorted(region for region, _, _ in self.calls)

    def decrypt_requests_for(self, region_name):
        return [request for region, operation, request in self.calls
                if region == region_name and operation == "Decrypt"]


@pytest.fixture
def fake_kms():
    with patch("aws_encryption_sdk.key_providers.kms.boto3.session.Session") as session_cls:
        fake = FakeRegionalKMS()
        session_cls.side_effect = fake
        yield fake


def _decrypt(provider, key_arn):
    return provider.decrypt_data_key_from_list([_edk(key_arn)], ALGORITHM, ENCRYPTION_CONTEXT)


def test_strict_mrk_allows_related_replica_in_other_region(fake_kms):
    """An EDK wrapped by a related replica is read through the configured primary's client."""
    provider = MRKAwareStrictAwsKmsMasterKeyProvider(key_ids=[MRK_PRIMARY])

    data_key = _decrypt(provider, MRK_REPLICA)

    assert data_key.data_key == PLAINTEXT_DATA_KEY
    # The cross-region read is allowed, but it is attributed to the configured primary
    # region: the replica region never receives a request.
    assert fake_kms.regions_contacted() == [PRIMARY_REGION]
    decrypt_requests = fake_kms.decrypt_requests_for(PRIMARY_REGION)
    assert len(decrypt_requests) == 1
    assert decrypt_requests[0] == {
        "CiphertextBlob": ENCRYPTED_DATA_KEY_BYTES,
        "KeyId": MRK_PRIMARY,
        "EncryptionContext": ENCRYPTION_CONTEXT,
    }
    assert fake_kms.decrypt_requests_for(REPLICA_REGION) == []


def test_strict_mrk_primary_arn_uses_primary_client(fake_kms):
    """An EDK wrapped directly by the configured MRK primary selects that same key and client."""
    provider = MRKAwareStrictAwsKmsMasterKeyProvider(key_ids=[MRK_PRIMARY])

    data_key = _decrypt(provider, MRK_PRIMARY)

    assert data_key.data_key == PLAINTEXT_DATA_KEY
    assert fake_kms.regions_contacted() == [PRIMARY_REGION]
    assert fake_kms.decrypt_requests_for(PRIMARY_REGION)[0]["KeyId"] == MRK_PRIMARY
    assert fake_kms.decrypt_requests_for(REPLICA_REGION) == []


def test_strict_mrk_rejects_other_account_candidate_without_calling_kms(fake_kms):
    """A candidate from another account never matches and must not trigger any KMS request."""
    provider = MRKAwareStrictAwsKmsMasterKeyProvider(key_ids=[MRK_PRIMARY])

    with pytest.raises(DecryptKeyError):
        _decrypt(provider, OTHER_ACCOUNT_MRK)

    # The primary region client exists because the configured key was vended at init,
    # but no KMS operation is ever sent for the rejected other-account candidate.
    assert fake_kms.calls == []


def test_strict_mrk_rejects_plain_single_region_key_without_calling_kms(fake_kms):
    """A non-MRK key does not match the configured MRK even within the same account."""
    provider = MRKAwareStrictAwsKmsMasterKeyProvider(key_ids=[MRK_PRIMARY])

    with pytest.raises(DecryptKeyError):
        _decrypt(provider, SINGLE_REGION_KEY)

    assert fake_kms.calls == []


def test_non_mrk_aware_strict_provider_rejects_replica_without_calling_kms(fake_kms):
    """The plain strict provider requires an exact ARN match, so the replica is refused."""
    provider = StrictAwsKmsMasterKeyProvider(key_ids=[MRK_PRIMARY])

    with pytest.raises(DecryptKeyError):
        _decrypt(provider, MRK_REPLICA)

    assert fake_kms.calls == []


def test_strict_provider_rejects_configuring_related_mrks_together():
    """Configuring two keys from the same MRK group is rejected up front as a config error."""
    with pytest.raises(ConfigMismatchError) as excinfo:
        MRKAwareStrictAwsKmsMasterKeyProvider(key_ids=[MRK_PRIMARY, MRK_REPLICA])
    excinfo.match("Configured key ids must be unique")


def test_discovery_mrk_redirects_replica_read_to_discovery_region(fake_kms):
    """Discovery mode rewrites a related MRK ARN to the discovery region for the call."""
    provider = MRKAwareDiscoveryAwsKmsMasterKeyProvider(discovery_region=DISCOVERY_REGION)

    data_key = _decrypt(provider, MRK_REPLICA)

    assert data_key.data_key == PLAINTEXT_DATA_KEY
    # The EDK names the replica region, but the request is attributed to the discovery
    # region and uses the discovery-region form of the related MRK ARN.
    assert fake_kms.regions_contacted() == [DISCOVERY_REGION]
    decrypt_requests = fake_kms.decrypt_requests_for(DISCOVERY_REGION)
    assert len(decrypt_requests) == 1
    assert decrypt_requests[0]["KeyId"] == MRK_PRIMARY
    assert decrypt_requests[0]["CiphertextBlob"] == ENCRYPTED_DATA_KEY_BYTES
    assert fake_kms.decrypt_requests_for(REPLICA_REGION) == []


def test_discovery_single_region_key_uses_its_native_region(fake_kms):
    """A single-Region key is not redirected: its own region owns the decrypt call."""
    provider = MRKAwareDiscoveryAwsKmsMasterKeyProvider(discovery_region=DISCOVERY_REGION)

    data_key = _decrypt(provider, SINGLE_REGION_KEY)

    assert data_key.data_key == PLAINTEXT_DATA_KEY
    assert fake_kms.regions_contacted() == [REPLICA_REGION]
    decrypt_requests = fake_kms.decrypt_requests_for(REPLICA_REGION)
    assert len(decrypt_requests) == 1
    assert decrypt_requests[0]["KeyId"] == SINGLE_REGION_KEY
    assert fake_kms.decrypt_requests_for(DISCOVERY_REGION) == []


def test_discovery_filter_allows_related_mrk_in_trusted_account(fake_kms):
    """The same-account MRK group passes the discovery filter and still reads cross-region."""
    provider = MRKAwareDiscoveryAwsKmsMasterKeyProvider(
        discovery_region=DISCOVERY_REGION,
        discovery_filter=DiscoveryFilter(partition=PARTITION, account_ids=(TRUSTED_ACCOUNT,)),
    )

    data_key = _decrypt(provider, MRK_REPLICA)

    assert data_key.data_key == PLAINTEXT_DATA_KEY
    assert fake_kms.regions_contacted() == [DISCOVERY_REGION]
    assert fake_kms.decrypt_requests_for(DISCOVERY_REGION)[0]["KeyId"] == MRK_PRIMARY


def test_discovery_filter_rejects_other_account_without_calling_any_client(fake_kms):
    """A filtered-out account is refused while no regional KMS client is ever created."""
    provider = MRKAwareDiscoveryAwsKmsMasterKeyProvider(
        discovery_region=DISCOVERY_REGION,
        discovery_filter=DiscoveryFilter(partition=PARTITION, account_ids=(TRUSTED_ACCOUNT,)),
    )

    with pytest.raises(MasterKeyProviderError) as excinfo:
        _decrypt(provider, OTHER_ACCOUNT_MRK)
    excinfo.match("not allowed by this Master Key Provider")

    # The refusal happens before client vending: not a single unapproved client is touched.
    assert fake_kms.calls == []
    assert fake_kms.clients_by_region == {}


def test_discovery_filter_rejects_other_account_alongside_allowed_mrk(fake_kms):
    """A rejected EDK never reaches an unapproved client, even next to an allowed MRK.

    The allowed replica EDK is listed first and succeeds through the trusted discovery
    region. The other-account EDK then fails filter validation while its key is being
    vended, so it adds no further KMS traffic against any regional client.
    """
    provider = MRKAwareDiscoveryAwsKmsMasterKeyProvider(
        discovery_region=DISCOVERY_REGION,
        discovery_filter=DiscoveryFilter(partition=PARTITION, account_ids=(TRUSTED_ACCOUNT,)),
    )

    data_key = provider.decrypt_data_key_from_list(
        [_edk(MRK_REPLICA), _edk(OTHER_ACCOUNT_MRK)], ALGORITHM, ENCRYPTION_CONTEXT
    )

    assert data_key.data_key == PLAINTEXT_DATA_KEY
    # Only the trusted discovery region client is ever used; the other-account candidate
    # never causes a request against the replica region or any other client.
    assert fake_kms.regions_contacted() == [DISCOVERY_REGION]
    decrypt_requests = fake_kms.decrypt_requests_for(DISCOVERY_REGION)
    assert len(decrypt_requests) == 1
    assert decrypt_requests[0]["KeyId"] == MRK_PRIMARY
    assert fake_kms.decrypt_requests_for(REPLICA_REGION) == []
