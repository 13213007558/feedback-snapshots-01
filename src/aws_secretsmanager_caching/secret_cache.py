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
"""High level AWS Secrets Manager caching client."""
from copy import deepcopy

from importlib.metadata import version, PackageNotFoundError
import botocore.config
import botocore.session

from .cache import LRUCache, SecretCacheItem, SecretCacheVersion
from .config import SecretCacheConfig


class _IdentityScope:
    """Hashable identity wrapper for an unhashable authorization context.

    It keeps a strong reference to the wrapped value so the identity cannot
    be reused by an unrelated object while the key is held by the cache.
    """

    __slots__ = ("value",)

    def __init__(self, value):
        self.value = value

    def __hash__(self):
        return id(self.value)

    def __eq__(self, other):
        return isinstance(other, _IdentityScope) and other.value is self.value


class SecretCache:
    """Secret Cache client for AWS Secrets Manager secrets"""

    # Marks the kind of cache entry so a version-pinned entry can never be
    # mistaken for a stage-based one, even for the same secret and version.
    _STAGE_ENTRY = "stage"
    _VERSION_ENTRY = "version"

    try:
        __version__ = version('aws_secretsmanager_caching')
    except PackageNotFoundError:
        __version__ = '0.0.0'

    def __init__(self, config=SecretCacheConfig(), client=None):
        """Construct a secret cache using the given configuration and
        AWS Secrets Manager boto client.

        :type config: aws_secretsmanager_caching.SecretCacheConfig
        :param config: Secret cache configuration

        :type client: botocore.client.BaseClient
        :param client: botocore 'secretsmanager' client
        """

        self._client = client
        self._config = deepcopy(config)
        self._cache = LRUCache(max_size=self._config.max_cache_size)
        boto_config = botocore.config.Config(**{
            "user_agent_extra": f"AwsSecretCache/{SecretCache.__version__}",
        })
        if self._client is None:
            self._client = botocore.session.get_session().create_client("secretsmanager", config=boto_config)

    def _resolve_authorization_context(self, authorization_context, default_client):
        """Resolve the authorization scope used to partition cache entries.

        When no explicit scope is given, the client that performs the call is
        used. Two roles that run with distinct clients therefore never share
        entries, which keeps a warmed value from leaking across a role switch.

        :type authorization_context: object
        :param authorization_context: The authorization scope of the caller.

        :type default_client: botocore.client.BaseClient
        :param default_client: The client used when no scope is given.

        :rtype: object
        :return: A hashable authorization scope to use as part of the cache key.
        """
        if authorization_context is None:
            return default_client
        try:
            hash(authorization_context)
        except TypeError:
            return _IdentityScope(authorization_context)
        return authorization_context

    @classmethod
    def _stage_cache_key(cls, secret_id, authorization_context):
        """Build the cache key for a stage-based entry.

        :type secret_id: str
        :param secret_id: The secret identifier

        :type authorization_context: object
        :param authorization_context: The authorization scope of the caller.

        :rtype: tuple
        :return: The cache key for the stage-based entry.
        """
        return (cls._STAGE_ENTRY, secret_id, authorization_context)

    @classmethod
    def _version_cache_key(cls, secret_id, version_id, authorization_context):
        """Build the cache key for a version-pinned entry.

        :type secret_id: str
        :param secret_id: The secret identifier

        :type version_id: str
        :param version_id: The explicit version identifier.

        :type authorization_context: object
        :param authorization_context: The authorization scope of the caller.

        :rtype: tuple
        :return: The cache key for the version-pinned entry.
        """
        return (cls._VERSION_ENTRY, secret_id, version_id, authorization_context)

    def _get_cached_secret(self, secret_id, authorization_context=None, client=None):
        """Get a cached stage-based secret for the given identifier and scope.

        :type secret_id: str
        :param secret_id: The secret identifier

        :type authorization_context: object
        :param authorization_context: The authorization scope of the caller.

        :type client: botocore.client.BaseClient
        :param client: An optional client to use for this entry instead of the
            cache-wide client.

        :rtype: aws_secretsmanager_caching.cache.SecretCacheItem
        :return: The associated cached secret item
        """
        client = self._client if client is None else client
        authorization_context = self._resolve_authorization_context(authorization_context, client)
        key = self._stage_cache_key(secret_id, authorization_context)
        secret = self._cache.get(key)
        if secret is not None:
            return secret
        self._cache.put_if_absent(
            key, SecretCacheItem(config=self._config, client=client, secret_id=secret_id)
        )
        return self._cache.get(key)

    def _get_cached_version(self, secret_id, version_id, authorization_context=None, client=None):
        """Get a cached version-pinned secret for the given identifier and scope.

        A pinned entry never consults DescribeSecret and never shares a
        cache entry with the stage-based path, so a value warmed by a wider
        role cannot be served to a narrower one.

        :type secret_id: str
        :param secret_id: The secret identifier

        :type version_id: str
        :param version_id: The explicit version identifier.

        :type authorization_context: object
        :param authorization_context: The authorization scope of the caller.

        :type client: botocore.client.BaseClient
        :param client: An optional client to use for this entry instead of the
            cache-wide client.

        :rtype: aws_secretsmanager_caching.cache.SecretCacheVersion
        :return: The associated cached secret version item
        """
        client = self._client if client is None else client
        key = self._version_cache_key(
            secret_id, version_id, self._resolve_authorization_context(authorization_context, client)
        )
        secret = self._cache.get(key)
        if secret is not None:
            return secret
        self._cache.put_if_absent(
            key,
            SecretCacheVersion(
                config=self._config,
                client=client,
                secret_id=secret_id,
                version_id=version_id,
                revalidate=True,
            ),
        )
        return self._cache.get(key)

    def _get_cache_entry(self, secret_id, version_id=None, authorization_context=None, client=None):
        """Get the cache entry for a stage-based or version-pinned read.

        :type secret_id: str
        :param secret_id: The secret identifier

        :type version_id: str
        :param version_id: The explicit version identifier, if pinned.

        :type authorization_context: object
        :param authorization_context: The authorization scope of the caller.

        :type client: botocore.client.BaseClient
        :param client: An optional client for this call.

        :rtype: aws_secretsmanager_caching.cache.SecretCacheObject
        :return: The cache entry that serves the request.
        """
        if version_id is not None:
            return self._get_cached_version(secret_id, version_id, authorization_context, client)
        return self._get_cached_secret(secret_id, authorization_context, client)

    def get_secret_string(self, secret_id, version_stage=None, version_id=None, authorization_context=None,
                          client=None):
        """Get the secret string value from the cache.

        If ``version_id`` is given, the value is read for that exact version
        with ``GetSecretValue``/``VersionId`` and ``DescribeSecret`` is never
        called. Otherwise the existing stage-based lookup is used.

        :type secret_id: str
        :param secret_id: The secret identifier

        :type version_stage: str
        :param version_stage: The stage for the requested version.

        :type version_id: str
        :param version_id: An explicit version identifier to pin the read to.

        :type authorization_context: object
        :param authorization_context: The authorization scope of the caller.
            Entries are cached separately per scope.

        :type client: botocore.client.BaseClient
        :param client: An optional client for this call. It also defaults the
            authorization context when none is given.

        :rtype: str
        :return: The associated secret string value
        """
        entry = self._get_cache_entry(secret_id, version_id, authorization_context, client)
        secret = entry.get_secret_value(version_stage)
        if secret is None:
            return secret
        return secret.get("SecretString")

    def get_secret_binary(self, secret_id, version_stage=None, version_id=None, authorization_context=None,
                          client=None):
        """Get the secret binary value from the cache.

        If ``version_id`` is given, the value is read for that exact version
        with ``GetSecretValue``/``VersionId`` and ``DescribeSecret`` is never
        called. Otherwise the existing stage-based lookup is used.

        :type secret_id: str
        :param secret_id: The secret identifier

        :type version_stage: str
        :param version_stage: The stage for the requested version.

        :type version_id: str
        :param version_id: An explicit version identifier to pin the read to.

        :type authorization_context: object
        :param authorization_context: The authorization scope of the caller.
            Entries are cached separately per scope.

        :type client: botocore.client.BaseClient
        :param client: An optional client for this call. It also defaults the
            authorization context when none is given.

        :rtype: bytes
        :return: The associated secret binary value
        """
        entry = self._get_cache_entry(secret_id, version_id, authorization_context, client)
        secret = entry.get_secret_value(version_stage)
        if secret is None:
            return secret
        return secret.get("SecretBinary")

    def refresh_secret_now(self, secret_id, version_id=None, authorization_context=None, client=None):
        """Immediately refresh the secret in the cache.

        :type secret_id: str
        :param secret_id: The secret identifier

        :type version_id: str
        :param version_id: An explicit version identifier to pin the refresh to.

        :type authorization_context: object
        :param authorization_context: The authorization scope of the caller.

        :type client: botocore.client.BaseClient
        :param client: An optional client for this call.

        :rtype: bool
        :return: True if the secret metadata was refreshed.
        """
        return self._get_cache_entry(
            secret_id, version_id, authorization_context, client
        ).refresh_secret_now()

