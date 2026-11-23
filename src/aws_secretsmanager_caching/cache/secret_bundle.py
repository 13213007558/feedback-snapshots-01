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
"""Read a coordinated bundle of secret values from one approved release."""
from dataclasses import dataclass, field
from enum import Enum

from .items import SecretCacheVersion
from .lru import LRUCache


class ComponentStatus(str, Enum):
    """The availability of a single component within a release."""

    AVAILABLE = "AVAILABLE"
    NULL = "NULL"
    UNAVAILABLE = "UNAVAILABLE"


class SecretBundleUnavailableError(Exception):
    """Raised when no approved release yields a complete bundle.

    This is an explicit, distinct signal: every still-approved release had at
    least one component that was null or could not be retrieved, so no coherent
    set can be returned.
    """


@dataclass
class SecretBundle:
    """The values for one complete, approved release.

    :type release_id: str
    :param release_id: The identifier of the release the values came from.

    :type values: dict
    :param values: Mapping of component name to its SecretString value.

    :type statuses: dict
    :param statuses: Mapping of component name to its ComponentStatus.
    """

    release_id: str
    values: dict = field(default_factory=dict)
    statuses: dict = field(default_factory=dict)

    def get(self, name):
        """Return the SecretString value for the named component."""
        return self.values.get(name)


class SecretBundleReader:
    """Resolve a release manifest into a complete bundle of cached secrets.

    The reader walks the still-approved releases newest-first. Each component is
    fetched by the explicit version id pinned by the release, so the returned
    values always belong to the same publication. A release is only used when
    every component is available; a null value or an unavailable component
    skips the release and the previous still-approved release is tried.

    Nothing incomplete is cached as a successful bundle. The individual pinned
    versions are cached through SecretCacheVersion, which keeps serving a
    previously retrieved value when a later refresh attempt fails instead of
    replacing it with a partial result.
    """

    def __init__(self, config, client, max_cache_size):
        self._config = config
        self._client = client
        self._versions = LRUCache(max_size=max_cache_size)

    def _get_pinned_version(self, component):
        """Get the cached secret value object for a pinned component.

        :type component: aws_secretsmanager_caching.release_manifest.SecretComponent
        :param component: The component whose pinned version should be read.

        :rtype: dict
        :return: The cached GetSecretValue result, or None if unavailable.
        """
        cache_key = (component.secret_id, component.version_id)
        version = self._versions.get(cache_key)
        if version is None:
            version = SecretCacheVersion(
                self._config, self._client, component.secret_id, component.version_id
            )
            self._versions.put_if_absent(cache_key, version)
            version = self._versions.get(cache_key)
        try:
            return version.get_secret_value()
        except Exception:  # pylint: disable=broad-except
            return None

    def _resolve_component(self, component):
        """Resolve one component to its value and status.

        A value object that is missing or carries an empty SecretString is
        treated as NULL; a failed retrieval is UNAVAILABLE. Neither qualifies
        as a usable value.

        :rtype: tuple(str, ComponentStatus)
        :return: The value (or None) paired with its status.
        """
        value_object = self._get_pinned_version(component)
        if value_object is None:
            return None, ComponentStatus.UNAVAILABLE
        value = value_object.get("SecretString")
        if not value:
            return value, ComponentStatus.NULL
        return value, ComponentStatus.AVAILABLE

    def _try_release(self, release):
        """Attempt to build a complete bundle from one release.

        :rtype: SecretBundle
        :return: A complete bundle, or None if any component is not available.
        """
        bundle = SecretBundle(release_id=release.release_id)
        complete = True
        for component in release.components:
            value, status = self._resolve_component(component)
            bundle.statuses[component.name] = status
            bundle.values[component.name] = value
            if status is not ComponentStatus.AVAILABLE:
                complete = False
        if not complete:
            return None
        return bundle

    def get_secret_bundle(self, manifest):
        """Return a complete bundle from the newest usable approved release.

        :type manifest: aws_secretsmanager_caching.release_manifest.SecretReleaseManifest
        :param manifest: The release manifest describing the coordinated set.

        :rtype: SecretBundle
        :return: A complete bundle whose values share one approved release.

        :raises SecretBundleUnavailableError: if no approved release is complete.
        """
        for release in manifest.approved_releases():
            bundle = self._try_release(release)
            if bundle is not None:
                return bundle
        raise SecretBundleUnavailableError(
            f"No approved release of manifest '{manifest.name}' produced a complete bundle"
        )
