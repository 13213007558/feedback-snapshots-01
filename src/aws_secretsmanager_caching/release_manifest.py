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
"""Release manifest for reading a coordinated set of secrets.

A release manifest groups the individual Secrets Manager secrets that make up a
single coherent configuration (for example a database username and password)
into *releases*. Each release pins every component to an explicit secret
version id, so the values returned for the components are guaranteed to come
from one approved publication. Releases move through approval independently of
the underlying secret versions, which allows a partially rolled-out set of
secret versions to fall back to the previous still-approved release.
"""
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SecretComponent:
    """A single secret entry that participates in a release.

    :type name: str
    :param name: The component name used as the key when returning a bundle.

    :type secret_id: str
    :param secret_id: The Secrets Manager secret identifier.

    :type version_id: str
    :param version_id: The explicit secret version id pinned by the release.
    """

    name: str
    secret_id: str
    version_id: str


@dataclass
class SecretRelease:
    """An approved publication that pins every component to a version id.

    :type release_id: str
    :param release_id: The unique identifier of the release.

    :type components: list[SecretComponent]
    :param components: The pinned secret components that make up the release.
    """

    release_id: str
    components: list
    approved: bool = True

    def component(self, name):
        """Return the component with the given name, or None if absent."""
        for entry in self.components:
            if entry.name == name:
                return entry
        return None


@dataclass
class SecretReleaseManifest:
    """An ordered collection of releases for one coordinated secret set.

    Releases are stored newest-first. A release is only eligible to be returned
    while it is approved; revoking a release removes it from the set of
    releases that may be served.
    """

    name: str
    releases: list = field(default_factory=list)

    def add_release(self, release):
        """Add a release as the newest entry in the manifest.

        :type release: SecretRelease
        :param release: The release to add.

        :rtype: SecretRelease
        :return: The release that was added.
        """
        self.releases.insert(0, release)
        return release

    def revoke_release(self, release_id):
        """Revoke a previously approved release.

        :type release_id: str
        :param release_id: The identifier of the release to revoke.

        :rtype: SecretRelease
        :return: The revoked release.
        """
        for release in self.releases:
            if release.release_id == release_id:
                release.approved = False
                return release
        raise KeyError(release_id)

    def approved_releases(self):
        """Return the still-approved releases, newest-first."""
        return [release for release in self.releases if release.approved]
