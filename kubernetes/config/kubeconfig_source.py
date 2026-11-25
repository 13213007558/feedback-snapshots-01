# Copyright 2026 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Source provenance and capability policy for merged kubeconfig files.

A merged kubeconfig is not a single trust domain.  Contexts, clusters and
users may each come from a different file, and only some of those files may be
allowed to do more than describe a cluster.  Checking the file that was passed
to ``load_kube_config`` is therefore not sufficient: the interesting question
is where the *resolved* cluster, user and exec plugin definition came from.

The helpers in this module keep that decision explicit:

* :class:`KubeConfigSourcePolicy` maps canonical file identities to the
  capabilities they were approved for (``describe``, ``authenticate`` and
  ``exec``).
* :class:`KubeConfigAudit` records what was actually used for a load: source
  file identities, certificate origin and digest, the resulting identity and
  whether an authentication plugin was actually spawned (and whether it
  succeeded).

Paths are canonicalised with ``realpath`` so public aliases (symlinks, relative
paths, ``~`` expansions) resolve to the same approved identity.  Canonicalising
also means an alias can never be used to grant capabilities to a different
file.
"""

import hashlib
import os

from .config_exception import ConfigException


CAPABILITY_DESCRIBE = "describe"
CAPABILITY_AUTHENTICATE = "authenticate"
CAPABILITY_EXEC = "exec"

CAPABILITIES = frozenset(
    (CAPABILITY_DESCRIBE, CAPABILITY_AUTHENTICATE, CAPABILITY_EXEC))

_CAPABILITY_ALIASES = {
    "cluster": CAPABILITY_DESCRIBE,
    "describe-cluster": CAPABILITY_DESCRIBE,
    "read": CAPABILITY_DESCRIBE,
    "user": CAPABILITY_AUTHENTICATE,
    "auth": CAPABILITY_AUTHENTICATE,
    "credentials": CAPABILITY_AUTHENTICATE,
    "plugin": CAPABILITY_EXEC,
    "exec-plugin": CAPABILITY_EXEC,
}


def canonical_source_path(path):
    """Return a stable identity for a kubeconfig source path.

    ``None`` is preserved: an in-memory config has no file provenance and the
    policy has to decide explicitly whether that is acceptable.
    """

    if path is None:
        return None
    return os.path.realpath(os.path.abspath(os.path.expanduser(str(path))))


def _normalize_capabilities(capabilities):
    if len(capabilities) == 1 and isinstance(
            capabilities[0], (list, tuple, set, frozenset)):
        capabilities = tuple(capabilities[0])
    result = set()
    for capability in capabilities:
        name = str(capability).strip().lower()
        if name in ("all", "*"):
            result.update(CAPABILITIES)
            continue
        name = _CAPABILITY_ALIASES.get(name, name)
        if name not in CAPABILITIES:
            raise ValueError(
                "Unknown kubeconfig source capability: %s (expected one of %s)"
                % (capability, ", ".join(sorted(CAPABILITIES))))
        result.add(name)
    return frozenset(result)


class KubeConfigSourceError(ConfigException):
    """Raised when a resolved kubeconfig component comes from a source that
    was not approved for the capability it is about to use."""

    def __init__(self, message, source=None, capability=None, stage=None):
        super().__init__(message)
        self.source = source
        self.capability = capability
        self.stage = stage


class KubeConfigSourcePolicy:
    """Approved capabilities per kubeconfig source file.

    By default every capability is denied.  Approve a file explicitly::

        policy = KubeConfigSourcePolicy()
        policy.approve("/etc/kube/team-a.yaml",
                       "describe", "authenticate", "exec")
        policy.approve("/etc/kube/shared-clusters.yaml", "describe")

    A file may also be registered under an alias, although canonical paths
    already make symlinks and relative paths work::

        policy.alias("/home/me/.kube/team-a.yaml", "/etc/kube/team-a.yaml")
    """

    def __init__(self, default_capabilities=()):
        self._default = _normalize_capabilities(default_capabilities)
        self._grants = {}
        self._aliases = {}

    def approve(self, path, *capabilities):
        """Grant capabilities to the file identified by ``path``."""

        if not capabilities:
            raise ValueError("At least one capability must be approved")
        granted = _normalize_capabilities(capabilities)
        key = self._target_path(path)
        self._grants[key] = self._grants.get(key, frozenset()) | granted
        return self

    def revoke(self, path, *capabilities):
        """Remove capabilities from ``path``; with no arguments remove all."""

        key = self._target_path(path)
        if not capabilities:
            self._grants.pop(key, None)
            return self
        revoked = _normalize_capabilities(capabilities)
        current = self._grants.get(key)
        if current is not None:
            self._grants[key] = current - revoked
        return self

    def alias(self, alias_path, target_path):
        """Register ``alias_path`` as another name for ``target_path``."""

        self._aliases[canonical_source_path(alias_path)] = \
            canonical_source_path(target_path)
        return self

    def capabilities_for(self, path):
        key = self._target_path(path)
        return self._grants.get(key, self._default)

    def allows(self, path, capability):
        return _normalize_capabilities((capability,)) <= \
            self.capabilities_for(path)

    def check(self, path, capability, stage=None):
        """Raise :class:`KubeConfigSourceError` if ``path`` is not approved."""

        capability = next(iter(_normalize_capabilities((capability,))))
        if self.allows(path, capability):
            return
        canonical = canonical_source_path(path)
        if canonical is None:
            message = (
                "kubeconfig source is not verifiable for %s: the resolved "
                "component has no originating file" % (stage or capability))
        else:
            message = (
                "kubeconfig source %s is not approved for %s (needed by %s)"
                % (canonical, capability, stage or capability))
        raise KubeConfigSourceError(
            message, source=canonical, capability=capability,
            stage=stage or capability)

    def _target_path(self, path):
        canonical = canonical_source_path(path)
        seen = set()
        while canonical in self._aliases and canonical not in seen:
            seen.add(canonical)
            canonical = self._aliases[canonical]
        return canonical


def sha256_file(path):
    """Return the SHA-256 digest of a file, or ``None`` when unavailable."""

    if not path:
        return None
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


class KubeConfigAuditRecord:
    """One record of what a kubeconfig load actually resolved and used.

    The record separates three things that are easy to conflate:

    * where each resolved component was declared (``context``/``cluster``/
      ``user`` sources, canonicalised),
    * which certificate material was actually obtained, including whether it
      came from inline ``-data`` or from a file and its SHA-256 digest,
    * which identity the load ended up using and whether the authentication
      plugin was really spawned.

    It never stores token values, private keys or certificate bodies.
    """

    def __init__(self, context_name=None, context_source=None,
                 cluster_name=None, cluster_source=None,
                 user_name=None, user_source=None):
        self.context_name = context_name
        self.context_source = context_source
        self.context_source_realpath = canonical_source_path(context_source)
        self.cluster_name = cluster_name
        self.cluster_source = cluster_source
        self.cluster_source_realpath = canonical_source_path(cluster_source)
        self.user_name = user_name
        self.user_source = user_source
        self.user_source_realpath = canonical_source_path(user_source)
        self.server = None
        self.verify_ssl = None
        self.certificate_authority = None
        self.client_certificate = None
        self.client_key = None
        self.identity = {"method": "anonymous"}
        self.exec_configured = False
        self.exec_command = None
        self.exec_authorized = None
        self.exec_invocations = 0
        self.exec_succeeded = False
        self.policy_enforced = False
        self.source_capabilities = {}
        self.decision = "allowed"
        self.denied_capability = None
        self.denied_stage = None
        self.denied_source = None
        self.error = None

    def to_dict(self):
        return {
            "context": {
                "name": self.context_name,
                "source": self.context_source,
                "source_realpath": self.context_source_realpath,
            },
            "cluster": {
                "name": self.cluster_name,
                "source": self.cluster_source,
                "source_realpath": self.cluster_source_realpath,
                "server": self.server,
                "verify_ssl": self.verify_ssl,
                "certificate_authority": self.certificate_authority,
            },
            "user": {
                "name": self.user_name,
                "source": self.user_source,
                "source_realpath": self.user_source_realpath,
                "client_certificate": self.client_certificate,
                "client_key": self.client_key,
            },
            "identity": dict(self.identity) if self.identity else None,
            "exec": {
                "configured": self.exec_configured,
                "command": list(self.exec_command)
                if self.exec_command else None,
                "authorized": self.exec_authorized,
                "invocations": self.exec_invocations,
                "spawned": self.exec_invocations > 0,
                "succeeded": self.exec_succeeded,
            },
            "policy_enforced": self.policy_enforced,
            "source_capabilities": {
                (key if key is not None else "<in-memory>"): sorted(value)
                for key, value in self.source_capabilities.items()
            },
            "decision": self.decision,
            "denied": {
                "capability": self.denied_capability,
                "stage": self.denied_stage,
                "source": self.denied_source,
            } if self.decision == "denied" else None,
            "error": self.error,
        }


def describe_material(declared_value, resolved_file=None, kind=None,
                      origin=None):
    """Summarise one certificate field for the audit record.

    ``declared_value`` is the raw kubeconfig value (an inline ``-data`` blob
    or a path), ``resolved_file`` is the file actually handed to the client,
    ``kind`` says whether the value was inline (``data``) or a path, and
    ``origin`` distinguishes material that did not come from the kubeconfig
    at all (for example, a plugin's ``clientCertificateData``).
    Only the origin, the resolved path and a digest are kept; the material
    itself stays out of the record.
    """

    if declared_value is None and resolved_file is None:
        return None
    material = {
        "declared": None,
        "kind": kind,
        "origin": origin,
        "file": resolved_file,
        "sha256": sha256_file(resolved_file),
    }
    if declared_value is not None:
        if material["kind"] is None:
            material["kind"] = "path" if isinstance(
                declared_value, str) else "data"
        # A path is safe to record; inline material is not.
        material["declared"] = declared_value \
            if material["kind"] == "path" else "<inline>"
    elif resolved_file is not None and material["kind"] is None:
        material["kind"] = "file"
    return material


class KubeConfigAudit:
    """Collects :class:`KubeConfigAuditRecord` entries for one caller."""

    def __init__(self):
        self.records = []

    def new_record(self, **kwargs):
        record = KubeConfigAuditRecord(**kwargs)
        self.records.append(record)
        return record

    @property
    def last_record(self):
        return self.records[-1] if self.records else None

    def exec_invocations(self):
        return sum(record.exec_invocations for record in self.records)

    def to_dict(self):
        return {
            "records": [record.to_dict() for record in self.records],
            "exec_invocations": self.exec_invocations(),
        }
