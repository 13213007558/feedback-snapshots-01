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

"""Audit / provenance recording for kube-config selection and credential use.

When cluster configuration is rotated, support engineers must be able to
answer, for every Kubernetes request, *which* cluster configuration and
*which generation* of credentials were actually used.  This module provides
that audit trail on the controlled (client) side.

Privacy is structural, not a matter of caller discipline:

* Only named, non-secret "source identifiers" are ever captured.  Full
  kube-config documents, tokens, client keys and other credentials are never
  passed to this module and therefore can never be logged or shared.
* A refresh failure is recorded against the provenance snapshot that was in
  force when the refresh was *started*.  Because the snapshot is immutable and
  captured up front, an error that returns late still attributes to the
  configuration that was selected at decision time, even if the active
  context has since been rotated.
"""

import datetime
import itertools
import threading

from .dateutil import UTC, format_rfc3339

# Event type constants.  Kept as plain strings so audit output stays
# trivially serializable and stable across versions.
EVENT_SELECTION = "selection"
EVENT_REQUEST = "request"
EVENT_CREDENTIAL_REFRESH = "credential_refresh"
EVENT_CREDENTIAL_REFRESH_FAILED = "credential_refresh_failed"

# The only provenance fields that may leave the controlled side.  Anything not
# listed here (tokens, passwords, full config blobs, ...) is deliberately
# absent and has no code path into an audit record.
_ALLOWED_PROVENANCE_KEYS = (
    "context",
    "cluster",
    "user",
    "config_path",
    "cluster_path",
    "user_path",
    "auth_method",
    "credential_generation",
)

# Status values allowed in a shared diagnostic view.
_ALLOWED_STATUSES = ("succeeded", "failed")

_counter = itertools.count(1)


def _now():
    return datetime.datetime.now(tz=UTC)


class SelectionProvenance:
    """An immutable description of where a configuration decision came from.

    The object holds *identifiers* only.  It never holds the kube-config
    content or any secret material, so it is safe to retain and to surface in
    a shared diagnostic record.
    """

    __slots__ = (
        "_context",
        "_cluster",
        "_user",
        "_config_path",
        "_cluster_path",
        "_user_path",
        "_auth_method",
        "_credential_generation",
    )

    def __init__(self, context=None, cluster=None, user=None,
                 config_path=None, cluster_path=None, user_path=None,
                 auth_method=None, credential_generation=0):
        self._context = context
        self._cluster = cluster
        self._user = user
        self._config_path = config_path
        self._cluster_path = cluster_path
        self._user_path = user_path
        self._auth_method = auth_method
        self._credential_generation = int(credential_generation)

    @property
    def context(self):
        return self._context

    @property
    def cluster(self):
        return self._cluster

    @property
    def user(self):
        return self._user

    @property
    def config_path(self):
        return self._config_path

    @property
    def cluster_path(self):
        return self._cluster_path

    @property
    def user_path(self):
        return self._user_path

    @property
    def auth_method(self):
        return self._auth_method

    @property
    def credential_generation(self):
        return self._credential_generation

    def with_generation(self, generation):
        """Return a copy carrying a new credential generation."""
        return SelectionProvenance(
            context=self._context,
            cluster=self._cluster,
            user=self._user,
            config_path=self._config_path,
            cluster_path=self._cluster_path,
            user_path=self._user_path,
            auth_method=self._auth_method,
            credential_generation=generation)

    def diagnostic_dict(self):
        """Return only the allowed, non-secret source identifiers."""
        values = (
            self._context,
            self._cluster,
            self._user,
            self._config_path,
            self._cluster_path,
            self._user_path,
            self._auth_method,
            self._credential_generation,
        )
        result = {}
        for key, value in zip(_ALLOWED_PROVENANCE_KEYS, values):
            if value is None or value == "":
                continue
            # Generation zero means "not established yet"; omit it.
            if key == "credential_generation" and value == 0:
                continue
            result[key] = value
        return result

    def __eq__(self, other):
        if not isinstance(other, SelectionProvenance):
            return NotImplemented
        return self.diagnostic_dict() == other.diagnostic_dict()

    def __repr__(self):
        return "SelectionProvenance(%r)" % self.diagnostic_dict()


class AuditEvent:
    """A single, immutable audit record.

    Only allowed source identifiers, an outcome and timestamps are stored.
    ``error`` carries an error *type/message*, never credentials.
    """

    __slots__ = ("_event_id", "_event_type", "_timestamp", "_provenance",
                 "_status", "_error")

    def __init__(self, event_type, provenance, timestamp, status=None,
                 error=None, event_id=None):
        self._event_id = event_id if event_id is not None else next(_counter)
        self._event_type = event_type
        self._timestamp = timestamp
        self._provenance = provenance
        self._status = status
        self._error = error

    @property
    def event_id(self):
        return self._event_id

    @property
    def event_type(self):
        return self._event_type

    @property
    def timestamp(self):
        return self._timestamp

    @property
    def provenance(self):
        return self._provenance

    @property
    def status(self):
        return self._status

    @property
    def error(self):
        return self._error

    def diagnostic_dict(self):
        """Serialize to a shareable, secret-free dictionary."""
        record = {
            "event_id": self._event_id,
            "event_type": self._event_type,
            "timestamp": format_rfc3339(self._timestamp),
            "provenance": self._provenance.diagnostic_dict(),
        }
        if self._status is not None:
            record["status"] = self._status
        if self._error is not None:
            record["error"] = self._error
        return record

    def __repr__(self):
        return "AuditEvent(%r)" % self.diagnostic_dict()


class AuditLog:
    """A thread-safe, in-memory recorder of configuration/credential events.

    The log retains provenance identifiers only; full configurations and
    tokens live exclusively in the loader/configuration objects, never here.
    """

    def __init__(self, max_events=1000):
        self._events = []
        self._lock = threading.RLock()
        self._max_events = max_events

    def _record(self, event_type, provenance, status=None, error=None,
                timestamp=None):
        event = AuditEvent(
            event_type=event_type,
            provenance=provenance,
            timestamp=timestamp or _now(),
            status=status,
            error=error)
        with self._lock:
            self._events.append(event)
            if self._max_events and len(self._events) > self._max_events:
                del self._events[:len(self._events) - self._max_events]
        return event

    def record_selection(self, provenance, timestamp=None):
        """Record that a context/config was selected for use."""
        return self._record(EVENT_SELECTION, provenance,
                            timestamp=timestamp)

    def record_request(self, provenance, timestamp=None):
        """Record that a request was issued under a provenance snapshot."""
        return self._record(EVENT_REQUEST, provenance,
                            timestamp=timestamp)

    def record_credential_refresh(self, provenance, timestamp=None):
        """Record that a credential refresh was started.

        The provenance snapshot is captured before any refresh work runs, so a
        later (even delayed) failure can be matched to this start point.
        """
        return self._record(EVENT_CREDENTIAL_REFRESH, provenance,
                            timestamp=timestamp)

    def record_credential_refresh_failed(self, provenance, error,
                                         timestamp=None):
        """Record a refresh failure against the provenance selected at start.

        ``error`` is expected to be an exception instance or a short message;
        it must not contain secret material.
        """
        message = error if isinstance(error, str) else str(error)
        return self._record(EVENT_CREDENTIAL_REFRESH_FAILED, provenance,
                            status="failed", error=message,
                            timestamp=timestamp)

    def events(self, event_type=None, context=None):
        """Return a list of recorded events, optionally filtered."""
        with self._lock:
            result = list(self._events)
        if event_type is not None:
            result = [e for e in result if e.event_type == event_type]
        if context is not None:
            result = [
                e for e in result
                if e.provenance.context == context]
        return result

    def diagnostics(self, event_type=None, context=None):
        """Return shareable, secret-free dictionaries for recorded events."""
        return [
            event.diagnostic_dict()
            for event in self.events(event_type=event_type, context=context)
        ]

    def last_event(self, event_type=None):
        with self._lock:
            if not self._events:
                return None
            if event_type is None:
                return self._events[-1]
            for event in reversed(self._events):
                if event.event_type == event_type:
                    return event
        return None

    def clear(self):
        with self._lock:
            self._events = []


# A process-wide default log.  Loaders that are not handed an explicit
# AuditLog use this one, so callers without wiring still get an audit trail.
_default_audit_log = AuditLog()
_default_audit_lock = threading.Lock()


def get_default_audit_log():
    return _default_audit_log


def set_default_audit_log(audit_log):
    """Replace the process-wide default audit log (handy for tests)."""
    global _default_audit_log
    with _default_audit_lock:
        _default_audit_log = audit_log


def record_request_for_configuration(client_configuration):
    """Record a Kubernetes request against a loaded client Configuration.

    The loader attaches a secret-free provenance snapshot and the audit log to
    the Configuration.  This reads those back and appends a ``request`` event,
    returning the provenance snapshot (or ``None`` when the Configuration was
    not produced by an instrumented loader).  No token or config content is
    involved.
    """
    provenance = getattr(client_configuration, "provenance", None)
    if provenance is None:
        return None
    audit_log = getattr(
        client_configuration, "audit_log", get_default_audit_log())
    audit_log.record_request(provenance)
    return provenance
