#  BSD 3-Clause License
#
#  Copyright (c) 2012, the Sentry Team, see AUTHORS for more details
#  Copyright (c) 2019, Elasticsearch BV
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
#  * Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE


"""
Process-local error diagnostics.

The APM agent has two audiences for an error event:

* in-process code that needs the original details to debug a failure, and
* the outbound APM intake, which must only receive the redacted projection
  produced by :mod:`elasticapm.redaction` at serialization time.

Events are captured and queued before processors and serialization run. A
diagnostic snapshot is therefore taken at capture time, before any processor
can mutate the queued event. The snapshot is kept in a bounded, process-local
store keyed by the error event ID and is never serialized.
"""

import copy
import threading
from collections import OrderedDict

from elasticapm.utils.logging import get_logger

logger = get_logger("elasticapm.diagnostics")

# Keep the number of retained snapshots bounded so a long-running process
# cannot grow without limit if callers never consume diagnostics.
DEFAULT_ERROR_DIAGNOSTIC_CAPACITY = 1000


class ErrorDiagnosticStore(object):
    """
    Bounded, thread-safe store for full-fidelity error snapshots.

    Values returned by :meth:`get` are deep copies so internal readers cannot
    change the retained object, and so the retained object can never become
    the source of an outbound event.
    """

    # Only these fields are ever reused for the outbound view. They are the
    # approved correlation, never captured payload data.
    CORRELATION_FIELDS = ("id", "trace_id", "transaction_id", "parent_id")

    def __init__(self, capacity=DEFAULT_ERROR_DIAGNOSTIC_CAPACITY):
        self._capacity = max(0, int(capacity))
        self._items = OrderedDict()
        self._correlations = OrderedDict()
        self._lock = threading.Lock()
        self.dropped = 0

    def retain(self, event) -> None:
        if not isinstance(event, dict) or "id" not in event:
            return
        # Copy outside the lock so a large event does not block readers.
        snapshot = copy.deepcopy(event)
        correlation = {key: event[key] for key in self.CORRELATION_FIELDS if event.get(key) is not None}
        with self._lock:
            # A re-submitted event must not replace the richer snapshot taken
            # at original capture time with a potentially redacted copy.
            if event["id"] in self._items:
                return
            self._items[event["id"]] = snapshot
            self._correlations[event["id"]] = correlation
            while len(self._items) > self._capacity:
                dropped_id, _ = self._items.popitem(last=False)
                self._correlations.pop(dropped_id, None)
                self.dropped += 1

    def get(self, event_id):
        with self._lock:
            item = self._items.get(event_id)
            return copy.deepcopy(item) if item is not None else None

    def pop(self, event_id):
        with self._lock:
            self._correlations.pop(event_id, None)
            return self._items.pop(event_id, None)

    def correlation(self, event_id):
        """
        Return only the capture-time correlation fields for ``event_id``.

        This deliberately excludes every piece of payload data retained for
        in-process diagnostics.
        """
        with self._lock:
            correlation = self._correlations.get(event_id)
            return dict(correlation) if correlation is not None else None

    def peek(self, event_id):
        with self._lock:
            return copy.deepcopy(self._items.get(event_id))

    def ids(self):
        with self._lock:
            return list(self._items.keys())

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
            self._correlations.clear()
            self.dropped = 0

    def __contains__(self, event_id):
        with self._lock:
            return event_id in self._items

    def __len__(self):
        with self._lock:
            return len(self._items)


def retain_error_diagnostic(client, event) -> None:
    """
    Retain a full-fidelity copy of an error event for in-process readers.

    A failure here must never prevent the event from being queued.
    """
    if client is None:
        return
    store = getattr(client, "error_diagnostics", None)
    if store is None:
        return
    try:
        store.retain(event)
    except Exception:
        logger.warning("Failed to retain error diagnostic for event %s", event.get("id"), exc_info=True)


def get_error_correlation(client, event_id):
    """Return the approved capture-time correlation for an error event."""
    if client is None:
        return None
    store = getattr(client, "error_diagnostics", None)
    if store is None:
        return None
    return store.correlation(event_id)


def get_error_diagnostic(client, event_id, consume=False):
    """
    Return the retained internal view for ``event_id``.

    :param client: the ElasticAPM client that captured the error
    :param event_id: the ID returned by ``capture_exception``/``capture_message``
    :param consume: if True, remove the snapshot after reading it
    """
    if client is None:
        return None
    store = getattr(client, "error_diagnostics", None)
    if store is None:
        return None
    return store.pop(event_id) if consume else store.get(event_id)


__all__ = (
    "DEFAULT_ERROR_DIAGNOSTIC_CAPACITY",
    "ErrorDiagnosticStore",
    "get_error_correlation",
    "get_error_diagnostic",
    "retain_error_diagnostic",
)
