# -*- coding: utf-8 -*-

#  BSD 3-Clause License
#
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
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
Optional discard convention for the transport event queue.

The convention is opt-in: a :class:`DiscardPolicy` is only active when one is
passed to the transport.  When active it

* puts a hard upper bound on the number of accepted-but-unprocessed events,
* evicts lower retention classes (e.g. ordinary metrics) before higher ones
  (e.g. security/audit events),
* keeps an exact ledger of records that were really discarded versus records
  that were put on the wire but never acknowledged, and
* builds gap reports that are embedded in the next outgoing batch and only
  marked as acknowledged once that batch was accepted by the sender.

The ledger is deliberately cumulative for the lifetime of the transport.  A
failed send therefore cannot erase the description of an earlier gap: the
counters only move forward and the next successfully delivered batch carries
the complete picture again.
"""

import copy
import json
import threading
import time
from collections import defaultdict


class _EvictMiss(object):
    def __repr__(self):
        return "<no eviction candidate>"


EVICT_MISS = _EvictMiss()


def evict_from_queue(queue_obj, should_evict):
    """Remove the first item accepted by ``should_evict`` from a queue.

    Works with ``queue.Queue`` and the agent's ``ChilledQueue`` without
    depending on private attributes that monkeypatched implementations may not
    provide.  The queue counters are kept consistent so that the consumer does
    not wait for a phantom task.
    """
    items = getattr(queue_obj, "queue", None)
    if items is None:
        return EVICT_MISS
    lock = getattr(queue_obj, "not_full", None) or getattr(queue_obj, "mutex", None)
    if lock is None:
        return EVICT_MISS
    with lock:
        for item in list(items):
            if not should_evict(item):
                continue
            try:
                items.remove(item)
            except ValueError:
                # The consumer removed it between snapshot and deletion.
                continue
            unfinished_tasks = getattr(queue_obj, "unfinished_tasks", None)
            if unfinished_tasks is not None:
                queue_obj.unfinished_tasks = max(0, unfinished_tasks - 1)
            not_full = getattr(queue_obj, "not_full", None)
            if not_full is not None:
                not_full.notify()
            return item
    return EVICT_MISS


def queue_items(queue_obj):
    """Return a snapshot of the items currently waiting in ``queue_obj``."""
    items = getattr(queue_obj, "queue", None)
    if items is None:
        return []
    lock = getattr(queue_obj, "not_full", None) or getattr(queue_obj, "mutex", None)
    if lock is None:
        return list(items)
    with lock:
        return list(items)


def queue_event_type(item):
    if isinstance(item, tuple) and item:
        return item[0]
    return None


def queue_counts(queue_obj, is_control=None) -> dict:
    """Count waiting, non-control queue items by event type."""
    counts = defaultdict(int)
    for item in queue_items(queue_obj):
        event_type = queue_event_type(item)
        if is_control is not None and is_control(event_type):
            continue
        if event_type is not None:
            counts[event_type] += 1
    return dict(counts)


class DiscardPolicy(object):
    """Retention classes and the hard limit for the transport event queue."""

    CONTROL_EVENT_TYPES = frozenset((None, "close"))

    # Security/audit records are kept in preference to ordinary telemetry.
    DEFAULT_EVENT_CLASSES = {
        "error": "security",
        "transaction": "ordinary",
        "span": "ordinary",
        "metricset": "ordinary",
    }
    # A higher priority is kept longer.  Equal priorities never displace each
    # other; the incoming record is discarded instead.
    DEFAULT_CLASS_PRIORITIES = {"ordinary": 0, "security": 10}

    def __init__(self, max_queue_size=1000, event_classes=None, class_priorities=None) -> None:
        if isinstance(max_queue_size, bool) or not isinstance(max_queue_size, int) or max_queue_size <= 0:
            raise ValueError("max_queue_size must be a positive integer")
        self.max_queue_size = max_queue_size

        classes = dict(self.DEFAULT_EVENT_CLASSES)
        if event_classes:
            if not isinstance(event_classes, dict):
                raise TypeError("event_classes must be a mapping of event type to retention class")
            for event_type, retention_class in event_classes.items():
                if not isinstance(event_type, str) or not isinstance(retention_class, str):
                    raise TypeError("event_classes keys and values must be strings")
                classes[event_type] = retention_class
        self.event_classes = classes

        priorities = dict(self.DEFAULT_CLASS_PRIORITIES)
        if class_priorities:
            if not isinstance(class_priorities, dict):
                raise TypeError("class_priorities must be a mapping of retention class to integer priority")
            for retention_class, priority in class_priorities.items():
                if not isinstance(retention_class, str) or isinstance(priority, bool) or not isinstance(priority, int):
                    raise TypeError("class_priorities keys must be strings and values must be integers")
                priorities[retention_class] = priority
        self.class_priorities = priorities

    @classmethod
    def from_value(cls, value, strict=True):
        """Build a policy from ``None``, a mapping, a JSON string or a policy."""
        if value is None or isinstance(value, cls):
            return value
        if isinstance(value, str):
            value = value.strip()
            if not value:
                return None
            try:
                value = json.loads(value)
            except ValueError as exc:
                raise ValueError("expected a JSON object: %s" % exc) from exc
        if not isinstance(value, dict):
            raise TypeError("expected a mapping or a JSON object")

        kwargs = {}
        aliases = {
            "max_queue_size": "max_queue_size",
            "max_queue": "max_queue_size",
            "queue_max_size": "max_queue_size",
            "event_classes": "event_classes",
            "retention": "event_classes",
            "class_priorities": "class_priorities",
            "priorities": "class_priorities",
        }
        unknown = [key for key in value if key not in aliases]
        if unknown and strict:
            raise ValueError("unknown discard policy option %r" % (unknown[0],))
        for key in value:
            if key in aliases:
                kwargs[aliases[key]] = value[key]
        if not kwargs:
            return None
        return cls(**kwargs)

    def is_control(self, event_type) -> bool:
        return event_type in self.CONTROL_EVENT_TYPES

    def event_class(self, event_type) -> str:
        return self.event_classes.get(event_type, "ordinary")

    def priority_for(self, event_type) -> int:
        return self.class_priorities.get(self.event_class(event_type), 0)

    def to_dict(self) -> dict:
        return {
            "max_queue_size": self.max_queue_size,
            "event_classes": dict(self.event_classes),
            "class_priorities": dict(self.class_priorities),
        }


def _as_counts(value) -> dict:
    if isinstance(value, str):
        return {value: 1}
    if isinstance(value, dict):
        return {str(k): int(v) for k, v in value.items() if int(v)}
    raise TypeError("counts must be an event type or a mapping")


def _copy_counts(value) -> dict:
    return {str(k): int(v) for k, v in value.items() if int(v)}


class DiscardLedger(object):
    """Thread-safe accounting of discarded and unacknowledged records.

    Two buckets are kept strictly separate:

    ``discarded``
        Records the agent knows it will not send (queue bound, transport
        back-off).  These are real gaps.
    ``unconfirmed``
        Records that were handed to the sender without a final receipt.  The
        request may still be delivered; they are neither a discarding decision
        nor a confirmed gap.  A failed recovery attempt never clears them.
    """

    def __init__(self, policy) -> None:
        self.policy = policy
        self._lock = threading.Lock()
        self._accepted = defaultdict(int)
        self._discarded = defaultdict(int)
        self._discard_reasons = defaultdict(int)
        self._unconfirmed = defaultdict(int)
        self._unconfirmed_reasons = defaultdict(int)
        self._confirmed = defaultdict(int)
        self._first_discard_at = None
        self._last_discard_at = None
        # Only gap-relevant changes (discards / unconfirmed sends) advance the
        # revision.  Successfully delivered records are not a gap and do not
        # require another report.
        self._revision = 0
        self._acknowledged_revision = 0
        self._last_acknowledged = None
        self._last_attempted = None

    @property
    def revision(self) -> int:
        with self._lock:
            return self._revision

    @property
    def pending(self) -> bool:
        with self._lock:
            return self._revision > self._acknowledged_revision

    @property
    def last_acknowledged(self):
        with self._lock:
            return copy.deepcopy(self._last_acknowledged)

    @property
    def last_attempted(self):
        with self._lock:
            return copy.deepcopy(self._last_attempted)

    def _mark_gap_locked(self) -> None:
        self._revision += 1

    def record_accepted(self, counts) -> None:
        counts = _as_counts(counts)
        if not counts:
            return
        with self._lock:
            for event_type, count in counts.items():
                self._accepted[event_type] += count

    def record_discard(self, counts, reason="queue_full") -> None:
        counts = _as_counts(counts)
        if not counts:
            return
        now = time.time()
        with self._lock:
            for event_type, count in counts.items():
                self._discarded[event_type] += count
            self._discard_reasons[reason] += sum(counts.values())
            if self._first_discard_at is None:
                self._first_discard_at = now
            self._last_discard_at = now
            self._mark_gap_locked()

    def record_unconfirmed(self, counts, reason="send_failed") -> None:
        counts = _as_counts(counts)
        if not counts:
            return
        with self._lock:
            for event_type, count in counts.items():
                self._unconfirmed[event_type] += count
            self._unconfirmed_reasons[reason] += sum(counts.values())
            self._mark_gap_locked()

    def record_confirmed(self, counts) -> None:
        counts = _as_counts(counts)
        if not counts:
            return
        with self._lock:
            for event_type, count in counts.items():
                self._confirmed[event_type] += count

    def begin_attempt(self, report) -> None:
        """Remember the report that is about to be handed to the sender."""
        if report is None:
            return
        with self._lock:
            self._last_attempted = copy.deepcopy(report)

    def acknowledge(self, report, confirmed_counts=None) -> None:
        """Mark a report as delivered and account for the batch's records.

        A report is only acknowledged after the sender accepted the batch that
        carried it.  Failed attempts leave both the ledger counters and the
        attempted report untouched, so a later batch repeats the full gap.
        """
        self.record_confirmed(confirmed_counts or {})
        if report is None:
            return
        report_revision = int(report.get("revision", self._revision))
        with self._lock:
            if report_revision > self._acknowledged_revision:
                self._acknowledged_revision = report_revision
            acknowledged = copy.deepcopy(report)
            acknowledged["acknowledged"] = True
            self._last_acknowledged = acknowledged

    def _report_locked(self, live=None) -> dict:
        pending = self._revision > self._acknowledged_revision
        report = {
            "revision": self._revision,
            "acknowledged": not pending,
            "pending": pending,
            "pending_acknowledgement": pending,
            "acknowledged_revision": self._acknowledged_revision,
            "discarded": {
                "total": sum(self._discarded.values()),
                "by_event_type": _copy_counts(self._discarded),
                "by_reason": _copy_counts(self._discard_reasons),
            },
            "unconfirmed": {
                # A failed send keeps its records here forever: the payload may
                # or may not have reached the server, so it is not a real
                # discard and cannot be "settled" by later successes.
                "total": sum(self._unconfirmed.values()),
                "by_event_type": _copy_counts(self._unconfirmed),
                "by_reason": _copy_counts(self._unconfirmed_reasons),
            },
            "accepted": {"total": sum(self._accepted.values()), "by_event_type": _copy_counts(self._accepted)},
            "confirmed": {"total": sum(self._confirmed.values()), "by_event_type": _copy_counts(self._confirmed)},
            "policy": self.policy.to_dict(),
        }
        if self._first_discard_at is not None:
            report["first_discard_at"] = self._first_discard_at
            report["last_discard_at"] = self._last_discard_at
        if live:
            report.update(copy.deepcopy(live))
        return report

    def snapshot(self, live=None) -> dict:
        with self._lock:
            return self._report_locked(live=live)
