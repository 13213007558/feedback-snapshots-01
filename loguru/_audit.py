"""Audit receipts tracking the terminal state of records accepted by a sink.

The machinery in this module is opt-in: a handler only records audit state when it is added with
``audit=True``. Each accepted record is assigned a per-handler correlation identifier and goes
through the following states:

- ``QUEUED``:  the record entered the sink (or its internal queue), no terminal outcome yet.
- ``SUCCESS``: the sink finished writing the record without error.
- ``FAILED``:  the sink raised an exception while writing the record.
- ``PENDING``: the outcome could not be confirmed before the receipt cutoff, for instance because
  the write is scheduled on a different event loop than the one requesting the receipt.

A receipt is bounded by a cutoff captured when it is requested: only records accepted before that
point are reported, and the materialized snapshot can never be altered by subsequent writes.
"""

import threading
from collections import namedtuple

# The record was accepted by the sink (or its queue) but has no terminal outcome yet.
QUEUED = "queued"
# The sink finished writing the record without raising.
SUCCESS = "success"
# The sink explicitly raised an exception while writing the record.
FAILED = "failed"
# The outcome of the record could not be confirmed within the receipt cutoff.
PENDING = "pending"

_TERMINAL_STATES = (SUCCESS, FAILED)


class AuditEntry(namedtuple("AuditEntry", ("id", "status", "record"))):
    """The state of a single record accepted by an audited sink.

    Attributes
    ----------
    id : int
        Per-handler monotonic correlation identifier assigned when the record is accepted.
    status : str
        One of ``QUEUED``, ``SUCCESS``, ``FAILED`` or ``PENDING``.
    record : dict
        The Loguru record associated with the correlation identifier.
    """

    __slots__ = ()


class AuditTracker:
    """Track the state of every record accepted by one audited handler."""

    def __init__(self):
        self._lock = threading.Lock()
        self._counter = 0
        self._entries = {}

    def register(self, record):
        """Assign a correlation identifier to a newly accepted record.

        Parameters
        ----------
        record : dict
            The Loguru record that was accepted by the handler.

        Returns
        -------
        AuditEntry
            The entry in the ``QUEUED`` state associated with the record.
        """
        with self._lock:
            self._counter += 1
            entry = AuditEntry(self._counter, QUEUED, record)
            self._entries[entry.id] = entry
            return entry

    def resolve(self, entry_id, status):
        """Move an entry to a terminal state, unless it already reached one.

        Parameters
        ----------
        entry_id : int
            The correlation identifier returned when the record was registered.
        status : str
            ``SUCCESS`` or ``FAILED``.
        """
        if status not in _TERMINAL_STATES:
            raise ValueError("Invalid audit terminal status: %r" % status)
        with self._lock:
            current = self._entries.get(entry_id)
            if current is not None and current.status == QUEUED:
                self._entries[entry_id] = AuditEntry(entry_id, status, current.record)

    def cutoff(self):
        """Return the identifier of the most recently accepted record."""
        with self._lock:
            return self._counter

    def snapshot(self, cutoff):
        """Build an immutable view of all entries up to and including ``cutoff``.

        Entries still in the ``QUEUED`` state are reported as ``PENDING`` because their outcome
        cannot be confirmed. Records accepted after the cutoff are excluded.

        Parameters
        ----------
        cutoff : int
            The largest correlation identifier covered by the receipt.

        Returns
        -------
        tuple of AuditEntry
        """
        with self._lock:
            entries = []
            for entry_id in sorted(self._entries):
                if entry_id > cutoff:
                    break
                entry = self._entries[entry_id]
                if entry.status == QUEUED:
                    entry = AuditEntry(entry_id, PENDING, entry.record)
                entries.append(entry)
            return tuple(entries)

    def __getstate__(self):
        state = self.__dict__.copy()
        state["_lock"] = None
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self._lock = threading.Lock()


class Receipt:
    """An immutable, cutoff-bounded confirmation for one audited handler.

    The receipt covers only records accepted before it was requested. It can be awaited so that
    writes scheduled on the running event loop reach a terminal state before the snapshot is
    materialized. Reading the receipt also materializes it, after which later writes can never
    change the reported entries.
    """

    def __init__(self, handler_id, tracker, cutoff, task_factory):
        self._handler_id = handler_id
        self._tracker = tracker
        self._cutoff = cutoff
        self._task_factory = task_factory
        self._entries = None

    @property
    def handler_id(self):
        """The identifier of the audited handler this receipt belongs to."""
        return self._handler_id

    @property
    def cutoff(self):
        """The largest correlation identifier covered by this receipt."""
        return self._cutoff

    @property
    def entries(self):
        """The materialized, immutable tuple of :class:`AuditEntry` objects."""
        return self._freeze()

    def _freeze(self):
        if self._entries is None:
            self._entries = self._tracker.snapshot(self._cutoff)
        return self._entries

    def __await__(self):
        if self._entries is None:
            for task in self._task_factory():
                yield from task.__await__()
            self._freeze()
        return self

    def __len__(self):
        return len(self._freeze())

    def __iter__(self):
        return iter(self._freeze())

    def __getitem__(self, entry_id):
        for entry in self._freeze():
            if entry.id == entry_id:
                return entry
        raise KeyError(entry_id)

    def __repr__(self):
        entries = self._freeze()
        return "(handler=%d, cutoff=%d, entries=%r)" % (
            self._handler_id,
            self._cutoff,
            list(entries),
        )


class ReceiptBook(dict):
    """A mapping of audited handler identifiers to their :class:`Receipt` objects."""

    def __await__(self):
        for receipt in self.values():
            yield from receipt.__await__()
        return self
