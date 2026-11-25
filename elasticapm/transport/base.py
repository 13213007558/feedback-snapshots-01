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

import gzip
import io
import os
import queue as _queue
import random
import sys
import threading
import time
import timeit
from collections import defaultdict

from elasticapm.transport.discard import (
    EVICT_MISS,
    DiscardLedger,
    DiscardPolicy,
    evict_from_queue,
    queue_counts,
    queue_event_type,
)
from elasticapm.utils import json_encoder
from elasticapm.utils.logging import get_logger
from elasticapm.utils.threading import ThreadManager

logger = get_logger("elasticapm.transport")

# The underlying queue keeps a small amount of head-room for control records
# (flush markers and shutdown) so that flow control can never be blocked by an
# internal marker.  The discard policy's ``max_queue_size`` bounds only data
# events and is enforced with ``_queued_data_count``.
_CONTROL_HEADROOM = 16


class Transport(ThreadManager):
    """
    All transport implementations need to subclass this class

    You must implement a send method..
    """

    async_mode = False

    def __init__(
        self,
        client,
        compress_level=5,
        json_serializer=json_encoder.dumps,
        queue_chill_count=500,
        queue_chill_time=1.0,
        processors=None,
        discard_policy=None,
        **kwargs
    ) -> None:
        """
        Create a new Transport instance

        :param compress_level: GZip compress level. If zero, no GZip compression will be used
        :param json_serializer: serializer to use for JSON encoding
        :param discard_policy: optional :class:`DiscardPolicy` that bounds the
            event queue and reports discarded/unconfirmed records.  When omitted
            the agent keeps its historical unbounded-ish behaviour.
        :param kwargs:
        """
        self.client = client
        self.state = TransportState()
        self._metadata = None
        self._compress_level = min(9, max(0, compress_level if compress_level is not None else 0))
        self._json_serializer = json_serializer
        self._queued_data = None
        self._discard_policy = DiscardPolicy.from_value(discard_policy)
        self._discard_ledger = DiscardLedger(self._discard_policy) if self._discard_policy is not None else None
        self._queued_data_count = 0
        self._queued_data_lock = threading.Lock()
        self._admission_lock = threading.Lock()
        self._event_queue = self._init_event_queue(
            chill_until=queue_chill_count,
            max_chill_time=queue_chill_time,
            maxsize=(
                self._discard_policy.max_queue_size + _CONTROL_HEADROOM
                if self._discard_policy is not None
                else 10000
            ),
        )
        self._is_chilled_queue = isinstance(self._event_queue, ChilledQueue)
        self._thread = None
        self._last_flush = timeit.default_timer()
        self._counts = defaultdict(int)
        self._flushed = threading.Event()
        self._closed = False
        self._processors = processors if processors is not None else []
        super(Transport, self).__init__()
        self.start_stop_order = sys.maxsize  # ensure that the transport thread is always started/stopped last

    @property
    def _max_flush_time_seconds(self):
        return self.client.config.api_request_time.total_seconds() if self.client else None

    @property
    def _max_buffer_size(self):
        return self.client.config.api_request_size if self.client else None

    @property
    def discard_policy(self):
        return self._discard_policy

    @property
    def discard_ledger(self):
        return self._discard_ledger

    @property
    def last_discard_report(self):
        """
        The most recent report a later attempt succeeded in delivering.

        This may be a report that was written into an earlier, failed batch:
        only the next successful send of a batch carrying that report (or a
        newer one) advances the acknowledged revision.
        """
        if self._discard_ledger is None:
            return None
        return self._discard_ledger.last_acknowledged

    def get_discard_report(self):
        """
        Return the current cumulative discard/gap ledger.

        ``discarded`` counts records that were really thrown away (queue bound,
        back-off).  ``unconfirmed`` counts records that were handed to the
        sender but whose delivery has not been confirmed by a successful send;
        they must not be reported as discarded.  ``pending`` indicates whether
        the latest gap has not yet been acknowledged.
        """
        if self._discard_ledger is None:
            return None
        report = self._discard_ledger.snapshot()
        report["queue"] = {
            "max_size": self._discard_policy.max_queue_size,
            "depth": self._queued_events(),
        }
        report["last_attempted"] = self._discard_ledger.last_attempted
        return report

    def _admit_event(self, event_type, item, kwargs) -> None:
        """
        Put an event on the queue, applying the optional discard convention.

        Control records (flush markers and shutdown) are never subject to the
        bound: dropping them would stall the consumer instead of applying
        back-pressure to producers.
        """
        policy = self._discard_policy
        if policy is None:
            # Historical behaviour: no policy, no bound beyond the queue's own
            # generous maxsize.
            try:
                self._event_queue.put(item, block=False, **kwargs)
            except _queue.Full:
                logger.debug("Event of type %s dropped due to full event queue", event_type)
            return

        if policy.is_control(event_type):
            try:
                self._event_queue.put(item, block=False, **kwargs)
            except _queue.Full:
                # Control records keep flow control moving.  If the queue's
                # small head-room is exhausted, retire the oldest data record
                # rather than losing a flush/shutdown marker.
                evicted = evict_from_queue(
                    self._event_queue,
                    lambda queued: not policy.is_control(queue_event_type(queued)),
                )
                if evicted is not EVICT_MISS:
                    self._adjust_queued_data_count(-1)
                    self._record_discard(queue_event_type(evicted), "queue_high_water")
                    try:
                        self._event_queue.put(item, block=False, **kwargs)
                    except _queue.Full:
                        logger.debug("Control event of type %s dropped due to full event queue", event_type)
                else:
                    logger.debug("Control event of type %s dropped due to full event queue", event_type)
            return

        # Serialize producers so the data-event bound is exact even when many
        # threads enqueue at once.  The count is incremented before the put, so
        # a racing admission can never undershoot the bound.
        with self._admission_lock:
            if self._queued_events() >= policy.max_queue_size:
                evicted = self._make_room(event_type)
                if evicted is not EVICT_MISS:
                    self._adjust_queued_data_count(-1)
                    self._record_discard(queue_event_type(evicted), "queue_high_water")
                else:
                    self._record_discard(event_type, "queue_full")
                    logger.debug("Event of type %s dropped due to full event queue", event_type)
                    return
            self._adjust_queued_data_count(1)
            try:
                self._event_queue.put(item, block=False, **kwargs)
            except _queue.Full:
                self._adjust_queued_data_count(-1)
                self._record_discard(event_type, "queue_full")
                logger.debug("Event of type %s dropped due to full event queue", event_type)
                return
            if self._discard_ledger is not None:
                self._discard_ledger.record_accepted(event_type)

    def _adjust_queued_data_count(self, delta) -> None:
        with self._queued_data_lock:
            self._queued_data_count = max(0, self._queued_data_count + delta)

    def _queued_events(self) -> int:
        """Number of data records currently waiting for the consumer."""
        with self._queued_data_lock:
            return self._queued_data_count

    def _make_room(self, incoming_type):
        """
        Evict the oldest queued record whose retention is no stricter than the
        incoming record.

        Returns the evicted item (callers must account for it) or ``EVICT_MISS``.

        Records with a higher retention (e.g. security events) are never
        displaced by lower-retention traffic, while equal-retention traffic
        retires in FIFO order so that at least the same class keeps flowing.
        If no record qualifies the incoming record will be discarded by the
        caller.
        """
        policy = self._discard_policy
        incoming_priority = policy.priority_for(incoming_type)
        evicted = evict_from_queue(
            self._event_queue,
            lambda queued: (
                not policy.is_control(queue_event_type(queued))
                and policy.priority_for(queue_event_type(queued)) <= incoming_priority
            ),
        )
        if evicted is not EVICT_MISS:
            logger.debug(
                "Discarded event of type %s to make room for %s in bounded event queue",
                queue_event_type(evicted),
                incoming_type,
            )
            return evicted
        return EVICT_MISS

    def _record_discard(self, event_type, reason) -> None:
        if self._discard_ledger is None or self._discard_policy is None:
            return
        if not self._discard_policy.is_control(event_type):
            self._discard_ledger.record_discard(event_type, reason=reason)

    def queue(self, event_type, data, flush=False) -> None:
        self._flushed.clear()
        kwargs = {"chill": not (event_type == "close" or flush)} if self._is_chilled_queue else {}
        try:
            self._admit_event(event_type, (event_type, data, flush), kwargs)
        except _queue.Full:  # defensive: custom queue implementations may enforce their own bound
            self._record_discard(event_type, "queue_full")
            logger.debug("Event of type %s dropped due to full event queue", event_type)

    def _process_queue(self) -> None:
        # Rebuild the metadata to capture new process information
        if self.client:
            self._metadata = self.client.build_metadata()

        buffer = self._init_buffer()
        buffer_written = False
        batch_counts = defaultdict(int)
        batch_report = None
        # add some randomness to timeout to avoid stampedes of several workers that are booted at the same time
        max_flush_time = (
            self._max_flush_time_seconds * random.uniform(0.9, 1.1) if self._max_flush_time_seconds else None
        )

        while True:
            since_last_flush = timeit.default_timer() - self._last_flush
            # take max flush time into account to calculate timeout
            timeout = max(0, max_flush_time - since_last_flush) if max_flush_time else None
            timed_out = False
            try:
                event_type, data, flush = self._event_queue.get(block=True, timeout=timeout)
                if self._discard_policy is not None and not self._discard_policy.is_control(event_type):
                    self._adjust_queued_data_count(-1)
            except _queue.Empty:
                event_type, data, flush = None, None, None
                timed_out = True

            if event_type == "close":
                if buffer_written:
                    try:
                        self._flush(buffer, batch_counts=batch_counts, report=batch_report)
                    except Exception as exc:
                        logger.error(
                            "Exception occurred while flushing the buffer "
                            "before closing the transport connection: {0}".format(exc)
                        )
                self._flushed.set()
                return  # time to go home!

            if data is not None:
                data = self._process_event(event_type, data)
                if data is not None:
                    if not buffer_written:
                        # Write metadata just in time to allow for late metadata changes (such as in lambda)
                        batch_report = self._build_gap_report(in_flight={event_type: 1})
                        self._write_metadata(buffer, report=batch_report)
                    buffer.write((self._json_serializer({event_type: data}) + "\n").encode("utf-8"))
                    buffer_written = True
                    self._counts[event_type] += 1
                    batch_counts[event_type] += 1

            queue_size = 0 if buffer.fileobj is None else buffer.fileobj.tell()

            forced_flush = flush
            if forced_flush:
                logger.debug("forced flush")
            elif timed_out or timeout == 0:
                # update last flush time, as we might have waited for a non trivial amount of time in
                # _event_queue.get()
                since_last_flush = timeit.default_timer() - self._last_flush
                logger.debug(
                    "flushing due to time since last flush %.3fs > max_flush_time %.3fs",
                    since_last_flush,
                    max_flush_time,
                )
                flush = True
            elif self._max_buffer_size and queue_size > self._max_buffer_size:
                logger.debug(
                    "flushing since queue size %d bytes > max_queue_size %d bytes", queue_size, self._max_buffer_size
                )
                flush = True
            if flush:
                if buffer_written:
                    self._flush(buffer, forced_flush=forced_flush, batch_counts=batch_counts, report=batch_report)
                elif forced_flush and any(x in self.client.config.server_url for x in ("/localhost:", "/127.0.0.1:")):
                    # No data on buffer, but due to manual flush we should send
                    # an empty payload with flushed=true query param, but only
                    # to a local APM server (or lambda extension)
                    try:
                        self.send("", forced_flush=True)
                        self.handle_transport_success()
                    except Exception as e:
                        self.handle_transport_fail(e)
                self._last_flush = timeit.default_timer()
                buffer = self._init_buffer()
                buffer_written = False
                batch_counts = defaultdict(int)
                batch_report = None
                max_flush_time = (
                    self._max_flush_time_seconds * random.uniform(0.9, 1.1) if self._max_flush_time_seconds else None
                )
                self._flushed.set()

    def _process_event(self, event_type, data):
        # Run the data through processors
        for processor in self._processors:
            if not hasattr(processor, "event_types") or event_type in processor.event_types:
                try:
                    data = processor(self.client, data)
                    if not data:
                        logger.debug(
                            "Dropped event of type %s due to processor %s.%s",
                            event_type,
                            processor.__module__,
                            processor.__name__,
                        )
                        return None
                except Exception:
                    logger.warning(
                        "Dropped event of type %s due to exception in processor %s.%s",
                        event_type,
                        processor.__module__,
                        processor.__name__,
                        exc_info=True,
                    )
                    return None
        return data

    def _init_buffer(self):
        buffer = gzip.GzipFile(fileobj=io.BytesIO(), mode="w", compresslevel=self._compress_level)
        return buffer

    def _build_gap_report(self, in_flight=None):
        """
        Snapshot the discard ledger for the batch that is about to be sent.

        Returns ``None`` while there is nothing to report, which keeps payloads
        under normal load identical to the historical behaviour.  Once a gap
        exists, every batch repeats the cumulative report until a send is
        acknowledged, so a later reconnect can always verify the real gap.
        """
        if self._discard_ledger is None or self._metadata is None:
            return None
        snapshot = self._discard_ledger.snapshot()
        if not snapshot["discarded"]["total"] and not snapshot["unconfirmed"]["total"]:
            # No gap has ever occurred: keep payloads byte-for-byte identical
            # to the historical behaviour.  Once a gap exists the cumulative
            # report stays in every batch, so even a reconnect after the report
            # was first acknowledged can still verify the real gap.
            return None
        snapshot["queue"] = {
            "max_size": self._discard_policy.max_queue_size,
            "depth": self._queued_events(),
            # Records already moved into the forming batch when this metadata
            # line was written.  They are neither discarded nor sent yet.
            "batch_at_start": dict(in_flight or {}),
            "waiting_by_event_type": queue_counts(self._event_queue, self._discard_policy.is_control),
        }
        return snapshot

    def _write_metadata(self, buffer, report=None) -> None:
        metadata = self._metadata
        if report is not None:
            metadata = dict(metadata or {})
            metadata["discard"] = report
        data = (self._json_serializer({"metadata": metadata}) + "\n").encode("utf-8")
        buffer.write(data)

    def _init_event_queue(self, chill_until, max_chill_time, maxsize=10000):
        # some libraries like eventlet monkeypatch queue.Queue and switch out the implementation.
        # In those cases we can't rely on internals of queue.Queue to be there, so we simply use
        # their queue and forgo the optimizations of ChilledQueue. In the case of eventlet, this
        # isn't really a loss, because the main reason for ChilledQueue (avoiding context switches
        # due to the event processor thread being woken up all the time) is not an issue.
        if all(
            (
                hasattr(_queue.Queue, "not_full"),
                hasattr(_queue.Queue, "not_empty"),
                hasattr(_queue.Queue, "unfinished_tasks"),
            )
        ):
            return ChilledQueue(maxsize=maxsize, chill_until=chill_until, max_chill_time=max_chill_time)
        else:
            return _queue.Queue(maxsize=maxsize)

    def _flush(self, buffer, forced_flush=False, batch_counts=None, report=None) -> None:
        """
        Flush the queue. This method should only be called from the event processing queue
        :return: None
        """
        batch_counts = batch_counts or {}
        if not self.state.should_try():
            logger.error("dropping flushed data due to transport failure back-off")
            buffer.close()
            # Back-off drops a formed batch that was never handed to the
            # transport.  That is a known discard, not an undetermined send.
            if self._discard_ledger is not None:
                self._discard_ledger.record_discard(batch_counts, reason="transport_back_off")
        else:
            fileobj = buffer.fileobj  # get a reference to the fileobj before closing the gzip file
            buffer.close()

            data = fileobj.getbuffer()
            try:
                if self._discard_ledger is not None:
                    self._discard_ledger.begin_attempt(report)
                self.send(data, forced_flush=forced_flush)
                self.handle_transport_success()
                if self._discard_ledger is not None:
                    self._discard_ledger.acknowledge(report, confirmed_counts=batch_counts)
            except Exception as e:
                self.handle_transport_fail(e)
                # The payload may have reached the server, or not.  Until a
                # subsequent send succeeds these records stay unconfirmed and
                # the gap report stays pending: a failed attempt must never
                # clear it.
                if self._discard_ledger is not None:
                    self._discard_ledger.record_unconfirmed(batch_counts, reason="send_failed")

            data.release()

    def start_thread(self, pid=None) -> None:
        super(Transport, self).start_thread(pid=pid)
        if (not self._thread or self.pid != self._thread.pid) and not self._closed:
            self.handle_fork()
            try:
                self._thread = threading.Thread(target=self._process_queue, name="eapm event processor thread")
                self._thread.daemon = True
                self._thread.pid = self.pid
                self._thread.start()
            except RuntimeError:
                pass

    def send(self, data, forced_flush=False):
        """
        You need to override this to do something with the actual
        data. Usually - this is sending to a server
        """
        raise NotImplementedError

    def close(self) -> None:
        """
        Cleans up resources and closes connection
        :return:
        """
        if self._closed or (not self._thread or self._thread.pid != os.getpid()):
            return
        self._closed = True
        self.queue("close", None)
        if not self._flushed.wait(timeout=self._max_flush_time_seconds):
            logger.error("Closing the transport connection timed out.")

    def stop_thread(self) -> None:
        self.close()

    def flush(self):
        """
        Trigger a flush of the queue.
        Note: this method will only return once the queue is empty. This means it can block indefinitely if more events
        are produced in other threads than can be consumed.
        """
        self.queue(None, None, flush=True)
        if not self._flushed.wait(timeout=self._max_flush_time_seconds):
            raise ValueError("flush timed out")

    def handle_transport_success(self, **kwargs) -> None:
        """
        Success handler called by the transport on successful send
        """
        self.state.set_success()

    def handle_transport_fail(self, exception=None, **kwargs) -> None:
        """
        Failure handler called by the transport on send failure
        """
        message = str(exception)
        logger.error("Failed to submit message: %r", message, exc_info=False)
        self.state.set_fail()

    def handle_fork(self) -> None:
        """Helper method to run code after a fork has been detected"""
        pass


# left for backwards compatibility
AsyncTransport = Transport


class TransportState(object):
    ONLINE = 1
    ERROR = 0

    def __init__(self) -> None:
        self.status = self.ONLINE
        self.last_check = None
        self.retry_number = -1

    def should_try(self):
        if self.status == self.ONLINE:
            return True

        interval = min(self.retry_number, 6) ** 2

        return timeit.default_timer() - self.last_check > interval

    def set_fail(self) -> None:
        self.status = self.ERROR
        self.retry_number += 1
        self.last_check = timeit.default_timer()

    def set_success(self) -> None:
        self.status = self.ONLINE
        self.last_check = None
        self.retry_number = -1

    def did_fail(self):
        return self.status == self.ERROR


class ChilledQueue(_queue.Queue, object):
    """
    A queue subclass that is a bit more chill about how often it notifies the not empty event

    Note: we inherit from object because queue.Queue is an old-style class in Python 2. This can
    be removed once we stop support for Python 2
    """

    def __init__(self, maxsize=0, chill_until=100, max_chill_time=1.0) -> None:
        self._chill_until = chill_until
        self._max_chill_time = max_chill_time
        self._last_unchill = time.time()
        super(ChilledQueue, self).__init__(maxsize=maxsize)

    def put(self, item, block=True, timeout=None, chill=True):
        """Put an item into the queue.

        If optional args 'block' is true and 'timeout' is None (the default),
        block if necessary until a free slot is available. If 'timeout' is
        a non-negative number, it blocks at most 'timeout' seconds and raises
        the Full exception if no free slot was available within that time.
        Otherwise ('block' is false), put an item on the queue if a free slot
        is immediately available, else raise the Full exception ('timeout'
        is ignored in that case).
        """
        with self.not_full:
            if self.maxsize > 0:
                if not block:
                    if self._qsize() >= self.maxsize:
                        raise _queue.Full
                elif timeout is None:
                    while self._qsize() >= self.maxsize:
                        self.not_full.wait()
                elif timeout < 0:
                    raise ValueError("'timeout' must be a non-negative number")
                else:
                    endtime = time.time() + timeout
                    while self._qsize() >= self.maxsize:
                        remaining = endtime - time.time()
                        if remaining <= 0.0:
                            raise _queue.Full
                        self.not_full.wait(remaining)
            self._put(item)
            self.unfinished_tasks += 1
            if (
                not chill
                or self._qsize() > self._chill_until
                or (time.time() - self._last_unchill) > self._max_chill_time
            ):
                self.not_empty.notify()
                self._last_unchill = time.time()
