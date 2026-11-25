from __future__ import annotations

from datetime import timedelta
from uuid import UUID

import anyio
import attrs
from attrs.validators import gt

from ._enums import JobResultState
from ._events import Event, JobReleased
from ._structures import JobResultClaim, JobResultStatus
from .abc import DataStore, EventBroker


@attrs.define(eq=False, repr=False)
class JobResultPortal:
    """
    A result-facing facade over a data store, meant for portals that expose background
    job results to multiple interested parties.

    Unlike :meth:`~Scheduler.get_job_result`, which consumes the result, this class
    separates three concerns:

    * **observation** (:meth:`observe`) never consumes a result, so an audit team can
      repeatedly check whether a job has finished
    * **claiming** (:meth:`claim` / :meth:`wait_and_claim`) hands the payload to the
      owning business party exactly once
    * **expiry** is reported explicitly to both parties through
      :attr:`JobResultState.expired`, even after the payload is gone

    :param data_store: the data store holding job results
    :param event_broker: the event broker used to be notified of job completions
    :param poll_interval: how often to re-check for expiry while waiting
    """

    data_store: DataStore = attrs.field()
    event_broker: EventBroker = attrs.field()
    poll_interval: timedelta = attrs.field(
        converter=lambda value: (
            value if isinstance(value, timedelta) else timedelta(seconds=value)
        ),
        validator=gt(timedelta()),
        default=timedelta(seconds=1),
    )

    async def observe(self, job_id: UUID) -> JobResultStatus:
        """
        Return the current state of a job result without consuming it.

        This is safe to call any number of times, by any party, including before the
        job has finished.

        :param job_id: the identifier of the job
        :return: a read-only snapshot of the result's state
        """
        return await self.data_store.observe_job_result(job_id)

    async def claim(self, job_id: UUID, *, owner: str) -> JobResultClaim:
        """
        Claim a job result once, on behalf of the business party that owns the job.

        Calling this again after a successful claim, or from a party that does not own
        the job, returns a status explaining why no payload was handed out. The same
        applies once the result has expired.

        :param job_id: the identifier of the job
        :param owner: identifier of the business party claiming the result
        :return: the claim outcome
        """
        return await self.data_store.claim_job_result(job_id, owner=owner)

    async def wait_for_terminal_state(
        self,
        job_id: UUID,
        *,
        timeout: float | timedelta | None = None,
    ) -> JobResultStatus:
        """
        Wait until a result is no longer pending, then return its state.

        A result reaching :attr:`~JobResultState.expired` while waiting also ends the
        wait, so a waiter never blocks forever on a result that can no longer appear.

        :param job_id: the identifier of the job
        :param timeout: maximum time to wait, in seconds or as a timedelta
        :return: the terminal status observed
        """
        if isinstance(timeout, timedelta):
            deadline = anyio.current_time() + timeout.total_seconds()
        elif timeout is not None:
            deadline = anyio.current_time() + timeout
        else:
            deadline = None

        status = await self.observe(job_id)
        if status.state is not JobResultState.pending:
            return status

        while True:
            if deadline is not None and anyio.current_time() >= deadline:
                return status

            delay = self.poll_interval.total_seconds()
            if deadline is not None:
                delay = min(delay, max(deadline - anyio.current_time(), 0))

            with anyio.move_on_after(delay):
                await self._wait_for_release(job_id)

            status = await self.observe(job_id)
            if status.state is not JobResultState.pending:
                return status

    async def wait_and_claim(
        self,
        job_id: UUID,
        *,
        owner: str,
        timeout: float | timedelta | None = None,
    ) -> JobResultClaim:
        """
        Wait for a result and claim it once it becomes available.

        If the result expires while waiting, or is claimed by someone else first, the
        returned claim carries the corresponding state and no payload.

        :param job_id: the identifier of the job
        :param owner: identifier of the business party claiming the result
        :param timeout: maximum time to wait, in seconds or as a timedelta
        :return: the claim outcome
        """
        await self.wait_for_terminal_state(job_id, timeout=timeout)
        return await self.claim(job_id, owner=owner)

    async def _wait_for_release(self, job_id: UUID) -> None:
        event = anyio.Event()

        def listener(job_event: Event) -> None:
            if isinstance(job_event, JobReleased) and job_event.job_id == job_id:
                event.set()

        with self.event_broker.subscribe(listener, {JobReleased}):
            # Re-check once inside the subscription to avoid missing an event that
            # arrived between the check and the subscription
            status = await self.observe(job_id)
            if status.state is not JobResultState.pending:
                return

            await event.wait()
