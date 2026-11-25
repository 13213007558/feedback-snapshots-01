import asyncio
import inspect
import sys
from datetime import datetime, timedelta, timezone
from logging import basicConfig, getLogger
from typing import Any, TypeAlias
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import pycron

from taskiq.abc.schedule_source import ScheduleSource
from taskiq.cli.scheduler.args import SchedulerArgs
from taskiq.cli.utils import import_object, import_tasks
from taskiq.scheduler.scheduled_task import ScheduledTask
from taskiq.scheduler.scheduler import TaskiqScheduler
from taskiq.scheduler.source_rules import (
    DispatchContext,
    ResolvedSchedule,
    ResolvedSchedules,
    current_dispatch,
    schedule_occurrence,
)

logger = getLogger(__name__)


ScheduleId: TypeAlias = str


def to_tz_aware(time: datetime) -> datetime:
    """
    Convert datetime to timezone aware.

    This function takes a datetime and if
    timezone was not yet specified, it will
    be set to UTC.

    :param time: time to make timezone aware.
    :return: timezone aware time.
    """
    if time.tzinfo is None:
        return time.replace(tzinfo=timezone.utc)
    return time


async def get_schedules(source: ScheduleSource) -> list[ScheduledTask]:
    """
    Get schedules from source.

    If source raises an exception, it will be
    logged and an empty list will be returned.

    :param source: source to get schedules from.
    """
    try:
        return await source.get_schedules()
    except Exception:
        logger.exception("Cannot update schedules with source: %s", source)
        return []


async def get_all_schedules(
    scheduler: TaskiqScheduler,
) -> list[tuple[ScheduleSource, list[ScheduledTask]]]:
    """
    Task to update all schedules.

    This function updates all schedules
    from all sources and returns a list
    of (source, tasks) pairs.

    :param scheduler: current scheduler.
    :return: list of (source, tasks) pairs.
    """
    logger.debug("Started schedule update.")
    schedules: list[list[ScheduledTask]] = await asyncio.gather(
        *[get_schedules(source) for source in scheduler.sources],
    )
    return list(zip(scheduler.sources, schedules, strict=True))


class CronValueError(Exception):
    """Raised on invalid cron value."""


def is_cron_task_now(
    cron_value: str,
    now: datetime,
    offset: str | timedelta | None = None,
    last_run: datetime | None = None,
) -> bool:
    """
    Checks whether the cron task should start now.

    :raises CronValueError: On invalid cron value.
    """
    if last_run is not None:
        seconds_spend = (now - last_run).total_seconds()
        seconds_should_sped = timedelta(minutes=1).total_seconds()
        if round(seconds_spend) < round(seconds_should_sped):
            return False
    # If user specified cron offset we apply it.
    # If it's timedelta, we simply add the delta to current time.
    if offset and isinstance(offset, timedelta):
        now += offset
    # If timezone was specified as string we convert it timezone
    # offset and then apply.
    elif offset and isinstance(offset, str):
        try:
            now = now.astimezone(ZoneInfo(offset))
        # ZoneInfoNotFoundError for unknown keys, ModuleNotFoundError
        # for systems without timezone data available (e.g. missing
        # tzdata on Windows).
        except (ZoneInfoNotFoundError, ModuleNotFoundError) as e:
            raise CronValueError(e) from e

    try:
        return pycron.is_now(cron_value, now)
    except ValueError as e:
        raise CronValueError(e) from e


def is_time_task_now(
    time_value: datetime,
    now: datetime,
    last_run: datetime | None = None,
) -> bool:
    """Checks whether the time task should start now."""
    if last_run is not None:
        return False

    time_value = to_tz_aware(time_value)
    now = to_tz_aware(now)
    return time_value <= now


def is_interval_task_now(
    interval_value: int | timedelta,
    now: datetime,
    last_run: datetime | None = None,
) -> bool:
    """
    Checks whether the interval task should start now.

    Interval tasks must have a minimum interval of 1 second.
    Fractional intervals (e.g., 0.5 seconds) are not supported.

    :param interval_value: Interval as int (seconds) or timedelta
    :param now: Current datetime
    :param last_run: Last run datetime, None for first run
    :return: True if task should run now
    """
    if last_run is None:
        return True

    if isinstance(interval_value, int):
        interval_value = timedelta(seconds=interval_value)

    seconds_passed: float = (now - last_run).total_seconds()
    interval_seconds: float = interval_value.total_seconds()

    return round(seconds_passed) >= round(interval_seconds)


async def send(
    scheduler: TaskiqScheduler,
    source: ScheduleSource,
    task: ScheduledTask,
    *,
    occurrence: str | None = None,
    resolved: ResolvedSchedule | None = None,
) -> None:
    """
    Send a task.

    :param scheduler: current scheduler.
    :param source: source of the task.
    :param task: task to send.
    :param occurrence: occurrence key of this due item.
    :param resolved: resolved plan this dispatch belongs to.
    """
    logger.info(
        "Sending task %s with schedule_id %s from source %s.",
        task.task_name,
        task.schedule_id,
        resolved.source_name if resolved is not None else source.__class__.__name__,
    )
    context = None
    if resolved is not None:
        context = DispatchContext(
            occurrence=occurrence
            or schedule_occurrence(task, datetime.now(tz=timezone.utc)),
            resolved=resolved,
        )
    token = current_dispatch.set(context)
    try:
        await scheduler.on_ready(source, task)
    finally:
        current_dispatch.reset(token)


async def send_with_timeout(
    scheduler: TaskiqScheduler,
    source: ScheduleSource,
    task: ScheduledTask,
    timeout: float,
    *,
    occurrence: str | None = None,
    resolved: ResolvedSchedule | None = None,
) -> None:
    """
    Send a task, cancelling it if it does not complete within ``timeout`` seconds.

    A timed-out send is logged at WARNING and swallowed — re-raising would propagate
    out of the scheduler's main loop's ``add_done_callback``, which is not what we
    want. Suppressing it lets the done_callback clear ``running_schedules`` so the
    next cron boundary can re-dispatch the task. The slot is freed; the message is
    dropped (the broker did not acknowledge it within the budget).

    :param scheduler: current scheduler.
    :param source: source of the task.
    :param task: task to send.
    :param timeout: seconds to wait before cancelling the send. Must be > 0.
    :param occurrence: occurrence key of this due item.
    :param resolved: resolved plan this dispatch belongs to.
    """
    try:
        await asyncio.wait_for(
            send(
                scheduler,
                source,
                task,
                occurrence=occurrence,
                resolved=resolved,
            ),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.warning(
            "Sending task %s with schedule_id %s timed out after %.1fs "
            "and was cancelled. The next scheduled tick will retry.",
            task.task_name,
            task.schedule_id,
            timeout,
        )


async def _sleep_until_next_second() -> None:
    now = datetime.now(tz=timezone.utc)
    await asyncio.sleep(1 - now.microsecond / 1_000_000)


class SchedulerLoop:
    """Abstraction over scheduler loop."""

    def __init__(
        self,
        scheduler: TaskiqScheduler,
        *,
        event_loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        self.scheduler = scheduler
        self._event_loop = event_loop or asyncio.get_event_loop()

        # Variables for control the last run of schedules.
        self.cron_tasks_last_run: dict[ScheduleId, datetime] = {}
        self.interval_tasks_last_run: dict[ScheduleId, datetime] = {}
        self.time_tasks_last_run: dict[ScheduleId, datetime] = {}

        self.scheduled_tasks: list[tuple[ScheduleSource, list[ScheduledTask]]] = []
        self.resolved_schedules: ResolvedSchedules | None = None
        self.observed_schedules: tuple[ResolvedSchedule, ...] = ()
        self.running_occurrences: dict[str, asyncio.Task[Any]] = {}
        # Keyed by source object and schedule id, so a refresh mid pre_send
        # cannot start a second dispatch of the same plan.
        self.running_plan_keys: set[tuple[int, str]] = set()
        self.scheduled_tasks_updated_at: datetime | None = None
        self._update_schedules_task_future: asyncio.Task[Any] | None = None

    def _refresh_resolved(self) -> None:
        """Resolve the latest raw schedules through the source rules."""
        self.resolved_schedules = self.scheduler.source_rules.resolve(
            self.scheduled_tasks,
        )
        self.observed_schedules = self.resolved_schedules.observed
        for conflict in self.resolved_schedules.conflicts:
            logger.warning(
                "Schedule %s was offered by several dispatch sources %s; "
                "using %s.",
                conflict.identity,
                conflict.source_names,
                conflict.chosen_source,
            )

    def _update_schedules_task_future_callback(self, task_: asyncio.Task[Any]) -> None:
        if task_.cancelled():
            return
        self.scheduled_tasks = task_.result()
        self._refresh_resolved()

        new_schedules_ids: set[ScheduleId] = set()
        for source, task_list in self.scheduled_tasks:
            logger.debug("Got %d schedules from source %s.", len(task_list), source)
            new_schedules_ids.update({t.schedule_id for t in task_list})

        # Deleting irrelevant scheduled tasks so they don't take up memory.
        for id_ in self.cron_tasks_last_run.keys() - new_schedules_ids:
            del self.cron_tasks_last_run[id_]
        for id_ in self.interval_tasks_last_run.keys() - new_schedules_ids:
            del self.interval_tasks_last_run[id_]
        for id_ in self.time_tasks_last_run.keys() - new_schedules_ids:
            del self.time_tasks_last_run[id_]

    async def _update_scheduled_tasks(self) -> None:
        if (
            self._update_schedules_task_future is not None
            and not self._update_schedules_task_future.done()
        ):
            logger.warning(
                "Schedules getting task started "
                "before the previous one finished. "
                "Consider increasing the update_interval.",
            )
        else:
            self._update_schedules_task_future = self._event_loop.create_task(
                get_all_schedules(self.scheduler),
            )
            self._update_schedules_task_future.add_done_callback(
                self._update_schedules_task_future_callback,
            )

    def _mark_cron_tasks_as_already_run(self) -> None:
        current_minute = datetime.now(tz=timezone.utc).replace(second=0, microsecond=0)
        for _, task_list in self.scheduled_tasks:
            for task in task_list:
                if task.cron is not None:
                    self.cron_tasks_last_run[task.schedule_id] = current_minute

    def _is_schedule_ready_to_send(
        self,
        task: ScheduledTask,
        now: datetime,
    ) -> bool:
        is_ready_to_send: bool = False

        if not is_ready_to_send and task.cron is not None:
            try:
                is_ready_to_send = is_cron_task_now(
                    cron_value=task.cron,
                    now=now,
                    offset=task.cron_offset,
                    last_run=self.cron_tasks_last_run.get(task.schedule_id),
                )
            except CronValueError:
                logger.warning(
                    "Cannot parse cron: %s for task: %s, schedule_id: %s.",
                    task.cron,
                    task.task_name,
                    task.schedule_id,
                )
            if is_ready_to_send:
                self.cron_tasks_last_run[task.schedule_id] = now

        if not is_ready_to_send and task.interval is not None:
            is_ready_to_send = is_interval_task_now(
                interval_value=task.interval,
                now=now,
                last_run=self.interval_tasks_last_run.get(task.schedule_id),
            )
            if is_ready_to_send:
                self.interval_tasks_last_run[task.schedule_id] = now

        if not is_ready_to_send and task.time is not None:
            is_ready_to_send = is_time_task_now(
                time_value=task.time,
                now=now,
                last_run=self.time_tasks_last_run.get(task.schedule_id),
            )
            if is_ready_to_send:
                self.time_tasks_last_run[task.schedule_id] = now

        return is_ready_to_send

    def dispatch_due(
        self,
        now: datetime,
        *,
        send_timeout: float | None = None,
    ) -> list[asyncio.Task[Any]]:
        """
        Start dispatch tasks for every due plan allowed by the source rules.

        A plan from an observation source, a revoked source, an already
        handled occurrence, or one that is already in flight is skipped.

        :param now: scheduler time used for due and occurrence checks.
        :param send_timeout: optional per-send timeout.
        :return: tasks spawned during this sweep.
        """
        resolved = self.resolved_schedules or ResolvedSchedules(
            dispatch=(),
            observed=(),
            conflicts=(),
        )
        spawned: list[asyncio.Task[Any]] = []
        for entry in resolved.dispatch:
            source = entry.source
            task = entry.task
            if not self.scheduler.source_rules.is_dispatch_allowed(source):
                continue

            occurrence = schedule_occurrence(task, now)
            if self.scheduler.audit_ledger.is_handled(occurrence):
                continue
            if occurrence in self.running_occurrences:
                continue
            plan_key = (id(source), task.schedule_id)
            if plan_key in self.running_plan_keys:
                continue

            is_ready_to_send = self._is_schedule_ready_to_send(
                task=task,
                now=now,
            )
            if not is_ready_to_send:
                continue

            if send_timeout is not None:
                send_coro = send_with_timeout(
                    self.scheduler,
                    source,
                    task,
                    timeout=send_timeout,
                    occurrence=occurrence,
                    resolved=entry,
                )
            else:
                send_coro = send(
                    self.scheduler,
                    source,
                    task,
                    occurrence=occurrence,
                    resolved=entry,
                )
            send_task = self._event_loop.create_task(
                send_coro,
                # We need to set the name of the task
                # to be able to discard its reference
                # after it is done.
                name=f"occurrence_{occurrence}",
            )
            self.running_occurrences[occurrence] = send_task
            self.running_plan_keys.add(plan_key)
            send_task.add_done_callback(
                lambda task_future, key=plan_key: self._finish_dispatch(
                    task_future,
                    key,
                ),
            )
            spawned.append(send_task)
        return spawned

    def _finish_dispatch(
        self,
        task_future: asyncio.Task[Any],
        plan_key: tuple[int, str],
    ) -> None:
        """Drop bookkeeping after a dispatch task completes."""
        self.running_occurrences.pop(
            task_future.get_name().removeprefix("occurrence_"),
            None,
        )
        self.running_plan_keys.discard(plan_key)

    def observed_plans(self) -> tuple[ResolvedSchedule, ...]:
        """Return every plan visible from all sources, including display-only."""
        return self.observed_schedules

    async def refresh(self) -> None:
        """Re-read every source and rebuild dispatch/observation plans."""
        self.scheduled_tasks = await get_all_schedules(self.scheduler)
        self._refresh_resolved()
        self.scheduled_tasks_updated_at = datetime.now(tz=timezone.utc)

    async def run(  # noqa: C901
        self,
        *,
        update_interval: timedelta | None = None,
        loop_interval: timedelta | None = None,
        skip_first_run: bool = False,
        send_timeout: float | None = None,
    ) -> None:
        """
        Runs scheduler loop.

        This function imports taskiq scheduler
        and runs tasks when needed.

        :param update_interval: interval to check for schedule updates.
        :param loop_interval: interval to check tasks to send.
        :param skip_first_run: Wait for the beginning of the next minute
            to skip the first run.
        :param send_timeout: optional per-send timeout (seconds). If set, each
            spawned send task is wrapped in :func:`asyncio.wait_for` with this
            timeout, preventing a single hung ``broker.kick`` from permanently
            blocking subsequent ticks of the same ``schedule_id`` via the
            ``running_schedules`` skip check. Default ``None`` (no timeout —
            backwards-compatible behavior).
        """
        if update_interval is None:
            update_interval = timedelta(minutes=1)
        if loop_interval is None:
            loop_interval = timedelta(seconds=1)
        if send_timeout is not None and send_timeout <= 0:
            raise ValueError("send_timeout must be > 0 when provided")

        self.scheduled_tasks = await get_all_schedules(self.scheduler)
        self._refresh_resolved()
        self.scheduled_tasks_updated_at = datetime.now(tz=timezone.utc)

        if skip_first_run:
            self._mark_cron_tasks_as_already_run()

        await _sleep_until_next_second()

        while True:
            now = datetime.now(tz=timezone.utc)
            next_run = (now + loop_interval).replace(microsecond=0)

            if now - self.scheduled_tasks_updated_at >= update_interval:
                await self._update_scheduled_tasks()
                self.scheduled_tasks_updated_at = now

            self.dispatch_due(now, send_timeout=send_timeout)

            delay = next_run - datetime.now(tz=timezone.utc)
            logger.debug(
                "Sleeping for %.3f seconds before getting schedules.",
                delay.total_seconds(),
            )
            await asyncio.sleep(delay.total_seconds())


async def _startup_scheduler(scheduler: TaskiqScheduler) -> None:
    """Start sources and scheduler, rolling back sources if startup fails."""
    started_sources: list[ScheduleSource] = []
    try:
        for source in scheduler.sources:
            await source.startup()
            started_sources.append(source)

        logger.info("Starting scheduler.")
        await scheduler.startup()
    except (Exception, asyncio.CancelledError):
        # Only completed startups have a matching shutdown contract.
        for source in reversed(started_sources):
            try:
                await source.shutdown()
            except (Exception, asyncio.CancelledError):
                logger.exception(
                    "Cannot shut down source after startup failure: %s",
                    source,
                )
        raise


async def run_scheduler(args: SchedulerArgs) -> None:
    """
    Run scheduler.

    This function takes all CLI arguments
    and starts the scheduler process.

    :param args: parsed CLI arguments.
    """
    if args.configure_logging:
        basicConfig(
            level=args.log_level,
            format=(
                "[%(asctime)s][%(levelname)-7s]"
                "[%(module)s:%(funcName)s:%(lineno)d]"
                " %(message)s"
            ),
        )
    getLogger("taskiq").setLevel(level=args.log_level)

    if isinstance(args.scheduler, str):
        scheduler = import_object(args.scheduler, app_dir=args.app_dir)
        if inspect.isfunction(scheduler):
            scheduler = scheduler()
    else:
        scheduler = args.scheduler
    if not isinstance(scheduler, TaskiqScheduler):
        logger.error(
            "Imported scheduler is not a subclass of TaskiqScheduler.",
        )
        sys.exit(1)

    scheduler.broker.is_scheduler_process = True
    import_tasks(args.modules, args.tasks_pattern, args.fs_discover)
    update_interval = timedelta(seconds=60)
    if args.update_interval is not None:
        update_interval = timedelta(seconds=args.update_interval)

    loop_interval = timedelta(seconds=1)
    if args.loop_interval is not None:
        loop_interval = timedelta(seconds=args.loop_interval)

    await _startup_scheduler(scheduler)
    logger.info("Startup completed.")

    scheduler_loop = SchedulerLoop(scheduler)
    try:
        await scheduler_loop.run(
            update_interval=update_interval,
            loop_interval=loop_interval,
            skip_first_run=args.skip_first_run,
            send_timeout=args.send_timeout,
        )
    except asyncio.CancelledError:
        logger.info("Shutting down scheduler.")
        await scheduler.shutdown()
        for source in scheduler.sources:
            await source.shutdown()
        logger.info("Scheduler shut down. Good bye!")
