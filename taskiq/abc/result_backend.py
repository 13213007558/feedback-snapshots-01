from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from taskiq.exceptions import SecurityError
from taskiq.result import TaskiqResult

if TYPE_CHECKING:  # pragma: no cover
    from taskiq.depends.progress_tracker import TaskProgress


_ReturnType = TypeVar("_ReturnType")


class AsyncResultBackend(ABC, Generic[_ReturnType]):
    """Async result backend."""

    async def startup(self) -> None:
        """Do something when starting broker."""

    async def shutdown(self) -> None:
        """Do something on shutdown."""

    @abstractmethod
    async def set_result(self, task_id: str, result: TaskiqResult[_ReturnType]) -> None:
        """
        Saves result to the result backend.

        Result must be save so it can be accessed later
        by the calling side of the system.

        :param task_id: id of a task to save.
        :param result: result of execution.
        :return: nothing.
        """

    @abstractmethod
    async def is_result_ready(self, task_id: str) -> bool:
        """
        Checks that result of task is ready.

        :param task_id: task's id.
        :return: True if task is completed.
        """

    @abstractmethod
    async def get_result(
        self,
        task_id: str,
        with_logs: bool = False,
    ) -> TaskiqResult[_ReturnType]:
        """
        Gets result from the task.

        :param task_id: task's id.
        :param with_logs: if True it will download task's logs.
        :return: task's return value.
        """

    async def get_public_status(self, task_id: str) -> Any:
        """
        Return a non-sensitive public status.

        Backends can override this to read a dedicated public record. The
        default implementation derives a redacted view from ``get_result``.
        """
        from taskiq.secure_results import PublicTaskStatus

        result = await self.get_result(task_id)
        return PublicTaskStatus.from_result(task_id, result)

    async def get_admin_result(
        self,
        task_id: str,
        *args: Any,
        **kwargs: Any,
    ) -> TaskiqResult[_ReturnType]:
        """Fetch full details through an authorized diagnostic API."""
        del task_id, args, kwargs
        raise SecurityError(
            description="This result backend does not provide admin diagnostics.",
        )

    async def set_attempt_result(
        self,
        task_id: str,
        result: TaskiqResult[_ReturnType],
    ) -> None:
        """
        Persist state for an intermediate attempt.

        The default implementation does nothing because intermediate results are
        often suppressed while a retry is pending. Backends that expose public
        task status can override this method to persist a redacted status.

        :param task_id: id of a task.
        :param result: result of an attempt.
        """

    async def set_progress(
        self,
        task_id: str,
        progress: "TaskProgress[Any]",
    ) -> None:
        """
        Saves progress.

        :param task_id: task's id.
        :param progress: progress of execution.
        """

    async def get_progress(
        self,
        task_id: str,
    ) -> "TaskProgress[Any] | None":
        """
        Gets progress.

        :param task_id: task's id.
        """
