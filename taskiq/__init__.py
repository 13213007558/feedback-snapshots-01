"""Distributed task manager."""

from importlib.metadata import version

from taskiq_dependencies import Depends as TaskiqDepends

from taskiq.abc.broker import AsyncBroker, AsyncTaskiqDecoratedTask
from taskiq.abc.formatter import TaskiqFormatter
from taskiq.abc.middleware import TaskiqMiddleware
from taskiq.abc.result_backend import AsyncResultBackend
from taskiq.abc.schedule_source import ScheduleSource
from taskiq.acks import AckableMessage, AcknowledgeType, SourcedMessage
from taskiq.brokers.inmemory_broker import InMemoryBroker
from taskiq.brokers.multi_broker import MultiBroker
from taskiq.brokers.shared_broker import async_shared_broker
from taskiq.brokers.zmq_broker import ZeroMQBroker
from taskiq.context import Context
from taskiq.events import TaskiqEvents
from taskiq.exceptions import (
    NoResultError,
    ResultGetError,
    ResultIsReadyError,
    SecurityError,
    SendTaskError,
    SourceNotAuthorizedError,
    TaskiqError,
    TaskiqResultTimeoutError,
)
from taskiq.funcs import gather
from taskiq.message import BrokerMessage, TaskiqMessage
from taskiq.middlewares import (
    PrometheusMiddleware,
    SimpleRetryMiddleware,
    SmartRetryMiddleware,
)
from taskiq.receive_context import ReceiveContext, get_receive_context
from taskiq.result import TaskiqResult
from taskiq.scheduler.scheduled_task import ScheduledTask
from taskiq.scheduler.scheduler import TaskiqScheduler
from taskiq.state import TaskiqState
from taskiq.task import AsyncTaskiqTask

__version__ = version("taskiq")

__all__ = [
    "AckableMessage",
    "AcknowledgeType",
    "AsyncBroker",
    "AsyncResultBackend",
    "AsyncTaskiqDecoratedTask",
    "AsyncTaskiqTask",
    "BrokerMessage",
    "Context",
    "InMemoryBroker",
    "MultiBroker",
    "NoResultError",
    "PrometheusMiddleware",
    "ReceiveContext",
    "ResultGetError",
    "ResultIsReadyError",
    "ScheduleSource",
    "ScheduledTask",
    "SecurityError",
    "SendTaskError",
    "SimpleRetryMiddleware",
    "SmartRetryMiddleware",
    "SourceNotAuthorizedError",
    "SourcedMessage",
    "TaskiqDepends",
    "TaskiqError",
    "TaskiqEvents",
    "TaskiqFormatter",
    "TaskiqMessage",
    "TaskiqMiddleware",
    "TaskiqResult",
    "TaskiqResultTimeoutError",
    "TaskiqScheduler",
    "TaskiqState",
    "ZeroMQBroker",
    "__version__",
    "async_shared_broker",
    "gather",
    "get_receive_context",
]
