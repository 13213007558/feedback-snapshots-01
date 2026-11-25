from abc import ABC, abstractmethod
from typing import ClassVar

from taskiq.message import BrokerMessage, TaskiqMessage


class TaskiqFormatter(ABC):
    """Custom formatter for brokers."""

    # Wire version name used by channel-bound format policies.
    version: ClassVar[str] = "default"

    @abstractmethod
    def dumps(self, message: TaskiqMessage) -> BrokerMessage:
        """
        Dump message to broker message instance.

        :param message: message to send.
        :return: message for brokers.
        """

    @abstractmethod
    def loads(self, message: bytes) -> TaskiqMessage:
        """
        Parses broker message to TaskiqMessage.

        :param message: message to parse.
        :return: parsed taskiq message.
        """

    def matches(self, message: bytes) -> bool | None:
        """
        Check whether a payload belongs to this formatter's wire version.

        Channel-bound policies use this check before parsing: a payload
        that belongs to another approved format must not be accepted just
        because this formatter happens to parse it. Implementations that
        can verify the exact wire representation should return ``True``
        or ``False``. The default ``None`` means the formatter has no
        opinion and parsing alone decides.

        :param message: raw payload received from a channel.
        :return: True if the payload is this exact version, False if it is
            another version, None if the formatter cannot tell.
        """
        return None
