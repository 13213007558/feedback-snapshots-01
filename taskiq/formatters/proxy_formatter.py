from typing import TYPE_CHECKING

from taskiq.abc.formatter import TaskiqFormatter
from taskiq.formatters._wire_signature import json_separator_style
from taskiq.message import BrokerMessage, TaskiqMessage
from taskiq.serializers.json_serializer import JSONSerializer

if TYPE_CHECKING:
    from taskiq.abc.broker import AsyncBroker


class ProxyFormatter(TaskiqFormatter):
    """Default taskiq formatter."""

    version = "proxy"

    def __init__(self, broker: "AsyncBroker") -> None:
        self.broker = broker

    def dumps(self, message: TaskiqMessage) -> BrokerMessage:
        """
        Dumps taskiq message to some broker message format.

        :param message: message to send.
        :return: Dumped message.
        """
        return BrokerMessage(
            task_id=message.task_id,
            task_name=message.task_name,
            message=self.broker.serializer.dumpb(message.model_dump(mode="json")),
            labels=message.labels,
        )

    def loads(self, message: bytes) -> TaskiqMessage:
        """
        Loads json from message.

        :param message: broker's message.
        :return: parsed taskiq message.
        """
        return TaskiqMessage.model_validate(self.broker.serializer.loadb(message))

    def matches(self, message: bytes) -> bool | None:
        """
        Check that the payload is this serializer-backed representation.

        This formatter delegates to the broker serializer. With the default
        JSON serializer its output uses ``json.dumps`` defaults, which pad
        object separators; the signature probe distinguishes it from the
        compact ``JSONFormatter`` without parsing. Other serializers have
        their own wire format, so the probe reports no opinion and the
        channel's declared order decides.

        :param message: raw payload received from a channel.
        :return: True for padded JSON, False for compact JSON, None when
            the serializer is not JSON or the payload cannot be classified.
        """
        if not isinstance(self.broker.serializer, JSONSerializer):
            return None
        padded = json_separator_style(message)
        if padded is None:
            return None
        return padded
