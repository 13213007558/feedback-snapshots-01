from taskiq.abc.formatter import TaskiqFormatter
from taskiq.formatters._wire_signature import json_separator_style
from taskiq.message import BrokerMessage, TaskiqMessage


class JSONFormatter(TaskiqFormatter):
    """JSON taskiq formatter."""

    version = "json"

    def dumps(self, message: TaskiqMessage) -> BrokerMessage:
        """
        Dumps taskiq message to some broker message format.

        :param message: message to send.
        :return: Dumped message.
        """
        return BrokerMessage(
            task_id=message.task_id,
            task_name=message.task_name,
            message=message.model_dump_json().encode(),
            labels=message.labels,
        )

    def loads(self, message: bytes) -> TaskiqMessage:
        """
        Loads json from message.

        :param message: broker's message.
        :return: parsed taskiq message.
        """
        return TaskiqMessage.model_validate_json(message)

    def matches(self, message: bytes) -> bool | None:
        """
        Check that the payload is this compact JSON representation.

        The default proxy formatter emits JSON with padded separators,
        while this formatter emits compact JSON. The signature probe reads
        the bytes only, so selection never parses the payload twice.

        :param message: raw payload received from a channel.
        :return: True if the payload uses this formatter's separator style,
            False if it uses the other approved style, None if unknown.
        """
        padded = json_separator_style(message)
        if padded is None:
            return None
        return not padded
