import mimetypes
import os
from typing import TYPE_CHECKING

from sentry_sdk.envelope import Item, PayloadRef, _now

if TYPE_CHECKING:
    from typing import Callable, Optional, Union


class Attachment:
    """Additional files/data to send along with an event.

    This class stores attachments that can be sent along with an event. Attachments are files or other data, e.g.
    config or log files, that are relevant to an event. Attachments are set on the ``Scope``, and are sent along with
    all non-transaction events (or all events including transactions if ``add_to_transactions`` is ``True``) that are
    captured within the ``Scope``.

    To add an attachment to a ``Scope``, use :py:meth:`sentry_sdk.Scope.add_attachment`. The parameters for
    ``add_attachment`` are the same as the parameters for this class's constructor.

    :param bytes: Raw bytes of the attachment, or a function that returns the raw bytes. Must be provided unless
                  ``path`` is provided.
    :param filename: The filename of the attachment. Must be provided unless ``path`` is provided.
    :param path: Path to a file to attach. Must be provided unless ``bytes`` is provided.
    :param content_type: The content type of the attachment. If not provided, it will be guessed from the ``filename``
                         parameter, if available, or the ``path`` parameter if ``filename`` is ``None``.
    :param add_to_transactions: Whether to add this attachment to transactions. Defaults to ``False``.
    :param ttl: Time to live, in monotonic seconds, for this attachment. When set, the attachment is only sent if the
                envelope reaches the transport before the deadline. The deadline is computed once, here, so queueing,
                retrying or re-batching the envelope never extends or resets it. ``None`` (the default) means the
                attachment never expires.
    """

    def __init__(
        self,
        bytes: "Union[None, bytes, Callable[[], bytes]]" = None,
        filename: "Optional[str]" = None,
        path: "Optional[str]" = None,
        content_type: "Optional[str]" = None,
        add_to_transactions: bool = False,
        ttl: "Optional[float]" = None,
    ) -> None:
        if bytes is None and path is None:
            raise TypeError("path or raw bytes required for attachment")
        if filename is None and path is not None:
            filename = os.path.basename(path)
        if filename is None:
            raise TypeError("filename is required for attachment")
        if content_type is None:
            content_type = mimetypes.guess_type(filename)[0]
        self.bytes = bytes
        self.filename = filename
        self.path = path
        self.content_type = content_type
        self.add_to_transactions = add_to_transactions
        # Compute the absolute deadline exactly once. Every envelope item
        # produced from this attachment inherits the same deadline, so the
        # attachment's permission cannot be renewed while it sits in the queue.
        self.expires_at = (_now() + ttl) if ttl is not None else None

    def to_envelope_item(self) -> "Item":
        """Returns an envelope item for this attachment."""
        payload: "Union[PayloadRef, bytes]"
        if self.bytes is not None:
            if callable(self.bytes):
                payload = PayloadRef(
                    bytes=self.bytes(), expires_at=self.expires_at
                )
            else:
                payload = PayloadRef(bytes=self.bytes, expires_at=self.expires_at)
        else:
            payload = PayloadRef(path=self.path, expires_at=self.expires_at)
        return Item(
            payload=payload,
            type="attachment",
            content_type=self.content_type,
            filename=self.filename,
        )

    def __repr__(self) -> str:
        return "<Attachment %r>" % (self.filename,)
