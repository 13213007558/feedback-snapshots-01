# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Per-subscriber disclosure of ended spans.

An application opts in by giving its :class:`TracerProvider` a
:class:`SpanDisclosurePolicy`. The policy registered there is the ceiling: a
span processor can ask for less, never for more. Without a ceiling the legacy
behaviour is kept and nothing is filtered.

Exception events (``name == "exception"``) always keep
``exception.type`` and ``exception.escaped``. ``exception.message``,
``exception.stacktrace`` and any application supplied attributes are only
disclosed when the policy allows them. The status code is always visible; the
status description is only visible when the policy allows it.

The same rules apply whether the event was recorded automatically when a span
context exited, by an explicit ``record_exception`` call, or whether the status
was set by the application or by the automatic exception handler.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, Any

from opentelemetry.attributes import BoundedAttributes
from opentelemetry.sdk.util import BoundedList
from opentelemetry.semconv.attributes.exception_attributes import (
    EXCEPTION_ESCAPED,
    EXCEPTION_MESSAGE,
    EXCEPTION_STACKTRACE,
    EXCEPTION_TYPE,
)
from opentelemetry.trace import Link, Status

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import Event, ReadableSpan


_EXCEPTION_EVENT_NAME = "exception"
_ALWAYS_VISIBLE_EXCEPTION_ATTRIBUTES = frozenset({EXCEPTION_TYPE, EXCEPTION_ESCAPED})


@dataclass(frozen=True)
class SpanDisclosurePolicy:
    """Controls which error details a span subscriber may read.

    The policy is used in two places. The application opts in by passing one to
    :class:`~opentelemetry.sdk.trace.TracerProvider` as
    ``span_disclosure_policy``; that policy is the ceiling. Each subscriber
    (span processor) may pass its own policy to ``add_span_processor``; the
    effective policy is the intersection of both. A subscriber that does not
    pass one is treated as an external subscriber and only receives the
    exception type, the ``exception.escaped`` flag and the status code.

    Args:
        exception_message: Disclose ``exception.message``.
        exception_stacktrace: Disclose ``exception.stacktrace``.
        exception_attributes: Disclose additional attributes on exception
            events, including attributes passed to ``record_exception``.
        status_description: Disclose the status description. This matters for
            auto-generated descriptions such as ``ValueError: bad input`` and
            for descriptions set explicitly by the application.
    """

    exception_message: bool = False
    exception_stacktrace: bool = False
    exception_attributes: bool = False
    status_description: bool = False

    @classmethod
    def full(cls) -> "SpanDisclosurePolicy":
        """Disclose every exception field and the status description."""
        return cls(
            exception_message=True,
            exception_stacktrace=True,
            exception_attributes=True,
            status_description=True,
        )

    @classmethod
    def summary(cls) -> "SpanDisclosurePolicy":
        """Disclose only the exception type, the escaped flag and the status code."""
        return cls()

    def restrict(self, other: "SpanDisclosurePolicy") -> "SpanDisclosurePolicy":
        """Return the least-privilege combination of this and ``other``."""
        return type(self)(
            exception_message=self.exception_message and other.exception_message,
            exception_stacktrace=self.exception_stacktrace and other.exception_stacktrace,
            exception_attributes=self.exception_attributes and other.exception_attributes,
            status_description=self.status_description and other.status_description,
        )


def effective_policy(
    ceiling: SpanDisclosurePolicy | None,
    subscriber: SpanDisclosurePolicy | None,
) -> SpanDisclosurePolicy | None:
    """Resolve the policy for one subscriber.

    Without an application ceiling the legacy, unfiltered view is returned
    unless the subscriber explicitly asks for a narrower one.
    """
    if ceiling is None:
        return subscriber
    if subscriber is None:
        subscriber = SpanDisclosurePolicy.summary()
    return ceiling.restrict(subscriber)


def _exception_attribute_is_visible(key: str, policy: SpanDisclosurePolicy) -> bool:
    if key in _ALWAYS_VISIBLE_EXCEPTION_ATTRIBUTES:
        return True
    if key == EXCEPTION_MESSAGE:
        return policy.exception_message
    if key == EXCEPTION_STACKTRACE:
        return policy.exception_stacktrace
    return policy.exception_attributes


def _copy_attributes(
    attributes: Any,
    key_filter: Callable[[str], bool] | None = None,
) -> Any:
    if attributes is None:
        return None
    values = {
        key: copy.deepcopy(value)
        for key, value in attributes.items()
        if key_filter is None or key_filter(key)
    }
    if isinstance(attributes, BoundedAttributes):
        # Each view is mutable but private to one subscriber, so redacting or
        # enriching it never leaks into another subscriber's view.
        copied = BoundedAttributes(
            maxlen=attributes.maxlen,
            attributes=values,
            immutable=False,
            max_value_len=attributes.max_value_len,
        )
        copied.dropped = attributes.dropped
        return copied
    return values


def _copy_event(
    event: "Event",
    policy: SpanDisclosurePolicy | None,
) -> "Event":
    from opentelemetry.sdk.trace import Event  # pylint: disable=import-outside-toplevel

    key_filter = None
    if policy is not None and event.name == _EXCEPTION_EVENT_NAME:
        key_filter = partial(_exception_attribute_is_visible, policy=policy)
    return Event(
        name=event.name,
        attributes=_copy_attributes(event.attributes, key_filter),
        timestamp=event.timestamp,
    )


def _copy_link(link: Link) -> Link:
    return Link(
        context=link.context,
        attributes=_copy_attributes(link.attributes),
    )


def _copy_sequence(
    source: Sequence[Any],
    copier: Callable[[Any], Any],
) -> Any:
    copied_items = [copier(item) for item in source]
    if isinstance(source, BoundedList):
        # pylint: disable=protected-access
        copied: BoundedList[Any] = BoundedList.from_seq(
            source._dq.maxlen,
            copied_items,
        )
        copied.dropped = source.dropped
        return copied
    return tuple(copied_items)


def _copy_status(
    status: Status,
    policy: SpanDisclosurePolicy | None,
) -> Status:
    description = status.description
    if policy is not None and not policy.status_description:
        description = None
    return Status(status.status_code, description)


def materialize_span(
    span: "ReadableSpan",
    policy: SpanDisclosurePolicy | None,
) -> "ReadableSpan":
    """Build a fresh, policy-filtered view of ``span``.

    Every subscriber gets its own containers, so a subscriber that mutates its
    view cannot affect what another subscriber reads.
    """
    from opentelemetry.sdk.trace import (  # pylint: disable=import-outside-toplevel
        ReadableSpan,
    )

    return ReadableSpan(
        name=span.name,
        context=span.context,
        parent=span.parent,
        resource=span.resource,
        attributes=_copy_attributes(
            span._attributes,  # pylint: disable=protected-access
        ),
        events=_copy_sequence(
            span._events,  # pylint: disable=protected-access
            partial(_copy_event, policy=policy),
        ),
        links=_copy_sequence(
            span._links,  # pylint: disable=protected-access
            _copy_link,
        ),
        kind=span.kind,
        instrumentation_info=span._instrumentation_info,  # pylint: disable=protected-access
        status=_copy_status(span.status, policy),
        start_time=span.start_time,
        end_time=span.end_time,
        instrumentation_scope=span.instrumentation_scope,
    )
