"""
Data category policy.

Implements the ``data_category_policy`` client option, which lets users decide
which envelope data categories are allowed to leave the process. The policy is
evaluated immediately before an envelope is sent, so a single envelope holding
items of different categories (for instance a transaction together with its
profiler sample) can be trimmed to only the categories the project is approved
to send.

This mirrors the data categories Sentry uses for rate limiting
(https://develop.sentry.dev/sdk/rate-limiting/#definitions) and the
``data_category`` exposed on :class:`sentry_sdk.envelope.Item`.

Two equivalent ways of configuring the policy are supported:

* a sequence of allowed category names, e.g. ``["error", "transaction"]``
* a callable taking a category name and returning ``True`` when the category
  may be sent, e.g. ``lambda category: category != "profile"``

A callable is re-evaluated for every envelope, so flipping a flag inside the
callback is enough to disable and later re-enable a category without
re-initializing the SDK.
"""

from typing import TYPE_CHECKING, Any, Callable, Optional, Sequence

if TYPE_CHECKING:
    from sentry_sdk._types import EventDataCategory

# Reason recorded on client reports for items dropped by the policy.
DATA_CATEGORY_POLICY_REASON = "data_category_policy"


class DataCategoryPolicy:
    """Decides whether envelope items of a given data category may be sent."""

    def __init__(
        self,
        allowed: "Optional[Any]" = None,
    ) -> None:
        if allowed is None:
            self._allowed_categories: "Optional[frozenset[EventDataCategory]]" = None
            self._callback: "Optional[Callable[[EventDataCategory], bool]]" = None
        elif callable(allowed):
            self._allowed_categories = None
            self._callback = allowed
        else:
            self._allowed_categories = frozenset(allowed)
            self._callback = None

    def allows(self, data_category: "EventDataCategory") -> bool:
        """Return whether items of the given category may be sent."""
        if self._callback is not None:
            return bool(self._callback(data_category))
        if self._allowed_categories is not None:
            return data_category in self._allowed_categories
        return True

    def __repr__(self) -> str:
        if self._callback is not None:
            return "<DataCategoryPolicy callback={!r}>".format(self._callback)
        if self._allowed_categories is not None:
            return "<DataCategoryPolicy allowed={!r}>".format(
                sorted(self._allowed_categories)
            )
        return "<DataCategoryPolicy allow-all>"


def _build_data_category_policy(
    value: "Optional[Any]",
) -> "Optional[DataCategoryPolicy]":
    """
    Normalize the user-provided ``data_category_policy`` option into a
    :class:`DataCategoryPolicy`.

    ``None`` means no policy is configured and every category may be sent.
    A :class:`DataCategoryPolicy` instance is returned unchanged so the same
    object can be shared across clients. Any other value (a sequence or a
    callable) is wrapped in a new policy.
    """
    if value is None:
        return None
    if isinstance(value, DataCategoryPolicy):
        return value
    if isinstance(value, str):
        raise TypeError(
            "`data_category_policy` must be a sequence of allowed data "
            'categories (e.g. ["error", "transaction"]), not a single '
            "string; got {!r}.".format(value)
        )
    if not (callable(value) or isinstance(value, Sequence)):
        raise TypeError(
            "`data_category_policy` must be a sequence of allowed data "
            "categories, a callable, or a DataCategoryPolicy, got {!r}.".format(
                type(value).__name__
            )
        )
    return DataCategoryPolicy(value)
