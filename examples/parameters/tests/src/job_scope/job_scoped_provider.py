"""Powertools parameter provider constrained to one job's registered paths.

The wrapper keeps every Powertools feature (cache, transforms, ``get_multiple``)
but adds two enforcement points:

1. Before any SDK call, the requested name or batch path is authorized. A rejected
   request raises ``JobAccessDeniedError`` and never reaches the wrapped provider,
   so no forbidden call is sent to the SDK.
2. After a batch response, every returned key is checked again. Entries the service
   leaks from another scope are dropped, so callers only ever see allowed keys.

One wrapper instance is created per job, which also gives every job its own cache:
a value fetched for job A can never be served from a shared cache to job B.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from aws_lambda_powertools.utilities.parameters.base import BaseProvider

from .fake_backends import FakeSecretsProvider

if TYPE_CHECKING:
    from aws_lambda_powertools.utilities.parameters.types import TransformOptions

    from .policy import JobAccessPolicy

logger = logging.getLogger(__name__)


class JobScopedProvider(BaseProvider):
    """Wrap any ``BaseProvider`` and enforce a :class:`JobAccessPolicy`."""

    def __init__(self, inner: BaseProvider, policy: JobAccessPolicy):
        super().__init__()
        self._inner = inner
        self._policy = policy

    def get(self, name: str, *args: Any, **kwargs: Any) -> str | bytes | dict | None:
        self._policy.authorize(name)
        # Go through BaseProvider.get (not the inner provider) so reads are cached
        # in this job's own store and never in a provider shared across jobs.
        return super().get(name, *args, **kwargs)

    def get_multiple(
        self,
        path: str | list[str],
        max_age: int | None = None,
        transform: TransformOptions = None,
        raise_on_transform_error: bool = False,
        force_fetch: bool = False,
        **sdk_options: Any,
    ) -> dict[str, Any]:
        self._authorize_batch(path)
        return super().get_multiple(
            path,
            max_age=max_age,
            transform=transform,
            raise_on_transform_error=raise_on_transform_error,
            force_fetch=force_fetch,
            **sdk_options,
        )

    def _get(self, name: str, **sdk_options: Any) -> str | bytes | dict[str, Any]:
        # Reached through BaseProvider.get only after get() authorized the name.
        self._policy.authorize(name)
        return self._inner._get(name, **sdk_options)

    def _get_multiple(self, path: str | list[str], **sdk_options: Any) -> dict[str, Any]:
        if isinstance(self._inner, FakeSecretsProvider):
            return self._get_multiple_secrets(path, **sdk_options)
        return self._get_multiple_by_path(path, **sdk_options)

    def _get_multiple_by_path(self, path: str | list[str], **sdk_options: Any) -> dict[str, Any]:
        requested_path = self._as_path(path)
        values = self._inner._get_multiple(requested_path, **sdk_options)
        return self._filter_values(requested_path, values)

    def _get_multiple_secrets(self, path: str | list[str], **sdk_options: Any) -> dict[str, Any]:
        requested_path = self._as_path(path)
        names = self._inner.list_names(requested_path)
        # Narrow the list before fetching values: leaked names never hit the SDK.
        allowed_names = self._policy.filter_visible(requested_path, names)
        dropped = sorted(set(names) - set(allowed_names))
        if dropped:
            logger.warning("job %s: dropping out-of-scope secrets before fetch: %s", self._policy.job_id, dropped)
        return self._inner.fetch_many(allowed_names, **sdk_options)

    def _filter_values(self, requested_path: str, values: dict[str, Any]) -> dict[str, Any]:
        visible_keys = self._policy.filter_visible(requested_path, list(values))
        dropped = sorted(set(values) - set(visible_keys))
        if dropped:
            logger.warning(
                "job %s: service returned out-of-scope keys, dropped: %s",
                self._policy.job_id,
                dropped,
            )
        return {key: values[key] for key in visible_keys}

    def _authorize_batch(self, path: str | list[str]) -> None:
        if isinstance(path, list):
            for name in path:
                self._policy.authorize(name)
            return
        self._policy.authorize(path)

    @staticmethod
    def _as_path(path: str | list[str]) -> str:
        if isinstance(path, list):
            # Secrets-style batches carry full names; their common scope is checked
            # entry-by-entry in _authorize_batch, so the first entry anchors filtering.
            return path[0]
        return path
