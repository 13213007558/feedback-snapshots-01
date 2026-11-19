from __future__ import annotations

from collections.abc import Coroutine
from functools import wraps
from typing import TYPE_CHECKING, Any, Callable, Union, cast

from asgiref.sync import iscoroutinefunction, markcoroutinefunction

if TYPE_CHECKING:
    from django.http import HttpResponseBase

    # A generic Django view function
    _VIEW_T = Callable[..., HttpResponseBase]
    # An async Django view function
    _ASYNC_VIEW_T = Callable[..., Coroutine[Any, Any, HttpResponseBase]]
    _ANY_VIEW_T = Union[_VIEW_T, _ASYNC_VIEW_T]
    _VIEW_DECORATOR_T = Callable[[_ANY_VIEW_T], _ANY_VIEW_T]


def _make_decorator(set_override: Callable[[HttpResponseBase], None]) -> _VIEW_DECORATOR_T:
    """
    Build a view decorator that applies ``set_override`` to the response.

    The returned decorator preserves the sync/async nature of the wrapped view
    so that Django's async request path keeps working for coroutine views.
    """

    def decorator(f: _ANY_VIEW_T) -> _ANY_VIEW_T:
        if iscoroutinefunction(f):

            @wraps(f)
            async def _async_wrapped(*a: Any, **kw: Any) -> HttpResponseBase:
                resp = await cast("_ASYNC_VIEW_T", f)(*a, **kw)
                set_override(resp)
                return resp

            return markcoroutinefunction(_async_wrapped)

        @wraps(f)
        def _wrapped(*a: Any, **kw: Any) -> HttpResponseBase:
            resp = cast("_VIEW_T", f)(*a, **kw)
            set_override(resp)
            return resp

        return _wrapped

    return decorator


def csp_exempt(REPORT_ONLY: bool | None = None) -> _VIEW_DECORATOR_T:
    if callable(REPORT_ONLY):
        raise RuntimeError(
            "Incompatible `csp_exempt` decorator usage. This decorator now requires arguments, "
            "even if none are passed. Change bare decorator usage (@csp_exempt) to parameterized "
            "decorator usage (@csp_exempt()). See the django-csp 4.0 migration guide for more "
            "information."
        )

    def set_override(resp: HttpResponseBase) -> None:
        if REPORT_ONLY:
            setattr(resp, "_csp_exempt_ro", True)
        else:
            setattr(resp, "_csp_exempt", True)

    return _make_decorator(set_override)


# Error message for deprecated decorator arguments.
DECORATOR_DEPRECATION_ERROR = (
    "Incompatible `{fname}` decorator arguments. This decorator now takes a single dict argument. "
    "See the django-csp 4.0 migration guide for more information."
)


def csp_update(config: dict[str, Any] | None = None, REPORT_ONLY: bool = False, **kwargs: Any) -> _VIEW_DECORATOR_T:
    if config is None and kwargs:
        raise RuntimeError(DECORATOR_DEPRECATION_ERROR.format(fname="csp_update"))

    def set_override(resp: HttpResponseBase) -> None:
        if REPORT_ONLY:
            setattr(resp, "_csp_update_ro", config)
        else:
            setattr(resp, "_csp_update", config)

    return _make_decorator(set_override)


def csp_replace(config: dict[str, Any] | None = None, REPORT_ONLY: bool = False, **kwargs: Any) -> _VIEW_DECORATOR_T:
    if config is None and kwargs:
        raise RuntimeError(DECORATOR_DEPRECATION_ERROR.format(fname="csp_replace"))

    def set_override(resp: HttpResponseBase) -> None:
        if REPORT_ONLY:
            setattr(resp, "_csp_replace_ro", config)
        else:
            setattr(resp, "_csp_replace", config)

    return _make_decorator(set_override)


def csp(config: dict[str, Any] | None = None, REPORT_ONLY: bool = False, **kwargs: Any) -> _VIEW_DECORATOR_T:
    if config is None and kwargs:
        raise RuntimeError(DECORATOR_DEPRECATION_ERROR.format(fname="csp"))

    if config is None:
        processed_config: dict[str, list[Any]] = {}
    else:
        processed_config = {k: [v] if isinstance(v, str) else v for k, v in config.items()}

    def set_override(resp: HttpResponseBase) -> None:
        if REPORT_ONLY:
            setattr(resp, "_csp_config_ro", processed_config)
        else:
            setattr(resp, "_csp_config", processed_config)

    return _make_decorator(set_override)
