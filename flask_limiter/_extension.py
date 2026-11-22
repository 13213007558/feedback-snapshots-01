"""
Flask-Limiter Extension
"""

from __future__ import annotations

import dataclasses
import datetime
import functools
import itertools
import logging
import time
import warnings
import weakref
from collections import defaultdict
from functools import partial
from typing import overload

import flask
import flask.wrappers
from limits import RateLimitItem, WindowStats
from limits.errors import ConfigurationError
from limits.storage import MemoryStorage, Storage, storage_from_string
from limits.strategies import STRATEGIES, RateLimiter
from ordered_set import OrderedSet
from werkzeug.http import http_date, parse_date

from ._compat import request_context
from ._limits import (
    ApplicationLimit,
    Limit,
    MetaLimit,
    MultiLimit,
    RouteLimit,
    RuntimeLimit,
)
from ._manager import LimitManager
from ._typing import (
    Callable,
    P,
    R,
    Sequence,
    cast,
)
from .constants import MAX_BACKEND_CHECKS, ConfigVars, ExemptionScope, HeaderNames
from .errors import RateLimitExceeded
from .util import get_qualified_name


class RequestLimit:
    """
    Provides details of a rate limit within the context of a request
    """

    #: The instance of the rate limit
    limit: RateLimitItem

    #: The full key for the request against which the rate limit is tested
    key: str

    #: Whether the limit was breached within the context of this request
    breached: bool

    #: Whether the limit is a shared limit
    shared: bool

    #: Identity of the rule declaration this limit belongs to (``None`` for a plain
    #: single-key limit). Useful to tell which rule rejected a multi-dimensional request.
    rule_id: str | None

    #: Name of the dimension within :attr:`rule_id` (``None`` for a plain limit).
    dimension: str | None

    #: The runtime limit definition that produced this request limit.
    #:
    #: :meta private:
    source: RuntimeLimit | None

    def __init__(
        self,
        extension: Limiter,
        limit: RateLimitItem,
        request_args: list[str],
        breached: bool,
        shared: bool,
        rule_id: str | None = None,
        dimension: str | None = None,
        source: RuntimeLimit | None = None,
    ) -> None:
        self.extension: weakref.ProxyType[Limiter] = weakref.proxy(extension)
        self.limit = limit
        self.request_args = request_args
        self.key = limit.key_for(*request_args)
        self.breached = breached
        self.shared = shared
        self.rule_id = rule_id
        self.dimension = dimension
        self.source = source
        self._window: WindowStats | None = None

    @property
    def limiter(self) -> RateLimiter:
        return cast(RateLimiter, self.extension.limiter)

    @property
    def window(self) -> WindowStats:
        if not self._window:
            self._window = self.limiter.get_window_stats(self.limit, *self.request_args)

        return self._window

    @property
    def reset_at(self) -> int:
        """Timestamp at which the rate limit will be reset"""

        return int(self.window[0] + 1)

    @property
    def remaining(self) -> int:
        """Quantity remaining for this rate limit"""

        return self.window[1]


@dataclasses.dataclass
class LimiterContext:
    view_rate_limit: RequestLimit | None = None
    view_rate_limits: list[RequestLimit] = dataclasses.field(default_factory=list)
    conditional_deductions: dict[RuntimeLimit, list[str]] = dataclasses.field(default_factory=dict)
    seen_limits: OrderedSet[RuntimeLimit] = dataclasses.field(default_factory=OrderedSet)

    def reset(self) -> None:
        self.view_rate_limit = None
        self.view_rate_limits.clear()
        self.conditional_deductions.clear()
        self.seen_limits.clear()


class Limiter:
    """
    The :class:`Limiter` class initializes the Flask-Limiter extension.

    :param key_func: a callable that returns the domain to rate limit by.
    :param app: :class:`flask.Flask` instance to initialize the extension with.
    :param default_limits: a list of strings, callables returning strings denoting default limits
     or :class:`Limit` instances to apply to all routes that are not explicitely decorated with a
     limit. :ref:`ratelimit-string` for  more details.
    :param default_limits_per_method: whether default limits are applied per method, per route or
     as a combination of all method per route.
    :param default_limits_exempt_when: a function that should return True/False to decide if the
     default limits should be skipped
    :param default_limits_deduct_when: a function that receives the current :class:`flask.Response`
     object and returns True/False to decide  if a deduction should be made from the default rate
     limit(s)
    :param default_limits_cost: The cost of a hit to the default limits as an integer or a function
     that takes no parameters and returns an integer (Default: ``1``).
    :param application_limits: a list of strings, callables returning strings for limits or
     :class:`ApplicationLimit` that are applied to  the entire application
     (i.e a shared limit for all routes)
    :param application_limits_per_method: whether application limits are applied per method, per
     route or as a combination of all method per route.
    :param application_limits_exempt_when: a function that should return True/False to decide if the
     application limits should be skipped
    :param application_limits_deduct_when: a function that receives the current
     :class:`flask.Response` object and returns True/False to decide  if a deduction should be made
     from the application rate limit(s)
    :param application_limits_cost: The cost of a hit to the global application limits as an integer
     or a function that takes no parameters and returns an integer (Default: ``1``).
    :param headers_enabled: whether ``X-RateLimit`` response headers are written.
    :param header_name_mapping: Mapping of header names to use if :paramref:`Limiter.headers_enabled`
     is ``True``. If no mapping is provided the default values will be used.
    :param strategy: the strategy to use. Refer to :ref:`ratelimit-strategy`
    :param storage_uri: the storage location. Refer to :data:`RATELIMIT_STORAGE_URI`
    :param storage_options: kwargs to pass to the storage implementation upon instantiation.
    :param swallow_errors: whether to swallow any errors when hitting a rate limit. An exception
     will still be logged. default ``False``
    :param fail_on_first_breach: whether to stop processing remaining limits after the first breach.
     default ``True``
    :param on_breach: a function that will be called when any limit in this extension is breached.
     If the function returns an instance of :class:`flask.Response` that will be the response
     embedded into the :exc:`RateLimitExceeded` exception raised.
    :param meta_limits: a list of strings, callables returning strings for limits or
     :class:`MetaLimit` that are used to control the upper limit of  a requesting client hitting
     any configured rate limit. Once a meta limit is exceeded all subsequent requests will
     raise a :class:`~flask_limiter.RateLimitExceeded` for the duration of the meta limit window.
    :param on_meta_breach: a function that will be called when a meta limit in this extension is
     breached. If the function returns an instance of :class:`flask.Response` that will be the
     response embedded into the :exc:`RateLimitExceeded` exception raised.
    :param in_memory_fallback: a list of strings or callables returning strings denoting fallback
     limits to apply when the storage is down.
    :param in_memory_fallback_enabled: fall back to in memory storage when the main storage is down
     and inherits the original limits. default ``False``
    :param retry_after: Allows configuration of how the value of the `Retry-After` header is
     rendered. One of `http-date` or `delta-seconds`.
    :param key_prefix: prefix prepended to rate limiter keys and app context global names.
    :param request_identifier: a callable that returns the unique identity the current request.
     Defaults to :attr:`flask.Request.endpoint`
    :param enabled: Whether the extension is enabled or not
    """

    def __init__(
        self,
        key_func: Callable[[], str],
        *,
        app: flask.Flask | None = None,
        default_limits: list[str | Callable[[], str] | Limit] | None = None,
        default_limits_per_method: bool | None = None,
        default_limits_exempt_when: Callable[[], bool] | None = None,
        default_limits_deduct_when: Callable[[flask.wrappers.Response], bool] | None = None,
        default_limits_cost: int | Callable[[], int] | None = None,
        application_limits: list[str | Callable[[], str] | ApplicationLimit] | None = None,
        application_limits_per_method: bool | None = None,
        application_limits_exempt_when: Callable[[], bool] | None = None,
        application_limits_deduct_when: Callable[[flask.wrappers.Response], bool] | None = None,
        application_limits_cost: int | Callable[[], int] | None = None,
        headers_enabled: bool | None = None,
        header_name_mapping: dict[HeaderNames, str] | None = None,
        strategy: str | None = None,
        storage_uri: str | None = None,
        storage_options: dict[str, str | int] | None = None,
        swallow_errors: bool | None = None,
        fail_on_first_breach: bool | None = None,
        on_breach: Callable[[RequestLimit], flask.wrappers.Response | None] | None = None,
        meta_limits: list[str | Callable[[], str] | MetaLimit] | None = None,
        on_meta_breach: Callable[[RequestLimit], flask.wrappers.Response | None] | None = None,
        in_memory_fallback: list[str] | None = None,
        in_memory_fallback_enabled: bool | None = None,
        retry_after: str | None = None,
        key_prefix: str = "",
        request_identifier: Callable[..., str] | None = None,
        enabled: bool = True,
    ) -> None:
        self.app = app
        self.logger = logging.getLogger("flask-limiter")

        self.enabled = enabled
        self.initialized = False
        self._default_limits_per_method = default_limits_per_method
        self._default_limits_exempt_when = default_limits_exempt_when
        self._default_limits_deduct_when = default_limits_deduct_when
        self._default_limits_cost = default_limits_cost
        self._application_limits_per_method = application_limits_per_method
        self._application_limits_exempt_when = application_limits_exempt_when
        self._application_limits_deduct_when = application_limits_deduct_when
        self._application_limits_cost = application_limits_cost
        self._in_memory_fallback = []
        self._in_memory_fallback_enabled = in_memory_fallback_enabled or (
            in_memory_fallback and len(in_memory_fallback) > 0
        )
        self._route_exemptions: dict[str, ExemptionScope] = {}
        self._blueprint_exemptions: dict[str, ExemptionScope] = {}
        self._request_filters: list[Callable[[], bool]] = []

        self._headers_enabled = headers_enabled
        self._header_mapping = header_name_mapping or {}
        self._retry_after = retry_after
        self._strategy = strategy
        self._storage_uri = storage_uri
        self._storage_options = storage_options or {}
        self._swallow_errors = swallow_errors
        self._fail_on_first_breach = fail_on_first_breach
        self._on_breach = on_breach
        self._on_meta_breach = on_meta_breach

        self._key_func = key_func
        self._key_prefix = key_prefix
        self._request_identifier = request_identifier

        _default_limits = (
            [
                Limit(
                    limit_provider=limit,
                    key_function=self._key_func,
                    finalized=False,
                ).bind(self)
                if not isinstance(limit, Limit)
                else limit.bind(self)
                for limit in default_limits
            ]
            if default_limits
            else []
        )

        _application_limits = (
            [
                ApplicationLimit(
                    limit_provider=limit,
                    finalized=False,
                ).bind(self)
                if not isinstance(limit, Limit)
                else limit.bind(self)
                for limit in application_limits
            ]
            if application_limits
            else []
        )

        self._meta_limits = (
            [
                MetaLimit(
                    limit_provider=limit,
                ).bind(self)
                if not isinstance(limit, Limit)
                else limit.bind(self)
                for limit in meta_limits
            ]
            if meta_limits
            else []
        )

        if in_memory_fallback:
            for limit in in_memory_fallback:
                self._in_memory_fallback.append(
                    Limit(
                        limit_provider=limit,
                        key_function=self._key_func,
                    )
                    if not isinstance(limit, Limit)
                    else limit
                )

        self._storage: Storage | None = None
        self._limiter: RateLimiter | None = None
        self._storage_dead = False
        self._fallback_limiter: RateLimiter | None = None

        self.__check_backend_count = 0
        self.__last_check_backend = time.time()
        self._marked_for_limiting: set[str] = set()

        self.logger.addHandler(logging.NullHandler())

        self.limit_manager = LimitManager(
            application_limits=_application_limits,
            default_limits=_default_limits,
            decorated_limits={},
            blueprint_limits={},
            route_exemptions=self._route_exemptions,
            blueprint_exemptions=self._blueprint_exemptions,
        )

        if app:
            self.init_app(app)

    def init_app(self, app: flask.Flask) -> None:
        """
        :param app: :class:`flask.Flask` instance to rate limit.
        """
        config = app.config
        self.enabled = config.setdefault(ConfigVars.ENABLED, self.enabled)

        if not self.enabled:
            return

        if self._default_limits_per_method is None:
            self._default_limits_per_method = bool(
                config.get(ConfigVars.DEFAULT_LIMITS_PER_METHOD, False)
            )
        self._default_limits_exempt_when = self._default_limits_exempt_when or config.get(
            ConfigVars.DEFAULT_LIMITS_EXEMPT_WHEN
        )
        self._default_limits_deduct_when = self._default_limits_deduct_when or config.get(
            ConfigVars.DEFAULT_LIMITS_DEDUCT_WHEN
        )
        self._default_limits_cost = self._default_limits_cost or config.get(
            ConfigVars.DEFAULT_LIMITS_COST, 1
        )

        if self._swallow_errors is None:
            self._swallow_errors = bool(config.get(ConfigVars.SWALLOW_ERRORS, False))

        if self._fail_on_first_breach is None:
            self._fail_on_first_breach = bool(config.get(ConfigVars.FAIL_ON_FIRST_BREACH, True))

        if self._headers_enabled is None:
            self._headers_enabled = bool(config.get(ConfigVars.HEADERS_ENABLED, False))

        self._storage_options.update(config.get(ConfigVars.STORAGE_OPTIONS, {}))
        storage_uri_from_config = config.get(ConfigVars.STORAGE_URI, None)

        if not storage_uri_from_config:
            if not self._storage_uri:
                warnings.warn(
                    "Using the in-memory storage for tracking rate limits as no storage "
                    "was explicitly specified. This is not recommended for production use. "
                    "See: https://flask-limiter.readthedocs.io#configuring-a-storage-backend "
                    "for documentation about configuring the storage backend."
                )
            storage_uri_from_config = "memory://"
        self._storage = cast(
            Storage,
            storage_from_string(
                self._storage_uri or storage_uri_from_config, **self._storage_options
            ),
        )
        self._strategy = self._strategy or config.setdefault(ConfigVars.STRATEGY, "fixed-window")

        if self._strategy not in STRATEGIES:
            raise ConfigurationError("Invalid rate limiting strategy %s" % self._strategy)
        self._limiter = STRATEGIES[self._strategy](self._storage)

        self._header_mapping = {
            HeaderNames.RESET: self._header_mapping.get(
                HeaderNames.RESET,
                config.get(ConfigVars.HEADER_RESET, HeaderNames.RESET.value),
            ),
            HeaderNames.REMAINING: self._header_mapping.get(
                HeaderNames.REMAINING,
                config.get(ConfigVars.HEADER_REMAINING, HeaderNames.REMAINING.value),
            ),
            HeaderNames.LIMIT: self._header_mapping.get(
                HeaderNames.LIMIT,
                config.get(ConfigVars.HEADER_LIMIT, HeaderNames.LIMIT.value),
            ),
            HeaderNames.RETRY_AFTER: self._header_mapping.get(
                HeaderNames.RETRY_AFTER,
                config.get(ConfigVars.HEADER_RETRY_AFTER, HeaderNames.RETRY_AFTER.value),
            ),
        }
        self._retry_after = self._retry_after or config.get(ConfigVars.HEADER_RETRY_AFTER_VALUE)

        self._key_prefix = self._key_prefix or config.get(ConfigVars.KEY_PREFIX, "")
        self._request_identifier = self._request_identifier or config.get(
            ConfigVars.REQUEST_IDENTIFIER, lambda: flask.request.endpoint or ""
        )
        app_limits = config.get(ConfigVars.APPLICATION_LIMITS, None)
        self._application_limits_cost = self._application_limits_cost or config.get(
            ConfigVars.APPLICATION_LIMITS_COST, 1
        )

        if self._application_limits_per_method is None:
            self._application_limits_per_method = bool(
                config.get(ConfigVars.APPLICATION_LIMITS_PER_METHOD, False)
            )
        self._application_limits_exempt_when = self._application_limits_exempt_when or config.get(
            ConfigVars.APPLICATION_LIMITS_EXEMPT_WHEN
        )
        self._application_limits_deduct_when = self._application_limits_deduct_when or config.get(
            ConfigVars.APPLICATION_LIMITS_DEDUCT_WHEN
        )

        if not self.limit_manager._application_limits and app_limits:
            self.limit_manager.set_application_limits(
                [
                    ApplicationLimit(
                        limit_provider=app_limits,
                        per_method=self._application_limits_per_method,
                        exempt_when=self._application_limits_exempt_when,
                        deduct_when=self._application_limits_deduct_when,
                        cost=self._application_limits_cost,
                    ).bind(self)
                ]
            )
        else:
            app_limits = self.limit_manager._application_limits

            for group in app_limits:
                if not group.finalized:
                    group.cost = self._application_limits_cost
                    group.per_method = self._application_limits_per_method
                    group.exempt_when = self._application_limits_exempt_when
                    group.deduct_when = self._application_limits_deduct_when
                    group.finalized = True
            self.limit_manager.set_application_limits(app_limits)

        conf_limits = config.get(ConfigVars.DEFAULT_LIMITS, None)

        if not self.limit_manager._default_limits and conf_limits:
            self.limit_manager.set_default_limits(
                [
                    Limit(
                        limit_provider=conf_limits,
                        key_function=self._key_func,
                        per_method=self._default_limits_per_method,
                        exempt_when=self._default_limits_exempt_when,
                        deduct_when=self._default_limits_deduct_when,
                        cost=self._default_limits_cost,
                    ).bind(self)
                ]
            )
        else:
            default_limit_groups = self.limit_manager._default_limits

            for default_group in default_limit_groups:
                if not default_group.finalized:
                    default_group.cost = self._default_limits_cost
                    default_group.per_method = self._default_limits_per_method
                    default_group.exempt_when = self._default_limits_exempt_when
                    default_group.deduct_when = self._default_limits_deduct_when
                    default_group.finalized = True
            self.limit_manager.set_default_limits(default_limit_groups)

        meta_limits = config.get(ConfigVars.META_LIMITS, None)

        if not self._meta_limits and meta_limits:
            self._meta_limits = [
                MetaLimit(
                    limit_provider=meta_limits,
                    key_function=self._key_func,
                ).bind(self)
                if not isinstance(meta_limits, MetaLimit)
                else meta_limits.bind(self)
            ]

        self._on_breach = self._on_breach or config.get(ConfigVars.ON_BREACH, None)
        self._on_meta_breach = self._on_meta_breach or config.get(ConfigVars.ON_META_BREACH, None)

        self.__configure_fallbacks(app, self._strategy)

        if self not in app.extensions.setdefault("limiter", set()):
            app.before_request(self._check_request_limit)
            app.after_request(partial(Limiter.__inject_headers, self))
            app.teardown_request(self.__release_context)
        app.extensions["limiter"].add(self)
        self.initialized = True

    @property
    def context(self) -> LimiterContext:
        """
        The context is meant to exist for the lifetime of a request/response cycle per instance of
        the extension so as to keep track of any state used at different steps in the lifecycle
        (for example to pass information from the before request hook to the after_request hook)

        :meta private:
        """
        ctx = request_context()

        if not hasattr(ctx, "_limiter_request_context"):
            ctx._limiter_request_context = defaultdict(LimiterContext)  # type: ignore

        return cast(
            dict[Limiter, LimiterContext],
            ctx._limiter_request_context,  # type: ignore
        )[self]

    def limit(
        self,
        limit_value: str | Callable[[], str],
        *,
        key_func: Callable[[], str] | None = None,
        per_method: bool = False,
        methods: list[str] | None = None,
        error_message: str | Callable[[], str] | None = None,
        exempt_when: Callable[[], bool] | None = None,
        override_defaults: bool = True,
        deduct_when: Callable[[flask.wrappers.Response], bool] | None = None,
        on_breach: None | (Callable[[RequestLimit], flask.wrappers.Response | None]) = None,
        cost: int | Callable[[], int] = 1,
        scope: str | Callable[[str], str] | None = None,
        meta_limits: Sequence[str | Callable[[], str] | MetaLimit] | None = None,
    ) -> RouteLimit:
        """
        Decorator to be used for rate limiting individual routes or blueprints.

        :param limit_value: rate limit string or a callable that returns a string.
         :ref:`ratelimit-string` for more details.
        :param key_func: function/lambda to extract the unique identifier for the rate limit.
        :param per_method: whether the limit is sub categorized into the http method of the request.
        :param methods: if specified, only the methods in this list will be rate limited
         (default: ``None``).
        :param error_message: string (or callable that returns one) to override the error message
         used in the response.
        :param exempt_when: function/lambda used to decide if the rate limit should skipped.
        :param override_defaults:  whether the decorated limit overrides the default limits
         (Default: ``True``).

         .. note:: When used with a :class:`~flask.Blueprint` the meaning
            of the parameter extends to any parents the blueprint instance is
            registered under. For more details see :ref:`recipes:nested blueprints`

        :param deduct_when: a function that receives the current :class:`flask.Response` object and
         returns True/False to decide if a deduction should be done from the rate limit
        :param on_breach: a function that will be called when this limit is breached. If the
         function returns an instance of :class:`flask.Response` that will be the response embedded
         into the :exc:`RateLimitExceeded` exception raised.
        :param cost: The cost of a hit or a function that takes no parameters and returns the cost
         as an integer (Default: ``1``).
        :param scope: a string or callable that returns a string for further categorizing the rate
         limiting scope. This scope is combined with the current endpoint of the request.


        Changes
          - .. versionadded:: 2.9.0

               The returned object can also be used as a context manager
               for rate limiting a code block inside a view. For example::

                 @app.route("/")
                 def route():
                   try:
                     with limiter.limit("10/second"):
                       # something expensive
                   except RateLimitExceeded: pass

        """

        return RouteLimit(
            limit_provider=limit_value,
            limiter=self,
            key_function=key_func or self._key_func,
            shared=False,
            scope=scope,
            per_method=per_method,
            methods=methods,
            error_message=error_message,
            exempt_when=exempt_when,
            override_defaults=override_defaults,
            deduct_when=deduct_when,
            on_breach=on_breach,
            cost=cost,
            meta_limits=meta_limits,
        )

    def shared_limit(
        self,
        limit_value: str | Callable[[], str],
        scope: str | Callable[[str], str],
        *,
        key_func: Callable[[], str] | None = None,
        per_method: bool = False,
        methods: list[str] | None = None,
        error_message: str | Callable[[], str] | None = None,
        exempt_when: Callable[[], bool] | None = None,
        override_defaults: bool = True,
        deduct_when: Callable[[flask.wrappers.Response], bool] | None = None,
        on_breach: None | (Callable[[RequestLimit], flask.wrappers.Response | None]) = None,
        cost: int | Callable[[], int] = 1,
        meta_limits: Sequence[str | Callable[[], str] | MetaLimit] | None = None,
    ) -> RouteLimit:
        """
        decorator to be applied to multiple routes sharing the same rate limit.

        :param limit_value: rate limit string or a callable that returns a string.
         :ref:`ratelimit-string` for more details.
        :param scope: a string or callable that returns a string for defining the rate limiting scope.
        :param key_func: function/lambda to extract the unique identifier for the rate limit.
        :param per_method: whether the limit is sub categorized into the http method of the request.
        :param methods: if specified, only the methods in this list will be rate limited
         (default: ``None``).
        :param error_message: string (or callable that returns one) to override the error message
         used in the response.
        :param function exempt_when: function/lambda used to decide if the rate limit should skipped.
        :param override_defaults: whether the decorated limit overrides the default limits.
         (default: ``True``)

         .. note:: When used with a :class:`~flask.Blueprint` the meaning
            of the parameter extends to any parents the blueprint instance is
            registered under. For more details see :ref:`recipes:nested blueprints`
        :param deduct_when: a function that receives the current :class:`flask.Response` object and
         returns True/False to decide if a deduction should be done from the rate limit
        :param on_breach: a function that will be called when this limit is breached.
         If the function returns an instance of :class:`flask.Response` that will be the response
         embedded into the :exc:`RateLimitExceeded` exception raised.
        :param cost: The cost of a hit or a function that takes no parameters and returns the cost
         as an integer (default: ``1``).
        """

        return RouteLimit(
            limit_provider=limit_value,
            limiter=self,
            key_function=key_func or self._key_func,
            shared=True,
            scope=scope,
            per_method=per_method,
            methods=methods,
            error_message=error_message,
            exempt_when=exempt_when,
            override_defaults=override_defaults,
            deduct_when=deduct_when,
            on_breach=on_breach,
            cost=cost,
            meta_limits=meta_limits,
        )

    def multi_limit(
        self,
        dimensions: Sequence[
            tuple[str, str | Callable[[], str]]
            | tuple[str, str | Callable[[], str], Callable[[], str] | None]
            | tuple[
                str,
                str | Callable[[], str],
                Callable[[], str] | None,
                Callable[[], bool] | None,
            ]
        ],
        *,
        name: str | None = None,
        key_func: Callable[[], str] | None = None,
        shared: bool = True,
        per_method: bool = False,
        methods: list[str] | None = None,
        error_message: str | Callable[[], str] | None = None,
        exempt_when: Callable[[], bool] | None = None,
        override_defaults: bool = True,
        deduct_when: Callable[[flask.wrappers.Response], bool] | None = None,
        on_breach: None | (Callable[[RequestLimit], flask.wrappers.Response | None]) = None,
        cost: int | Callable[[], int] = 1,
        scope: str | Callable[[str], str] | None = None,
        meta_limits: Sequence[str | Callable[[], str] | MetaLimit] | None = None,
    ) -> MultiLimit:
        """
        Decorator to declare several independent rate limits for the same route, each
        one keyed by its own business identity.

        Each dimension is specified as a tuple of
        ``(name, rate_limit, key_func?, when?)``. The ``name`` identifies the dimension
        (for example ``"employee"`` or ``"project"``), ``rate_limit`` is a limit string
        or a callable returning one, ``key_func`` extracts that dimension's identity
        and ``when`` is an optional predicate deciding whether the dimension applies
        to the current request.

        All dimensions are evaluated against the same request. Each one is counted
        independently (and in its own storage namespace, so an employee id and a project
        id with the same value never share a bucket). If a dimension is not applicable
        (for example because the authenticated employee has no access to the requested
        project) it is skipped without being charged, and the other dimensions are still
        accounted normally. A request that breaches one dimension is rejected by that
        dimension; the dimensions that were not breached keep their usage (or their
        remaining allowance, when they were only tested).

        :param dimensions: the ``(name, rate_limit, key_func?, when?)`` declarations.
        :param name: optional name for this declaration reported by
         :attr:`~flask_limiter.RateLimitExceeded.rejected_rule`. Defaults to a generated id.
        :param key_func: default identity used by dimensions declared without a
         ``key_func``. It is not called when every dimension provides its own.
        :param shared: whether the declared ``scope`` is shared between all routes and
         blueprints using this declaration instead of being namespaced by endpoint.
        :param per_method: whether each dimension is sub categorized by HTTP method.
        :param methods: if specified, only the requests with these methods are limited.
        :param error_message: string (or callable returning one) used for the rejection
         message of any dimension of this declaration.
        :param exempt_when: function/lambda used to decide if *all* dimensions should be
         skipped. Individual dimensions can be skipped with their ``when`` predicate.
        :param override_defaults: whether this declaration overrides the default limits.
        :param deduct_when: decides, after the response, whether each dimension should
         still be charged.
        :param on_breach: callback invoked when a dimension is breached.
        :param cost: cost of a hit for each dimension (or a callable returning it).
        :param scope: a string or callable returning a string used to further categorize
         each dimension's scope. The scope is combined with the endpoint unless the
         dimension should be shared across routes (use a callable/constant scope).
        :param meta_limits: meta limits charged whenever one of the dimensions is breached.

        Example::

            submit_limit = limiter.multi_limit(
                [
                    ("employee", "5/hour", lambda: g.employee_id),
                    ("project", "20/hour", project_key, can_access_project),
                ],
                scope="claim-submit",
            )

            @app.route("/claims", methods=["POST"])
            @submit_limit
            def submit_claim():
                ...

        A rejected request keeps the state of the other dimensions. The raised
        :class:`~flask_limiter.RateLimitExceeded` reports which declaration and which
        dimension rejected it, and the remaining allowance of every evaluated
        dimension::

            @app.errorhandler(RateLimitExceeded)
            def rate_limited(exc):
                return {
                    "rule": exc.rejected_rule,
                    "dimension": exc.rejected_dimension,
                    "remaining": exc.remaining_by_dimension(),
                }, 429

        .. note:: This decorator is additive: unlike :meth:`limit` it does not replace
           limits declared by other decorators on the same view.
        """

        return MultiLimit(
            "",
            limiter=self,
            name=name,
            dimensions=dimensions,
            key_function=key_func or self._key_func,
            shared=shared,
            scope=scope,
            per_method=per_method,
            methods=methods,
            error_message=error_message,
            exempt_when=exempt_when,
            override_defaults=override_defaults,
            deduct_when=deduct_when,
            on_breach=on_breach,
            cost=cost,
            meta_limits=meta_limits,
        )

    @overload
    def exempt(
        self,
        obj: flask.Blueprint,
        *,
        flags: ExemptionScope = ExemptionScope.APPLICATION
        | ExemptionScope.DEFAULT
        | ExemptionScope.META,
    ) -> flask.Blueprint: ...

    @overload
    def exempt(
        self,
        obj: Callable[..., R],
        *,
        flags: ExemptionScope = ExemptionScope.APPLICATION
        | ExemptionScope.DEFAULT
        | ExemptionScope.META,
    ) -> Callable[..., R]: ...

    @overload
    def exempt(
        self,
        *,
        flags: ExemptionScope = ExemptionScope.APPLICATION
        | ExemptionScope.DEFAULT
        | ExemptionScope.META,
    ) -> (
        Callable[[Callable[P, R]], Callable[P, R]] | Callable[[flask.Blueprint], flask.Blueprint]
    ): ...

    def exempt(
        self,
        obj: Callable[..., R] | flask.Blueprint | None = None,
        *,
        flags: ExemptionScope = ExemptionScope.APPLICATION
        | ExemptionScope.DEFAULT
        | ExemptionScope.META,
    ) -> (
        Callable[..., R]
        | flask.Blueprint
        | Callable[[Callable[P, R]], Callable[P, R]]
        | Callable[[flask.Blueprint], flask.Blueprint]
    ):
        """
        Mark a view function or all views in a blueprint as exempt from rate limits.

        :param obj: view function or blueprint to mark as exempt.
        :param flags: Controls the scope of the exemption. By default application wide limits,
         defaults configured on the extension and meta limits are opted out of. Additional flags
         can be used to control the behavior when :paramref:`obj` is a Blueprint that is nested
         under another Blueprint or has other Blueprints nested under it
         (See :ref:`recipes:nested blueprints`)

        The method can be used either as a decorator without any arguments (the default
        flags will apply and the route will be exempt from default and application limits::

            @app.route("...")
            @limiter.exempt
            def route(...):
               ...

        Specific exemption flags can be provided at decoration time::

            @app.route("...")
            @limiter.exempt(flags=ExemptionScope.APPLICATION)
            def route(...):
                ...

        If an entire blueprint (i.e. all routes under it) are to be exempted the method can be
        called with the blueprint as the first parameter and any additional flags::

            bp = Blueprint(...)
            limiter.exempt(bp)
            limiter.exempt(
                bp,
                flags=ExemptionScope.DEFAULT|ExemptionScope.APPLICATION|ExemptionScope.ANCESTORS
            )

        """

        if isinstance(obj, flask.Blueprint):
            self.limit_manager.add_blueprint_exemption(obj.name, flags)
        elif obj:
            self.limit_manager.add_route_exemption(get_qualified_name(obj), flags)
        else:
            return functools.partial(self.exempt, flags=flags)

        return obj

    def request_filter(self, fn: Callable[[], bool]) -> Callable[[], bool]:
        """
        Decorator to mark a function as a filter to be executed to check if the request is exempt
        from rate limiting.

        :param fn: The function will be called before evaluating any rate limits to decide whether
         to perform rate limit or skip it.
        """
        self._request_filters.append(fn)

        return fn

    def __configure_fallbacks(self, app: flask.Flask, strategy: str) -> None:
        config = app.config
        fallback_enabled = config.get(ConfigVars.IN_MEMORY_FALLBACK_ENABLED, False)
        fallback_limits = config.get(ConfigVars.IN_MEMORY_FALLBACK, None)

        if not self._in_memory_fallback and fallback_limits:
            self._in_memory_fallback = [
                Limit(
                    limit_provider=fallback_limits,
                    key_function=self._key_func,
                    scope=None,
                    per_method=False,
                    cost=1,
                ).bind(self)
            ]

        if not self._in_memory_fallback_enabled:
            self._in_memory_fallback_enabled = fallback_enabled or len(self._in_memory_fallback) > 0

        if self._in_memory_fallback_enabled:
            self._fallback_storage = MemoryStorage()
            self._fallback_limiter = STRATEGIES[strategy](self._fallback_storage)

    def __should_check_backend(self) -> bool:
        if self.__check_backend_count > MAX_BACKEND_CHECKS:
            self.__check_backend_count = 0

        if time.time() - self.__last_check_backend > pow(2, self.__check_backend_count):
            self.__last_check_backend = time.time()
            self.__check_backend_count += 1

            return True

        return False

    def reset(self) -> None:
        """
        resets the storage if it supports being reset
        """
        try:
            self.storage.reset()
            self.logger.info("Storage has been reset and all limits cleared")
        except NotImplementedError:
            self.logger.warning("This storage type does not support being reset")

    @property
    def storage(self) -> Storage:
        """
        The backend storage configured for the rate limiter
        """
        assert self._storage

        return self._storage

    @property
    def limiter(self) -> RateLimiter:
        """
        Instance of the rate limiting strategy used for performing rate limiting.
        """

        if self._storage_dead and self._in_memory_fallback_enabled:
            limiter = self._fallback_limiter
        else:
            limiter = self._limiter
        assert limiter

        return limiter

    @property
    def current_limit(self) -> RequestLimit | None:
        """
        Get details for the most relevant rate limit used in this request.

        In a scenario where multiple rate limits are active for a single request and none are
        breached, the rate limit which applies to the smallest time window will be returned.

        .. important:: The value of ``remaining`` in :class:`RequestLimit` is after
           deduction for the current request.


        For example::

            @limit("1/second")
            @limit("60/minute")
            @limit("2/day")
            def route(...):
                ...

        - Request 1 at ``t=0`` (no breach): this will return the details for for ``1/second``
        - Request 2 at ``t=1`` (no breach): it will still return the details for ``1/second``
        - Request 3 at ``t=2`` (breach): it will return the details for ``2/day``
        """

        return self.context.view_rate_limit

    @property
    def current_limits(self) -> list[RequestLimit]:
        """
        Get a list of all rate limits that were applicable and evaluated
        within the context of this request.

        The limits are returned in a sorted order by smallest window size first.
        """

        return self.context.view_rate_limits

    def identify_request(self) -> str:
        """
        Returns the identity of the request (by default this is the :attr:`flask.Request.endpoint`
        associated by the view function that is handling the request). The behavior can be customized
        by initializing the extension with a callable argument for
        :paramref:`~flask_limiter.Limiter.request_identifier`.
        """

        if self.initialized and self.enabled:
            assert self._request_identifier

            return self._request_identifier()

        return ""

    def __check_conditional_deductions(self, response: flask.wrappers.Response) -> None:
        for lim, args in self.context.conditional_deductions.items():
            if lim.deduct_when and lim.deduct_when(response):
                try:
                    self.limiter.hit(lim.limit, *args, cost=lim.deduction_amount)
                except Exception as err:
                    if self._swallow_errors:
                        self.logger.exception("Failed to deduct rate limit. Swallowing error")
                    else:
                        raise err

    def __inject_headers(self, response: flask.wrappers.Response) -> flask.wrappers.Response:
        self.__check_conditional_deductions(response)
        header_limit = self.current_limit

        if self.enabled and self._headers_enabled and header_limit and self._header_mapping:
            try:
                reset_at = header_limit.reset_at
                response.headers.add(
                    self._header_mapping[HeaderNames.LIMIT],
                    str(header_limit.limit.amount),
                )
                response.headers.add(
                    self._header_mapping[HeaderNames.REMAINING],
                    str(header_limit.remaining),
                )
                response.headers.add(self._header_mapping[HeaderNames.RESET], str(reset_at))

                # response may have an existing retry after
                existing_retry_after_header = response.headers.get("Retry-After")

                if existing_retry_after_header is not None:
                    # might be in http-date format
                    retry_after: float | datetime.datetime | None = parse_date(
                        existing_retry_after_header
                    )

                    # parse_date failure returns None

                    if retry_after is None:
                        retry_after = time.time() + int(existing_retry_after_header)

                    if isinstance(retry_after, datetime.datetime):
                        retry_after = time.mktime(retry_after.timetuple())

                    reset_at = max(int(retry_after), reset_at)

                # set the header instead of using add
                response.headers.set(
                    self._header_mapping[HeaderNames.RETRY_AFTER],
                    str(
                        http_date(reset_at)
                        if self._retry_after == "http-date"
                        else int(reset_at - time.time())
                    ),
                )
            except Exception as e:  # noqa: E722
                if self._in_memory_fallback_enabled and not self._storage_dead:
                    self.logger.warning(
                        "Rate limit storage unreachable - falling back to in-memory storage"
                    )
                    self._storage_dead = True
                    response = self.__inject_headers(response)
                else:
                    if self._swallow_errors:
                        self.logger.exception(
                            "Failed to update rate limit headers. Swallowing error"
                        )
                    else:
                        raise e

        return response

    def __check_all_limits_exempt(
        self,
        endpoint: str | None,
    ) -> bool:
        return bool(
            not endpoint
            or not (self.enabled and self.initialized)
            or endpoint.split(".")[-1] == "static"
            or any(fn() for fn in self._request_filters)
        )

    def __filter_limits(
        self,
        endpoint: str | None,
        blueprint: str | None,
        callable_name: str | None,
        in_middleware: bool = False,
    ) -> list[RuntimeLimit]:
        if callable_name:
            name = callable_name
        else:
            view_func = flask.current_app.view_functions.get(endpoint or "", None)
            name = get_qualified_name(view_func) if view_func else ""

        if self.__check_all_limits_exempt(endpoint):
            return []

        marked_for_limiting = name in self._marked_for_limiting or self.limit_manager.has_hints(
            endpoint or ""
        )
        fallback_limits = []

        if self._storage_dead and self._fallback_limiter:
            if in_middleware and name in self._marked_for_limiting:
                pass
            else:
                if self.__should_check_backend() and self._storage and self._storage.check():
                    self.logger.info("Rate limit storage recovered")
                    self._storage_dead = False
                    self.__check_backend_count = 0
                else:
                    fallback_limits = list(itertools.chain(*self._in_memory_fallback))

        if fallback_limits:
            return fallback_limits

        defaults, decorated = self.limit_manager.resolve_limits(
            flask.current_app,
            endpoint,
            blueprint,
            name,
            in_middleware,
            marked_for_limiting,
        )
        limits = OrderedSet(defaults) - self.context.seen_limits
        self.context.seen_limits.update(defaults)

        return list(limits) + list(decorated)

    def __evaluate_limits(self, endpoint: str, limits: list[RuntimeLimit]) -> None:
        failed_limits: list[tuple[RuntimeLimit, list[str]]] = []
        limit_for_header: RequestLimit | None = None
        view_limits: list[RequestLimit] = []
        meta_limits = [
            meta_limit
            for meta_limit in itertools.chain(
                *self._meta_limits,
                *[limit.meta_limits for limit in limits if limit.meta_limits],
            )
            if not meta_limit.is_exempt
        ]
        if not (
            ExemptionScope.META
            & self.limit_manager.exemption_scope(
                flask.current_app, endpoint, flask.request.blueprint
            )
        ):
            for lim in meta_limits:
                limit_key, scope = lim.key_func(), lim.scope_for(endpoint, None)
                args = [limit_key, scope]
                on_breach = lim.on_breach or self._on_meta_breach
                if not self.limiter.test(lim.limit, *args, cost=lim.deduction_amount):
                    breached_meta_limit = RequestLimit(self, lim.limit, args, True, lim.shared)
                    self.context.view_rate_limit = breached_meta_limit
                    self.context.view_rate_limits = [breached_meta_limit]
                    meta_breach_response = None

                    if on_breach:
                        try:
                            cb_response = on_breach(breached_meta_limit)

                            if isinstance(cb_response, flask.wrappers.Response):
                                meta_breach_response = cb_response
                        except Exception as err:  # noqa
                            if self._swallow_errors:
                                self.logger.exception(
                                    "on_meta_breach callback failed with error %s", err
                                )
                            else:
                                raise err
                    raise RateLimitExceeded(lim, response=meta_breach_response)

        # Limits that belong to a multi-dimensional declaration are always evaluated
        # together: one request must not be rejected by one dimension before the other
        # dimensions of the same declaration have been accounted. Plain limits keep
        # honoring ``fail_on_first_breach`` as before.
        multi_rule_ids = {lim.rule_id for lim in limits if lim.rule_id}
        stop_after_rule: str | None = None
        should_stop = False

        for lim in sorted(limits, key=lambda x: x.limit):
            if lim.is_exempt or lim.method_exempt:
                continue

            if stop_after_rule is not None:
                if lim.rule_id != stop_after_rule:
                    continue

            limit_scope = lim.scope_for(endpoint, flask.request.method)
            limit_key = lim.key_func()
            args = [limit_key, limit_scope]
            kwargs = {}

            if not all(args):
                self.logger.error(f"Skipping limit: {lim.limit}. Empty value found in parameters.")

                continue

            if self._key_prefix:
                args = [self._key_prefix, *args]

            if lim.deduct_when:
                self.context.conditional_deductions[lim] = args
                method = self.limiter.test
            else:
                method = self.limiter.hit
            kwargs["cost"] = lim.deduction_amount

            request_limit = RequestLimit(
                self,
                lim.limit,
                args,
                False,
                lim.shared,
                rule_id=lim.rule_id,
                dimension=lim.dimension,
                source=lim,
            )
            view_limits.append(request_limit)

            if not method(lim.limit, *args, **kwargs):
                self.logger.info(
                    "ratelimit %s (%s) exceeded at endpoint: %s",
                    lim.limit,
                    limit_key,
                    limit_scope,
                )
                failed_limits.append((lim, args))
                view_limits[-1].breached = True
                limit_for_header = view_limits[-1]

                if self._fail_on_first_breach:
                    if lim.rule_id in multi_rule_ids:
                        stop_after_rule = lim.rule_id
                    else:
                        should_stop = True

            if should_stop:
                break

        if not limit_for_header and view_limits:
            # Pick a non shared limit over a shared one if possible
            # when no rate limit has been hit. This should be the best hint
            # for the client.
            explicit = [limit for limit in view_limits if not limit.shared]
            candidates = explicit or view_limits
            dimensional = [limit for limit in candidates if limit.rule_id]

            if dimensional:
                # For a multi-dimensional declaration the client should be told about
                # the tightest budget instead of whichever dimension was declared
                # first. The rejection itself still identifies the breached dimension.
                limit_for_header = min(dimensional, key=lambda limit: limit.remaining)
            else:
                limit_for_header = candidates[0]

        self.context.view_rate_limit = limit_for_header or None
        self.context.view_rate_limits = view_limits

        on_breach_response = None

        for request_limit in view_limits:
            if not request_limit.breached:
                continue

            lim = request_limit.source

            if lim is None:
                continue

            for cb in dict.fromkeys([self._on_breach, lim.on_breach]):
                if cb:
                    try:
                        cb_response = cb(request_limit)

                        if isinstance(cb_response, flask.wrappers.Response):
                            on_breach_response = cb_response
                    except Exception as err:  # noqa
                        if self._swallow_errors:
                            self.logger.exception("on_breach callback failed with error %s", err)
                        else:
                            raise err

        if failed_limits:
            meta_limits = [
                meta_limit
                for meta_limit in itertools.chain(
                    *self._meta_limits,
                    *[list(lim[0].meta_limits) for lim in failed_limits if lim[0].meta_limits],
                )
                if not meta_limit.is_exempt
            ]
            for lim in meta_limits:
                limit_scope = lim.scope_for(endpoint, flask.request.method)
                limit_key = lim.key_func()
                args = [limit_key, limit_scope]
                self.limiter.hit(lim.limit, *args)
            raise RateLimitExceeded(
                sorted(failed_limits, key=lambda x: x[0].limit)[0][0],
                response=on_breach_response,
                # Snapshot the evaluated limits: ``view_limits`` is the list stored on
                # the request context and is cleared on teardown.
                limits=list(view_limits),
            )

    def _check_request_limit(
        self, callable_name: str | None = None, in_middleware: bool = True
    ) -> None:
        endpoint = self.identify_request()
        try:
            all_limits = self.__filter_limits(
                endpoint,
                flask.request.blueprint,
                callable_name,
                in_middleware,
            )
            self.__evaluate_limits(endpoint, all_limits)
        except Exception as e:
            if isinstance(e, RateLimitExceeded):
                raise e

            if self._in_memory_fallback_enabled and not self._storage_dead:
                self.logger.warning(
                    "Rate limit storage unreachable - falling back to in-memory storage"
                )
                self._storage_dead = True
                self.context.seen_limits.clear()
                self._check_request_limit(callable_name=callable_name, in_middleware=in_middleware)
            else:
                if self._swallow_errors:
                    self.logger.exception("Failed to rate limit. Swallowing error")
                else:
                    raise e

    def __release_context(self, _: BaseException | None = None) -> None:
        self.context.reset()
