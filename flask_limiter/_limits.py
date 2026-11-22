from __future__ import annotations

import dataclasses
import itertools
import traceback
import weakref
from functools import wraps
from types import TracebackType
from typing import TYPE_CHECKING, cast, overload

import flask
from flask import request
from flask.wrappers import Response
from limits import RateLimitItem, parse_many
from limits.errors import ConfigurationError

from ._typing import Callable, Iterable, Iterator, P, R, Self, Sequence
from .util import get_qualified_name

if TYPE_CHECKING:
    from flask_limiter import Limiter, RequestLimit


@dataclasses.dataclass(eq=True, unsafe_hash=True)
class RuntimeLimit:
    """
    Final representation of a rate limit before it is triggered during a request
    """

    limit: RateLimitItem
    key_func: Callable[[], str]
    scope: str | Callable[[str], str] | None
    per_method: bool = False
    methods: Sequence[str] | None = None
    error_message: str | Callable[[], str] | None = None
    exempt_when: Callable[[], bool] | None = None
    override_defaults: bool | None = False
    deduct_when: Callable[[Response], bool] | None = None
    on_breach: Callable[[RequestLimit], Response | None] | None = None
    cost: Callable[[], int] | int = 1
    shared: bool = False
    meta_limits: tuple[RuntimeLimit, ...] | None = None
    #: Identity of the declared rule that produced this runtime limit.
    #:
    #: All dimensions of the same :class:`MultiLimit` share one rule identity so that a
    #: single request can be attributed to the declaration that rejected it (while each
    #: dimension is still counted in its own storage key).
    rule_id: str | None = None
    #: Name of the dimension this runtime limit accounts for (e.g. ``"employee"``).
    dimension: str | None = None
    #: Name of the rule declaration this limit belongs to.
    rule_name: str | None = None

    def __post_init__(self) -> None:
        if self.methods:
            self.methods = tuple([k.lower() for k in self.methods])

    @property
    def is_exempt(self) -> bool:
        """Check if the limit is exempt."""

        if self.exempt_when:
            return self.exempt_when()

        return False

    @property
    def deduction_amount(self) -> int:
        """How much to deduct from the limit"""

        return self.cost() if callable(self.cost) else self.cost

    @property
    def method_exempt(self) -> bool:
        """Check if the limit is not applicable for this method"""

        return self.methods is not None and request.method.lower() not in self.methods

    def scope_for(self, endpoint: str, method: str | None) -> str:
        """
        Derive final bucket (scope) for this limit given the endpoint and request method.
        If the limit is shared between multiple routes, the scope does not include the endpoint.
        """
        limit_scope = self.scope(request.endpoint or "") if callable(self.scope) else self.scope

        if limit_scope:
            if self.shared:
                scope = limit_scope
            else:
                scope = f"{endpoint}:{limit_scope}"
        else:
            scope = endpoint

        if self.per_method:
            assert method
            scope += f":{method.upper()}"

        # Dimensions of a multi-dimensional limit always keep their own storage
        # namespace, even when two business identities happen to have the same
        # string value (for example an employee id and a project id).
        if self.dimension:
            scope += f":dimension={self.dimension}"

        return scope


@dataclasses.dataclass(eq=True, unsafe_hash=True)
class Limit:
    """
    The definition of a rate limit to be used by the extension as a default limit::


        def default_key_function():
            return request.remote_addr

        def username_key_function():
            return request.headers.get("username", "guest")

        limiter = flask_limiter.Limiter(
            default_key_function,
            default_limits = [
                # 10/second by username
                flask_limiter.Limit("10/second", key_function=username_key_function),
                # 100/second by ip (i.e. default_key_function)
                flask_limiter.Limit("100/second),

            ]
        )
        limit.init_app(app)

    - For application wide limits see :class:`ApplicationLimit`
    - For meta limits see :class:`MetaLimit`
    """

    #: Rate limit string or a callable that returns a string.
    #:  :ref:`ratelimit-string` for more details.
    limit_provider: Callable[[], str] | str
    #: Callable to extract the unique identifier for the rate limit.
    #: If not provided the key_function will default to the key function
    #: that the :class:`Limiter` was initialized with (:paramref:`Limiter.key_func`)
    key_function: Callable[[], str] | None = None
    #: A string or callable that returns a unique scope for the rate limit.
    #: The scope is combined with current endpoint of the request if
    #: :paramref:`shared` is ``False``
    scope: str | Callable[[str], str] | None = None
    #: The cost of a hit or a function that
    #: takes no parameters and returns the cost as an integer (Default: ``1``).
    cost: Callable[[], int] | int | None = None
    #: If this a shared limit (i.e. to be used by different endpoints)
    shared: bool = False
    #: If specified, only the methods in this list will
    #: be rate limited.
    methods: Sequence[str] | None = None
    #: Whether the limit is sub categorized into the
    #: http method of the request.
    per_method: bool = False
    #: String (or callable that returns one) to override
    #: the error message used in the response.
    error_message: str | Callable[[], str] | None = None
    #: Meta limits to trigger everytime this rate limit definition is exceeded
    meta_limits: Iterable[Callable[[], str] | str | MetaLimit] | None = None
    #: Callable used to decide if the rate
    #: limit should skipped.
    exempt_when: Callable[[], bool] | None = None
    #: A function that receives the current
    #: :class:`flask.Response` object and returns True/False to decide if a
    #: deduction should be done from the rate limit
    deduct_when: Callable[[Response], bool] | None = None
    #: A function that will be called when this limit
    #: is breached. If the function returns an instance of :class:`flask.Response`
    #: that will be the response embedded into the :exc:`RateLimitExceeded` exception
    #: raised.
    on_breach: Callable[[RequestLimit], Response | None] | None = None
    #: Whether the decorated limit overrides
    #: the default limits (Default: ``True``).
    #:
    #: .. note:: When used with a :class:`~flask.Blueprint` the meaning
    #:    of the parameter extends to any parents the blueprint instance is
    #:    registered under. For more details see :ref:`recipes:nested blueprints`
    #:
    #: :meta private:
    override_defaults: bool | None = dataclasses.field(default=False, init=False)
    #: Weak reference to the limiter that this limit definition is bound to
    #:
    #: :meta private:
    limiter: weakref.ProxyType[Limiter] = dataclasses.field(
        init=False, hash=False, kw_only=True, repr=False
    )
    #: :meta private:
    finalized: bool = dataclasses.field(default=True)

    def __post_init__(self) -> None:
        if self.methods:
            self.methods = tuple([k.lower() for k in self.methods])

        if self.meta_limits:
            self.meta_limits = tuple(self.meta_limits)

    def __iter__(self) -> Iterator[RuntimeLimit]:
        limit_str = self.limit_provider() if callable(self.limit_provider) else self.limit_provider
        limit_items = parse_many(limit_str) if limit_str else []
        meta_limits: tuple[RuntimeLimit, ...] = ()

        if self.meta_limits:
            meta_limits = tuple(
                itertools.chain(
                    *[
                        list(
                            MetaLimit(meta_limit).bind_parent(self)
                            if not isinstance(meta_limit, MetaLimit)
                            else meta_limit
                        )
                        for meta_limit in self.meta_limits
                    ]
                )
            )

        for limit in limit_items:
            yield RuntimeLimit(
                limit,
                self.limit_by,
                scope=self.scope,
                per_method=self.per_method,
                methods=self.methods,
                error_message=self.error_message,
                exempt_when=self.exempt_when,
                deduct_when=self.deduct_when,
                override_defaults=self.override_defaults,
                on_breach=self.on_breach,
                cost=self.cost or 1,
                shared=self.shared,
                meta_limits=meta_limits,
            )

    @property
    def limit_by(self) -> Callable[[], str]:
        return self.key_function or self.limiter._key_func

    def bind(self: Self, limiter: Limiter) -> Self:
        """
        Returns an instance of the limit definition that binds to a weak reference of an instance
        of :class:`Limiter`.

        :meta private:
        """
        self.limiter = weakref.proxy(limiter)
        [
            meta_limit.bind(limiter)
            for meta_limit in self.meta_limits or ()
            if isinstance(meta_limit, MetaLimit)
        ]

        return self


@dataclasses.dataclass(unsafe_hash=True, kw_only=True)
class RouteLimit(Limit):
    """
    A variant of :class:`Limit` that can be used to to decorate a flask route or blueprint directly
    instead of by using :meth:`Limiter.limit` or :meth:`Limiter.shared_limit`.

    Decorating individual routes::

        limiter = flask_limiter.Limiter(.....)
        limiter.init_app(app)

        @app.route("/")
        @flask_limiter.RouteLimit("2/second", limiter=limiter)
        def view_function():
            ...

    """

    #: Whether the decorated limit overrides
    #: the default limits (Default: ``True``).
    #:
    #: .. note:: When used with a :class:`~flask.Blueprint` the meaning
    #:    of the parameter extends to any parents the blueprint instance is
    #:    registered under. For more details see :ref:`recipes:nested blueprints`
    override_defaults: bool | None = False

    limiter: dataclasses.InitVar[Limiter] = dataclasses.field(hash=False)

    def __post_init__(self, limiter: Limiter) -> None:
        self.bind(limiter)
        super().__post_init__()

    def __enter__(self) -> None:
        tb = traceback.extract_stack(limit=2)
        qualified_location = f"{tb[0].filename}:{tb[0].name}:{tb[0].lineno}"

        # TODO: if use as a context manager becomes interesting/valuable
        #  a less hacky approach than using the traceback and piggy backing
        #  on the limit manager's knowledge of decorated limits might be worth it.
        self.limiter.limit_manager.add_decorated_limit(qualified_location, self, override=True)

        self.limiter.limit_manager.add_endpoint_hint(
            self.limiter.identify_request(), qualified_location
        )

        self.limiter._check_request_limit(in_middleware=False, callable_name=qualified_location)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...

    @overload
    def __call__(self, obj: Callable[P, R]) -> Callable[P, R]: ...

    @overload
    def __call__(self, obj: flask.Blueprint) -> None: ...

    def __call__(self, obj: Callable[P, R] | flask.Blueprint) -> Callable[P, R] | None:
        if isinstance(obj, flask.Blueprint):
            name = obj.name
        else:
            name = get_qualified_name(obj)

        if isinstance(obj, flask.Blueprint):
            self.limiter.limit_manager.add_blueprint_limit(name, self)

            return None
        else:
            self.limiter._marked_for_limiting.add(name)
            self.limiter.limit_manager.add_decorated_limit(name, self)

            @wraps(obj)
            def __inner(*a: P.args, **k: P.kwargs) -> R:
                if not getattr(obj, "__wrapper-limiter-instance", None) == self.limiter:
                    identity = self.limiter.identify_request()

                    if identity:
                        view_func = flask.current_app.view_functions.get(identity, None)

                        if view_func and not get_qualified_name(view_func) == name:
                            self.limiter.limit_manager.add_endpoint_hint(identity, name)

                    self.limiter._check_request_limit(in_middleware=False, callable_name=name)

                return cast(R, flask.current_app.ensure_sync(obj)(*a, **k))

            # mark this wrapper as wrapped by a decorator from the limiter
            # from which the decorator was created. This ensures that stacked
            # decorations only trigger rate limiting from the inner most
            # decorator from each limiter instance (the weird need for
            # keeping track of the instance is to handle cases where multiple
            # limiter extensions are registered on the same application).
            setattr(__inner, "__wrapper-limiter-instance", self.limiter)

            return __inner


@dataclasses.dataclass(unsafe_hash=True, kw_only=True)
class MultiLimit(RouteLimit):
    """
    A declaration of several independent budgets that are all evaluated for the same
    request, each one keyed by its own business identity.

    :meth:`Limiter.limit` evaluates every rule with the same key function, which makes
    it unsuitable when one request must be counted in more than one domain (for
    example once per employee and once per project). A :class:`MultiLimit` accepts a
    sequence of ``(dimension, budget)`` pairs. Every pair becomes its own rate limit
    rule with its own key and scope, while all of them still belong to one declaration
    so the request can report which rule rejected it::

        submit_limit = limiter.multi_limit(
            [
                ("employee", "5/hour", lambda: g.employee_id),
                ("project", "20/hour", lambda: g.project_id),
            ],
            scope="per-identity",
        )

        @app.post("/claims")
        @submit_limit
        def submit():
            ...

    Dimensions without a resolvable identity (for example a project that the
    authenticated employee cannot access) can be declared with ``when``. Such a
    dimension is skipped instead of being counted into a shared/fallback bucket, and
    the remaining dimensions continue to be accounted normally::

        ("project", "20/hour", project_key, project_is_authorized)

    ``key_func`` is only used as the default identity for dimensions declared without
    one. It is never evaluated when every dimension provides its own key function.
    """

    #: Optional human readable name for this declaration. It is reported by
    #: :attr:`~flask_limiter.RateLimitExceeded.rejected_rule` so an application can
    #: tell which declaration rejected the request. Defaults to a generated id.
    name: str | None = None
    #: A declared ``scope`` is shared between all routes using this declaration,
    #: mirroring :meth:`Limiter.shared_limit`. Without a ``scope`` every route keeps
    #: its own bucket.
    shared: bool = True
    #: ``(dimension_name, rate_limit, key_func?, when?)`` declarations.
    dimensions: Sequence[
        tuple[str, "str | Callable[[], str]"]
        | tuple[str, "str | Callable[[], str]", "Callable[[], str] | None"]
        | tuple[
            str,
            "str | Callable[[], str]",
            "Callable[[], str] | None",
            "Callable[[], bool] | None",
        ]
    ] = ()

    def __post_init__(self, limiter: Limiter) -> None:
        self.dimensions = tuple(self.dimensions)

        for dimension in self.dimensions:
            if not 2 <= len(dimension) <= 4 or not dimension[0]:
                raise ConfigurationError(
                    "Each multi-dimensional limit must be declared as "
                    "'(name, rate_limit, key_func?, when?)' with a non-empty name."
                )

        super().__post_init__(limiter)

    def _exempt_when_for(
        self, enabled_when: Callable[[], bool] | None
    ) -> Callable[[], bool] | None:
        """
        Combine a dimension's ``when`` predicate with the declaration's ``exempt_when``.

        :meta private:
        """
        if enabled_when is None:
            return self.exempt_when

        exempt = self.exempt_when

        if exempt is None:

            def dimension_disabled() -> bool:
                return not enabled_when()

            return dimension_disabled

        def dimension_disabled_or_exempt() -> bool:
            return not enabled_when() or exempt()

        return dimension_disabled_or_exempt

    def __iter__(self) -> Iterator[RuntimeLimit]:  # type: ignore[override]
        meta_limits: tuple[RuntimeLimit, ...] = ()

        if self.meta_limits:
            meta_limits = tuple(
                itertools.chain(
                    *[
                        list(
                            MetaLimit(meta_limit).bind_parent(self)
                            if not isinstance(meta_limit, MetaLimit)
                            else meta_limit
                        )
                        for meta_limit in self.meta_limits
                    ]
                )
            )

        rule_id = f"multi_limit:{id(self)}"
        rule_name = self.name or rule_id

        for dimension in self.dimensions:
            name, limit_provider, *rest = dimension
            key_function = rest[0] if rest else None
            enabled_when = rest[1] if len(rest) > 1 else None
            limit_str = limit_provider() if callable(limit_provider) else limit_provider
            limit_items = parse_many(limit_str) if limit_str else []
            # ``when`` decides whether the dimension applies; ``exempt_when`` skips a
            # limit. Invert the predicate so that the dimension is skipped when the
            # application says it does not apply, without losing a global exemption.
            exempt_when = self._exempt_when_for(enabled_when)

            for limit in limit_items:
                yield RuntimeLimit(
                    limit,
                    key_function or self.limit_by,
                    scope=self.scope,
                    per_method=self.per_method,
                    methods=self.methods,
                    error_message=self.error_message,
                    exempt_when=exempt_when,
                    deduct_when=self.deduct_when,
                    override_defaults=self.override_defaults,
                    on_breach=self.on_breach,
                    cost=self.cost or 1,
                    shared=self.shared,
                    meta_limits=meta_limits,
                    rule_id=rule_id,
                    rule_name=rule_name,
                    dimension=name,
                )


@dataclasses.dataclass(kw_only=True, unsafe_hash=True)
class ApplicationLimit(Limit):
    """
    Variant of :class:`Limit` to be used for declaring an application wide limit that can be passed
    to :class:`Limiter` as one of the members of :paramref:`Limiter.application_limits`
    """

    #: The scope to use for the application wide limit
    scope: str | Callable[[str], str] | None = dataclasses.field(default="global")
    #: Application limits are always "shared"
    #:
    #: :meta private:
    shared: bool = dataclasses.field(init=False, default=True)


@dataclasses.dataclass(kw_only=True, unsafe_hash=True)
class MetaLimit(Limit):
    """
    Variant of :class:`Limit` to be used for declaring a meta limit that can be passed to
    either :class:`Limiter` as one of the  members of :paramref:`Limiter.meta_limits` or to another
    instance of :class:`Limit` as a member of :paramref:`Limit.meta_limits`
    """

    #: The scope to use for the meta limit
    scope: str | Callable[[str], str] | None = dataclasses.field(default="meta")
    #: meta limits can't have meta limits - at least here :)
    #:
    #: :meta private:
    meta_limits: Sequence[Callable[[], str] | str | MetaLimit] | None = dataclasses.field(
        init=False, default=None
    )
    #: The rate limit this meta limit is limiting.
    #:
    # :meta private:
    parent_limit: Limit | None = dataclasses.field(init=False, default=None)
    #: Meta limits are always "shared"
    #:
    #: :meta private:
    shared: bool = dataclasses.field(init=False, default=True)
    #: Meta limits can't have conditional deductions
    #:
    #: :meta private:
    deduct_when: Callable[[Response], bool] | None = dataclasses.field(init=False, default=None)
    #: Callable to extract the unique identifier for the rate limit.
    #: If not provided the key_function will fallback to:
    #:
    #: - the key function of the parent limit this meta limit is declared for
    #: - the key function for the :class:`Limiter` instance this meta limit
    #:   is eventually used with.
    key_function: Callable[[], str] | None = None

    @property
    def limit_by(self) -> Callable[[], str]:
        return (
            self.key_function
            or self.parent_limit
            and self.parent_limit.key_function
            or self.limiter._key_func
        )

    def bind_parent(self: Self, parent: Limit) -> Self:
        """
        Binds this meta limit to be associated as a child of the ``parent`` limit.

        :meta private:
        """
        self.parent_limit = parent
        return self
