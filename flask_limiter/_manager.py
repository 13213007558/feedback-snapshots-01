from __future__ import annotations

import itertools
import logging
import threading
from collections.abc import Iterable
from typing import TYPE_CHECKING

import flask
from ordered_set import OrderedSet

from ._limits import ApplicationLimit, RuntimeLimit
from .constants import ExemptionScope
from .util import get_qualified_name

if TYPE_CHECKING:
    from . import Limit


class LimitManager:
    def __init__(
        self,
        application_limits: list[ApplicationLimit],
        default_limits: list[Limit],
        decorated_limits: dict[str, OrderedSet[Limit]],
        blueprint_limits: dict[str, OrderedSet[Limit]],
        route_exemptions: dict[str, ExemptionScope],
        blueprint_exemptions: dict[str, ExemptionScope],
    ) -> None:
        self._application_limits = application_limits
        self._default_limits = default_limits
        self._decorated_limits = decorated_limits
        self._blueprint_limits = blueprint_limits
        self._route_exemptions = route_exemptions
        self._blueprint_exemptions = blueprint_exemptions
        self._endpoint_hints: dict[str, OrderedSet[str]] = {}
        self._limits_lock = threading.RLock()
        self._logger = logging.getLogger("flask-limiter")

    @property
    def application_limits(self) -> list[RuntimeLimit]:
        with self._limits_lock:
            return list(itertools.chain(*self._application_limits))

    @property
    def default_limits(self) -> list[RuntimeLimit]:
        with self._limits_lock:
            return list(itertools.chain(*self._default_limits))

    def set_application_limits(self, limits: list[ApplicationLimit]) -> None:
        with self._limits_lock:
            self._application_limits = limits

    def set_default_limits(self, limits: list[Limit]) -> None:
        with self._limits_lock:
            self._default_limits = limits

    def set_limits(
        self,
        application_limits: list[ApplicationLimit] | None = None,
        default_limits: list[Limit] | None = None,
    ) -> None:
        """
        Replace the application and/or default limits as a single operation.

        A group passed as ``None`` is retained. Both groups that are provided
        are swapped while holding the same lock that guards reads in
        :meth:`snapshot_limit_groups`, so a request can never observe a state
        in which only one of the two groups was replaced.

        :meta private:
        """
        with self._limits_lock:
            if application_limits is not None:
                self._application_limits = application_limits
            if default_limits is not None:
                self._default_limits = default_limits

    def snapshot_limit_groups(self) -> tuple[list[ApplicationLimit], list[Limit]]:
        """
        Capture both limit groups from the same configuration generation.

        The groups are materialized (and dynamic providers evaluated) by the
        caller, outside the lock. This keeps the evaluation semantics of
        dynamic limits unchanged while guaranteeing that a single request is
        resolved against one consistent generation of the configuration.

        :meta private:
        """
        with self._limits_lock:
            return list(self._application_limits), list(self._default_limits)

    def add_decorated_limit(self, route: str, limit: Limit | None, override: bool = False) -> None:
        if limit:
            if not override:
                self._decorated_limits.setdefault(route, OrderedSet()).add(limit)
            else:
                self._decorated_limits[route] = OrderedSet([limit])

    def add_blueprint_limit(self, blueprint: str, limit: Limit | None) -> None:
        if limit:
            self._blueprint_limits.setdefault(blueprint, OrderedSet()).add(limit)

    def add_route_exemption(self, route: str, scope: ExemptionScope) -> None:
        self._route_exemptions[route] = scope

    def add_blueprint_exemption(self, blueprint: str, scope: ExemptionScope) -> None:
        self._blueprint_exemptions[blueprint] = scope

    def add_endpoint_hint(self, endpoint: str, callable: str) -> None:
        self._endpoint_hints.setdefault(endpoint, OrderedSet()).add(callable)

    def has_hints(self, endpoint: str) -> bool:
        return bool(self._endpoint_hints.get(endpoint))

    def resolve_limits(
        self,
        app: flask.Flask,
        endpoint: str | None = None,
        blueprint: str | None = None,
        callable_name: str | None = None,
        in_middleware: bool = False,
        marked_for_limiting: bool = False,
    ) -> tuple[list[RuntimeLimit], ...]:
        before_request_context = in_middleware and marked_for_limiting
        decorated_limits = []
        hinted_limits = []
        if endpoint:
            if not in_middleware:
                if not callable_name:
                    view_func = app.view_functions.get(endpoint, None)
                    name = get_qualified_name(view_func) if view_func else ""
                else:
                    name = callable_name
                decorated_limits.extend(self.decorated_limits(name))

            for hint in self._endpoint_hints.get(endpoint, OrderedSet()):
                hinted_limits.extend(self.decorated_limits(hint))

        if blueprint:
            if not before_request_context and (
                not decorated_limits
                or all(not limit.override_defaults for limit in decorated_limits)
            ):
                decorated_limits.extend(self.blueprint_limits(app, blueprint))
        exemption_scope = self.exemption_scope(app, endpoint, blueprint)
        application_groups, default_groups = self.snapshot_limit_groups()
        application_limits = list(itertools.chain(*application_groups))
        default_limits = list(itertools.chain(*default_groups))

        all_limits = (
            application_limits
            if in_middleware and not (exemption_scope & ExemptionScope.APPLICATION)
            else []
        )
        # all_limits += decorated_limits
        explicit_limits_exempt = all(limit.method_exempt for limit in decorated_limits)

        # all  the decorated limits explicitly declared
        # that they don't override the defaults - so, they should
        # be included.
        combined_defaults = all(not limit.override_defaults for limit in decorated_limits)
        # previous requests to this endpoint have exercised decorated
        # rate limits on callables that are not view functions. check
        # if all of them declared that they don't override defaults
        # and if so include the default limits.
        hinted_limits_request_defaults = (
            all(not limit.override_defaults for limit in hinted_limits) if hinted_limits else False
        )
        if (
            (explicit_limits_exempt or combined_defaults)
            and (not (before_request_context or exemption_scope & ExemptionScope.DEFAULT))
        ) or hinted_limits_request_defaults:
            all_limits += default_limits
        return all_limits, decorated_limits

    def exemption_scope(
        self, app: flask.Flask, endpoint: str | None, blueprint: str | None
    ) -> ExemptionScope:
        view_func = app.view_functions.get(endpoint or "", None)
        name = get_qualified_name(view_func) if view_func else ""
        route_exemption_scope = self._route_exemptions.get(name, ExemptionScope.NONE)
        blueprint_instance = app.blueprints.get(blueprint) if blueprint else None

        if not blueprint_instance:
            return route_exemption_scope
        else:
            assert blueprint
            (
                blueprint_exemption_scope,
                ancestor_exemption_scopes,
            ) = self._blueprint_exemption_scope(app, blueprint)
            if (
                blueprint_exemption_scope & ~(ExemptionScope.DEFAULT | ExemptionScope.APPLICATION)
                or ancestor_exemption_scopes
            ):
                for exemption in ancestor_exemption_scopes.values():
                    blueprint_exemption_scope |= exemption
            return route_exemption_scope | blueprint_exemption_scope

    def decorated_limits(self, callable_name: str) -> list[RuntimeLimit]:
        limits = []
        if not self._route_exemptions.get(callable_name, ExemptionScope.NONE):
            if callable_name in self._decorated_limits:
                for group in self._decorated_limits[callable_name]:
                    try:
                        for limit in group:
                            limits.append(limit)
                    except ValueError as e:
                        self._logger.error(
                            f"failed to load ratelimit for function {callable_name}: {e}",
                        )
        return limits

    def blueprint_limits(self, app: flask.Flask, blueprint: str) -> list[RuntimeLimit]:
        limits: list[RuntimeLimit] = []

        blueprint_instance = app.blueprints.get(blueprint) if blueprint else None
        if blueprint_instance:
            blueprint_name = blueprint_instance.name
            blueprint_ancestory = set(blueprint.split(".") if blueprint else [])

            self_exemption, ancestor_exemptions = self._blueprint_exemption_scope(app, blueprint)

            if not (self_exemption & ~(ExemptionScope.DEFAULT | ExemptionScope.APPLICATION)):
                blueprint_self_limits = self._blueprint_limits.get(blueprint_name, OrderedSet())
                blueprint_limits: Iterable[Limit] = (
                    itertools.chain(
                        *(
                            self._blueprint_limits.get(member, [])
                            for member in blueprint_ancestory.intersection(
                                self._blueprint_limits
                            ).difference(ancestor_exemptions)
                        )
                    )
                    if not (
                        blueprint_self_limits
                        and all(limit.override_defaults for limit in blueprint_self_limits)
                    )
                    and not self._blueprint_exemptions.get(blueprint_name, ExemptionScope.NONE)
                    & ExemptionScope.ANCESTORS
                    else blueprint_self_limits
                )
                if blueprint_limits:
                    for limit_group in blueprint_limits:
                        try:
                            limits.extend(
                                [
                                    RuntimeLimit(
                                        limit.limit,
                                        limit.key_func,
                                        limit.scope,
                                        limit.per_method,
                                        limit.methods,
                                        limit.error_message,
                                        limit.exempt_when,
                                        limit.override_defaults,
                                        limit.deduct_when,
                                        limit.on_breach,
                                        limit.cost,
                                        limit.shared,
                                    )
                                    for limit in limit_group
                                ]
                            )
                        except ValueError as e:
                            self._logger.error(
                                f"failed to load ratelimit for blueprint {blueprint_name}: {e}",
                            )
        return limits

    def _blueprint_exemption_scope(
        self, app: flask.Flask, blueprint_name: str
    ) -> tuple[ExemptionScope, dict[str, ExemptionScope]]:
        name = app.blueprints[blueprint_name].name
        exemption = self._blueprint_exemptions.get(name, ExemptionScope.NONE) & ~(
            ExemptionScope.ANCESTORS
        )

        ancestory = set(blueprint_name.split("."))
        ancestor_exemption = {
            k for k, f in self._blueprint_exemptions.items() if f & ExemptionScope.DESCENDENTS
        }.intersection(ancestory)

        return exemption, {
            k: self._blueprint_exemptions.get(k, ExemptionScope.NONE) for k in ancestor_exemption
        }
