"""Approved-scope views over token streams.

The parser owns the original :class:`~markdown_it.token.Token` tree.  Rendering
must never mutate that tree on behalf of a particular reader.  This module
creates a reusable, renderer-compatible projection containing only the tokens
and token components approved for an :class:`ApprovalScope`.

The projection contains real :class:`Token` objects, so existing render rules
and renderer subclasses keep their usual ``(tokens, idx, options, env)``
signature.  A projected token exposes only approved ``content``, ``attrs``,
``meta`` and ``children``; there is deliberately no back-reference to the
source token.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass, field
from enum import IntEnum
from types import MappingProxyType
from typing import Any, Literal, TypeAlias, overload

from .token import Token

SCOPE_ENV_KEY = "markdown_it.approval_scope"
"""Canonical ``env`` key containing the active :class:`ApprovalScope`."""

POLICY_ENV_KEY = "markdown_it.access_policy"
"""Canonical ``env`` key containing the active :class:`AccessPolicy`."""

ACCESS_META_KEY = "access"
"""Metadata key used by :func:`label_access`."""

_LEVEL_ALIASES: dict[str, int] = {
    "public": 0,
    "公开": 0,
    "internal": 1,
    "inner": 1,
    "内部": 1,
    "restricted": 2,
    "confidential": 3,
    "secret": 3,
    "机密": 3,
}


class AccessLevel(IntEnum):
    """Convenience ordered levels.

    Applications are not required to use these values; an ordered mapping of
    their own level names can be passed to :class:`ApprovalScope`.
    """

    PUBLIC = 0
    INTERNAL = 1
    RESTRICTED = 2
    CONFIDENTIAL = 3


LevelLike: TypeAlias = int | str | AccessLevel
ComponentName: TypeAlias = Literal[
    "token", "content", "attrs", "attr", "meta", "info", "markup", "map"
]
CanReadCallback: TypeAlias = Callable[["AccessRequest"], bool | None]


@dataclass(frozen=True)
class AccessRequirement:
    """Minimum clearance and optional named approvals for a component."""

    level: LevelLike = AccessLevel.PUBLIC
    scopes: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class AccessRequest:
    """Information passed to a custom :class:`AccessPolicy` callback."""

    component: str
    """Component kind, such as ``"token"``, ``"content"`` or ``"attr"``."""

    source: Token
    """The original token currently being projected.

    This is available to trusted policy code.  Render plugins receive the
    projected token instead, which has unapproved components removed.
    """

    scope: ApprovalScope
    """The reader scope requesting access."""

    name: str | None = None
    """Attribute or metadata key when :attr:`component` is ``"attr"``/``"meta"``."""

    requirement: AccessRequirement | None = None
    """The label discovered on the source component, if any."""


@dataclass(frozen=True)
class ApprovalScope:
    """The levels and named scopes approved for one rendering pass."""

    name: str = "reader"
    clearance: int = AccessLevel.PUBLIC
    approved_scopes: frozenset[str] = field(default_factory=frozenset)
    levels: Mapping[str, int] = field(
        default_factory=lambda: MappingProxyType(dict(_LEVEL_ALIASES))
    )
    redaction: str | None = None
    """Optional replacement for denied scalar content.

    ``None`` removes denied nodes/components or makes text empty.  A string is
    emitted as ordinary text and therefore escaped by the normal text renderer.
    """

    @classmethod
    def public(cls, *, redaction: str | None = None) -> ApprovalScope:
        return cls(name="public", clearance=0, redaction=redaction)

    @classmethod
    def internal(cls, *, redaction: str | None = None) -> ApprovalScope:
        return cls(name="internal", clearance=1, redaction=redaction)

    def __hash__(self) -> int:
        return hash(
            (
                self.name,
                self.clearance,
                self.approved_scopes,
                self.redaction,
            )
        )

    def rank(self, level: LevelLike) -> int:
        if isinstance(level, int):
            return int(level)
        normalized = str(level).strip().lower()
        if normalized in self.levels:
            return int(self.levels[normalized])
        if normalized in _LEVEL_ALIASES:
            return _LEVEL_ALIASES[normalized]
        try:
            return int(normalized)
        except ValueError as exc:
            raise ValueError(f"Unknown access level: {level!r}") from exc

    def allows(self, requirement: AccessRequirement | None) -> bool:
        if requirement is None:
            return True
        if self.rank(requirement.level) > self.clearance:
            return False
        return requirement.scopes <= self.approved_scopes

    def can_read(
        self,
        token: Token,
        component: str = "token",
        name: str | None = None,
        requirement: AccessRequirement | None = None,
        policy: AccessPolicy | None = None,
    ) -> bool:
        """Check a component using *policy* or the default metadata policy."""

        active_policy = policy or AccessPolicy()
        request = AccessRequest(
            component=component,
            source=token,
            scope=self,
            name=name,
            requirement=requirement,
        )
        return active_policy.allows(request)


@dataclass(frozen=True)
class AccessPolicy:
    """Resolve labels and decide whether an :class:`AccessRequest` is allowed.

    If *can_read* is supplied and returns a boolean, that decision wins.  It may
    return ``None`` to defer to the built-in level/scope label check.
    """

    can_read: CanReadCallback | None = None
    meta_keys: Sequence[str] = (
        ACCESS_META_KEY,
        "access_label",
        "access_level",
        "security",
        "security_level",
        "classification",
        "sensitivity",
        "clearance",
    )

    def allows(self, request: AccessRequest) -> bool:
        if self.can_read is not None:
            decision = self.can_read(request)
            if decision is not None:
                return decision
        return request.scope.allows(request.requirement)


DisplayPolicy = AccessPolicy
"""Descriptive alias for the display/approval policy."""

ScopePolicy = AccessPolicy


class TokenView(list[Token]):
    """A list of projected tokens with the scope used to create it."""

    def __init__(
        self,
        tokens: Sequence[Token],
        scope: ApprovalScope,
        policy: AccessPolicy,
    ) -> None:
        super().__init__(tokens)
        self.scope = scope
        self.policy = policy


ApprovedTokenView = TokenView
ScopedTokenView = TokenView


def coerce_scope(
    scope: ApprovalScope | LevelLike | Mapping[str, Any] | None = None,
    **kwargs: Any,
) -> ApprovalScope:
    """Coerce a level name, integer clearance, mapping or scope object."""

    if isinstance(scope, ApprovalScope):
        if not kwargs:
            return scope
        merged: dict[str, Any] = {
            "name": scope.name,
            "clearance": scope.clearance,
            "approved_scopes": scope.approved_scopes,
            "levels": scope.levels,
            "redaction": scope.redaction,
        }
        merged.update(kwargs)
        return ApprovalScope(**merged)

    options: dict[str, Any] = (
        dict(scope) if isinstance(scope, Mapping) else dict(kwargs)
    )

    if "approved" in options and "approved_scopes" not in options:
        approved = options.pop("approved")
        options["approved_scopes"] = frozenset(
            approved
            if isinstance(approved, set | frozenset | list | tuple)
            else [approved]
        )

    levels = options.get("levels", _LEVEL_ALIASES)
    level = options.pop("level", None)
    if level is not None and "clearance" not in options:
        options["clearance"] = (
            int(level)
            if isinstance(level, int)
            else int(levels[str(level).strip().lower()])
        )

    if isinstance(scope, int):
        options.setdefault("clearance", int(scope))
    elif isinstance(scope, str):
        options.setdefault("name", scope)
        options.setdefault("clearance", ApprovalScope().rank(scope))

    if scope is None and not options:
        return ApprovalScope.public()
    if scope is not None and not isinstance(scope, Mapping | str | int | ApprovalScope):
        raise TypeError(f"Unsupported approval scope: {scope!r}")
    return ApprovalScope(**options)


def coerce_requirement(value: Any) -> AccessRequirement | None:
    if value is None:
        return None
    if isinstance(value, AccessRequirement):
        return value
    if isinstance(value, Mapping):
        level = value.get(
            "level",
            value.get("min_level", value.get("clearance", AccessLevel.PUBLIC)),
        )
        scopes = value.get("scopes", value.get("approved_scopes", ()))
        if isinstance(scopes, str):
            scopes = (scopes,)
        return AccessRequirement(level=level, scopes=frozenset(scopes))
    return AccessRequirement(level=value)


def label_access(
    token: Token,
    default: Any | None = None,
    *,
    token_level: Any | None = None,
    content: Any | None = None,
    info: Any | None = None,
    markup: Any | None = None,
    map_level: Any | None = None,
    attrs: Mapping[str, Any] | None = None,
    meta: Mapping[str, Any] | None = None,
    fields: Mapping[str, Any] | None = None,
    scopes: str | Sequence[str] | None = None,
) -> Token:
    """Attach a built-in access label to *token* and return it.

    A scalar positional label applies to the whole token and all of its
    components.  Keyword labels can tighten individual components while the
    token itself remains renderable.
    """

    data: dict[str, Any] = {}
    if default is not None:
        data["default"] = _with_scopes(default, scopes)
    if token_level is not None:
        data["token"] = _with_scopes(token_level, scopes)
    if content is not None:
        data["content"] = _with_scopes(content, scopes)
    if info is not None:
        data["info"] = _with_scopes(info, scopes)
    if markup is not None:
        data["markup"] = _with_scopes(markup, scopes)
    if map_level is not None:
        data["map"] = _with_scopes(map_level, scopes)
    if attrs:
        data["attrs"] = {
            key: _with_scopes(value, scopes) for key, value in attrs.items()
        }
    if meta:
        data["meta"] = {key: _with_scopes(value, scopes) for key, value in meta.items()}
    if fields:
        data["fields"] = {
            key: _with_scopes(value, scopes) for key, value in fields.items()
        }
    token.meta[ACCESS_META_KEY] = data
    return token


def _with_scopes(value: Any, scopes: str | Sequence[str] | None) -> Any:
    if scopes is None:
        return value
    scope_set = {scopes} if isinstance(scopes, str) else set(scopes)
    if isinstance(value, Mapping):
        result = dict(value)
        existing = result.get("scopes", ())
        if isinstance(existing, str):
            existing = (existing,)
        result["scopes"] = frozenset(set(existing) | scope_set)
        return result
    return {"level": value, "scopes": frozenset(scope_set)}


def _access_data(token: Token, policy: AccessPolicy) -> Any:
    meta = token.meta
    if not isinstance(meta, Mapping):
        return None
    for key in policy.meta_keys:
        if key not in meta:
            continue
        value = meta[key]
        if key == ACCESS_META_KEY or key == "access_label":
            return value
        if key in {"access_level", "security_level"}:
            return {"default": value}
        if isinstance(value, Mapping):
            return value
        return {"default": value}
    return None


def _requirement_for(
    data: Any,
    component: str,
    name: str | None = None,
) -> AccessRequirement | None:
    if data is None:
        return None
    if not isinstance(data, Mapping):
        return coerce_requirement(data)

    if name is not None:
        group_name = "attrs" if component == "attr" else component
        group = data.get(group_name) or data.get(f"{group_name}s") or {}
        if isinstance(group, Mapping) and name in group:
            return coerce_requirement(group[name])
        default_key = f"{component}_default"
        if default_key in data:
            return coerce_requirement(data[default_key])

    fields = data.get("fields")
    if isinstance(fields, Mapping) and component in fields:
        return coerce_requirement(fields[component])
    if component in data:
        return coerce_requirement(data[component])
    if "default" in data:
        return coerce_requirement(data["default"])
    if "level" in data:
        return coerce_requirement(
            {"level": data["level"], "scopes": data.get("scopes", ())}
        )
    return None


def _allowed(
    token: Token,
    component: str,
    scope: ApprovalScope,
    policy: AccessPolicy,
    *,
    name: str | None = None,
    data: Any = None,
) -> bool:
    label_data = _access_data(token, policy) if data is None else data
    requirement = _requirement_for(label_data, component, name)
    return policy.allows(AccessRequest(component, token, scope, name, requirement))


def _skip_denied_range(tokens: Sequence[Token], start: int) -> int:
    token = tokens[start]
    if token.nesting != 1:
        return start + 1

    depth = 1
    index = start + 1
    while index < len(tokens):
        depth += tokens[index].nesting
        if depth == 0:
            return index + 1
        if depth < 0:
            return index
        index += 1
    return len(tokens)


def approved_view(
    tokens: Sequence[Token],
    scope: ApprovalScope | LevelLike | Mapping[str, Any] | None = None,
    *,
    policy: AccessPolicy | CanReadCallback | None = None,
    env: MutableMapping[str, Any] | None = None,
    **scope_kwargs: Any,
) -> TokenView:
    """Return a renderer-safe approved projection of *tokens*.

    The source tokens and their children, attrs and meta are not modified.
    """

    approval = coerce_scope(scope, **scope_kwargs)
    if callable(policy) and not isinstance(policy, AccessPolicy):
        active_policy = AccessPolicy(can_read=policy)
    else:
        active_policy = policy or AccessPolicy()

    view = _project_sequence(tokens, approval, active_policy)
    if env is not None:
        if not isinstance(env, MutableMapping):
            raise TypeError("env must be a MutableMapping, not " + type(env).__name__)
        env[SCOPE_ENV_KEY] = approval
        env["approval_scope"] = approval
        env["access_scope"] = approval
        env[POLICY_ENV_KEY] = active_policy
        env["access_policy"] = active_policy
    return view


scoped_view = approved_view
"""Conventional alias for :func:`approved_view`."""


def _project_sequence(
    tokens: Sequence[Token] | None,
    scope: ApprovalScope,
    policy: AccessPolicy,
) -> TokenView:
    projected: list[Token] = []
    if not tokens:
        return TokenView(projected, scope, policy)

    index = 0
    while index < len(tokens):
        token = tokens[index]
        data = _access_data(token, policy)
        if not _allowed(token, "token", scope, policy, data=data):
            if scope.redaction is not None and token.nesting >= 0:
                projected.append(_redaction_token(token, scope))
            index = _skip_denied_range(tokens, index)
            continue
        projected.append(_project_token(token, scope, policy, data))
        index += 1

    return TokenView(projected, scope, policy)


def _denied_scalar(scope: ApprovalScope) -> str:
    return scope.redaction if scope.redaction is not None else ""


def _redaction_token(source: Token, scope: ApprovalScope) -> Token:
    return Token(
        type="text",
        tag="",
        nesting=0,
        content=_denied_scalar(scope),
        map=source.map,
        level=source.level,
        block=source.block,
        meta={},
    )


def _project_token(
    token: Token,
    scope: ApprovalScope,
    policy: AccessPolicy,
    data: Any,
) -> Token:
    view = token.copy(attrs={}, meta={}, children=None)

    if _allowed(token, "content", scope, policy, data=data):
        view.content = token.content
    else:
        view.content = _denied_scalar(scope)

    if _allowed(token, "info", scope, policy, data=data):
        view.info = token.info
    if _allowed(token, "markup", scope, policy, data=data):
        view.markup = token.markup
    if _allowed(token, "map", scope, policy, data=data):
        view.map = token.map
    else:
        view.map = None

    view.attrs = {}
    for key, value in token.attrItems():
        if _allowed(token, "attr", scope, policy, name=key, data=data):
            view.attrs[key] = value

    view.meta = {}
    for key, value in token.meta.items():
        if key in policy.meta_keys:
            continue
        if _allowed(token, "meta", scope, policy, name=key, data=data):
            view.meta[key] = value

    if token.children is not None:
        view.children = _project_sequence(token.children, scope, policy)

    if token.type == "image":
        # ``alt`` is derived from ``children`` by RendererHTML.image.  Discard
        # any value left by an earlier higher-clearance render so custom image
        # rules cannot read stale derived text either.
        view.attrs["alt"] = ""

    return view


def scope_from_env(env: Mapping[str, Any] | None) -> ApprovalScope | None:
    """Return the active scope installed by :func:`approved_view`, if any."""

    if not env:
        return None
    value = (
        env.get(SCOPE_ENV_KEY) or env.get("approval_scope") or env.get("access_scope")
    )
    return value if isinstance(value, ApprovalScope) else coerce_scope(value)


@overload
def view_for_env(
    tokens: None,
    env: Mapping[str, Any] | None,
) -> None: ...


@overload
def view_for_env(
    tokens: Sequence[Token],
    env: Mapping[str, Any] | None,
) -> Sequence[Token]: ...


def view_for_env(
    tokens: Sequence[Token] | None,
    env: Mapping[str, Any] | None,
) -> Sequence[Token] | None:
    """Project raw *tokens* when *env* declares an approval scope.

    Existing :class:`TokenView` instances already have the correct scope and are
    returned unchanged.  This is a defence-in-depth sink for derived text, such
    as image alt, when a rule passes a raw child sequence to a renderer helper.
    """

    if tokens is None:
        return None
    scope = scope_from_env(env)
    if scope is None:
        return tokens
    if isinstance(tokens, TokenView) and tokens.scope == scope:
        return tokens

    policy_value = None
    if env:
        policy_value = env.get(POLICY_ENV_KEY) or env.get("access_policy")
    policy = policy_value if isinstance(policy_value, AccessPolicy) else None
    return approved_view(tokens, scope, policy=policy)


def approved_components(token: Token) -> Mapping[str, Any]:
    """Return a read-only mapping of the ingredients render plugins may use.

    For a token received from :func:`approved_view`, these are exactly the
    approved components.  The mapping is intended for plugins that want to
    expose their inputs in auxiliary output or diagnostics.
    """

    return MappingProxyType(
        {
            "type": token.type,
            "tag": token.tag,
            "nesting": token.nesting,
            "level": token.level,
            "attrs": MappingProxyType(dict(token.attrs)),
            "content": token.content,
            "children": tuple(token.children or ()),
            "meta": MappingProxyType(dict(token.meta)),
            "markup": token.markup,
            "info": token.info,
            "map": token.map,
            "block": token.block,
            "hidden": token.hidden,
        }
    )
