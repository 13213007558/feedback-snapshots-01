"""Output access levels for schemas.

One schema can serve several audiences (internal services and third-party
consumers, for instance). This module adds *output levels* to the dump path so
that a single schema definition can emit either the full payload or a reduced
one containing only public data.

Rules
-----

1. Every field declares the minimum level it is visible at through the
   ``metadata={"access": AccessLevel.INTERNAL}`` entry. Fields without an entry
   default to :attr:`AccessLevel.PUBLIC`, so adding the mixin does not change
   the shape of existing payloads at the highest level.
2. Levels are ordered integers. A field with level ``n`` is emitted when the
   caller's level is greater than or equal to ``n`` and filtered otherwise.
3. Filtering runs on the *output* keys, so ``data_key`` aliases and the
   ``only``/``exclude`` projections keep working unchanged: projection first
   decides which fields are serialized, access control then decides which
   serialized keys survive.
4. The active level is propagated through :class:`contextvars.ContextVar`,
   which means nested :class:`AccessLevelSchema` instances (including
   ``Nested`` and ``List(Nested(...))``) apply the same level automatically.
   A nested schema may narrow the level further but never widen it.
5. Keys added by ``post_dump`` processors have no field declaration. Their
   origin and default handling are explicit:

   * keys registered on ``output_access`` are treated like declared fields,
     at the level they were registered with;
   * unregistered keys are treated as :attr:`AccessLevel.INTERNAL` by default
     and are therefore stripped from every non-internal response. The policy
     can be changed with the ``unregistered_output_policy`` class attribute to
     :attr:`UnregisteredOutputPolicy.RAISE` to fail loudly instead.

Filtering never changes a value; it only removes keys, so allowed fields keep
their current serialized representation.
"""

from __future__ import annotations

import contextvars
import enum
import typing

from marshmallow import Schema, post_dump
from marshmallow.exceptions import MarshmallowError

#: Access level in effect for the schema currently being serialized.
_CURRENT_ACCESS: contextvars.ContextVar[AccessLevel] = contextvars.ContextVar(
    "marshmallow_access_level"
)


class AccessLevel(enum.IntEnum):
    """Ordered output levels.

    Lower numbers are more restrictive. A field visible at
    :attr:`PUBLIC` is visible at every level above it.
    """

    PUBLIC = 10
    INTERNAL = 20


class UnregisteredOutputPolicy(enum.Enum):
    """How to treat post_dump keys that have no declared level."""

    #: Strip unregistered keys at every level below INTERNAL (default).
    DROP = "drop"
    #: Raise :class:`UnregisteredOutputError` instead of silently dropping.
    RAISE = "raise"


class UnregisteredOutputError(MarshmallowError):
    """Raised when a post_dump key has no registered output level.

    The offending key is stored on :attr:`key` so callers can register it on
    ``output_access`` or adjust the processor.
    """

    def __init__(self, key: str, schema_name: str) -> None:
        self.key = key
        self.schema_name = schema_name
        super().__init__(
            f"Key {key!r} added by a post_dump processor of {schema_name} "
            "has no registered output level."
        )


class AccessLevelSchema(Schema):
    """Schema base enforcing output access levels on dump.

    Subclass it directly or combine it through cooperative multiple
    inheritance::

        class AccountSchema(AccessLevelSchema, Schema):
            display_name = fields.String()
            email = fields.String(
                data_key="contactEmail",
                metadata={"access": AccessLevel.INTERNAL},
            )

    :cvar output_access: maps *output* keys (i.e. ``data_key`` aliases when
        used) to the minimum level they require. Use it to whitelist business
        fields added by ``post_dump``. Subclasses inherit and extend their
        parents' mappings.
    :cvar unregistered_output_policy: handling of output keys that are neither
        declared fields nor present in :attr:`output_access`.
    """

    output_access: typing.Mapping[str, AccessLevel] = {}
    unregistered_output_policy: UnregisteredOutputPolicy = UnregisteredOutputPolicy.DROP

    @classmethod
    def _merged_output_access(cls) -> dict[str, AccessLevel]:
        merged: dict[str, AccessLevel] = {}
        for base in reversed(cls.__mro__):
            mapping = getattr(base, "output_access", None)
            if mapping:
                merged.update(mapping)
        return merged

    @classmethod
    def _field_output_access(cls) -> dict[str, AccessLevel]:
        """Minimum level of every declared field, keyed by output key."""
        levels: dict[str, AccessLevel] = {}
        for field_name, field in cls._declared_fields.items():
            level = field.metadata.get("access", AccessLevel.PUBLIC)
            output_key = field.data_key if field.data_key is not None else field_name
            levels[output_key] = level
        return levels

    def dump(self, obj, *, many: bool | None = None, access: AccessLevel | None = None):
        """Serialize ``obj`` keeping only the keys allowed at ``access``.

        :param access: level of the caller. When ``None``, an active parent
            level is inherited; a top-level call without a parent runs at the
            highest level (:attr:`AccessLevel.INTERNAL`).
        """
        effective = self._effective_access(access)
        token = _CURRENT_ACCESS.set(effective)
        try:
            result = super().dump(obj, many=many)
        finally:
            _CURRENT_ACCESS.reset(token)
        return self._filter_output(result, effective)

    def dumps(self, obj, *args, many: bool | None = None, access=None, **kwargs):
        """Same as :meth:`dump`, returning a JSON-encoded string."""
        serialized = self.dump(obj, many=many, access=access)
        return self.opts.render_module.dumps(serialized, *args, **kwargs)

    def _effective_access(self, access: AccessLevel | None) -> AccessLevel:
        if access is None:
            return _CURRENT_ACCESS.get(AccessLevel.INTERNAL)
        # A nested schema may narrow the propagated level but never widen it.
        return min(access, _CURRENT_ACCESS.get(access))

    @post_dump
    def _strip_disallowed_items(self, data, **kwargs):
        # Per-item pass: runs before subclass post_dump processors, so keys
        # added by those processors are handled by the final dump() pass with
        # the unregistered-key policy. Marshmallow invokes this once per item
        # in many mode, so branch on the data shape rather than the many flag.
        access = _CURRENT_ACCESS.get(AccessLevel.INTERNAL)
        return self._filter_output(data, access)

    def _filter_output(self, data, access: AccessLevel):
        if isinstance(data, list):
            return [self._filter_mapping(item, access) for item in data]
        if isinstance(data, dict):
            return self._filter_mapping(data, access)
        # Envelopes or other non-mapping output cannot be key-filtered.
        return data

    def _filter_mapping(self, data: dict, access: AccessLevel) -> dict:
        field_levels = self._field_output_access()
        registered = self._merged_output_access()
        known = {**field_levels, **registered}
        filtered = self.dict_class()
        for key, value in data.items():
            if key in known:
                level = known[key]
            elif (
                self.unregistered_output_policy is UnregisteredOutputPolicy.RAISE
                and access < AccessLevel.INTERNAL
            ):
                # Only fail when the key would actually be removed; at the
                # highest level the default INTERNAL treatment still allows it.
                raise UnregisteredOutputError(key, type(self).__name__)
            else:
                level = AccessLevel.INTERNAL
            if access >= level:
                filtered[key] = value
        return filtered
