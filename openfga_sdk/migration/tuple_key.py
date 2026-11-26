"""
Stable identity helpers for relationship tuples used during migration.

A tuple key is the unique identity of a stored relationship in OpenFGA:
the (user, relation, object) triple. Conditions are intentionally excluded
from the identity because two tuples sharing the same key cannot coexist
in a store, regardless of their condition.
"""

from collections.abc import Mapping

from openfga_sdk.client.models.tuple import ClientTuple


class TupleKeyError(ValueError):
    """Raised when a relationship tuple cannot produce a valid identity."""


def tuple_identity(tuple_key: ClientTuple | Mapping[str, str]) -> str:
    """
    Return a stable, order-independent string identity for a tuple key.

    The identity only covers user, relation and object, matching the unique
    constraint enforced by the OpenFGA store.
    """
    user = _field(tuple_key, "user")
    relation = _field(tuple_key, "relation")
    object_ = _field(tuple_key, "object")

    if not user or not relation or not object_:
        raise TupleKeyError(
            "tuple key requires non-empty user, relation and object fields"
        )

    return f"{object_}#{relation}@{user}"


def parse_tuple_identity(identity: str) -> tuple[str, str, str]:
    """
    Split an identity produced by :func:`tuple_identity` back into parts.

    :returns: A ``(object, relation, user)`` tuple.
    """
    try:
        object_, remainder = identity.split("#", 1)
        relation, user = remainder.split("@", 1)
    except ValueError as err:
        raise TupleKeyError(f"malformed tuple identity: {identity!r}") from err

    if not object_ or not relation or not user:
        raise TupleKeyError(f"malformed tuple identity: {identity!r}")

    return object_, relation, user


def to_client_tuple(tuple_key: ClientTuple | Mapping[str, str]) -> ClientTuple:
    """
    Normalize a mapping or :class:`ClientTuple` into a :class:`ClientTuple`.
    """
    if isinstance(tuple_key, ClientTuple):
        return tuple_key

    return ClientTuple(
        user=_field(tuple_key, "user"),
        relation=_field(tuple_key, "relation"),
        object=_field(tuple_key, "object"),
    )


def _field(tuple_key: ClientTuple | Mapping[str, str], name: str) -> str:
    if isinstance(tuple_key, ClientTuple):
        return getattr(tuple_key, name) or ""

    value = tuple_key.get(name, "")
    return value if value is not None else ""
