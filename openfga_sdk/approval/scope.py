from dataclasses import dataclass

from openfga_sdk.client.models.tuple import ClientTuple


@dataclass(frozen=True)
class TupleScope:
    """
    The object/relation range an approval's temporary relationship is
    restricted to.

    A tuple is inside the scope when its ``object`` matches ``object`` and its
    ``relation`` matches ``relation``. A ``None`` field means the caller did not
    constrain that dimension, so any value is accepted.
    """

    object: str | None = None
    relation: str | None = None

    def contains(self, tuple_key: ClientTuple) -> bool:
        if self.object is not None and tuple_key.object != self.object:
            return False

        if self.relation is not None and tuple_key.relation != self.relation:
            return False

        return True


class ScopeViolation(Exception):
    """
    Raised when a temporary relationship falls outside the scope the caller
    attached to an approval.
    """

    def __init__(self, tuple_key: ClientTuple, scope: TupleScope):
        self.tuple_key = tuple_key
        self.scope = scope
        super().__init__(
            "temporary tuple "
            f"(user={tuple_key.user}, relation={tuple_key.relation}, "
            f"object={tuple_key.object}) is outside the approved scope "
            f"(object={scope.object}, relation={scope.relation})"
        )


def enforce_scope(
    tuple_keys: list[ClientTuple], scope: TupleScope | None
) -> list[ClientTuple]:
    """
    Reject any tuple that does not fit the approved scope.
    """
    if scope is None:
        return list(tuple_keys)

    for tuple_key in tuple_keys:
        if not scope.contains(tuple_key):
            raise ScopeViolation(tuple_key, scope)

    return list(tuple_keys)
