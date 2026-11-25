"""Per-reader resource budgets for decoded PDF objects."""

from __future__ import annotations

from .errors import ResourceBudgetExceededError


class ResourceBudget:
    """
    Mutable resource budget shared by every object decoded by one reader.

    Each indirect object which is actually decoded from the file is charged
    exactly once to the budget. Reusing the same object through multiple
    indirect references does not charge it again, as the decoded value is
    served from the reader's object cache without any additional processing.

    Args:
        maximum_object_count: The maximum number of distinct objects which may
            be decoded. ``None`` disables the object count limit.
        maximum_byte_count: The maximum number of input bytes which may be
            consumed while decoding objects. For an object stored directly in
            the file this is the size of its serialized representation; for an
            object embedded in an object stream the bytes are charged once to
            the enclosing object stream. ``None`` disables the byte limit.
    """

    def __init__(
        self,
        maximum_object_count: int | None,
        maximum_byte_count: int | None,
    ) -> None:
        self.maximum_object_count = maximum_object_count
        self.maximum_byte_count = maximum_byte_count
        self.decoded_object_count = 0
        self.decoded_byte_count = 0
        self._charged_objects: set[tuple[int, int]] = set()

    def charge(
        self,
        generation: int,
        idnum: int,
        byte_count: int,
    ) -> None:
        """
        Charge one decoded object and the bytes consumed while decoding it.

        Args:
            generation: The object generation number.
            idnum: The object identifier number.
            byte_count: The number of input bytes consumed while decoding the
                object.

        Raises:
            ResourceBudgetExceededError: If charging the object would exceed
                the configured object count or byte budget.
        """
        key = (generation, idnum)
        if key in self._charged_objects:
            # Shared objects are decoded once and served from the cache;
            # repeated references must not consume additional budget.
            return
        if byte_count < 0:
            byte_count = 0

        new_object_count = self.decoded_object_count + 1
        if (
            self.maximum_object_count is not None
            and new_object_count > self.maximum_object_count
        ):
            raise ResourceBudgetExceededError(
                "Decoded object budget exceeded: "
                f"{new_object_count} > {self.maximum_object_count}."
            )

        new_byte_count = self.decoded_byte_count + byte_count
        if (
            self.maximum_byte_count is not None
            and new_byte_count > self.maximum_byte_count
        ):
            raise ResourceBudgetExceededError(
                "Decoded byte budget exceeded: "
                f"{new_byte_count} > {self.maximum_byte_count}."
            )

        self._charged_objects.add(key)
        self.decoded_object_count = new_object_count
        self.decoded_byte_count = new_byte_count
