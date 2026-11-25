import builtins
import json
import pickle
import sys
from typing import Any, Generic, TypeVar

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    field_serializer,
    field_validator,
)

from taskiq.serialization import exception_to_python, prepare_exception

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

_ReturnType = TypeVar("_ReturnType")


class TaskiqResult(BaseModel, Generic[_ReturnType]):
    """Result of a remote task invocation."""

    is_err: bool
    # Log is a deprecated field. It would be removed in future releases of not,
    # if we find a way to capture logs in async environment.
    log: str | None = None
    return_value: _ReturnType
    execution_time: float
    failure_category: str | None = None
    labels: dict[str, Any] = Field(default_factory=dict)

    error: BaseException | None = None

    model_config = ConfigDict(arbitrary_types_allowed=True)

    _original_error: BaseException | None = PrivateAttr(default=None)

    def set_original_error(self, error: BaseException | None) -> None:
        """Store the original error behind a retry-suppression marker."""
        self._original_error = error

    def get_original_error(self) -> BaseException | None:
        """Return an original error hidden from public serialization."""
        return self._original_error

    @field_serializer("error")
    def serialize_error(self, value: BaseException) -> Any:
        """
        Serialize error field.

        :returns: Any
        :param value: exception to serialize.
        """
        if value:
            return prepare_exception(value, json)

        return None

    def raise_for_error(self) -> "Self":
        """Raise exception if `error`.

        :raises error: task execution exception
        :returns: TaskiqResult
        """
        if self.error is not None:
            raise self.error
        return self

    def __getstate__(self) -> dict[Any, Any]:
        state = super().__getstate__()
        vals: builtins.dict[str, Any] = state["__dict__"]

        if "error" in vals and vals["error"] is not None:
            vals["error"] = prepare_exception(
                vals["error"],
                pickle,
            )

        private_values = state.get("__pydantic_private__")
        if isinstance(private_values, dict):
            private_values.pop("_original_error", None)

        return state

    @field_validator("error", mode="before")
    @classmethod
    def _validate_error(cls, value: Any) -> BaseException | None:
        return exception_to_python(value)
