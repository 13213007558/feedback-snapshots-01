"""Exception classes for marshmallow-related errors."""

from __future__ import annotations

import typing

# Key used for schema-level validation errors
SCHEMA = "_schema"

#: Keys that mark a mapping as a structured error message, e.g.
#: ``{"message": "City required", "code": 400}``.
_STRUCTURED_MESSAGE_KEYS = frozenset({"code", "message"})


class _CodedMessage(str):
    """A string error message that remembers its error category.

    It compares equal to (and serializes like) a normal string so that
    ``ValidationError.messages`` keeps its public shape.
    """

    code: typing.Any

    def __new__(cls, value: str, code: typing.Any = None):
        obj = super().__new__(cls, value)
        obj.code = code
        return obj


def _is_structured_message(value: typing.Mapping) -> bool:
    """Return whether ``value`` describes a message rather than nested errors."""
    return (
        "message" in value
        and set(value) <= _STRUCTURED_MESSAGE_KEYS
        and isinstance(value["message"], (str, bytes))
    )


def _with_code(messages: typing.Any, code: typing.Any) -> typing.Any:
    """Return a copy of ``messages`` with ``code`` attached to leaf messages.

    Codes that are already attached are preserved. Mappings that describe a
    message (e.g. ``{"message": ..., "code": ...}``) are treated as leaves.
    """
    if code is None:
        return messages
    if isinstance(messages, _CodedMessage):
        return _CodedMessage(messages, messages.code or code)
    if isinstance(messages, str):
        return _CodedMessage(messages, code)
    if isinstance(messages, bytes):
        return messages
    if isinstance(messages, list):
        return [_with_code(message, code) for message in messages]
    if isinstance(messages, dict):
        if _is_structured_message(messages):
            return messages
        return {key: _with_code(value, code) for key, value in messages.items()}
    return messages


class MarshmallowError(Exception):
    """Base class for all marshmallow-related errors."""


class ValidationError(MarshmallowError):
    """Raised when validation fails on a field or schema.

    Validators and custom fields should raise this exception.

    :param message: An error message, list of error messages, or dict of
        error messages. If a dict, the keys are subitems and the values are error messages.
    :param field_name: Field name to store the error on.
    :param data: Raw input data.
    :param valid_data: Valid (de)serialized data.
    :param code: Machine-readable error category, e.g. ``"required"`` or
        ``"invalid"``. It is not included in ``messages``.

    .. versionchanged:: 4.5.0
        Add ``code`` and :meth:`to_public_dict`.
    """

    def __init__(
        self,
        message: str | list | dict,
        field_name: str = SCHEMA,
        data: typing.Mapping[str, typing.Any]
        | typing.Iterable[typing.Mapping[str, typing.Any]]
        | None = None,
        valid_data: list[typing.Any] | dict[str, typing.Any] | None = None,
        *,
        code: typing.Any = None,
        **kwargs,
    ):
        self.messages = [message] if isinstance(message, (str, bytes)) else message
        self.field_name = field_name
        self.data = data
        self.valid_data = valid_data
        self.code = code
        self.kwargs = kwargs
        super().__init__(message)

    def normalized_messages(self):
        if self.field_name == SCHEMA and isinstance(self.messages, dict):
            return self.messages
        return {self.field_name: self.messages}

    @property
    def messages_dict(self) -> dict[str, typing.Any]:
        if not isinstance(self.messages, dict):
            raise TypeError(
                "cannot access 'messages_dict' when 'messages' is of type "
                + type(self.messages).__name__
            )
        return self.messages

    def to_public_dict(self, *, include_messages: bool = False) -> dict[str, list]:
        """Build a response-safe representation of the validation errors.

        Each entry contains the location of the offending field and a
        machine-readable code. Locations follow the input data, so aliased
        fields use their ``data_key`` and errors on collection items include
        the item index. Schema-level (cross-field) errors have an empty
        location.

        ``data`` and ``valid_data`` are never included. Messages are omitted
        by default as well because they may embed the submitted values; pass
        ``include_messages=True`` to include them.

        :return: ``{"errors": [{"location": [...], "code": ...}, ...]}``.

        .. versionadded:: 4.5.0
        """
        errors = _collect_public_errors(
            self.normalized_messages(),
            path=[],
            default_code=self.code,
            include_messages=include_messages,
        )
        return {"errors": errors}


def _collect_public_errors(
    messages: typing.Any,
    *,
    path: list,
    default_code: typing.Any,
    include_messages: bool,
) -> list[dict[str, typing.Any]]:
    """Flatten an error-message tree into public ``location``/``code`` entries."""
    if isinstance(messages, _CodedMessage):
        return [
            _public_error(
                path, messages.code or default_code, messages, include_messages
            )
        ]
    if isinstance(messages, str):
        return [_public_error(path, default_code, messages, include_messages)]
    if isinstance(messages, list):
        result = []
        for message in messages:
            result.extend(
                _collect_public_errors(
                    message,
                    path=path,
                    default_code=default_code,
                    include_messages=include_messages,
                )
            )
        return result
    if isinstance(messages, dict):
        if _is_structured_message(messages):
            return [
                _public_error(
                    path,
                    messages.get("code", default_code),
                    messages["message"],
                    include_messages,
                )
            ]
        result = []
        for key, value in messages.items():
            key_path = path if key == SCHEMA else [*path, key]
            result.extend(
                _collect_public_errors(
                    value,
                    path=key_path,
                    default_code=default_code,
                    include_messages=include_messages,
                )
            )
        return result
    return [_public_error(path, default_code, messages, include_messages)]


def _public_error(
    path: list, code: typing.Any, message: typing.Any, include_messages: bool
) -> dict[str, typing.Any]:
    error: dict[str, typing.Any] = {
        "location": list(path),
        "code": code or ("schema" if not path else "invalid"),
    }
    if include_messages:
        error["message"] = str(message)
    return error


class RegistryError(NameError):
    """Raised when an invalid operation is performed on the serializer
    class registry.
    """


class StringNotCollectionError(MarshmallowError, TypeError):
    """Raised when a string is passed when a list of strings is expected."""


class _FieldInstanceResolutionError(MarshmallowError, TypeError):
    """Raised when an argument is passed to a field class that cannot be resolved to a Field instance."""
