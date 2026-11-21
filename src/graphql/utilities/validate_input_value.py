"""Input value validation"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, NamedTuple, cast

from ..error import GraphQLError
from ..language import (
    ListValueNode,
    Node,
    NullValueNode,
    ObjectFieldNode,
    ObjectValueNode,
    StringValueNode,
    ValueNode,
    VariableNode,
)
from ..language.printer import print_for_error
from ..pyutils import (
    Path,
    Undefined,
    did_you_mean,
    inspect,
    is_iterable,
    suggestion_list,
)
from ..type import (
    GraphQLInputType,
    GraphQLScalarType,
    assert_leaf_type,
    is_enum_type,
    is_input_object_type,
    is_list_type,
    is_non_null_type,
    is_required_input_field,
)
from .replace_variables import replace_variables

if TYPE_CHECKING:
    from ..execution.values import FragmentVariableValues, VariableValues

__all__ = ["validate_input_literal", "validate_input_value"]

OnErrorCB = Callable[[GraphQLError, "list[str | int]"], None]

# Placeholder rendered in place of an input value that must not be exposed in
# public validation error output (e.g. a one-time credential).
REDACTED = "[redacted]"


def validate_input_value(
    input_value: Any,
    type_: GraphQLInputType,
    on_error: OnErrorCB,
    hide_suggestions: bool = False,
    sensitive: bool = False,
) -> None:
    """Validate that the provided input value is allowed for this type.

    All errors are collected via a callback function.

    :param input_value: Python value to validate.
    :param type_: GraphQL input type to validate the value against.
    :param on_error: Callback invoked for each validation error and path.
    :param hide_suggestions: Whether suggestion text should be omitted from errors.
    :param sensitive: Whether the validated value is sensitive. When set, error
        messages never render the input value (including nested values), while
        the error path still identifies which field was invalid. This keeps
        one-time credentials out of public error output.

    Collect validation errors with their input paths:

    >>> from graphql import (
    ...     GraphQLInputField,
    ...     GraphQLInputObjectType,
    ...     GraphQLInt,
    ...     GraphQLNonNull,
    ... )
    >>> from graphql.utilities import validate_input_value
    >>> review_input = GraphQLInputObjectType(
    ...     'ReviewInput',
    ...     {'stars': GraphQLInputField(GraphQLNonNull(GraphQLInt))},
    ... )
    >>> errors = []
    >>> validate_input_value(
    ...     {'stars': 'bad'},
    ...     review_input,
    ...     lambda error, path: errors.append(
    ...         {'message': error.message, 'path': path}
    ...     ),
    ... )
    >>> errors
    [{'message': "Int cannot represent non-integer value: 'bad'", 'path': ['stars']}]

    This variant hides suggestion text for unknown input fields:

    >>> from graphql import GraphQLString
    >>> review_input = GraphQLInputObjectType(
    ...     'ReviewInput', {'comment': GraphQLInputField(GraphQLString)}
    ... )
    >>> errors = []
    >>> validate_input_value(
    ...     {'rating': 'extra field'},
    ...     review_input,
    ...     lambda error, _path: errors.append(error.message),
    ...     True,
    ... )
    >>> errors
    ["Expected value of type 'ReviewInput' not to include unknown field 'rating',
     found: {'rating': 'extra field'}."]

    Sensitive values are redacted instead of being rendered:

    >>> errors = []
    >>> validate_input_value(
    ...     {'stars': 'bad'},
    ...     GraphQLNonNull(GraphQLInt),
    ...     lambda error, path: errors.append(
    ...         {'message': error.message, 'path': path}
    ...     ),
    ...     sensitive=True,
    ... )
    >>> errors
    [{'message': "Expected value of type 'Int' to be valid.", 'path': []}]
    """
    validate_input_value_impl(
        input_value, type_, on_error, hide_suggestions, None, sensitive
    )


def validate_input_value_impl(
    input_value: Any,
    type_: GraphQLInputType,
    on_error: OnErrorCB,
    hide_suggestions: bool,
    path: Path | None,
    sensitive: bool = False,
) -> None:
    if is_non_null_type(type_):
        if input_value is Undefined:
            report_invalid_value(
                on_error,
                f"Expected a value of non-null type '{type_}' to be provided.",
                path,
                sensitive=sensitive,
            )
            return
        if input_value is None:
            report_invalid_value(
                on_error,
                f"Expected value of non-null type '{type_}' not to be None.",
                path,
                sensitive=sensitive,
            )
            return
        validate_input_value_impl(
            input_value, type_.of_type, on_error, hide_suggestions, path, sensitive
        )
        return

    if input_value is None or input_value is Undefined:
        return

    if is_list_type(type_):
        item_type = type_.of_type
        if not is_iterable(input_value):
            # Lists accept a non-list value as a list of one.
            validate_input_value_impl(
                input_value, item_type, on_error, hide_suggestions, path, sensitive
            )
        else:
            for index, item_value in enumerate(input_value):
                validate_input_value_impl(
                    item_value,
                    item_type,
                    on_error,
                    hide_suggestions,
                    Path(path, index, None),
                    sensitive,
                )
    elif is_input_object_type(type_):
        if not isinstance(input_value, dict):
            report_invalid_value(
                on_error,
                f"Expected value of type '{type_}' to be an object,"
                f" found: {redact_value(input_value, type_, sensitive)}.",
                path,
                sensitive=sensitive,
            )
            return

        field_defs = type_.fields

        for field_name, field in field_defs.items():
            field_value = input_value.get(field_name, Undefined)
            field_sensitive = sensitive or field.sensitive
            if field_value is Undefined:
                if is_required_input_field(field):
                    # The missing field carries no value, but the object may
                    # still contain sensitive siblings; redact the whole object
                    # when this type declares any sensitive field.
                    rendered = redact_value(
                        input_value,
                        type_,
                        sensitive or type_has_sensitive_fields(type_),
                    )
                    report_invalid_value(
                        on_error,
                        f"Expected value of type '{type_}' to include required"
                        f" field '{field_name}', found: {rendered}.",
                        path,
                        sensitive=field_sensitive,
                    )
            else:
                validate_input_value_impl(
                    field_value,
                    field.type,
                    on_error,
                    hide_suggestions,
                    Path(path, field_name, type_.name),
                    field_sensitive,
                )

        fields: list[str] = []
        # Ensure every provided field is defined.
        for field_name, field_value in input_value.items():
            if field_value is Undefined:
                continue
            if field_name not in field_defs:
                suggestion = (
                    ""
                    if hide_suggestions
                    else did_you_mean(suggestion_list(field_name, list(field_defs)))
                )
                report_invalid_value(
                    on_error,
                    f"Expected value of type '{type_}' not to include unknown"
                    f" field '{field_name}'"
                    + (f".{suggestion} Found" if suggestion else ", found")
                    + f": {redact_value(input_value, type_, sensitive)}.",
                    path,
                    sensitive=sensitive,
                )
                continue
            fields.append(field_name)

        if type_.is_one_of:
            if len(fields) != 1:
                report_invalid_value(
                    on_error,
                    get_one_of_input_object_error_message(type_),
                    path,
                    sensitive=sensitive,
                )

            if fields:
                field_name = fields[0]
                value = input_value[field_name]
                if value is None:
                    report_invalid_value(
                        on_error,
                        get_one_of_input_object_error_message(type_),
                        Path(path, field_name, type_.name),
                        sensitive=sensitive or field_defs[field_name].sensitive,
                    )
    else:
        assert_leaf_type(type_)

        result: Any = Undefined
        caught_error: Exception | None = None

        try:
            # Note: only enum types accept ``hide_suggestions``, since scalar
            # ``coerce_input_value`` functions are user-provided with a fixed
            # signature.
            if is_enum_type(type_):
                result = type_.coerce_input_value(input_value, hide_suggestions)
            else:
                scalar_type = cast("GraphQLScalarType", type_)
                result = scalar_type.coerce_input_value(input_value)
        except GraphQLError as error:
            on_error(
                redact_graphql_error(error, sensitive, type_),
                path.as_list() if path else [],
            )
            return
        except Exception as error:  # noqa: BLE001
            caught_error = error

        if result is Undefined:
            report_invalid_value(
                on_error,
                build_leaf_error_message(type_, caught_error, input_value, sensitive),
                path,
                caught_error,
                sensitive,
            )


def build_leaf_error_message(
    type_: GraphQLInputType,
    caught_error: Exception | None,
    input_value: Any,
    sensitive: bool,
) -> str:
    """Build the public message for a leaf value that failed coercion."""
    if sensitive:
        # Never render the supplied value (or a user-provided exception message
        # derived from it) for sensitive input. The error path still locates the
        # offending field.
        return f"Expected value of type '{type_}' to be valid."
    return (
        f"Expected value of type '{type_}'"
        + (
            f", but encountered error '{caught_error}'; found"
            if caught_error is not None
            else ", found"
        )
        + f": {inspect(input_value)}."
    )


def redact_value(
    value: Any,
    input_type: GraphQLInputType | None,
    whole_redact: bool,
) -> str:
    """Render a runtime value for an error message, redacting sensitive parts.

    When ``whole_redact`` is set (the validated argument or variable itself is
    marked sensitive), the entire value is replaced. Otherwise, only the fields
    marked sensitive on the given input object type are redacted, so an
    object-level error cannot print a credential through a sibling field while
    non-sensitive values stay visible.
    """
    if whole_redact:
        return REDACTED
    redacted = redact_runtime_value(value, input_type)
    return inspect(value) if redacted is None else inspect(redacted)


def type_has_sensitive_fields(type_: GraphQLInputType | None) -> bool:
    """Check whether an input type contains any field marked ``sensitive``.

    Wrapper types (non-null, list) are unwrapped. Input objects are checked
    recursively so that a missing required field on an object that also carries
    a sensitive sibling still triggers whole-object redaction.
    """
    seen: set[int] = set()

    def check(inner_type: GraphQLInputType | None) -> bool:
        while inner_type is not None and (
            is_non_null_type(inner_type) or is_list_type(inner_type)
        ):
            inner_type = inner_type.of_type
        if not is_input_object_type(inner_type):
            return False
        type_id = id(inner_type)
        if type_id in seen:
            return False
        seen.add(type_id)
        return any(
            field.sensitive or check(field.type)
            for field in inner_type.fields.values()
        )

    return check(type_)


def redact_runtime_value(
    value: Any, type_: GraphQLInputType | None
) -> Any:
    """Return a copy of ``value`` with sensitive fields replaced.

    Returns ``None`` when nothing had to be redacted, allowing the caller to
    render the original value unchanged.
    """
    if is_input_object_type(type_):
        if not isinstance(value, dict):
            return None
        field_defs = type_.fields
        redacted_dict: dict[str, Any] | None = None
        for key, item in value.items():
            field = field_defs.get(key)
            if field is None:
                # Unknown fields are not part of the type; render the value as
                # given without descending into it.
                continue
            if field.sensitive:
                if redacted_dict is None:
                    redacted_dict = dict(value)
                redacted_dict[key] = REDACTED
            else:
                redacted_item = redact_runtime_value(item, field.type)
                if redacted_item is not None:
                    if redacted_dict is None:
                        redacted_dict = dict(value)
                    redacted_dict[key] = redacted_item
        return redacted_dict
    if is_list_type(type_):
        item_type = type_.of_type
        if is_iterable(value) and not isinstance(value, (str, bytes)):
            redacted_list: list[Any] | None = None
            for index, item in enumerate(value):
                redacted_item = redact_runtime_value(item, item_type)
                if redacted_item is not None:
                    if redacted_list is None:
                        redacted_list = list(value)
                    redacted_list[index] = redacted_item
            return redacted_list
        # Lists accept a non-list value as a list of one.
        return redact_runtime_value(value, item_type)
    if is_non_null_type(type_):
        return redact_runtime_value(value, type_.of_type)
    return None


def redact_graphql_error(
    error: GraphQLError, sensitive: bool, type_: GraphQLInputType
) -> GraphQLError:
    """Redact a GraphQLError raised by user-provided scalar/enum coercion.

    The replacement keeps the original nodes and locations so callers can still
    point at the offending field, while dropping both the message (which may
    embed the supplied value) and the original error's extensions.
    """
    if not sensitive:
        return error
    return GraphQLError(
        f"Expected value of type '{type_}' to be valid.",
        error.nodes,
        source=error.source,
        positions=error.positions,
        path=error.path,
    )


def report_invalid_value(
    on_error: OnErrorCB,
    message: str,
    path: Path | None,
    original_error: Exception | None = None,
    sensitive: bool = False,
) -> None:
    if sensitive and original_error is not None:
        # Drop the original error: its message and extensions may embed the
        # supplied input value. The path passed to the callback still locates
        # the offending field.
        original_error = None
    on_error(
        GraphQLError(message, original_error=original_error),
        path.as_list() if path else [],
    )


def validate_input_literal(
    value_node: ValueNode,
    type_: GraphQLInputType,
    on_error: OnErrorCB,
    variables: VariableValues | None = None,
    fragment_variable_values: FragmentVariableValues | None = None,
    hide_suggestions: bool = False,
    sensitive: bool = False,
) -> None:
    """Validate that the provided input literal is allowed for this type.

    All errors are collected via a callback function.

    If variable values are not provided, the literal is validated statically (not
    assuming that those variables are missing runtime values).

    :param value_node: GraphQL value AST node to validate.
    :param type_: GraphQL input type to validate the literal against.
    :param on_error: Callback invoked for each validation error and path.
    :param variables: Operation variable values returned by
        :func:`~graphql.execution.get_variable_values`.
    :param fragment_variable_values: Fragment variable values for the current
        fragment scope.
    :param hide_suggestions: Whether suggestion text should be omitted from errors.
    :param sensitive: Whether the validated literal is sensitive. When set, error
        messages never render the literal (including nested literals), while the
        error path still identifies which field was invalid.

    Validate literal input values and collect literal paths:

    >>> from graphql import (
    ...     GraphQLInputField,
    ...     GraphQLInputObjectType,
    ...     GraphQLInt,
    ...     GraphQLNonNull,
    ...     parse_value,
    ... )
    >>> from graphql.utilities import validate_input_literal
    >>> review_input = GraphQLInputObjectType(
    ...     'ReviewInput',
    ...     {'stars': GraphQLInputField(GraphQLNonNull(GraphQLInt))},
    ... )
    >>> errors = []
    >>> validate_input_literal(
    ...     parse_value('{ stars: "bad" }'),
    ...     review_input,
    ...     lambda error, path: errors.append(
    ...         {'message': error.message, 'path': path}
    ...     ),
    ... )
    >>> errors
    [{'message': 'Int cannot represent non-integer value: "bad"', 'path': ['stars']}]

    This variant resolves variable references using the variable values returned by
    :func:`~graphql.execution.get_variable_values`:

    >>> from graphql import build_schema, parse
    >>> from graphql.execution import get_variable_values
    >>> schema = build_schema('''
    ...   type Query {
    ...     review(stars: Int): String
    ...   }
    ... ''')
    >>> document = parse('query ($stars: Int = 5) { review(stars: $stars) }')
    >>> operation = document.definitions[0]
    >>> variable_values = get_variable_values(
    ...     schema, operation.variable_definitions, {'stars': 4}
    ... )
    >>> errors = []
    >>> validate_input_literal(
    ...     parse_value('$stars'),
    ...     GraphQLInt,
    ...     lambda error, _path: errors.append(error.message),
    ...     variable_values,
    ...     None,
    ...     True,
    ... )
    >>> errors
    []
    """
    context = ValidationContext(
        static=not variables and not fragment_variable_values,
        on_error=on_error,
        variables=variables,
        fragment_variable_values=fragment_variable_values,
        sensitive=sensitive,
    )
    validate_input_literal_impl(
        context, value_node, type_, hide_suggestions, None, sensitive
    )


class ValidationContext(NamedTuple):
    """Context for validating an input literal."""

    static: bool
    on_error: OnErrorCB
    variables: VariableValues | None
    fragment_variable_values: FragmentVariableValues | None
    sensitive: bool = False


def validate_input_literal_impl(
    context: ValidationContext,
    value_node: ValueNode,
    type_: GraphQLInputType,
    hide_suggestions: bool,
    path: Path | None,
    sensitive: bool = False,
) -> None:
    if isinstance(value_node, VariableNode):
        if context.static:
            # If no variable values are provided, this is being validated
            # statically, and cannot yet produce any validation errors for
            # variables.
            return
        scoped_variable_values = get_scoped_variable_values(context, value_node)
        value = (
            scoped_variable_values.coerced.get(value_node.name.value, Undefined)
            if scoped_variable_values
            else Undefined
        )
        if is_non_null_type(type_):
            if value is Undefined:
                report_invalid_literal(
                    context.on_error,
                    f"Expected variable '${value_node.name.value}' provided"
                    f" to type '{type_}' to provide a runtime value.",
                    value_node,
                    path,
                    sensitive=sensitive,
                )
            elif value is None:
                report_invalid_literal(
                    context.on_error,
                    f"Expected variable '${value_node.name.value}' provided"
                    f" to non-null type '{type_}' not to be None.",
                    value_node,
                    path,
                    sensitive=sensitive,
                )
        # Note: This does no further checking that this variable is correct.
        # This assumes this variable usage has already been validated.
        return

    if is_non_null_type(type_):
        if isinstance(value_node, NullValueNode):
            report_invalid_literal(
                context.on_error,
                f"Expected value of non-null type '{type_}' not to be None.",
                value_node,
                path,
                sensitive=sensitive,
            )
            return
        validate_input_literal_impl(
            context, value_node, type_.of_type, hide_suggestions, path, sensitive
        )
        return

    if isinstance(value_node, NullValueNode):
        return

    if is_list_type(type_):
        item_type = type_.of_type
        if not isinstance(value_node, ListValueNode):
            # Lists accept a non-list value as a list of one.
            validate_input_literal_impl(
                context, value_node, item_type, hide_suggestions, path, sensitive
            )
        else:
            for index, item_node in enumerate(value_node.values):
                validate_input_literal_impl(
                    context,
                    item_node,
                    item_type,
                    hide_suggestions,
                    Path(path, index, None),
                    sensitive,
                )
    elif is_input_object_type(type_):
        if not isinstance(value_node, ObjectValueNode):
            report_invalid_literal(
                context.on_error,
                f"Expected value of type '{type_}' to be an object,"
                f" found: {redact_literal(value_node, type_, sensitive)}.",
                value_node,
                path,
                sensitive=sensitive,
            )
            return

        field_defs = type_.fields
        field_nodes = {field.name.value: field for field in value_node.fields}

        for field_name, field in field_defs.items():
            field_node = field_nodes.get(field_name)
            field_sensitive = sensitive or field.sensitive
            if field_node is None:
                if is_required_input_field(field):
                    rendered = redact_literal(
                        value_node,
                        type_,
                        sensitive or type_has_sensitive_fields(type_),
                    )
                    report_invalid_literal(
                        context.on_error,
                        f"Expected value of type '{type_}' to include required"
                        f" field '{field_name}', found: {rendered}.",
                        value_node,
                        path,
                        sensitive=field_sensitive,
                    )
            else:
                field_value_node = field_node.value
                if isinstance(field_value_node, VariableNode) and not context.static:
                    scoped_variable_values = get_scoped_variable_values(
                        context, field_value_node
                    )
                    variable_name = field_value_node.name.value
                    value = (
                        scoped_variable_values.coerced.get(variable_name, Undefined)
                        if scoped_variable_values
                        else Undefined
                    )
                    if type_.is_one_of:
                        if value is Undefined:
                            report_invalid_literal(
                                context.on_error,
                                f"Expected variable '${variable_name}' provided"
                                f" to field '{field_name}' for OneOf Input Object"
                                f" type '{type_}' to provide a runtime value.",
                                value_node,
                                path,
                                sensitive=field_sensitive,
                            )
                        elif value is None:
                            report_invalid_literal(
                                context.on_error,
                                f"Expected variable '${variable_name}' provided"
                                f" to field '{field_name}' for OneOf Input Object"
                                f" type '{type_}' not to be None.",
                                value_node,
                                path,
                                sensitive=field_sensitive,
                            )
                    elif value is Undefined and not is_required_input_field(field):
                        continue

                validate_input_literal_impl(
                    context,
                    field_value_node,
                    field.type,
                    hide_suggestions,
                    Path(path, field_name, type_.name),
                    field_sensitive,
                )

        fields = value_node.fields
        known_fields: list[ObjectFieldNode] = []
        # Ensure every provided field is defined.
        for field_node in fields:
            field_name = field_node.name.value
            if field_name not in field_defs:
                suggestion = (
                    ""
                    if hide_suggestions
                    else did_you_mean(suggestion_list(field_name, list(field_defs)))
                )
                report_invalid_literal(
                    context.on_error,
                    f"Expected value of type '{type_}' not to include unknown"
                    f" field '{field_name}'"
                    + (f".{suggestion} Found" if suggestion else ", found")
                    + f": {redact_literal(value_node, type_, sensitive)}.",
                    field_node,
                    path,
                    sensitive=sensitive,
                )
            else:
                known_fields.append(field_node)

        if type_.is_one_of:
            is_not_exactly_one_field = len(known_fields) != 1
            if is_not_exactly_one_field:
                report_invalid_literal(
                    context.on_error,
                    get_one_of_input_object_error_message(type_),
                    value_node,
                    path,
                    sensitive=sensitive,
                )
                return

            field_value_node = known_fields[0].value
            if isinstance(field_value_node, NullValueNode):
                field_name = known_fields[0].name.value
                report_invalid_literal(
                    context.on_error,
                    get_one_of_input_object_error_message(type_),
                    value_node,
                    Path(path, field_name, None),
                    sensitive=sensitive
                    or field_defs[field_name].sensitive,
                )
    else:
        leaf_type = assert_leaf_type(type_)

        result: Any = Undefined
        caught_error: Exception | None = None
        # Note: unlike GraphQL.js, which always replaces variables statically here
        # (without their runtime values), the available variable values are passed
        # through so that a leaf type coercing a literal that embeds variables sees
        # the same values used by ``coerce_input_literal``. This lets the runtime
        # argument-coercion fallback reproduce variable-dependent coercion errors.
        variables = context.variables
        fragment_variable_values = context.fragment_variable_values
        try:
            # Note: only enum types accept ``hide_suggestions``, since scalar
            # ``coerce_input_literal``/``parse_literal`` functions are
            # user-provided with a fixed signature.
            if is_enum_type(leaf_type):
                result = leaf_type.coerce_input_literal(
                    replace_variables(value_node, variables, fragment_variable_values),
                    hide_suggestions,
                )
            elif leaf_type.coerce_input_literal is not None:
                result = leaf_type.coerce_input_literal(
                    replace_variables(value_node, variables, fragment_variable_values)
                )
            else:
                result = leaf_type.parse_literal(
                    value_node, variables.coerced if variables else None
                )
        except GraphQLError as error:
            context.on_error(
                redact_graphql_error(error, sensitive, leaf_type),
                path.as_list() if path else [],
            )
            return
        except Exception as error:  # noqa: BLE001
            caught_error = error

        if result is Undefined:
            if sensitive:
                message = f"Expected value of type '{type_}' to be valid."
            else:
                message = (
                    f"Expected value of type '{type_}'"
                    + (
                        f", but encountered error '{caught_error}'; found"
                        if caught_error is not None
                        else ", found"
                    )
                    + f": {print_for_error(value_node)}."
                )
            report_invalid_literal(
                context.on_error,
                message,
                value_node,
                path,
                caught_error,
                sensitive,
            )


def get_scoped_variable_values(
    context: ValidationContext, value_node: VariableNode
) -> VariableValues | FragmentVariableValues | None:
    """Select the variable values that provide the given variable node.

    :meta private:
    """
    variable_name = value_node.name.value
    fragment_variable_values = context.fragment_variable_values
    if fragment_variable_values and variable_name in fragment_variable_values.sources:
        return fragment_variable_values
    return context.variables


def report_invalid_literal(
    on_error: OnErrorCB,
    message: str,
    value_node: Node,
    path: Path | None,
    original_error: Exception | None = None,
    sensitive: bool = False,
) -> None:
    if sensitive and original_error is not None:
        # Drop the original error: its message and extensions may embed the
        # supplied input value. The path passed to the callback still locates
        # the offending field.
        original_error = None
    on_error(
        GraphQLError(message, value_node, original_error=original_error),
        path.as_list() if path else [],
    )


def redact_literal(
    value_node: ValueNode,
    input_type: GraphQLInputType | None,
    whole_redact: bool,
) -> str:
    """Render a value literal for an error message, redacting sensitive parts.

    When ``whole_redact`` is set (the validated argument or variable itself is
    marked sensitive), the entire literal is replaced. Otherwise, only the
    fields marked sensitive on the given input object type are redacted, so an
    object-level error cannot print a credential through a sibling field while
    non-sensitive values stay visible.
    """
    if whole_redact:
        return REDACTED
    redacted_node = redact_literal_node(value_node, input_type)
    if redacted_node is None:
        return print_for_error(value_node)
    return print_for_error(redacted_node)


def redact_literal_node(
    value_node: ValueNode, type_: GraphQLInputType | None
) -> ValueNode | None:
    """Return a copy of ``value_node`` with sensitive fields replaced.

    Returns ``None`` when nothing had to be redacted, allowing the caller to
    print the original node unchanged.
    """
    if is_non_null_type(type_):
        return redact_literal_node(value_node, type_.of_type)
    if is_list_type(type_):
        item_type = type_.of_type
        if isinstance(value_node, ListValueNode):
            new_values: list[ValueNode] | None = None
            for index, item_node in enumerate(value_node.values):
                redacted_item = redact_literal_node(item_node, item_type)
                if redacted_item is not None:
                    if new_values is None:
                        new_values = list(value_node.values)
                    new_values[index] = redacted_item
            if new_values is None:
                return None
            return ListValueNode(values=tuple(new_values))
        # Lists accept a non-list value as a list of one.
        return redact_literal_node(value_node, item_type)
    if is_input_object_type(type_) and isinstance(value_node, ObjectValueNode):
        field_defs = type_.fields
        new_fields: list[ObjectFieldNode] | None = None
        for index, field_node in enumerate(value_node.fields):
            field = field_defs.get(field_node.name.value)
            if field is None:
                continue
            if field.sensitive:
                if new_fields is None:
                    new_fields = list(value_node.fields)
                new_fields[index] = ObjectFieldNode(
                    name=field_node.name,
                    value=StringValueNode(value=REDACTED),
                )
            else:
                redacted_field = redact_literal_node(field_node.value, field.type)
                if redacted_field is not None:
                    if new_fields is None:
                        new_fields = list(value_node.fields)
                    new_fields[index] = ObjectFieldNode(
                        name=field_node.name,
                        value=redacted_field,
                    )
        if new_fields is None:
            return None
        return ObjectValueNode(fields=tuple(new_fields))
    return None


def get_one_of_input_object_error_message(type_: GraphQLInputType) -> str:
    return (
        f"Within OneOf Input Object type '{type_}', exactly one field must be"
        " specified, and the value for that field must be non-null."
    )
