"""Side-effect-free wire signatures used to tell format versions apart."""

_JSON_WHITESPACE = b" \t\r\n"
_JSON_OBJECT_START = b"{"
_JSON_OBJECT_END = b"}"


def json_separator_style(message: bytes) -> bool | None:
    """
    Report whether a JSON payload uses padded object separators.

    ``JSONFormatter`` uses pydantic's compact output (``{"a":1}``), while
    the proxy formatter uses ``json.dumps`` defaults (``{"a": 1}``). Both
    are valid JSON, so the distinction is the separator style, not the
    parsed value. This probe must not parse: channel selection happens
    before the single parse the receiver is allowed to perform.

    String literals and escapes are skipped, so separators inside values
    do not influence the answer.

    :param message: raw payload.
    :return: True for padded separators, False for compact ones, None if
        the payload is not a JSON object and the style cannot be told.
    """
    if not message.startswith(_JSON_OBJECT_START):
        return None
    padded = False
    in_string = False
    escaped = False
    saw_separator = False
    index = 0
    length = len(message)
    while index < length:
        char = message[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == ord("\\"):
                escaped = True
            elif char == ord('"'):
                in_string = False
            index += 1
            continue
        if char == ord('"'):
            in_string = True
            index += 1
            continue
        if char in (ord(":"), ord(",")):
            saw_separator = True
            next_index = index + 1
            if next_index < length and message[next_index] in _JSON_WHITESPACE:
                padded = True
        index += 1
    if not saw_separator or not message.rstrip().endswith(_JSON_OBJECT_END):
        return None
    return padded
