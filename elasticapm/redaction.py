#  BSD 3-Clause License
#
#  Copyright (c) 2012, the Sentry Team, see AUTHORS for more details
#  Copyright (c) 2019, Elasticsearch BV
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
#  * Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE


import ast
import json
import urllib.parse

from elasticapm.conf.constants import BASE_SANITIZE_FIELD_NAMES, ERROR, MASK, TRANSACTION
from elasticapm.diagnostics import get_error_correlation
from elasticapm.utils import sanitize_url
from elasticapm.utils.encoding import force_text

# Event types that can carry request/response context or captured variables.
# Only these need the outbound projection.
_OUTBOUND_EVENT_TYPES = (ERROR, TRANSACTION)

# Values shorter than this are not used for cross-field scrubbing, to avoid
# masking incidental substrings (e.g. a one-character password).
_SECRET_SCRUB_MIN_LENGTH = 6

_FORM_BODY_SEPARATORS = ("&", "=")
_REQUEST_COOKIE_SEPARATORS = ("; ", "=")
_RESPONSE_COOKIE_SEPARATORS = (";", "=")


def project_event_for_export(client, event_type, event):
    """
    Return the outbound, redacted view of an event.

    Payload data is always derived from ``event`` alone. The only information
    read from :mod:`elasticapm.diagnostics` is the approved capture-time
    correlation record, which contains IDs and no payload. Re-submitting an
    event, reusing a transaction ID, or serializing twice therefore cannot
    resurrect values that were only retained for in-process troubleshooting.

    The input event is not modified: each section that can contain sensitive
    data is rebuilt rather than mutated in place, so processors or other
    threads still holding the queued event are unaffected.
    """
    if event_type not in _OUTBOUND_EVENT_TYPES or not isinstance(event, dict):
        return event

    sanitize_field_names = (
        getattr(getattr(client, "config", None), "sanitize_field_names", None) or BASE_SANITIZE_FIELD_NAMES
    )
    secrets = set()

    # Every section rewritten below is rebuilt rather than mutated in place,
    # so the queued event stays untouched without a full deep copy.
    projected = dict(event)

    context = projected.get("context")
    if isinstance(context, dict):
        projected["context"] = _redact_context(context, sanitize_field_names, secrets)

    exception = projected.get("exception")
    if isinstance(exception, dict):
        projected["exception"] = _redact_exception(exception, sanitize_field_names, secrets)

    log = projected.get("log")
    if isinstance(log, dict):
        projected["log"] = _redact_log(log, sanitize_field_names, secrets)

    if secrets:
        projected = _scrub_secret_values(projected, secrets)

    if event_type == ERROR:
        # Re-apply the capture-time correlation last so approved IDs are
        # emitted exactly as captured, even if a processor rewrote them or a
        # retention secret happened to share characters with them.
        projected = _restore_approved_correlation(client, projected)
    return projected


def _restore_approved_correlation(client, projected):
    """
    Re-apply the correlation captured with the error.

    Processors are allowed to rewrite event fields. The IDs that were approved
    at capture time are the ones the outbound event must keep, so they are read
    from the diagnostics correlation record rather than trusted from the
    possibly-modified event. Only correlation fields are consulted, never any
    retained payload.
    """
    correlation = get_error_correlation(client, projected.get("id"))
    if not correlation:
        return projected
    return dict(projected, **correlation)


def _redact_context(context, names, secrets):
    result = dict(context)
    request = context.get("request")
    if isinstance(request, dict):
        result["request"] = _redact_request(request, names, secrets)
    response = context.get("response")
    if isinstance(response, dict):
        result["response"] = _redact_response(response, names, secrets)
    for key in ("custom", "tags"):
        mapping = context.get(key)
        if isinstance(mapping, dict):
            result[key] = _redact_mapping(mapping, names, secrets)
    message = context.get("message")
    if isinstance(message, dict):
        message = dict(message)
        if "body" in message:
            message["body"] = _redact_body(message["body"], names, secrets)
        if isinstance(message.get("headers"), dict):
            message["headers"] = _redact_headers(message["headers"], names, secrets, response=False)
        result["message"] = message
    return result


def _redact_request(request, names, secrets):
    result = dict(request)
    if isinstance(request.get("headers"), dict):
        result["headers"] = _redact_headers(request["headers"], names, secrets, response=False)
    if isinstance(request.get("cookies"), dict):
        result["cookies"] = _redact_mapping(request["cookies"], names, secrets)
    if isinstance(request.get("env"), dict):
        result["env"] = _redact_mapping(request["env"], names, secrets)
    if "body" in request:
        result["body"] = _redact_body(request["body"], names, secrets)
    if isinstance(request.get("url"), dict):
        result["url"] = _redact_url(request["url"], names, secrets)
    return result


def _redact_response(response, names, secrets):
    result = dict(response)
    if isinstance(response.get("headers"), dict):
        result["headers"] = _redact_headers(response["headers"], names, secrets, response=True)
    if "body" in response:
        result["body"] = _redact_body(response["body"], names, secrets)
    return result


def _redact_headers(headers, names, secrets, response):
    result = {}
    for key, value in headers.items():
        lower_key = key.lower() if isinstance(key, str) else key
        if lower_key == "cookie" and not response:
            result[key] = _redact_pairs(value, *_REQUEST_COOKIE_SEPARATORS, names=names, secrets=secrets)
        elif lower_key == "set-cookie" and response:
            result[key] = _redact_pairs(value, *_RESPONSE_COOKIE_SEPARATORS, names=names, secrets=secrets)
        else:
            result[key] = _redact_value(key, value, names, secrets)
    return result


def _redact_url(url, names, secrets):
    result = dict(url)
    for field in ("search",):
        if isinstance(result.get(field), str):
            result[field] = _redact_pairs(
                result[field], *_FORM_BODY_SEPARATORS, names=names, secrets=secrets, keep_question_mark=True
            )
    for field in ("full", "raw"):
        if isinstance(result.get(field), str):
            result[field] = _redact_url_string(result[field], names, secrets)
    return result


def _redact_url_string(url, names, secrets):
    try:
        parts = urllib.parse.urlsplit(url)
        query = parts.query
        redacted_query = _redact_pairs(
            query,
            *_FORM_BODY_SEPARATORS,
            names=names,
            secrets=secrets,
            keep_question_mark=False,
            leading_question=False
        )
        if redacted_query != query:
            url = urllib.parse.urlunsplit(parts._replace(query=redacted_query))
        if "@" in url:
            url = sanitize_url(url)
        return url
    except Exception:
        return url


def _redact_body(body, names, secrets):
    if isinstance(body, dict):
        return _redact_mapping(body, names, secrets)
    if isinstance(body, (list, tuple, set)):
        return [_redact_body(item, names, secrets) for item in body]
    if isinstance(body, bytes):
        body = force_text(body, errors="replace")
    if not isinstance(body, str):
        return body

    stripped = body.lstrip()
    if stripped.startswith(("{", "[")):
        redacted = _redact_json_string(body, names, secrets)
        if redacted is not None:
            return redacted
        # Some framework adapters convert a parsed body back to a Python
        # repr (e.g. "{'password': '...'}"), which is neither JSON nor form
        # encoded. Parse it as a literal when possible.
        redacted = _redact_literal_string(body, names, secrets)
        if redacted is not None:
            return redacted
    if "=" in body:
        return _redact_pairs(body, *_FORM_BODY_SEPARATORS, names=names, secrets=secrets)
    return body


def _redact_literal_string(body, names, secrets):
    try:
        parsed = ast.literal_eval(body)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return None
    if not isinstance(parsed, (dict, list, tuple)):
        return None
    redacted = _redact_body(parsed, names, secrets)
    if redacted == parsed:
        return body
    return str(redacted)


def _redact_json_string(body, names, secrets):
    try:
        parsed = json.loads(body)
    except (TypeError, ValueError):
        return None
    if isinstance(parsed, dict):
        redacted = _redact_mapping(parsed, names, secrets)
    elif isinstance(parsed, list):
        redacted = [_redact_body(item, names, secrets) for item in parsed]
    else:
        return None
    if redacted == parsed:
        return body
    try:
        return json.dumps(redacted, ensure_ascii=False)
    except (TypeError, ValueError):
        return body


def _redact_exception(exception, names, secrets):
    result = dict(exception)
    if isinstance(exception.get("stacktrace"), list):
        result["stacktrace"] = _redact_stacktrace(exception["stacktrace"], names, secrets)
    cause = exception.get("cause")
    if isinstance(cause, list):
        result["cause"] = [
            _redact_exception(item, names, secrets) if isinstance(item, dict) else item for item in cause
        ]
    return result


def _redact_log(log, names, secrets):
    result = dict(log)
    if isinstance(log.get("stacktrace"), list):
        result["stacktrace"] = _redact_stacktrace(log["stacktrace"], names, secrets)
    return result


def _redact_stacktrace(frames, names, secrets):
    result = []
    for frame in frames:
        if not isinstance(frame, dict):
            result.append(frame)
            continue
        frame = dict(frame)
        if isinstance(frame.get("vars"), dict):
            frame["vars"] = _redact_mapping(frame["vars"], names, secrets)
        result.append(frame)
    return result


def _redact_mapping(mapping, names, secrets):
    result = {}
    for key, value in mapping.items():
        result[key] = _redact_value(key, value, names, secrets)
    return result


def _redact_value(key, value, names, secrets):
    if isinstance(value, dict):
        return _redact_mapping(value, names, secrets)
    if isinstance(value, (list, tuple, set)):
        return [_redact_value(key, item, names, secrets) for item in value]
    if _is_sensitive_key(key, names):
        _remember_secret(value, secrets)
        return MASK
    return value


def _redact_pairs(value, itemsep, kvsep, names, secrets, keep_question_mark=False, leading_question=False):
    if isinstance(value, (list, tuple)):
        return [
            _redact_pairs(item, itemsep, kvsep, names, secrets, keep_question_mark, leading_question) for item in value
        ]
    if isinstance(value, bytes):
        value = force_text(value, errors="replace")
    if not isinstance(value, str):
        return value
    if itemsep == "; " and "; " not in value and ";" in value:
        # Some servers omit the space after the semicolon in Cookie headers.
        itemsep = ";"

    prefix = ""
    if keep_question_mark:
        if value.startswith("?"):
            prefix = "?"
            value = value[1:]
        elif leading_question:
            prefix = "?"

    items = value.split(itemsep)
    redacted_items = []
    changed = False
    for item in items:
        pieces = item.split(kvsep, 1)
        if len(pieces) == 2 and _is_sensitive_key(pieces[0], names):
            _remember_secret(pieces[1], secrets)
            redacted_items.append(kvsep.join((pieces[0], MASK)))
            changed = True
        else:
            redacted_items.append(item)
    if not changed:
        return prefix + value
    return prefix + itemsep.join(redacted_items)


def _is_sensitive_key(key, names):
    if not isinstance(key, str) or not key:
        return False
    key = key.strip().lower()
    return any(pattern.match(key) for pattern in names)


def _remember_secret(value, secrets):
    if isinstance(value, bytes):
        value = force_text(value, errors="replace")
    if isinstance(value, str) and len(value) >= _SECRET_SCRUB_MIN_LENGTH and value != MASK:
        secrets.add(value)


def _scrub_secret_values(value, secrets):
    if isinstance(value, str):
        for secret in sorted(secrets, key=len, reverse=True):
            if secret and secret in value:
                value = value.replace(secret, MASK)
        return value
    if isinstance(value, dict):
        return {key: _scrub_secret_values(val, secrets) for key, val in value.items()}
    if isinstance(value, (list, tuple)):
        return [_scrub_secret_values(item, secrets) for item in value]
    return value
