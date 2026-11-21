# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.
#
#  Licensed to Elasticsearch B.V. under one or more contributor
#  license agreements. See the NOTICE file distributed with
#  this work for additional information regarding copyright
#  ownership. Elasticsearch B.V. licenses this file to you under
#  the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing,
#  software distributed under the License is distributed on an
#  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#  KIND, either express or implied.  See the License for the
#  specific language governing permissions and limitations
#  under the License.

import gzip
import io
import logging
import os
import re
import warnings
from platform import python_version
from typing import Any, Collection, Dict, List, Mapping, Optional, Union
from urllib.parse import urlsplit, urlunsplit

try:
    import simplejson as json
except ImportError:
    import json  # type: ignore

from .._version import __versionstr__
from ..exceptions import HTTP_EXCEPTIONS, OpenSearchWarning, TransportError

logger = logging.getLogger("opensearch")

# create the opensearchpy.trace logger, but only set propagate to False if the
# logger hasn't already been configured
TRACER_ALREADY_CONFIGURED = "opensearchpy.trace" in logging.Logger.manager.loggerDict
tracer = logging.getLogger("opensearchpy.trace")
if not TRACER_ALREADY_CONFIGURED:
    tracer.propagate = False

_WARNING_RE = re.compile(r"\"([^\"]*)\"")


class DebugTraceRecorder:
    """
    Collects sanitized request/response records that are safe to share with
    support when debugging search issues.

    Each record preserves the method and the structure of parameters and the
    query body, while authentication material (credentials in headers or in
    the URL) and caller-specified query body fields are replaced with a
    placeholder. Recording never mutates the live request or the data
    returned to the caller; only sanitized copies are kept.

    :arg redact_body_fields: names of JSON body fields whose values must be
        redacted (matched case-insensitively, at any nesting level)
    :arg extra_sensitive_headers: additional header names to redact on top
        of the built-in authentication headers
    """

    REDACTED = "<redacted>"

    DEFAULT_SENSITIVE_HEADERS = frozenset(
        {
            "authorization",
            "proxy-authorization",
            "x-api-key",
            "x-amz-security-token",
            "x-amz-credential",
            "cookie",
            "set-cookie",
        }
    )

    def __init__(
        self,
        redact_body_fields: Collection[str] = (),
        extra_sensitive_headers: Collection[str] = (),
    ) -> None:
        self.redact_body_fields = frozenset(
            field.lower() for field in redact_body_fields
        )
        self.sensitive_headers = self.DEFAULT_SENSITIVE_HEADERS | frozenset(
            header.lower() for header in extra_sensitive_headers
        )
        self.records: List[Dict[str, Any]] = []

    def record(
        self,
        method: str,
        url: str,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        body: Optional[Union[str, bytes]] = None,
        status_code: Optional[int] = None,
        response: Optional[str] = None,
        duration: Optional[float] = None,
        error: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Capture one sanitized trace + actual request/response pair."""
        entry = {
            "method": method,
            "url": self._sanitize_url(url),
            "params": dict(params) if params else {},
            "request": {
                "headers": self._sanitize_headers(headers),
                "body": self._sanitize_body(body),
            },
            "trace": self._build_trace(method, url, body),
            "response": {
                "status": status_code,
                "duration": duration,
                "body": response,
            },
            "error": error,
        }
        self.records.append(entry)
        return entry

    def clear(self) -> None:
        self.records[:] = []

    def to_dict(self) -> Dict[str, Any]:
        """Export the shareable record; everything in it is sanitized."""
        return {"records": json.loads(json.dumps(self.records, default=str))}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def _sanitize_headers(
        self, headers: Optional[Mapping[str, str]]
    ) -> Dict[str, str]:
        sanitized = {}
        for key, value in (headers or {}).items():
            if key.lower() in self.sensitive_headers:
                sanitized[key] = self.REDACTED
            else:
                sanitized[key] = value
        return sanitized

    def _sanitize_url(self, url: str) -> str:
        try:
            parts = urlsplit(url)
        except ValueError:
            return url
        if parts.username is None and parts.password is None:
            return url
        host = parts.hostname or ""
        if parts.port is not None:
            host = f"{host}:{parts.port}"
        return urlunsplit(parts._replace(netloc=host))

    def _sanitize_body(self, body: Optional[Union[str, bytes]]) -> Any:
        if body is None:
            return None
        if isinstance(body, bytes):
            body = body.decode("utf-8", "ignore")
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError):
            # non-JSON payloads (e.g. bulk NDJSON) are kept as-is
            return body
        return self._redact_fields(parsed)

    def _redact_fields(self, data: Any) -> Any:
        if isinstance(data, dict):
            return {
                key: (
                    self.REDACTED
                    if key.lower() in self.redact_body_fields
                    else self._redact_fields(value)
                )
                for key, value in data.items()
            }
        if isinstance(data, list):
            return [self._redact_fields(item) for item in data]
        return data

    def _build_trace(
        self, method: str, url: str, body: Optional[Union[str, bytes]]
    ) -> str:
        url = self._sanitize_url(url)
        url = url.replace("?", "?pretty&", 1) if "?" in url else url + "?pretty"
        sanitized_body = self._sanitize_body(body)
        if sanitized_body is not None and not isinstance(sanitized_body, str):
            sanitized_body = json.dumps(
                sanitized_body, sort_keys=True, indent=2, separators=(",", ": ")
            ).replace("'", r"\u0027")
        return "curl %s-X%s '%s' -d '%s'" % (
            "-H 'Content-Type: application/json' " if body else "",
            method,
            url,
            sanitized_body or "",
        )


class Connection:
    """
    Class responsible for maintaining a connection to an OpenSearch node. It
    holds persistent connection pool to it and its main interface
    (`perform_request`) is thread-safe.

    Also responsible for logging.

    :arg host: hostname of the node (default: localhost)
    :arg port: port to use (integer, default: 9200)
    :arg use_ssl: use ssl for the connection if `True`
    :arg url_prefix: optional url prefix for opensearch
    :arg timeout: default timeout in seconds (float, default: 10)
    :arg http_compress: Use gzip compression
    :arg opaque_id: Send this value in the 'X-Opaque-Id' HTTP header
        For tracing all requests made by this transport.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: Optional[int] = None,
        use_ssl: bool = False,
        url_prefix: str = "",
        timeout: int = 10,
        headers: Optional[Dict[str, str]] = None,
        http_compress: Optional[bool] = None,
        opaque_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        if port is None:
            port = 9200

        # Work-around if the implementing class doesn't
        # define the headers property before calling super().__init__()
        if not hasattr(self, "headers"):
            self.headers = {}

        headers = headers or {}
        for key in headers:
            self.headers[key.lower()] = headers[key]
        if opaque_id:
            self.headers["x-opaque-id"] = opaque_id

        if os.getenv("ELASTIC_CLIENT_APIVERSIONING") == "1":
            self.headers.setdefault(
                "accept", "application/vnd.elasticsearch+json;compatible-with=7"
            )

        self.headers.setdefault("content-type", "application/json")
        self.headers.setdefault("user-agent", self._get_default_user_agent())

        if http_compress:
            self.headers["accept-encoding"] = "gzip,deflate"

        scheme = kwargs.get("scheme", "http")
        if use_ssl or scheme == "https":
            scheme = "https"
            use_ssl = True
        self.use_ssl = use_ssl
        self.http_compress = http_compress or False

        self.scheme = scheme
        self.hostname = host
        self.port = port
        if ":" in host:  # IPv6
            self.host = f"{scheme}://[{host}]"
        else:
            self.host = f"{scheme}://{host}"
        if self.port is not None:
            self.host += f":{self.port}"
        if url_prefix:
            url_prefix = "/" + url_prefix.strip("/")
        self.url_prefix = url_prefix
        self.timeout = timeout
        self.debug_recorder: Optional[DebugTraceRecorder] = None

    def enable_debug_trace(
        self,
        redact_body_fields: Collection[str] = (),
        extra_sensitive_headers: Collection[str] = (),
    ) -> DebugTraceRecorder:
        """
        Start recording sanitized, shareable debug traces for every request
        made through this connection. Returns the recorder holding the
        records; call :meth:`disable_debug_trace` to stop recording.
        """
        self.debug_recorder = DebugTraceRecorder(
            redact_body_fields=redact_body_fields,
            extra_sensitive_headers=extra_sensitive_headers,
        )
        return self.debug_recorder

    def disable_debug_trace(self) -> None:
        """Stop recording debug traces; kept records stay on the recorder."""
        self.debug_recorder = None

    def _record_debug_trace(
        self,
        method: str,
        url: str,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        body: Optional[Union[str, bytes]] = None,
        status_code: Optional[int] = None,
        response: Optional[str] = None,
        duration: Optional[float] = None,
        error: Optional[str] = None,
    ) -> None:
        recorder = self.debug_recorder
        if recorder is None:
            return
        try:
            recorder.record(
                method,
                url,
                params=params,
                headers=headers,
                body=body,
                status_code=status_code,
                response=response,
                duration=duration,
                error=error,
            )
        except Exception:
            # recording must never break the actual request
            logger.warning("Failed to record debug trace", exc_info=True)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self.host}>"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Connection):
            raise TypeError(f"Unsupported equality check for {self} and {other}")
        return self.__hash__() == other.__hash__()

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Connection):
            raise TypeError(f"Unsupported lt check for {self} and {other}")
        return self.__hash__() < other.__hash__()

    def __hash__(self) -> int:
        return id(self)

    def _gzip_compress(self, body: Any) -> bytes:
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as f:
            f.write(body)
        return buf.getvalue()

    def _raise_warnings(self, warning_headers: Any) -> None:
        """If 'headers' contains a 'Warning' header raise
        the warnings to be seen by the user. Takes an iterable
        of string values from any number of 'Warning' headers.
        """
        if not warning_headers:
            return

        # Grab only the message from each header, the rest is discarded.
        # Format is: '(number) OpenSearch-(version)-(instance) "(message)"'
        warning_messages = []
        for header in warning_headers:
            # Because 'Requests' does its own folding of multiple HTTP headers
            # into one header delimited by commas (totally standard compliant, just
            # annoying for cases like this) we need to expect there may be
            # more than one message per 'Warning' header.
            matches = _WARNING_RE.findall(header)
            if matches:
                warning_messages.extend(matches)
            else:
                # Don't want to throw away any warnings, even if they
                # don't follow the format we have now. Use the whole header.
                warning_messages.append(header)

        for message in warning_messages:
            warnings.warn(message, category=OpenSearchWarning)

    def _pretty_json(self, data: Union[str, bytes]) -> str:
        # pretty JSON in tracer curl logs
        try:
            return json.dumps(
                json.loads(data), sort_keys=True, indent=2, separators=(",", ": ")
            ).replace("'", r"\u0027")
        except (ValueError, TypeError):
            # non-json data or a bulk request
            return data  # type: ignore

    def _log_request_response(
        self, body: Optional[Union[str, bytes]], response: Optional[str]
    ) -> None:
        if logger.isEnabledFor(logging.DEBUG):
            if body and isinstance(body, bytes):
                body = body.decode("utf-8", "ignore")
            logger.debug("> %s", body)
            if response is not None:
                logger.debug("< %s", response)

    def _log_trace(
        self,
        method: str,
        path: str,
        body: Optional[Union[str, bytes]],
        status_code: Optional[int],
        response: Optional[str],
        duration: Optional[float],
    ) -> None:
        if not tracer.isEnabledFor(logging.INFO) or not tracer.handlers:
            return

        # include pretty in trace curls
        path = path.replace("?", "?pretty&", 1) if "?" in path else path + "?pretty"
        if self.url_prefix:
            path = path.replace(self.url_prefix, "", 1)
        tracer.info(
            "curl %s-X%s 'http://localhost:9200%s' -d '%s'",
            "-H 'Content-Type: application/json' " if body else "",
            method,
            path,
            self._pretty_json(body) if body else "",
        )

        if tracer.isEnabledFor(logging.DEBUG):
            tracer.debug(
                "#[%s] (%.3fs)\n#%s",
                status_code,
                duration,
                self._pretty_json(response).replace("\n", "\n#") if response else "",
            )

    def perform_request(
        self,
        method: str,
        url: str,
        params: Optional[Mapping[str, Any]] = None,
        body: Optional[bytes] = None,
        timeout: Optional[Union[int, float]] = None,
        ignore: Collection[int] = (),
        headers: Optional[Mapping[str, str]] = None,
    ) -> Any:
        raise NotImplementedError()

    def log_request_success(
        self,
        method: str,
        full_url: str,
        path: str,
        body: Any,
        status_code: int,
        response: str,
        duration: float,
    ) -> None:
        """Log a successful API call."""
        #  TODO: optionally pass in params instead of full_url and do urlencode only when needed

        logger.info(
            "%s %s [status:%s request:%.3fs]", method, full_url, status_code, duration
        )

        self._log_request_response(body, response)
        self._log_trace(method, path, body, status_code, response, duration)

    def log_request_fail(
        self,
        method: str,
        full_url: str,
        path: str,
        body: Any,
        duration: float,
        status_code: Optional[int] = None,
        response: Optional[str] = None,
        exception: Optional[Exception] = None,
    ) -> None:
        """Log an unsuccessful API call."""
        # do not log 404s on HEAD requests
        if method == "HEAD" and status_code == 404:
            return
        logger.warning(
            "%s %s [status:%s request:%.3fs]",
            method,
            full_url,
            status_code or "N/A",
            duration,
            exc_info=exception is not None,
        )

        self._log_request_response(body, response)
        self._log_trace(method, path, body, status_code, response, duration)

    def _raise_error(
        self,
        status_code: int,
        raw_data: Union[str, bytes],
        content_type: Optional[str] = None,
    ) -> None:
        """Locate appropriate exception and raise it."""
        error_message = raw_data
        additional_info = None
        try:
            content_type = (
                "text/plain"
                if content_type is None
                else content_type.split(";")[0].strip()
            )
            if raw_data and content_type == "application/json":
                additional_info = json.loads(raw_data)
                error_message = additional_info.get("error", error_message)
                if isinstance(error_message, dict) and "type" in error_message:
                    error_message = error_message["type"]
        except (ValueError, TypeError) as err:
            logger.warning("Undecodable raw error response from server: %s", err)

        raise HTTP_EXCEPTIONS.get(status_code, TransportError)(
            status_code, error_message, additional_info
        )

    def _get_default_user_agent(self) -> str:
        return f"opensearch-py/{__versionstr__} (Python {python_version()})"

    @staticmethod
    def default_ca_certs() -> Union[str, None]:
        """
        Get the default CA certificate bundle, preferring those configured in
        the standard OpenSSL environment variables before those provided by
        certifi (if available)
        """
        ca_certs = os.environ.get("SSL_CERT_FILE") or os.environ.get("SSL_CERT_DIR")

        if not ca_certs:
            try:
                import certifi

                ca_certs = certifi.where()
            except ImportError:
                pass

        return ca_certs
