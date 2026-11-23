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


from contextvars import ContextVar, Token
from typing import Any, Collection, Dict, Mapping, NamedTuple, Optional

try:
    import simplejson as json
except ImportError:
    import json  # type: ignore

import uuid
from datetime import date, datetime
from decimal import Decimal

from .compat import string_types
from .exceptions import (
    ImproperlyConfigured,
    SerializationError,
    UnsupportedResponseFormatError,
)
from .helpers.utils import AttrList

INTEGER_TYPES = ()
FLOAT_TYPES = (Decimal,)
TIME_TYPES = (date, datetime)


class Serializer:
    mimetype: str = ""

    def loads(self, s: str) -> Any:
        raise NotImplementedError()

    def dumps(self, data: Any) -> Any:
        raise NotImplementedError()


class TextSerializer(Serializer):
    mimetype: str = "text/plain"

    def loads(self, s: str) -> Any:
        return s

    def dumps(self, data: Any) -> Any:
        if isinstance(data, string_types):
            return data

        raise SerializationError(f"Cannot serialize {data!r} into text.")


class JSONSerializer(Serializer):
    mimetype: str = "application/json"

    def default(self, data: Any) -> Any:
        if isinstance(data, TIME_TYPES):
            # Little hack to avoid importing pandas but to not
            # return 'NaT' string for pd.NaT as that's not a valid
            # date.
            formatted_data = data.isoformat()
            if formatted_data != "NaT":
                return formatted_data

        if isinstance(data, uuid.UUID):
            return str(data)
        elif isinstance(data, FLOAT_TYPES):
            return float(data)
        elif INTEGER_TYPES and isinstance(data, INTEGER_TYPES):
            return int(data)

        # Special cases for numpy and pandas types
        # These are expensive to import so we try them last.
        try:
            import numpy as np

            if isinstance(
                data,
                (
                    np.int_,
                    np.intc,
                    np.int8,
                    np.int16,
                    np.int32,
                    np.int64,
                    np.uint8,
                    np.uint16,
                    np.uint32,
                    np.uint64,
                ),
            ):
                return int(data)
            elif isinstance(
                data,
                (
                    np.float16,
                    np.float32,
                    np.float64,
                ),
            ):
                return float(data)
            elif isinstance(data, np.bool_):
                return bool(data)
            elif isinstance(data, np.datetime64):
                return data.item().isoformat()
            elif isinstance(data, np.ndarray):
                return data.tolist()
        except ImportError:
            pass

        try:
            import pandas as pd

            if isinstance(data, (pd.Series, pd.Categorical)):
                return data.tolist()
            elif isinstance(data, pd.Timestamp) and data is not getattr(
                pd, "NaT", None
            ):
                return data.isoformat()
            elif data is getattr(pd, "NA", None):
                return None
        except ImportError:
            pass

        raise TypeError(f"Unable to serialize {data!r} (type: {type(data)})")

    def loads(self, s: str) -> Any:
        try:
            return json.loads(s)
        except (ValueError, TypeError) as e:
            raise SerializationError(s, e)

    def dumps(self, data: Any) -> Any:
        # don't serialize strings
        if isinstance(data, string_types):
            return data

        try:
            return json.dumps(
                data, default=self.default, ensure_ascii=False, separators=(",", ":")
            )
        except (ValueError, TypeError) as e:
            raise SerializationError(data, e)


DEFAULT_SERIALIZERS: Dict[str, Serializer] = {
    JSONSerializer.mimetype: JSONSerializer(),
    TextSerializer.mimetype: TextSerializer(),
}


def normalize_mimetype(mimetype: Optional[str]) -> Optional[str]:
    """
    Normalize a response media type for comparison.

    Strips media type parameters (e.g. ``charset``), surrounding whitespace
    and case, and maps vendor JSON types to ``application/json``. Returns
    ``None`` when no media type is given.
    """
    if not mimetype:
        return None
    if not isinstance(mimetype, str):
        return None
    normalized = mimetype.partition(";")[0].strip().lower()
    if not normalized:
        return None
    if normalized == "application/vnd.elasticsearch+json":
        return JSONSerializer.mimetype
    return normalized


def _allowed_mimetypes_to_mapping(
    allowed_mimetypes: Optional[Collection[str]],
) -> Optional[Dict[str, Optional[Serializer]]]:
    if allowed_mimetypes is None:
        return None
    if isinstance(allowed_mimetypes, str):
        allowed_mimetypes = (allowed_mimetypes,)
    if isinstance(allowed_mimetypes, Mapping):
        return {
            normalize_mimetype(mimetype) or mimetype: serializer
            for mimetype, serializer in allowed_mimetypes.items()
        }
    return {
        normalize_mimetype(mimetype) or mimetype: None for mimetype in allowed_mimetypes
    }


class _ResponsePolicy(NamedTuple):
    allowed_mimetypes: Optional[Collection[str]]
    default_mimetype: Optional[str]


# The operation currently executing on this context. It lets the connection
# layer keep trace previews away from responses the request may not decode.
# A single context variable keeps the set/reset pair atomic even when
# requests are nested.
_CURRENT_POLICY: ContextVar[Optional[_ResponsePolicy]] = ContextVar(
    "opensearchpy_response_policy", default=None
)


def set_allowed_mimetypes(
    allowed_mimetypes: Optional[Collection[str]],
    default_mimetype: Optional[str] = None,
) -> "Token[Optional[_ResponsePolicy]]":
    """
    Record the response media types approved for the operation currently
    being executed.
    """
    if allowed_mimetypes is None:
        normalized = None
    else:
        if isinstance(allowed_mimetypes, str):
            allowed_mimetypes = (allowed_mimetypes,)
        normalized = tuple(
            normalize_mimetype(mimetype) or mimetype for mimetype in allowed_mimetypes
        )
    policy = _ResponsePolicy(
        allowed_mimetypes=normalized,
        default_mimetype=normalize_mimetype(default_mimetype),
    )
    return _CURRENT_POLICY.set(policy)


def reset_allowed_mimetypes(
    token: "Token[Optional[_ResponsePolicy]]",
) -> None:
    _CURRENT_POLICY.reset(token)


def current_allowed_mimetypes() -> Optional[Collection[str]]:
    policy = _CURRENT_POLICY.get()
    return policy.allowed_mimetypes if policy is not None else None


def current_default_mimetype() -> Optional[str]:
    policy = _CURRENT_POLICY.get()
    return policy.default_mimetype if policy is not None else None


class Deserializer:
    def __init__(
        self,
        serializers: Dict[str, Serializer],
        default_mimetype: str = "application/json",
    ) -> None:
        try:
            self.default = serializers[default_mimetype]
        except KeyError:
            raise ImproperlyConfigured(
                f"Cannot find default serializer ({default_mimetype})"
            )
        self.serializers = serializers
        self.default_mimetype = default_mimetype

    def _resolve(
        self,
        mimetype: Optional[str],
        allowed_mimetypes: Optional[Collection[str]] = None,
    ) -> Serializer:
        """
        Resolve the decoder for a response under a per-request allowlist.

        ``allowed_mimetypes`` may be a collection of media types or a mapping
        of media types to serializer instances. A mapping entry supplies the
        decoder for that request without changing the client-wide registry.
        """
        declared = normalize_mimetype(mimetype)
        effective = declared or normalize_mimetype(self.default_mimetype)
        assert effective is not None

        allowed = _allowed_mimetypes_to_mapping(allowed_mimetypes)
        if allowed is not None and effective not in allowed:
            raise UnsupportedResponseFormatError(effective, allowed.keys())

        if allowed is not None and allowed.get(effective) is not None:
            return allowed[effective]  # type: ignore[return-value]

        try:
            return self.serializers[effective]
        except KeyError:
            raise SerializationError(
                f"Unknown mimetype, unable to deserialize: {effective}"
            )

    def loads(
        self,
        s: str,
        mimetype: Optional[str] = None,
        allowed_mimetypes: Optional[Collection[str]] = None,
    ) -> Any:
        return self._resolve(mimetype, allowed_mimetypes).loads(s)


class AttrJSONSerializer(JSONSerializer):
    def default(self, data: Any) -> Any:
        if isinstance(data, AttrList):
            return data._l_
        if hasattr(data, "to_dict"):
            return data.to_dict()
        return super().default(data)


serializer = AttrJSONSerializer()
