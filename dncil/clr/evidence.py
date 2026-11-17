# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

import abc
import enum
from dataclasses import field, dataclass
from typing import Any, Dict, List, Tuple, Optional, Iterable, FrozenSet

from dncil.clr.token import USER_STRING_TABLE, MetadataTable, Token, TokenKind


class UnresolvedReason(enum.Enum):
    """why a token request could not be interpreted"""

    EMPTY_TOKEN = "empty token"
    INVALID_TABLE = "invalid metadata table"
    KIND_MISMATCH = "table not allowed for this operand context"
    MISSING_TABLE = "metadata table is not present"
    MISSING_ROW = "metadata row is not present"
    MISSING_USER_STRING = "user string is not present or decodable"
    PROVIDER_ERROR = "metadata provider raised an error"


@dataclass(frozen=True)
class TokenRequest:
    """a metadata lookup with the operand context that constrains its meaning"""

    token: Token
    kind: TokenKind
    offset: int

    @property
    def expected_tables(self) -> FrozenSet[MetadataTable]:
        """get metadata tables allowed for this request's kind"""
        return self.kind.expected_tables

    @property
    def is_user_string(self) -> bool:
        """check if this request names a #US heap entry"""
        return self.kind.is_user_string

    @property
    def table(self) -> int:
        """get the token's table index"""
        return self.token.table

    @property
    def rid(self) -> int:
        """get the token's row index"""
        return self.token.rid

    def __str__(self) -> str:
        return "%s@0x%04X %s" % (self.kind.name, self.offset, self.token)

    def __repr__(self) -> str:
        return str(self)


@dataclass(frozen=True)
class ResolutionIssue:
    """structured reason why a token request is unresolved"""

    reason: UnresolvedReason
    token: Token
    detail: str
    table: Optional[MetadataTable] = None
    rid: int = 0

    def __str__(self) -> str:
        return "%s: %s" % (self.reason.name, self.detail)

    def __repr__(self) -> str:
        return str(self)


@dataclass(frozen=True)
class TokenResolution:
    """the result of one token request, resolved or explicitly unresolved"""

    request: TokenRequest
    value: Any = None
    issue: Optional[ResolutionIssue] = None

    def __post_init__(self) -> None:
        if self.issue is not None and self.value is not None:
            raise ValueError("a resolution cannot carry both a value and an issue")

    @property
    def resolved(self) -> bool:
        """check if the request was interpreted successfully"""
        return self.issue is None

    @property
    def kind(self) -> TokenKind:
        """get the expected token kind from the request"""
        return self.request.kind

    @property
    def token(self) -> Token:
        """get the original token from the request"""
        return self.request.token

    @property
    def value_int(self) -> int:
        """get the original token value"""
        return self.request.token.value

    @property
    def offset(self) -> int:
        """get the instruction/header offset from the request"""
        return self.request.offset

    def describe(self) -> str:
        """get a traceable one-line description of this result"""
        if self.issue is not None:
            return "%s -> unresolved (%s)" % (self.request, self.issue)
        return "%s -> %s" % (self.request, self.value)

    def __str__(self) -> str:
        return self.describe()

    def __repr__(self) -> str:
        return str(self)


class TokenResolver(abc.ABC):
    """validate token requests against a metadata provider and cache by kind and value

    Cache entries are keyed by ``(TokenKind, token.value)``. The same integer used by
    two different operand kinds is therefore never served from another kind's entry,
    and per-request offsets are attached after the cache lookup so reused tokens keep
    the position of each use.
    """

    def __init__(self) -> None:
        self._cache: Dict[Tuple[TokenKind, int], Tuple[Any, Optional[ResolutionIssue]]] = {}

    def resolve(self, request: TokenRequest) -> TokenResolution:
        """resolve one token request"""
        key = self.cache_key(request)
        if key not in self._cache:
            self._cache[key] = self._lookup(request)
        value, issue = self._cache[key]
        return TokenResolution(request=request, value=value, issue=issue)

    def resolve_all(self, requests: Iterable[TokenRequest]) -> List[TokenResolution]:
        """resolve requests in order, keeping one result per input"""
        return [self.resolve(request) for request in requests]

    def cache_key(self, request: TokenRequest) -> Tuple[TokenKind, int]:
        """get the cache key for a request"""
        return request.kind, request.token.value

    def cache_keys(self) -> Tuple[Tuple[TokenKind, int], ...]:
        """get cache keys in insertion order, useful for tracing"""
        return tuple(self._cache.keys())

    def report(self, requests: Iterable[TokenRequest]) -> "ResolutionReport":
        """resolve requests and group successful and unknown references"""
        return ResolutionReport(resolutions=self.resolve_all(requests))

    def clear_cache(self) -> None:
        """drop cached lookup outcomes"""
        self._cache.clear()

    def _lookup(self, request: TokenRequest) -> Tuple[Any, Optional[ResolutionIssue]]:
        token: Token = request.token
        kind: TokenKind = request.kind

        if token.value == 0:
            return None, self._issue(request, UnresolvedReason.EMPTY_TOKEN, "token value is zero")

        if kind.is_user_string:
            if token.table != USER_STRING_TABLE:
                return None, self._issue(
                    request,
                    UnresolvedReason.KIND_MISMATCH,
                    "expected a #US token for %s, got table 0x%02X" % (kind.name, token.table),
                )
            if token.rid == 0:
                return None, self._issue(request, UnresolvedReason.MISSING_USER_STRING, "user string index is zero")
            try:
                value = self.get_user_string(token.rid)
            except Exception as e:
                return None, self._issue(request, UnresolvedReason.PROVIDER_ERROR, str(e))
            if value is None:
                return None, self._issue(
                    request,
                    UnresolvedReason.MISSING_USER_STRING,
                    "no user string at index 0x%X" % token.rid,
                )
            return value, None

        if token.table == USER_STRING_TABLE:
            return None, self._issue(
                request,
                UnresolvedReason.KIND_MISMATCH,
                "a #US token cannot be used as %s" % kind.name,
            )

        try:
            table = MetadataTable(token.table)
        except ValueError:
            return None, self._issue(
                request,
                UnresolvedReason.INVALID_TABLE,
                "token table 0x%02X is not a metadata table" % token.table,
            )

        if table not in kind.expected_tables:
            return None, self._issue(
                request,
                UnresolvedReason.KIND_MISMATCH,
                "%s does not allow table %s" % (kind.name, table.name),
                table,
            )

        if token.rid == 0:
            return None, self._issue(request, UnresolvedReason.EMPTY_TOKEN, "row index is zero", table)

        try:
            present = self.has_table(table)
        except Exception as e:
            return None, self._issue(request, UnresolvedReason.PROVIDER_ERROR, str(e), table)
        if not present:
            return None, self._issue(
                request,
                UnresolvedReason.MISSING_TABLE,
                "table %s has no available rows" % table.name,
                table,
            )

        row_count: Optional[int] = self.table_row_count(table)
        if row_count is not None and token.rid > row_count:
            return None, self._issue(
                request,
                UnresolvedReason.MISSING_ROW,
                "table %s has no row 0x%X" % (table.name, token.rid),
                table,
            )

        try:
            value = self.get_table_row(table, token.rid)
        except (IndexError, KeyError):
            return None, self._issue(
                request,
                UnresolvedReason.MISSING_ROW,
                "table %s has no row 0x%X" % (table.name, token.rid),
                table,
            )
        except Exception as e:
            return None, self._issue(request, UnresolvedReason.PROVIDER_ERROR, str(e), table)
        if value is None:
            return None, self._issue(
                request,
                UnresolvedReason.MISSING_ROW,
                "table %s has no row 0x%X" % (table.name, token.rid),
                table,
            )

        return value, None

    def table_row_count(self, table: MetadataTable) -> Optional[int]:
        """get the row count for a present table, when the provider can report it"""
        return None

    def _issue(
        self,
        request: TokenRequest,
        reason: UnresolvedReason,
        detail: str,
        table: Optional[MetadataTable] = None,
    ) -> ResolutionIssue:
        if table is None and request.token.table != USER_STRING_TABLE:
            try:
                table = MetadataTable(request.token.table)
            except ValueError:
                table = None
        return ResolutionIssue(
            reason=reason,
            token=request.token,
            detail=detail,
            table=table,
            rid=request.token.rid,
        )

    @abc.abstractmethod
    def has_table(self, table: MetadataTable) -> bool:
        """check if a metadata table is present in the provider"""
        ...

    @abc.abstractmethod
    def get_table_row(self, table: MetadataTable, rid: int) -> Any:
        """get a 1-based metadata table row, or None when absent"""
        ...

    @abc.abstractmethod
    def get_user_string(self, rid: int) -> Any:
        """get a #US heap entry, or None when absent"""
        ...


@dataclass
class ResolutionReport:
    """resolved and unresolved token evidence kept separately for review"""

    resolutions: List[TokenResolution] = field(default_factory=list)

    @property
    def resolved(self) -> List[TokenResolution]:
        """get results that carry an interpreted value"""
        return [resolution for resolution in self.resolutions if resolution.resolved]

    @property
    def unresolved(self) -> List[TokenResolution]:
        """get results that carry a structured issue"""
        return [resolution for resolution in self.resolutions if not resolution.resolved]

    @property
    def complete(self) -> bool:
        """check if every request was interpreted"""
        return not self.unresolved

    def extend(self, resolutions: Iterable[TokenResolution]) -> None:
        """append results to the report"""
        self.resolutions.extend(resolutions)

    def describe(self, formatter: Optional[Any] = None) -> List[str]:
        """get one line per result, optionally formatting resolved values"""
        lines: List[str] = []
        for resolution in self.resolutions:
            if resolution.resolved:
                value = formatter(resolution.value) if formatter is not None else resolution.value
                lines.append("%s -> %s" % (resolution.request, value))
            else:
                issue = resolution.issue
                lines.append(
                    "%s -> unresolved [%s] %s" % (resolution.request, issue.reason.name, issue.detail)
                )
        return lines
