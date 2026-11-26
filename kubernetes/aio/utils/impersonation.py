# Copyright 2026 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Kubernetes impersonation headers for the asynchronous client.

The async package is packaged separately from ``kubernetes``, so it cannot
import the synchronous helper. This module is deliberately identical in
behaviour to ``kubernetes/utils/impersonation.py``; keep both copies in sync.
"""

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Tuple, Union

IMPERSONATE_USER = "Impersonate-User"
IMPERSONATE_GROUP = "Impersonate-Group"
IMPERSONATE_UID = "Impersonate-Uid"
IMPERSONATE_EXTRA_PREFIX = "Impersonate-Extra-"

SINGLE_VALUE_HEADERS = frozenset({IMPERSONATE_USER, IMPERSONATE_UID})

# Sentinel used by the API client to distinguish "not supplied" from an
# explicit ``None`` (which means "no impersonation for this call").
UNSET = object()


class ImpersonationError(ValueError):
    """Raised when an impersonation configuration cannot be applied."""


@dataclass(frozen=True)
class ImpersonationRequest:
    """A frozen snapshot of impersonation headers for one logical call."""

    headers: Tuple[Tuple[str, str], ...]

    def __post_init__(self):
        seen_single = {}
        for name, value in self.headers:
            if not isinstance(name, str) or not isinstance(value, str):
                raise ImpersonationError(
                    "impersonation header names and values must be strings")
            if not value:
                raise ImpersonationError(
                    "%s must not be empty" % name)
            lowered = name.lower()
            if name in SINGLE_VALUE_HEADERS:
                if lowered in seen_single:
                    raise ImpersonationError(
                        "%s may only be supplied once" % name)
                seen_single[lowered] = value
            elif name != IMPERSONATE_GROUP and not name.lower().startswith(
                    IMPERSONATE_EXTRA_PREFIX.lower()):
                raise ImpersonationError(
                    "unsupported impersonation header %r" % name)

    @property
    def user(self) -> Optional[str]:
        for name, value in self.headers:
            if name == IMPERSONATE_USER:
                return value
        return None

    @property
    def groups(self) -> Tuple[str, ...]:
        return tuple(value for name, value in self.headers
                     if name == IMPERSONATE_GROUP)

    @property
    def uid(self) -> Optional[str]:
        for name, value in self.headers:
            if name == IMPERSONATE_UID:
                return value
        return None

    def extra(self, name: str) -> Tuple[str, ...]:
        target = (IMPERSONATE_EXTRA_PREFIX + name).lower()
        return tuple(value for header, value in self.headers
                     if header.lower() == target)

    def __bool__(self) -> bool:
        return bool(self.headers)

    def apply(self, headers):
        """Return a copy of ``headers`` with this snapshot's values.

        Re-applying the same snapshot to headers that already contain it is
        idempotent, so a page request or a retry that reuses the serialized
        headers cannot duplicate or drop identity lines.

        Existing impersonation headers in ``headers`` are removed first so a
        stale default can never be merged with a different identity. Other
        header names are preserved. A name that occurs more than once in the
        snapshot is returned as a list value, which the client expands back
        into repeated header lines for the wire so the API server sees each
        ``Impersonate-Group`` and ``Impersonate-Extra-*`` value separately.
        """
        if not headers:
            result = {}
        elif hasattr(headers, "items"):
            result = {}
            for name, value in headers.items():
                result[name] = value
        else:
            result = dict(headers)

        for existing in list(result):
            lowered = existing.lower()
            if lowered in (IMPERSONATE_USER.lower(),
                           IMPERSONATE_GROUP.lower(),
                           IMPERSONATE_UID.lower()) or \
                    lowered.startswith(IMPERSONATE_EXTRA_PREFIX.lower()):
                del result[existing]

        for name, value in self.headers:
            existing = result.get(name)
            if existing is None:
                result[name] = value
            elif isinstance(existing, list):
                result[name] = existing + [value]
            else:
                result[name] = [existing, value]
        return result

    def to_dict(self) -> dict:
        return dict(self.headers)


def _normalize_groups(groups: Union[None, str, Iterable[str]]
                      ) -> Tuple[str, ...]:
    if groups is None:
        return ()
    if isinstance(groups, str):
        return (groups,)
    normalized = []
    for group in groups:
        if not isinstance(group, str):
            raise ImpersonationError("impersonation groups must be strings")
        normalized.append(group)
    return tuple(normalized)


def _normalize_extra(extra: Union[None, Mapping[str, Any]]) -> Tuple[Tuple[str, str], ...]:
    if not extra:
        return ()
    rows = []
    for name, values in extra.items():
        header = IMPERSONATE_EXTRA_PREFIX + str(name)
        if isinstance(values, str):
            rows.append((header, values))
            continue
        try:
            iterator = list(values)
        except TypeError:
            raise ImpersonationError(
                "impersonation extra value for %r must be a string or an "
                "iterable of strings" % name)
        for value in iterator:
            if not isinstance(value, str):
                raise ImpersonationError(
                    "impersonation extra value for %r must be a string" % name)
            rows.append((header, value))
    return tuple(rows)


def extra_from_headers(snapshot: ImpersonationRequest) -> dict:
    """Group ``Impersonate-Extra-*`` values of a snapshot by their key."""
    extra = {}
    for name, value in snapshot.headers:
        lowered = name.lower()
        if lowered.startswith(IMPERSONATE_EXTRA_PREFIX.lower()):
            extra.setdefault(
                name[len(IMPERSONATE_EXTRA_PREFIX):], []).append(value)
    return extra


def config_from_snapshot(snapshot: ImpersonationRequest) -> "ImpersonationConfig":
    """Rebuild a mutable config from a frozen snapshot."""
    return ImpersonationConfig(
        user=snapshot.user,
        groups=snapshot.groups,
        uid=snapshot.uid,
        extra=extra_from_headers(snapshot) or None,
    )


def resolve_impersonation(user: Optional[str] = None,
                          groups: Union[None, str, Iterable[str]] = None,
                          uid: Optional[str] = None,
                          extra: Union[None, Mapping[str, Any]] = None,
                          ) -> ImpersonationRequest:
    """Build a frozen snapshot from Kubernetes impersonation fields."""
    if user is None and groups is None and uid is None and extra is None:
        return ImpersonationRequest(())
    if user is None:
        raise ImpersonationError(
            "impersonation requires a user")
    rows: list[Tuple[str, str]] = [(IMPERSONATE_USER, user)]
    for group in _normalize_groups(groups):
        rows.append((IMPERSONATE_GROUP, group))
    if uid is not None:
        rows.append((IMPERSONATE_UID, uid))
    rows.extend(_normalize_extra(extra))
    return ImpersonationRequest(tuple(rows))


def from_headers(headers) -> ImpersonationRequest:
    """Extract the impersonation snapshot carried by request headers.

    ``headers`` may be a mapping (``dict``, ``HTTPHeaderDict``,
    ``CIMultiDict``) or an iterable of ``(name, value)`` pairs. Values may be
    lists to express repeated header lines, which is how a caller passes
    multiple groups through the generated ``_headers`` argument.
    """
    if not headers:
        return ImpersonationRequest(())
    items = headers.items() if hasattr(headers, "items") else headers
    rows = []
    for name, value in items:
        if not isinstance(name, str):
            continue
        lowered = name.lower()
        if not (lowered == IMPERSONATE_USER.lower()
                or lowered == IMPERSONATE_GROUP.lower()
                or lowered == IMPERSONATE_UID.lower()
                or lowered.startswith(IMPERSONATE_EXTRA_PREFIX.lower())):
            continue
        canonical = name
        if lowered == IMPERSONATE_USER.lower():
            canonical = IMPERSONATE_USER
        elif lowered == IMPERSONATE_GROUP.lower():
            canonical = IMPERSONATE_GROUP
        elif lowered == IMPERSONATE_UID.lower():
            canonical = IMPERSONATE_UID
        else:
            canonical = IMPERSONATE_EXTRA_PREFIX + name[
                len(IMPERSONATE_EXTRA_PREFIX):]
        if isinstance(value, (list, tuple)):
            for entry in value:
                rows.append((canonical, entry))
        else:
            rows.append((canonical, value))
    return ImpersonationRequest(tuple(rows))




def resolve(value: Any) -> ImpersonationRequest:
    """Normalize supported impersonation inputs to one snapshot."""
    if value is None:
        return ImpersonationRequest(())
    if isinstance(value, ImpersonationRequest):
        return value
    if isinstance(value, ImpersonationConfig):
        return value.snapshot()
    if isinstance(value, (list, tuple)):
        return from_headers(value)
    if not isinstance(value, Mapping):
        raise ImpersonationError(
            "impersonation must be an ImpersonationConfig, an "
            "ImpersonationRequest, a mapping of Impersonate-* headers, or "
            "None")
    if any(str(key).lower().startswith("impersonate-") for key in value):
        return from_headers(value.items())
    unknown = set(value) - {"user", "groups", "uid", "extra"}
    if unknown:
        raise ImpersonationError(
            "unknown impersonation key(s): %s" % ", ".join(sorted(unknown)))
    return resolve_impersonation(
        user=value.get("user"),
        groups=value.get("groups"),
        uid=value.get("uid"),
        extra=value.get("extra"),
    )


class ImpersonationConfig:
    """Describes the Kubernetes identity an approved call impersonates."""

    def __init__(self,
                 user: Optional[str] = None,
                 groups: Union[None, str, Iterable[str]] = None,
                 uid: Optional[str] = None,
                 extra: Union[None, Mapping[str, Any]] = None,
                 *,
                 user_name: Optional[str] = None,
                 ) -> None:
        if user is not None and user_name is not None and user != user_name:
            raise ImpersonationError(
                "user and user_name disagree")
        self.user_name = user if user is not None else user_name
        self.groups = groups
        self.uid = uid
        self.extra = extra

    @property
    def user(self) -> Optional[str]:
        return self.user_name

    @user.setter
    def user(self, value: Optional[str]) -> None:
        self.user_name = value

    def as_dict(self) -> dict:
        return {
            "user": self.user_name,
            "groups": self.groups,
            "uid": self.uid,
            "extra": self.extra,
        }

    def snapshot(self) -> ImpersonationRequest:
        return resolve_impersonation(
            user=self.user_name,
            groups=self.groups,
            uid=self.uid,
            extra=self.extra,
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ImpersonationConfig):
            return NotImplemented
        return (self.user_name == other.user_name
                and _normalize_groups(self.groups)
                == _normalize_groups(other.groups)
                and self.uid == other.uid
                and _normalize_extra(self.extra) == _normalize_extra(
                    other.extra))

    def __repr__(self) -> str:
        return ("ImpersonationConfig(user=%r, groups=%r, uid=%r, extra=%r)"
                % (self.user_name, self.groups, self.uid, self.extra))
