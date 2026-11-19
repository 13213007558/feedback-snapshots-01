########################################################################
# File name: scram_cache.py
# This file is part of: aiosasl
#
# LICENSE
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/>.
#
########################################################################
"""
Optional, bounded cache for SCRAM-derived secrets.

The expensive part of a SCRAM exchange is the PBKDF invocation which
derives the salted password from the prepared password, the salt and the
iteration count.  That result is independent of the nonce and of the
channel binding data, so it can be re-used for a new handshake as long as
the credentials and the PBKDF parameters did not change.

This module provides :class:`DerivedKeyCache`.  Cache entries are keyed by
:class:`DerivedKeyCacheKey`, which binds:

* the trusted credential version supplied by the application,
* the prepared (SASLprep'ed) username and password,
* the digest algorithm,
* the salt, and
* the iteration count.

Neither the raw password nor the salted password is part of the key.  The
password is represented by a keyed digest using a process-local random
secret, and the salted password is only ever stored as the value of an
entry.  The representations of keys and entries redact secret-derived
values so they can be logged safely.

The cache is synchronous by design: aiosasl invokes it from the event loop
and no I/O is involved.  Entries are evicted in least-recently-used order
when the capacity is exceeded, and expire after an absolute lifetime.  A
hit updates recency but does not extend the lifetime.

Concurrent derivations are permitted.  The cache exposes a monotonically
increasing :attr:`DerivedKeyCache.generation`.  A successful SCRAM
exchange publishes its derived secret together with the generation it
observed before deriving.  If the application calls
:meth:`DerivedKeyCache.invalidate` while a derivation is in flight, the
late result is rejected and never becomes visible to later handshakes.

To use the cache, share one instance between all authentication attempts
and pass it to :class:`aiosasl.SCRAM` or :class:`aiosasl.SCRAMPLUS` as
``cache=``.  Whenever a credential is rotated or revoked, call
:meth:`DerivedKeyCache.invalidate`, and make sure the credential version
changes as well.
"""

import collections
import hashlib
import hmac
import os
import time
import typing


_PASSWORD_TAG_CONTEXT = b"aiosasl SCRAM derived cache password tag\x00"

_DEFAULT_CAPACITY = 64
_DEFAULT_TTL = 300.0


class DerivedKeyCacheKey(collections.namedtuple(
        "DerivedKeyCacheKeyBase",
        [
            "credential_version",
            "username",
            "password_tag",
            "digest",
            "salt",
            "iteration_count",
        ])):
    """
    Identity of a cached SCRAM-derived secret.

    Instances are obtained from :meth:`DerivedKeyCache.make_key`; direct
    construction is not part of the public interface.

    .. attribute:: credential_version

       Trusted credential version supplied by the application.

    .. attribute:: username

       Prepared username, encoded as UTF-8.

    .. attribute:: password_tag

       Keyed digest of the prepared password.  It does not reveal the
       password and is not included in :func:`repr`.

    .. attribute:: digest

       Digest algorithm name, for example ``"sha256"``.

    .. attribute:: salt

       Decoded salt as :class:`bytes`.

    .. attribute:: iteration_count

       PBKDF iteration count.
    """

    __slots__ = ()

    def __str__(self) -> str:
        return self.__repr__()

    def __format__(self, format_spec: str) -> str:
        if format_spec:
            raise ValueError("cache keys have no format specification")
        return self.__repr__()

    def __repr__(self) -> str:
        return (
            "DerivedKeyCacheKey(credential_version={!r}, username={!r}, "
            "digest={!r}, salt={!r}, iteration_count={!r}, "
            "password_tag=<redacted>)".format(
                self.credential_version,
                self.username,
                self.digest,
                self.salt,
                self.iteration_count,
            )
        )


class _CacheEntry:
    __slots__ = ("salted_password", "expires_at")

    def __init__(self, salted_password: bytes, expires_at: float) -> None:
        self.salted_password = salted_password
        self.expires_at = expires_at

    def __repr__(self) -> str:
        return "<DerivedKeyCacheEntry salted_password=<redacted>>"

    def __str__(self) -> str:
        return self.__repr__()

    def __format__(self, format_spec: str) -> str:
        if format_spec:
            raise ValueError("cache entries have no format specification")
        return self.__repr__()


def _ttl_seconds(value: typing.Any) -> float:
    total_seconds = getattr(value, "total_seconds", None)
    if total_seconds is not None:
        value = total_seconds()
    value = float(value)
    if value <= 0:
        raise ValueError("ttl must be a positive duration")
    return value


class DerivedKeyCache:
    """
    Capacity- and lifetime-bounded cache for SCRAM-derived secrets.

    :param capacity: Maximum number of entries kept in the cache.
    :param ttl: Absolute lifetime of an entry, in seconds.  A
        :class:`datetime.timedelta` is accepted as well.
    :param clock: Monotonic clock used for lifetime accounting.  Defaults
        to :func:`time.monotonic`; tests may supply their own.
    :param secret: Key used to turn prepared passwords into opaque
        password tags.  If omitted, a fresh random key is generated.  It
        must not be logged or persisted with the cache contents.

    Entries are evicted in least-recently-used order.  A lookup hit
    updates recency but does not extend the absolute lifetime.

    .. attribute:: hits

       Number of successful :meth:`get` calls.

    .. attribute:: misses

       Number of unsuccessful :meth:`get` calls.

    .. attribute:: evictions

       Number of entries removed because the capacity was exceeded.

    .. attribute:: expirations

       Number of expired entries removed.

    .. attribute:: rejected_stores

       Number of :meth:`put` calls rejected because the cache generation
       changed after the derivation started.
    """

    def __init__(
            self,
            capacity: int = _DEFAULT_CAPACITY,
            ttl: typing.Any = _DEFAULT_TTL,
            *,
            lifetime: typing.Any = None,
            max_entries: typing.Optional[int] = None,
            clock: typing.Optional[typing.Callable[[], float]] = None,
            secret: typing.Optional[bytes] = None):
        if max_entries is not None:
            if capacity != _DEFAULT_CAPACITY:
                raise TypeError(
                    "capacity and max_entries are mutually exclusive")
            capacity = max_entries
        if lifetime is not None:
            if ttl != _DEFAULT_TTL:
                raise TypeError(
                    "ttl and lifetime are mutually exclusive")
            ttl = lifetime
        try:
            capacity = int(capacity)
        except (TypeError, ValueError):
            raise TypeError("capacity must be an integer") from None
        if capacity < 0:
            raise ValueError("capacity must not be negative")

        if secret is None:
            secret = os.urandom(32)
        elif not isinstance(secret, bytes):
            raise TypeError("secret must be bytes")
        elif not secret:
            raise ValueError("secret must not be empty")

        self._capacity = capacity
        self._ttl = _ttl_seconds(ttl)
        self._clock = clock if clock is not None else time.monotonic
        self._secret = secret
        self._entries: typing.OrderedDict[
            DerivedKeyCacheKey, _CacheEntry
        ] = collections.OrderedDict()
        self._generation = 0

        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.expirations = 0
        self.rejected_stores = 0

    @property
    def capacity(self) -> int:
        """Maximum number of entries kept in the cache."""
        return self._capacity

    @capacity.setter
    def capacity(self, value: int) -> None:
        value = int(value)
        if value < 0:
            raise ValueError("capacity must not be negative")
        self._capacity = value
        self._evict_excess()

    @property
    def ttl(self) -> float:
        """Absolute entry lifetime in seconds."""
        return self._ttl

    @property
    def generation(self) -> int:
        """
        Monotonic revocation generation.

        :meth:`invalidate` increments this value.  A derivation may only
        be published if the generation it observed before deriving is
        still current.
        """
        return self._generation

    @property
    def size(self) -> int:
        """Number of entries currently stored, excluding expired ones."""
        self._purge_expired()
        return len(self._entries)

    def __len__(self) -> int:
        return self.size

    def __contains__(self, key: typing.Any) -> bool:
        entry = self._entries.get(key)
        if entry is None:
            return False
        if self._is_expired(entry):
            del self._entries[key]
            self.expirations += 1
            return False
        return True

    def _is_expired(self, entry: _CacheEntry) -> bool:
        return self._clock() >= entry.expires_at

    def _purge_expired(self) -> None:
        if not self._entries:
            return
        now = self._clock()
        expired = [
            key
            for key, entry in self._entries.items()
            if now >= entry.expires_at
        ]
        for key in expired:
            del self._entries[key]
            self.expirations += 1

    def _evict_excess(self) -> None:
        while len(self._entries) > self._capacity:
            self._entries.popitem(last=False)
            self.evictions += 1

    def make_key(
            self,
            credential_version: typing.Any,
            username: typing.Union[str, bytes],
            password: typing.Union[str, bytes],
            digest: typing.Any,
            salt: bytes,
            iteration_count: int,
            ) -> DerivedKeyCacheKey:
        """
        Build the identity for a derived secret.

        `username` and `password` must already have been prepared with
        SASLprep.  They may be :class:`str` (encoded as UTF-8) or
        :class:`bytes`.  `digest` is a digest name or an object carrying a
        ``hashfun_name`` attribute.  `salt` must be the decoded salt as
        :class:`bytes`.

        The password is transformed into a keyed digest with the cache's
        private key.  Neither the password nor the salted password becomes
        part of the returned key.
        """
        try:
            hash(credential_version)
        except TypeError:
            raise TypeError(
                "credential_version must be hashable") from None

        digest_name = getattr(digest, "hashfun_name", digest)
        if not isinstance(digest_name, str):
            raise TypeError("digest must be a string or a SCRAMHashInfo")

        if isinstance(username, str):
            username = username.encode("utf-8")
        if isinstance(password, str):
            password = password.encode("utf-8")
        if not isinstance(username, bytes):
            raise TypeError("username must be str or bytes")
        if not isinstance(password, bytes):
            raise TypeError("password must be str or bytes")
        if not isinstance(salt, bytes):
            raise TypeError("salt must be bytes")

        tag = hmac.new(self._secret, digestmod=hashlib.sha256)
        tag.update(_PASSWORD_TAG_CONTEXT)
        tag.update(len(username).to_bytes(4, "big"))
        tag.update(username)
        tag.update(len(password).to_bytes(8, "big"))
        tag.update(password)

        return DerivedKeyCacheKey(
            credential_version=credential_version,
            username=username,
            password_tag=tag.digest(),
            digest=digest_name,
            salt=salt,
            iteration_count=int(iteration_count),
        )

    def get(self, key: DerivedKeyCacheKey) -> typing.Optional[bytes]:
        """
        Return the cached salted password for `key`, or :data:`None`.

        A hit updates the entry's recency without extending its lifetime.
        """
        entry = self._entries.get(key)
        if entry is None:
            self.misses += 1
            return None
        if self._is_expired(entry):
            del self._entries[key]
            self.expirations += 1
            self.misses += 1
            return None
        self._entries.move_to_end(key)
        self.hits += 1
        return entry.salted_password

    def peek(self, key: DerivedKeyCacheKey) -> typing.Optional[bytes]:
        """Look up `key` without updating statistics or recency."""
        entry = self._entries.get(key)
        if entry is None:
            return None
        if self._is_expired(entry):
            del self._entries[key]
            self.expirations += 1
            return None
        return entry.salted_password

    def put(
            self,
            key: DerivedKeyCacheKey,
            salted_password: bytes,
            generation: typing.Optional[int] = None,
            ) -> bool:
        """
        Publish `salted_password` under `key`.

        If `generation` is supplied, publication is rejected when the
        cache generation has changed since that value was observed.  This
        is the boundary which keeps a derivation that started before a
        credential rotation from becoming visible afterwards.  Return
        :data:`True` when the value was stored.
        """
        if generation is not None and generation != self._generation:
            self.rejected_stores += 1
            return False
        if not isinstance(salted_password, bytes):
            raise TypeError("salted_password must be bytes")
        if self._capacity == 0:
            return False

        self._purge_expired()
        self._entries.pop(key, None)
        self._entries[key] = _CacheEntry(
            salted_password,
            self._clock() + self._ttl,
        )
        self._evict_excess()
        return True

    def discard(self, key: DerivedKeyCacheKey) -> None:
        """Remove `key` without advancing the revocation generation."""
        self._entries.pop(key, None)

    def invalidate(self) -> int:
        """
        Drop all entries and advance the revocation generation.

        Call this whenever a credential is rotated or revoked.  In-flight
        derivations which observed an older generation cannot publish
        their result afterwards.  Return the new generation.
        """
        self._entries.clear()
        self._generation += 1
        return self._generation

    def clear(self) -> int:
        """Alias for :meth:`invalidate`."""
        return self.invalidate()

    #: Alias for :meth:`make_key`.
    key = make_key
    #: Alias for :meth:`make_key`.
    build_key = make_key

    #: Alias for :meth:`get`.
    lookup = get

    #: Alias for :meth:`put`.
    store = put
    #: Alias for :meth:`put`.
    commit = put

    def rotate(self) -> int:
        """Alias for :meth:`invalidate`."""
        return self.invalidate()

    def revoke(self) -> int:
        """Alias for :meth:`invalidate`."""
        return self.invalidate()


#: Short alias for :class:`DerivedKeyCache`.
SCRAMCache = DerivedKeyCache
#: Compatibility alias for :class:`DerivedKeyCache`.
DerivedCache = DerivedKeyCache
#: Compatibility alias for :class:`DerivedKeyCache`.
PBKDF2Cache = DerivedKeyCache
#: Compatibility alias for :class:`DerivedKeyCache`.
SCRAMDerivedKeyCache = DerivedKeyCache
#: Compatibility alias for :class:`DerivedKeyCacheKey`.
CacheKey = DerivedKeyCacheKey

__all__ = [
    "CacheKey",
    "DerivedCache",
    "DerivedKeyCache",
    "DerivedKeyCacheKey",
    "PBKDF2Cache",
    "SCRAMCache",
    "SCRAMDerivedKeyCache",
]
