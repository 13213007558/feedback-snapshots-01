from __future__ import annotations

import http.client
import json
import math
import threading
import time
import urllib.request
from functools import lru_cache
from ssl import SSLContext
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

from .api_jwk import PyJWK, PyJWKSet
from .api_jwt import decode_complete as decode_token
from .exceptions import PyJWKClientConnectionError, PyJWKClientError
from .jwk_set_cache import JWKSetCache


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        return None


class PyJWKClient:
    def __init__(
        self,
        uri: str | None = None,
        cache_keys: bool = False,
        max_cached_keys: int = 16,
        cache_jwk_set: bool = True,
        lifespan: float = 300,
        headers: dict[str, Any] | None = None,
        timeout: float = 30,
        ssl_context: SSLContext | None = None,
        cooldown_duration: float = 30,
    ):
        """A client for retrieving signing keys from a JWKS endpoint.

        ``PyJWKClient`` uses a two-tier caching system to avoid unnecessary
        network requests:

        **Tier 1 — JWK Set cache** (enabled by default):
        Caches the entire JSON Web Key Set response from the endpoint.
        Controlled by:

        - ``cache_jwk_set``: Set to ``True`` (the default) to enable this
          cache. When enabled, the JWK Set is fetched from the network only
          when the cache is empty or expired.
        - ``lifespan``: Time in seconds before the cached JWK Set expires.
          Defaults to ``300`` (5 minutes). Must be greater than 0.

        Unknown key IDs can trigger one forced refresh after the cooldown
        period configured by ``cooldown_duration``. Every successful fetch
        starts this cooldown, including the initial fetch and cache-expiry
        fetches. A newly rotated key may therefore wait for the cooldown
        period before it is fetched; set ``cooldown_duration`` to ``0`` to
        disable this behavior. The cooldown is bypassed when
        ``cache_jwk_set`` is ``False``.

        **Offline mode** (no network access):
        Pass ``uri=None`` (or omit ``uri``) to create a client that never
        performs HTTP requests. Load key material directly with
        :meth:`load_jwk_set` or :meth:`load_jwk_set_json`, which is useful
        for clusters that distribute JWKS documents out of band. Individual
        keys can be disabled at any time with :meth:`revoke_key`; revocations
        persist across subsequent :meth:`load_jwk_set` calls, so a reloaded
        set cannot silently re-enable a revoked key. Every successful
        ``load_jwk_set`` and ``revoke_key`` call increments the observable
        :attr:`version` counter.

        **Tier 2 — Signing key cache** (disabled by default):
        Caches individual signing keys (looked up by ``kid``) using an LRU
        cache with **no time-based expiration**. Keys are evicted only when
        the cache reaches its maximum size. Controlled by:

        - ``cache_keys``: Set to ``True`` to enable this cache.
          Defaults to ``False``.
        - ``max_cached_keys``: Maximum number of signing keys to keep in
          the LRU cache. Defaults to ``16``.

        :param uri: The URL of the JWKS endpoint, or ``None`` for an
            offline client that only uses locally loaded JWK Sets.
        :type uri: str or None
        :param cache_keys: Enable the per-key LRU cache (Tier 2).
        :type cache_keys: bool
        :param max_cached_keys: Max entries in the signing key LRU cache.
        :type max_cached_keys: int
        :param cache_jwk_set: Enable the JWK Set response cache (Tier 1).
        :type cache_jwk_set: bool
        :param lifespan: TTL in seconds for the JWK Set cache.
        :type lifespan: float
        :param headers: Optional HTTP headers to include in requests.
        :type headers: dict or None
        :param timeout: HTTP request timeout in seconds.
        :type timeout: float
        :param ssl_context: Optional SSL context for the request.
        :type ssl_context: ssl.SSLContext or None
        :param cooldown_duration: Minimum time in seconds between forced
            refreshes after an unknown key ID. Defaults to ``30``.
        :type cooldown_duration: float
        """
        if headers is None:
            headers = {}
        # urllib's default OpenerDirector also handles file://, ftp://, and
        # data: URIs. Reject anything that isn't http(s) eagerly so a caller
        # passing an attacker-influenced URL (e.g. taken from a `jku` token
        # header) can't read local files or reach other unintended schemes.
        if uri is not None:
            scheme = urlparse(uri).scheme.lower()
            if scheme not in ("http", "https"):
                raise PyJWKClientError(
                    f"Invalid JWKS URI scheme {scheme!r}: only 'http' and 'https' "
                    f"are supported."
                )
        self.uri = uri
        self.jwk_set_cache: JWKSetCache | None = None
        self.headers = headers
        self.timeout = timeout
        self.ssl_context = ssl_context
        if cooldown_duration < 0:
            raise PyJWKClientError(
                "Cooldown duration must be greater than or equal to 0, "
                f'the input is "{cooldown_duration}"'
            )
        if not math.isfinite(cooldown_duration):
            raise PyJWKClientError(
                f'Cooldown duration must be finite, the input is "{cooldown_duration}"'
            )
        self.cooldown_duration = cooldown_duration
        self._last_successful_fetch: float | None = None
        self._client_lock = threading.RLock()
        self._loaded_jwk_set: PyJWKSet | None = None
        self._revoked_kids: set[str] = set()
        self._version = 0

        if cache_jwk_set:
            # Init jwt set cache with default or given lifespan.
            # Default lifespan is 300 seconds (5 minutes).
            if lifespan <= 0:
                raise PyJWKClientError(
                    f'Lifespan must be greater than 0, the input is "{lifespan}"'
                )
            self.jwk_set_cache = JWKSetCache(lifespan)
        else:
            self.jwk_set_cache = None

        if cache_keys:
            # Cache signing keys
            get_signing_key = lru_cache(maxsize=max_cached_keys)(self.get_signing_key)
            # Ignore mypy (https://github.com/python/mypy/issues/2427)
            self.get_signing_key = get_signing_key  # type: ignore[method-assign]

    @property
    def version(self) -> int:
        """Version of the key material managed by this client.

        Starts at ``0`` and increments by one on every successful
        :meth:`load_jwk_set` call and every :meth:`revoke_key` call that
        revokes a not-yet-revoked key ID. Useful for observing whether a
        configuration push actually reached the client.

        :rtype: int
        """
        return self._version

    @property
    def revoked_key_ids(self) -> frozenset[str]:
        """The key IDs currently revoked on this client.

        :rtype: frozenset[str]
        """
        return frozenset(self._revoked_kids)

    def load_jwk_set(self, jwk_set: dict[str, Any] | PyJWKSet) -> PyJWKSet:
        """Load a JWK Set directly, without contacting a JWKS endpoint.

        The loaded set becomes the key material served by
        :meth:`get_jwk_set` (and is written to the JWK Set cache when one
        is enabled), replacing any previously loaded or fetched set.
        Revoked key IDs are *not* cleared: a key revoked with
        :meth:`revoke_key` stays revoked even if the loaded set contains
        it again. Increments :attr:`version`.

        :param jwk_set: The JWK Set to load, as a decoded JWKS payload or
            an already-parsed :class:`PyJWKSet`.
        :returns: The parsed JWK Set.
        :rtype: PyJWKSet
        :raises PyJWKClientError: If the payload is not a JSON object.
        :raises PyJWKSetError: If the payload contains no usable keys.
        """
        if isinstance(jwk_set, PyJWKSet):
            parsed = jwk_set
        else:
            parsed = PyJWKSet.from_dict(self._as_jwk_set_payload(jwk_set))

        with self._client_lock:
            self._loaded_jwk_set = parsed
            if self.jwk_set_cache is not None:
                self.jwk_set_cache.put(parsed)
            self._version += 1
            self._clear_signing_key_cache()

        return parsed

    def load_jwk_set_json(self, data: str) -> PyJWKSet:
        """Load a JWK Set from a JSON string.

        Implicitly calls :meth:`load_jwk_set`.

        :param data: The JWK Set, as a JSON string.
        :type data: str
        :returns: The parsed JWK Set.
        :rtype: PyJWKSet
        """
        return self.load_jwk_set(PyJWKSet.from_json(data))

    def revoke_key(self, kid: str) -> None:
        """Revoke a signing key by its ``kid``.

        Revoked keys are never returned by :meth:`get_signing_keys` or
        :meth:`get_signing_key`, so tokens signed with them fail
        verification while the remaining keys keep working. The revocation
        persists across :meth:`load_jwk_set` calls and endpoint refreshes.
        Revoking an already-revoked ``kid`` is a no-op; any other
        successful call increments :attr:`version`.

        :param kid: The key ID to revoke.
        :type kid: str
        """
        with self._client_lock:
            if kid in self._revoked_kids:
                return
            self._revoked_kids.add(kid)
            self._version += 1
            self._clear_signing_key_cache()

    def _clear_signing_key_cache(self) -> None:
        # When the per-key LRU cache is enabled, `get_signing_key` is an
        # lru_cache wrapper; drop its entries so key material changes
        # (loads and revocations) take effect immediately.
        cache_clear = getattr(self.get_signing_key, "cache_clear", None)
        if cache_clear is not None:
            cache_clear()

    def fetch_data(self) -> Any:
        """Fetch the JWK Set from the JWKS endpoint.

        Makes an HTTP request to the configured ``uri`` and returns the
        parsed JSON response. If the JWK Set cache is enabled, the
        response is stored in the cache.

        :returns: The parsed JWK Set as a dictionary.
        :raises PyJWKClientConnectionError: If the HTTP request fails.
        :raises PyJWKClientError: If the client has no URI configured, or
            the endpoint does not return a JSON object.
        :raises PyJWKSetError: If the JWK Set cache is enabled and the
            response contains no usable keys.
        """
        if self.uri is None:
            raise PyJWKClientError(
                "This PyJWKClient was created without a URI and cannot fetch; "
                "use load_jwk_set() to provide a JWK Set"
            )
        try:
            r = urllib.request.Request(url=self.uri, headers=self.headers)
            handlers: list[Any] = [_NoRedirectHandler()]
            if self.ssl_context is not None:
                handlers.append(urllib.request.HTTPSHandler(context=self.ssl_context))
            opener = urllib.request.build_opener(*handlers)
            with opener.open(r, timeout=self.timeout) as response:
                jwk_set = json.load(response)
        except (URLError, TimeoutError, http.client.HTTPException) as e:
            if isinstance(e, HTTPError):
                e.close()
            raise PyJWKClientConnectionError(
                f'Fail to fetch data from the url, err: "{e}"'
            ) from e

        # Validate the payload before it reaches the cache, so an endpoint
        # returning something that isn't a JSON object is reported as such
        # rather than as a malformed JWK Set.
        jwk_set = self._as_jwk_set_payload(jwk_set)

        # Only update the cache on a successful fetch. Writing in a
        # `finally` block with `jwk_set=None` on error clears any
        # previously-cached JWKS, turning a transient outage into a cache
        # wipe that breaks legitimate auth.
        if self.jwk_set_cache is not None:
            self.jwk_set_cache.put(jwk_set)
        self._last_successful_fetch = time.monotonic()
        return jwk_set

    def get_jwk_set(self, refresh: bool = False) -> PyJWKSet:
        """Return the JWK Set, using the cache when available.

        :param refresh: Force a fresh fetch from the endpoint, bypassing
            the cache. Has no effect on an offline client (``uri=None``),
            which always serves the locally loaded set.
        :type refresh: bool
        :returns: The JWK Set.
        :rtype: PyJWKSet
        :raises PyJWKClientError: If the client has no URI configured and
            no JWK Set has been loaded, or the endpoint does not return a
            JSON object.
        """
        if self.uri is None:
            # Offline client: the locally loaded set is the only source of
            # key material, and refreshing is meaningless.
            if self._loaded_jwk_set is None:
                raise PyJWKClientError(
                    "This PyJWKClient was created without a URI; "
                    "call load_jwk_set() to provide a JWK Set"
                )
            return self._loaded_jwk_set

        data = None
        fetched = False
        if self.jwk_set_cache is not None and not refresh:
            data = self.jwk_set_cache.get()

        if data is None:
            data = self.fetch_data()
            fetched = True

        # A cache hit is already parsed, so serve it as-is. Only a fresh
        # fetch reaches the check below, which still matters because
        # `fetch_data()` may be overridden by a subclass.
        if isinstance(data, PyJWKSet):
            jwk_set = data
        else:
            jwk_set = PyJWKSet.from_dict(self._as_jwk_set_payload(data))

        # `fetch_data()` caches the payload it received from the endpoint,
        # but a subclass may filter or transform it before returning. Cache
        # the value actually being returned, so later cache hits serve the
        # same key set as this call rather than the pre-transform one.
        if fetched and self.jwk_set_cache is not None:
            self.jwk_set_cache.put(jwk_set)

        return jwk_set

    @staticmethod
    def _as_jwk_set_payload(data: Any) -> dict[str, Any]:
        if not isinstance(data, dict):
            raise PyJWKClientError("The JWKS endpoint did not return a JSON object")

        return data

    def get_signing_keys(self, refresh: bool = False) -> list[PyJWK]:
        """Return all signing keys from the JWK Set.

        Filters the JWK Set to keys whose ``use`` is ``"sig"`` (or
        unspecified) and that have a ``kid``.

        :param refresh: Force a fresh fetch from the endpoint, bypassing
            the cache.
        :type refresh: bool
        :returns: A list of signing keys, excluding revoked keys.
        :rtype: list[PyJWK]
        :raises PyJWKClientError: If no signing keys are found.
        """
        jwk_set = self.get_jwk_set(refresh)
        signing_keys = self._get_signing_keys_from_jwk_set(jwk_set)
        if self._revoked_kids:
            signing_keys = [
                key for key in signing_keys if key.key_id not in self._revoked_kids
            ]
            if not signing_keys:
                raise PyJWKClientError(
                    "The JWK Set has no usable signing keys: "
                    "all of them have been revoked"
                )
        return signing_keys

    @staticmethod
    def _get_signing_keys_from_jwk_set(jwk_set: PyJWKSet) -> list[PyJWK]:
        signing_keys = [
            jwk_set_key
            for jwk_set_key in jwk_set.keys
            if jwk_set_key.public_key_use in ["sig", None] and jwk_set_key.key_id
        ]

        if not signing_keys:
            raise PyJWKClientError("The JWKS endpoint did not contain any signing keys")

        return signing_keys

    def get_signing_key(self, kid: str) -> PyJWK:
        """Return the signing key matching the given ``kid``.

        If no match is found in the current JWK Set, the set is refreshed
        from the endpoint and the lookup is retried once when the refresh
        cooldown permits it.

        :param kid: The key ID to look up.
        :type kid: str
        :returns: The matching signing key.
        :rtype: PyJWK
        :raises PyJWKClientError: If the key has been revoked, or no
            matching key is found after refreshing.
        """
        with self._client_lock:
            if kid in self._revoked_kids:
                raise PyJWKClientError(
                    f'The signing key "{kid}" has been revoked'
                )
            signing_keys = self.get_signing_keys()
            signing_key = self.match_kid(signing_keys, kid)

            if not signing_key:
                cooling_down = (
                    self.jwk_set_cache is not None
                    and self._last_successful_fetch is not None
                    and time.monotonic() - self._last_successful_fetch
                    < self.cooldown_duration
                )
                if not cooling_down:
                    signing_keys = self.get_signing_keys(refresh=True)
                    self._last_successful_fetch = time.monotonic()
                    signing_key = self.match_kid(signing_keys, kid)

                if not signing_key:
                    raise PyJWKClientError(
                        f'Unable to find a signing key that matches: "{kid}"'
                    )

            return signing_key

    def get_signing_key_from_jwt(self, token: str | bytes) -> PyJWK:
        """Return the signing key for a JWT by reading its ``kid`` header.

        Extracts the ``kid`` from the token's unverified header and
        delegates to :meth:`get_signing_key`.

        :param token: The encoded JWT.
        :type token: str or bytes
        :returns: The matching signing key.
        :rtype: PyJWK
        """
        unverified = decode_token(token, options={"verify_signature": False})
        header = unverified["header"]
        return self.get_signing_key(header.get("kid"))

    @staticmethod
    def match_kid(signing_keys: list[PyJWK], kid: str) -> PyJWK | None:
        """Find a key in *signing_keys* that matches *kid*.

        :param signing_keys: The list of keys to search.
        :type signing_keys: list[PyJWK]
        :param kid: The key ID to match.
        :type kid: str
        :returns: The matching key, or ``None`` if not found.
        :rtype: PyJWK or None
        """
        signing_key = None

        for key in signing_keys:
            if key.key_id == kid:
                signing_key = key
                break

        return signing_key
