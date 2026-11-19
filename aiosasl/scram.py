########################################################################
# File name: scram.py
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
import abc
import base64
import collections
import functools
import hashlib
import hmac
import inspect
import logging
import random
import time
import typing

from . import channel_binding, common, statemachine, stringprep, utils
from .scram_cache import (  # noqa:F401
    CacheKey,
    DerivedCache,
    DerivedKeyCache,
    DerivedKeyCacheKey,
    PBKDF2Cache,
    SCRAMCache,
    SCRAMDerivedKeyCache,
)


def pbkdf2(
        hash_name: str,
        password: bytes,
        salt: bytes,
        iterations: int,
        dklen: typing.Optional[int] = None) -> bytes:
    """Thin indirection which keeps the PBKDF call patchable."""
    if dklen is None:
        return hashlib.pbkdf2_hmac(
            hash_name, password, salt, iterations)
    return hashlib.pbkdf2_hmac(
        hash_name, password, salt, iterations, dklen)


logger = logging.getLogger(__name__)


SCRAMHashInfo = collections.namedtuple(
    "SCRAMHashInfo",
    [
        "hashfun_name",
        "quality",
        "minimum_iteration_count",
    ]
)


_system_random = random.SystemRandom()


class Base:
    """
    Shared implementation of SCRAM and SCRAMPLUS.
    """

    _channel_binding = False

    def __init__(
            self,
            credential_provider: common.CredentialProvider,
            *,
            nonce_length: int = 15,
            enforce_minimum_iteration_count: bool = True,
            cache: typing.Optional[DerivedKeyCache] = None,
            derived_cache: typing.Optional[DerivedKeyCache] = None,
            cache_capacity: typing.Optional[int] = None,
            cache_size: typing.Optional[int] = None,
            cache_ttl: typing.Optional[float] = None,
            cache_lifetime: typing.Optional[float] = None,
            credential_version_provider: typing.Optional[
                typing.Callable[..., typing.Any]
            ] = None,
            credential_version: typing.Any = None):
        super().__init__()
        if cache is not None and derived_cache is not None:
            raise TypeError(
                "cache and derived_cache are mutually exclusive")
        if cache is None:
            cache = derived_cache
        if cache_capacity is not None and cache_size is not None:
            raise TypeError(
                "cache_capacity and cache_size are mutually exclusive")
        if cache_capacity is None:
            cache_capacity = cache_size
        if cache_ttl is not None and cache_lifetime is not None:
            raise TypeError(
                "cache_ttl and cache_lifetime are mutually exclusive")
        if cache_ttl is None:
            cache_ttl = cache_lifetime
        if cache is None and (cache_capacity is not None or
                              cache_ttl is not None):
            cache = DerivedKeyCache(
                capacity=(
                    cache_capacity
                    if cache_capacity is not None else 64
                ),
                ttl=cache_ttl if cache_ttl is not None else 300.0,
            )
        elif cache is not None and (cache_capacity is not None or
                                    cache_ttl is not None):
            raise TypeError(
                "an explicit cache cannot be combined with cache_capacity "
                "or cache_ttl")

        self._credential_provider = credential_provider
        self._cache = cache
        self._credential_version_provider = credential_version_provider
        self._credential_version = credential_version
        self.nonce_length = nonce_length
        self.enforce_minimum_iteration_count = enforce_minimum_iteration_count

    @property
    def cache(self) -> typing.Optional[DerivedKeyCache]:
        """The configured derived cache, or :data:`None` if disabled."""
        return self._cache

    @property
    def derived_cache(self) -> typing.Optional[DerivedKeyCache]:
        """Alias for :attr:`cache`."""
        return self._cache

    async def _resolve_credential_version(
            self,
            username: str,
            password: str) -> typing.Any:
        provider = self._credential_version_provider
        if provider is None:
            return self._credential_version
        try:
            signature = inspect.signature(provider)
        except (TypeError, ValueError):
            signature = None

        if signature is not None:
            positional = [
                parameter
                for parameter in signature.parameters.values()
                if parameter.kind in (
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                )
            ]
            has_varargs = any(
                parameter.kind == inspect.Parameter.VAR_POSITIONAL
                for parameter in signature.parameters.values()
            )
        else:
            positional = []
            has_varargs = False

        if has_varargs or len(positional) >= 2:
            result = provider(username, password)
        elif len(positional) == 1:
            result = provider(username)
        else:
            result = provider()
        if inspect.isawaitable(result):
            result = await result
        return result

    async def _resolve_credentials(
            self,
            ) -> typing.Tuple[str, str, typing.Any]:
        credentials = await self._credential_provider()
        if not isinstance(credentials, (tuple, list)):
            raise ValueError(
                "credential provider must return a (username, password) "
                "or (username, password, credential_version) tuple")
        try:
            length = len(credentials)
        except TypeError:
            raise ValueError(
                "credential provider must return a (username, password) "
                "or (username, password, credential_version) tuple"
            ) from None

        if length == 2:
            username, password = credentials
            version = await self._resolve_credential_version(
                username, password)
        elif length == 3:
            versioned = typing.cast(
                typing.Tuple[str, str, typing.Any], credentials)
            username, password, version = versioned
        else:
            raise ValueError(
                "credential provider must return a (username, password) "
                "or (username, password, credential_version) tuple")
        return username, password, version

    _supported_hashalgos = {
        # the second argument is for preference ordering (highest first)
        # if anyone has a better hash ordering suggestion, I’m open for it
        # a value of 1 is added if the -PLUS variant is used
        # -- JSC
        # the minimum iteration count is obtained from
        # <https://www.iana.org/assignments/sasl-mechanisms/sasl-mechanisms.xhtml>
        "SHA-1": SCRAMHashInfo("sha1", 1, 4096),
        "SHA-256": SCRAMHashInfo("sha256", 256, 4096),
    }

    @classmethod
    def any_supported(
            cls,
            mechanisms: typing.Iterable[str],
            ) -> typing.Optional[typing.Tuple[str, SCRAMHashInfo]]:
        supported = []
        for mechanism in mechanisms:
            if not mechanism.startswith("SCRAM-"):
                continue

            hashfun_key = mechanism[6:]

            if cls._channel_binding:
                if not mechanism.endswith("-PLUS"):
                    continue
                hashfun_key = hashfun_key[:-5]
            else:
                if mechanism.endswith("-PLUS"):
                    continue

            try:
                info = cls._supported_hashalgos[hashfun_key]
            except KeyError:
                continue

            supported.append(((1, info.quality), (mechanism, info,)))

        if not supported:
            return None
        supported.sort()

        return supported.pop()[1]

    @classmethod
    def parse_message(
            cls,
            msg: bytes,
            ) -> typing.Generator[typing.Tuple[bytes, bytes], None, None]:
        parts = (
            part
            for part in msg.split(b",")
            if part)

        for part in parts:
            key, _, value = part.partition(b"=")
            if len(key) > 1 or key == b"m":
                raise Exception("SCRAM protocol violation / unknown "
                                "future extension")
            if key == b"n" or key == b"a":
                value = value.replace(b"=2C", b",").replace(b"=3D", b"=")

            yield key, value

    @abc.abstractmethod
    def _get_gs2_header(self) -> bytes:
        raise NotImplementedError

    @abc.abstractmethod
    def _get_cb_data(self) -> bytes:
        raise NotImplementedError

    async def authenticate(
            self,
            sm: statemachine.SASLStateMachine,
            token: typing.Tuple[str, SCRAMHashInfo],
            ) -> None:
        mechanism, info, = token
        logger.info("attempting %s mechanism (using %s hashfun)",
                    mechanism,
                    info)
        # this is pretty much a verbatim implementation of RFC 5802.

        hashfun_factory = functools.partial(hashlib.new, info.hashfun_name)

        cache = self._cache
        # Observe the revocation generation before anything about this
        # attempt is read.  If a credential is revoked while we are still
        # preparing or deriving, the result belongs to the revoked
        # credentials and must not be published under the new generation.
        cache_generation = cache.generation if cache is not None else None

        gs2_header = self._get_gs2_header()
        username, password, credential_version = \
            await self._resolve_credentials()
        encoded_username = stringprep.saslprep(
            username,
            allow_unassigned=True,
        ).encode("utf-8")
        encoded_password = stringprep.saslprep(password).encode("utf-8")

        our_nonce = base64.b64encode(_system_random.getrandbits(
            self.nonce_length * 8
        ).to_bytes(
            self.nonce_length, "little"
        ))

        auth_message = b"n=" + encoded_username + b",r=" + our_nonce
        state, payload = await sm.initiate(
            mechanism,
            gs2_header + auth_message)

        if state != common.SASLState.CHALLENGE or payload is None:
            await sm.abort()
            raise common.SASLFailure(
                None,
                text="protocol violation: expected challenge with payload")

        auth_message += b"," + payload

        parsed_payload = dict(self.parse_message(payload))

        try:
            iteration_count = int(parsed_payload[b"i"])
            nonce = parsed_payload[b"r"]
            salt = base64.b64decode(parsed_payload[b"s"])
        except (ValueError, KeyError):
            await sm.abort()
            raise common.SASLFailure(
                None,
                text="malformed server message: {!r}".format(payload),
            )

        if not nonce.startswith(our_nonce):
            await sm.abort()
            raise common.SASLFailure(
                None,
                text="server nonce doesn't fit our nonce")

        if (self.enforce_minimum_iteration_count and
                iteration_count < info.minimum_iteration_count):
            raise common.SASLFailure(
                None,
                text="minimum iteration count for {} violated "
                "({} is less than {})".format(
                    mechanism,
                    iteration_count,
                    info.minimum_iteration_count,
                )
            )

        t0 = time.time()

        cache_key = None
        cache_hit = False
        salted_password = None
        if cache is not None:
            cache_key = cache.make_key(
                credential_version,
                encoded_username,
                encoded_password,
                info.hashfun_name,
                salt,
                iteration_count,
            )
            salted_password = cache.get(cache_key)
            if salted_password is None:
                logger.debug("SCRAM derived cache miss")
            else:
                logger.debug("SCRAM derived cache hit")
                cache_hit = True

        if salted_password is None:
            salted_password = pbkdf2(
                info.hashfun_name,
                encoded_password,
                salt,
                iteration_count)

        logger.debug("pbkdf2 timing: %f seconds", time.time() - t0)

        client_key = hmac.new(
            salted_password,
            b"Client Key",
            hashfun_factory).digest()

        stored_key = hashfun_factory(client_key).digest()

        reply = b"c=" + base64.b64encode(self._get_cb_data()) + b",r=" + nonce

        auth_message += b"," + reply

        client_proof = utils.xor_bytes(
            hmac.new(
                stored_key,
                auth_message,
                hashfun_factory).digest(),
            client_key)

        logger.debug("response generation time: %f seconds", time.time() - t0)
        try:
            state, payload = await sm.response(
                reply + b",p=" + base64.b64encode(client_proof)
            )
        except common.SASLFailure as err:
            raise err.promote_to_authentication_failure() from None

        # this is the pseudo-challenge for the server signature
        # we have to reply with the empty string!
        if state != common.SASLState.CHALLENGE:
            raise common.SASLFailure(
                "malformed-request",
                text="SCRAM protocol violation")

        state, dummy_payload = await sm.response(b"")
        if state != common.SASLState.SUCCESS or dummy_payload is not None:
            raise common.SASLFailure(
                None,
                "SASL protocol violation")

        server_signature = hmac.new(
            hmac.new(
                salted_password,
                b"Server Key",
                hashfun_factory).digest(),
            auth_message,
            hashfun_factory).digest()

        parsed_payload = dict(self.parse_message(payload or b""))

        if base64.b64decode(parsed_payload[b"v"]) != server_signature:
            raise common.SASLFailure(
                None,
                "authentication successful, but server signature invalid",
            )

        # Only a fully verified exchange may publish a derivation.  A
        # concurrent invalidation (credential rotation) advances the cache
        # generation; results derived before that boundary are discarded.
        if cache is not None and cache_key is not None and not cache_hit:
            if not cache.put(
                    cache_key,
                    salted_password,
                    generation=cache_generation):
                logger.debug(
                    "SCRAM derived cache publication rejected "
                    "due to concurrent invalidation")


class SCRAM(Base, statemachine.SASLMechanism):
    """
    The password-based SCRAM (non-PLUS) SASL mechanism (see :rfc:`5802`).

    :param credential_provider: A coroutine function which returns credentials.
    :param after_scram_plus: Flag to indicate that SCRAM-PLUS *is* supported by
        your implementation.
    :type after_scram_plus: :class:`bool`
    :param enforce_minimum_iteration_count: Enforce the minimum iteration
        count specified by the SCRAM specifications.
    :type enforce_minimum_iteration_count: :class:`bool`
    :param cache: Optional :class:`DerivedKeyCache` used to re-use expensive
        PBKDF derivations across handshakes.
    :type cache: :class:`DerivedKeyCache` or :data:`None`
    :param credential_version_provider: Optional callable (sync or async)
        which returns a trusted credential version.  It is invoked only
        when the credential provider returns a two-tuple.  The callable may
        take no arguments, the username, or the username and password.
    :type credential_version_provider: callable or :data:`None`
    :param credential_version: Trusted credential version used for every
        handshake when no `credential_version_provider` is given.  It is
        only relevant when a cache is configured.
    :param int cache_capacity: Capacity of a cache created implicitly when
        no `cache` instance is supplied.
    :param float cache_ttl: Absolute lifetime, in seconds, of a cache
        created implicitly when no `cache` instance is supplied.

    `credential_provider` must be a coroutine function which returns a
    ``(user, password)`` tuple.  When a cache is used, it may instead
    return a ``(user, password, credential_version)`` triple; the version
    must be trusted by the application and change whenever the password
    changes.

    .. note::

       As "non-PLUS" suggests, this does not support channel binding.
       Use :class:`SCRAMPLUS` if you want channel binding.

    .. note::

       Derived secrets are independent of the nonce and channel binding
       data.  A cache hit therefore still performs this handshake's own
       nonce exchange and proof computation; only the PBKDF invocation is
       skipped.  A failure at any point of the exchange does not publish
       the derivation.


    `credential_provider` must be coroutine function which returns a ``(user,
    password)`` tuple.

    If this is used after :class:`SCRAMPLUS` in a method list, the
    keyword argument `after_scram_plus` should be set to
    :data:`True`. Then we will use the gs2 header ``y,,`` to prevent
    down-grade attacks by a man-in-the-middle attacker.

    `enforce_minimum_iteration_count` controls the enforcement of the specified
    minimum iteration count for the key derivation function used in SCRAM. By
    default, this enforcement is enabled, and you are strongly advised to not
    disable it: it can be used to make the exchange weaker.

    Disabling `enforce_minimum_iteration_count` only makes sense if the
    authentication exchange would otherwise fall back to using :class:`PLAIN`
    or a similarly weak authentication mechanism.

    .. versionchanged:: 0.4

        The `enforce_minimum_iteration_count` argument and the behaviour to
        enforce the minimum iteration count by default was added.
    """

    def __init__(
            self,
            credential_provider: common.CredentialProvider,
            *,
            after_scram_plus: bool = False,
            **kwargs: typing.Any):
        super().__init__(credential_provider, **kwargs)
        self._after_scram_plus = after_scram_plus

    def _get_gs2_header(self) -> bytes:
        if self._after_scram_plus:
            return b"y,,"
        else:
            return b"n,,"

    def _get_cb_data(self) -> bytes:
        return self._get_gs2_header()


class SCRAMPLUS(Base, statemachine.SASLMechanism):
    """
    The password-based SCRAM-PLUS SASL mechanism (see :rfc:`5802`).

    :param credential_provider: A coroutine function which returns credentials.
    :param cb_provider: Object which provides channel binding data and
        information.
    :type cb_provider: :class:`.ChannelBindingProvider`
    :param after_scram_plus: Flag to indicate that SCRAM-PLUS *is* supported by
        your implementation.
    :type after_scram_plus: :class:`bool`
    :param enforce_minimum_iteration_count: Enforce the minimum iteration
        count specified by the SCRAM specifications.
    :type enforce_minimum_iteration_count: :class:`bool`
    :param cache: Optional :class:`DerivedKeyCache` used to re-use expensive
        PBKDF derivations across handshakes.  Each handshake still uses its
        own channel binding data in its transcript.
    :type cache: :class:`DerivedKeyCache` or :data:`None`

    `credential_provider` must be coroutine which returns a ``(user,
    password)`` tuple, or a ``(user, password, credential_version)`` triple
    when a cache is used.

    See :class:`SCRAM` for the cache and credential version parameters.

    `cb_provider` must be an instance of
    :class:`.ChannelBindingProvider`, which specifies and implements
    the channel binding type to use.

    `enforce_minimum_iteration_count` controls the enforcement of the specified
    minimum iteration count for the key derivation function used in SCRAM. By
    default, this enforcement is enabled, and you are strongly advised to not
    disable it: it can be used to make the exchange weaker.

    .. seealso::

        :class:`SCRAM` for more information on
        `enforce_minimum_iteration_count`.

    .. versionchanged:: 0.4

        The `enforce_minimum_iteration_count` argument and the behaviour to
        enforce the minimum iteration count by default was added.

    """
    _channel_binding = True

    def __init__(self,
                 credential_provider: common.CredentialProvider,
                 cb_provider: channel_binding.ChannelBindingProvider,
                 **kwargs: typing.Any):
        super().__init__(credential_provider, **kwargs)
        self._cb_provider = cb_provider

    def _get_gs2_header(self) -> bytes:
        return b"p=" + self._cb_provider.cb_name + b",,"

    def _get_cb_data(self) -> bytes:
        gs2_header = self._get_gs2_header()
        cb_data = self._cb_provider.extract_cb_data()
        return gs2_header + cb_data
