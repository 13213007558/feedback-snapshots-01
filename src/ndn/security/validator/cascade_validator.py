# -----------------------------------------------------------------------------
# Copyright (C) 2019-2026 The python-ndn authors
#
# This file is part of python-ndn.
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
# -----------------------------------------------------------------------------
from __future__ import annotations

import abc
import logging
import struct
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from Cryptodome.PublicKey import ECC, RSA

from ...encoding import (
    BinaryStr,
    Component,
    ContentType,
    FormalName,
    Name,
    SignaturePtrs,
    SignatureType,
    parse_data,
)
from ...app_support.security_v2 import KEY_COMPONENT, parse_certificate
from ...types import (
    InterestCanceled,
    InterestNack,
    InterestTimeout,
    NetworkError,
    ValidationFailure,
    ValidResult,
)
from ...utils import timestamp
from .known_key_validator import (
    verify_ecdsa,
    verify_ed25519,
    verify_rsa,
)


Validator = Callable[
    [FormalName, SignaturePtrs, dict[str, Any]],
    Awaitable[ValidResult],
]
_CHAIN_CONTEXT_KEY = 'cascade_checker_chain'


class PublicKeyStorage(abc.ABC):
    """
    Storage interface used by :class:`CascadeChecker`.

    Certificate expirations are tracked independently. The expiration of a
    parent certificate does not shorten the expiration of a validated
    subcertificate. Consequently, a cached subcertificate remains usable
    until its own expiration even if its parent certificate expires first.
    """

    @abc.abstractmethod
    def load(self, name: FormalName) -> bytes | None:
        """Load public key bits for a certificate name."""

    @abc.abstractmethod
    def save(self, name: FormalName, key_bits: bytes) -> None:
        """Save public key bits under a certificate name."""

    def save_with_expiration(
        self,
        name: FormalName,
        key_bits: bytes,
        expires_at: int,
    ) -> None:
        """
        Save public key bits with the named certificate's expiration timestamp.

        ``expires_at`` is not constrained by the expiration of the certificate
        that validated this certificate.
        """
        self.save(name, key_bits)


class EmptyKeyStorage(PublicKeyStorage):
    """A key storage implementation that never stores keys."""

    def load(self, name: FormalName) -> bytes | None:
        return None

    def save(self, name: FormalName, key_bits: bytes) -> None:
        pass


class MemoryKeyStorage(PublicKeyStorage):
    """A bounded, expiry-aware in-memory public key storage."""

    def __init__(self, max_entries: int = 256):
        if max_entries <= 0:
            raise ValueError('max_entries must be positive')
        self.max_entries = max_entries
        self._cache: OrderedDict[bytes, tuple[bytes, int | None]] = OrderedDict()

    def load(self, name: FormalName) -> bytes | None:
        key = Name.to_bytes(name)
        entry = self._cache.pop(key, None)
        if entry is None:
            return None
        key_bits, expires_at = entry
        if expires_at is not None and timestamp() > expires_at:
            return None
        self._cache[key] = entry
        return key_bits

    def save(self, name: FormalName, key_bits: bytes) -> None:
        self._save(name, key_bits, None)

    def save_with_expiration(
        self,
        name: FormalName,
        key_bits: bytes,
        expires_at: int,
    ) -> None:
        self._save(name, key_bits, expires_at)

    def _save(
        self,
        name: FormalName,
        key_bits: bytes,
        expires_at: int | None,
    ) -> None:
        key = Name.to_bytes(name)
        self._cache.pop(key, None)
        self._cache[key] = (key_bits, expires_at)
        while len(self._cache) > self.max_entries:
            self._cache.popitem(last=False)


class CascadeChecker:
    """
    Validate a packet by fetching and recursively validating its certificate.

    ``next_level`` controls validation of fetched certificates. It defaults to
    this checker and can be replaced with a policy-aware validator such as
    :func:`ndn.app_support.light_versec.lvs_validator`.

    A fetched certificate is admitted only if it is the certificate named by
    the KeyLocator, has a usable certificate structure, and carries a valid
    chain. Its public key enters the cache only after the packet that caused
    the fetch also passes signature verification with that key.
    """

    @staticmethod
    def _verify_sig(pub_key_bits: BinaryStr, sig_ptrs: SignaturePtrs) -> bool:
        sig_info = sig_ptrs.signature_info
        if sig_info is None or sig_ptrs.signature_value_buf is None:
            return False
        try:
            if sig_info.signature_type == SignatureType.SHA256_WITH_RSA:
                return verify_rsa(RSA.import_key(bytes(pub_key_bits)), sig_ptrs)
            if sig_info.signature_type == SignatureType.SHA256_WITH_ECDSA:
                return verify_ecdsa(ECC.import_key(bytes(pub_key_bits)), sig_ptrs)
            if sig_info.signature_type == SignatureType.ED25519:
                pub_key = ECC.import_key(bytes(pub_key_bits))
                return (
                    isinstance(pub_key, ECC.EccKey)
                    and verify_ed25519(pub_key, sig_ptrs)
                )
        except (TypeError, ValueError, IndexError):
            return False
        return False

    @staticmethod
    def _is_certificate_name(name: FormalName) -> bool:
        """Whether *name* has the shape of ``<identity>/KEY/<id>/<issuer>/v=<n>``."""
        return (
            len(name) >= 4
            and bytes(name[-4]) == bytes(KEY_COMPONENT)
            and Component.get_type(name[-1]) == Component.TYPE_VERSION
        )

    @staticmethod
    def _is_key_name(name: FormalName) -> bool:
        """Whether *name* has the shape of ``<identity>/KEY/<id>``."""
        return len(name) >= 2 and bytes(name[-2]) == bytes(KEY_COMPONENT)

    @classmethod
    def _certificate_matches_locator(
        cls,
        cert_name: FormalName,
        locator_name: FormalName,
    ) -> bool:
        """
        Check that a fetched certificate is the one named by a KeyLocator.

        A KeyLocator naming a complete certificate must match exactly, so a
        certificate sharing the key name but carrying a different issuer or
        version is rejected. A KeyLocator naming only the key accepts any
        certificate of that key, i.e. ``<key name>/<issuer>/<version>``.
        """
        if cls._is_certificate_name(locator_name):
            return Name.to_bytes(cert_name) == Name.to_bytes(locator_name)
        if cls._is_key_name(locator_name):
            return (
                len(cert_name) >= 2
                and Name.to_bytes(cert_name[:-2]) == Name.to_bytes(locator_name)
            )
        return False

    @staticmethod
    def _parse_certificate(
        wire: BinaryStr,
        expected_name: FormalName | None = None,
    ) -> tuple[FormalName, bytes, int]:
        cert = parse_certificate(wire)
        if cert.name is None or len(cert.name) < 4:
            raise ValueError('Certificate has a malformed name')
        if bytes(cert.name[-4]) != bytes(KEY_COMPONENT):
            raise ValueError('Certificate name does not contain KEY component')
        if Component.get_type(cert.name[-1]) != Component.TYPE_VERSION:
            raise ValueError('Certificate name does not end with Version component')
        if expected_name is not None:
            if not (
                CascadeChecker._is_certificate_name(expected_name)
                or CascadeChecker._is_key_name(expected_name)
            ):
                raise ValueError(
                    'KeyLocator does not name a certificate or a key'
                )
            if not CascadeChecker._certificate_matches_locator(
                cert.name,
                expected_name,
            ):
                raise ValueError(
                    'Fetched certificate name does not match KeyLocator'
                )
        if (
            cert.meta_info is None
            or cert.meta_info.content_type != ContentType.KEY
            or not cert.content
        ):
            raise ValueError('Certificate does not contain a public key')

        sig_info = cert.signature_info
        validity = sig_info.validity_period if sig_info is not None else None
        if (
            validity is None
            or validity.not_before is None
            or validity.not_after is None
        ):
            raise ValueError('Certificate does not contain a validity period')
        not_before = datetime.strptime(
            bytes(validity.not_before).decode(),
            '%Y%m%dT%H%M%S',
        ).replace(tzinfo=UTC)
        not_after = datetime.strptime(
            bytes(validity.not_after).decode(),
            '%Y%m%dT%H%M%S',
        ).replace(tzinfo=UTC)
        now = datetime.now(UTC)
        if not not_before <= now <= not_after:
            raise ValueError('Certificate is outside its validity period')
        return cert.name, bytes(cert.content), int(not_after.timestamp() * 1000)

    def __init__(
        self,
        app,
        trust_anchor: BinaryStr,
        storage: PublicKeyStorage | None = None,
        max_depth: int = 16,
    ):
        if max_depth <= 0:
            raise ValueError('max_depth must be positive')
        self.app = app
        self.next_level: Validator = self
        self.storage = storage if storage is not None else MemoryKeyStorage()
        self.max_depth = max_depth

        anchor_name, anchor_key, anchor_expires_at = self._parse_certificate(
            trust_anchor
        )
        _, _, _, sig_ptrs = parse_data(trust_anchor)
        self.anchor_name = [bytes(component) for component in anchor_name]
        self.anchor_key = anchor_key
        self.anchor_expires_at = anchor_expires_at
        self.anchor_implicit_digest = sha256(bytes(trust_anchor)).digest()
        if not self._verify_sig(self.anchor_key, sig_ptrs):
            raise ValueError('Trust anchor is not properly self-signed')
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def _strip_implicit_digest(
        name: FormalName,
    ) -> tuple[FormalName, bytes | None]:
        if (
            name
            and Component.get_type(name[-1]) == Component.TYPE_IMPLICIT_SHA256
        ):
            return name[:-1], bytes(Component.get_value(name[-1]))
        return name, None

    async def validate(
        self,
        name: FormalName,
        sig_ptrs: SignaturePtrs,
        context: dict[str, Any] | None = None,
    ) -> ValidResult:
        sig_info = sig_ptrs.signature_info
        if (
            sig_info is None
            or sig_info.key_locator is None
            or sig_info.key_locator.name is None
        ):
            return ValidResult.FAIL

        cert_name = sig_info.key_locator.name
        cert_data_name, implicit_digest = self._strip_implicit_digest(cert_name)
        self.logger.debug(
            'Verifying %s <- %s ...',
            Name.to_str(name),
            Name.to_str(cert_name),
        )
        pending_save = None
        if (
            Name.to_bytes(cert_data_name) == Name.to_bytes(self.anchor_name)
            or (
                implicit_digest is None
                and self._is_key_name(cert_data_name)
                and len(self.anchor_name) >= 2
                and Name.to_bytes(cert_data_name)
                == Name.to_bytes(self.anchor_name[:-2])
            )
        ):
            if timestamp() > self.anchor_expires_at:
                return ValidResult.FAIL
            if (
                implicit_digest is not None
                and implicit_digest != self.anchor_implicit_digest
            ):
                return ValidResult.FAIL
            self.logger.debug('Use trust anchor')
            key_bits = self.anchor_key
        else:
            if implicit_digest is not None:
                # An implicit digest can only name a Data packet. For a
                # certificate fetch, the remaining name must therefore be a
                # complete certificate name.
                if not self._is_certificate_name(cert_data_name):
                    self.logger.debug(
                        'Implicit digest does not name a certificate'
                    )
                    return ValidResult.FAIL
            elif not (
                self._is_certificate_name(cert_data_name)
                or self._is_key_name(cert_data_name)
            ):
                self.logger.debug(
                    'KeyLocator does not name a certificate or a key'
                )
                return ValidResult.FAIL
            cache_name = (
                cert_name
                if implicit_digest is not None
                else cert_data_name
            )
            key_bits = self.storage.load(cache_name)
            if key_bits is not None:
                self.logger.debug('Use cached public key')
            else:
                self.logger.debug('Cascade fetching public key')
                chain = (
                    context.get(_CHAIN_CONTEXT_KEY, ())
                    if context is not None
                    else ()
                )
                cert_key = Name.to_bytes(cert_data_name)
                if cert_key in chain or len(chain) >= self.max_depth:
                    self.logger.debug('Certificate chain is cyclic or too deep')
                    return ValidResult.FAIL
                next_chain = chain + (cert_key,)

                async def validate_next(
                    next_name: FormalName,
                    next_sig_ptrs: SignaturePtrs,
                    next_context: dict[str, Any],
                ) -> ValidResult:
                    next_context = next_context.copy()
                    next_context[_CHAIN_CONTEXT_KEY] = next_chain
                    return await self.next_level(
                        next_name,
                        next_sig_ptrs,
                        next_context,
                    )

                kwargs = {
                    'must_be_fresh': True,
                    'can_be_prefix': (
                        implicit_digest is None
                        and not self._is_certificate_name(cert_data_name)
                        and self._is_key_name(cert_data_name)
                    ),
                }
                if context is not None and context.get('deadline') is not None:
                    kwargs['lifetime'] = max(1, context['deadline'] - timestamp())
                try:
                    fetched_name, _, cert_context = await self.app.express(
                        cert_name,
                        validator=validate_next,
                        **kwargs,
                    )
                except InterestTimeout:
                    self.logger.debug('Public key fetch timed out')
                    return ValidResult.TIMEOUT
                except ValidationFailure as exc:
                    self.logger.debug('Public key is not valid')
                    if exc.result is ValidResult.TIMEOUT:
                        return ValidResult.TIMEOUT
                    return ValidResult.FAIL
                except (
                    InterestCanceled,
                    InterestNack,
                    NetworkError,
                ):
                    self.logger.debug('Public key is not valid')
                    return ValidResult.FAIL
                self.logger.debug('Public key fetched')
                raw_packet = cert_context.get('raw_packet')
                if raw_packet is None:
                    self.logger.debug('Fetched certificate has no raw packet')
                    return ValidResult.FAIL
                if (
                    implicit_digest is not None
                    and sha256(bytes(raw_packet)).digest() != implicit_digest
                ):
                    self.logger.debug(
                        'Fetched certificate does not match the requested digest'
                    )
                    return ValidResult.FAIL
                try:
                    parsed_name, key_bits, expires_at = self._parse_certificate(
                        raw_packet,
                        cert_data_name,
                    )
                except (IndexError, TypeError, ValueError, struct.error):
                    self.logger.debug('Fetched certificate is malformed')
                    return ValidResult.FAIL
                if Name.to_bytes(fetched_name) != Name.to_bytes(parsed_name):
                    self.logger.debug(
                        'Fetched certificate name does not match the response'
                    )
                    return ValidResult.FAIL
                # Do not publish the key yet: the packet that caused this
                # fetch must first verify with it. Only then is the fetched
                # certificate known to be both qualified and useful here.
                pending_save = (
                    cert_name if implicit_digest is not None
                    else cert_data_name,
                    key_bits,
                    expires_at,
                )

        if key_bits is None:
            return ValidResult.FAIL
        if not self._verify_sig(key_bits, sig_ptrs):
            return ValidResult.FAIL
        if pending_save is not None:
            self.storage.save_with_expiration(*pending_save)
        return ValidResult.PASS

    async def __call__(
        self,
        name: FormalName,
        sig_ptrs: SignaturePtrs,
        context: dict[str, Any],
    ) -> ValidResult:
        return await self.validate(name, sig_ptrs, context)
