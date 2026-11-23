# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""Secret cache hook"""

import base64
import hashlib
import hmac
import json
import os
import struct
import threading
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from datetime import datetime


class SecretCacheHook:  # pylint: disable=too-many-instance-attributes
    """Interface to hook the local in-memory cache.  This interface will allow
    for clients to perform actions on the items being stored in the in-memory
    cache.  One example would be encrypting/decrypting items stored in the
    in-memory cache."""

    __metaclass__ = ABCMeta

    def __init__(self):
        """Construct the secret cache hook."""

    @abstractmethod
    def put(self, obj):
        """Prepare the object for storing in the cache"""

    @abstractmethod
    def get(self, cached_obj):
        """Derive the object from the cached object."""

    def needs_rewrap(self, cached_obj):  # pylint: disable=unused-argument
        """Return True if the cached object should be rewritten with the
        current key on the next successful read.

        Hooks that do not implement key rotation can use the default value.
        """
        return False


class SecretCacheHookError(Exception):
    """Base class for secret cache hook errors."""


class SecretCacheEnvelopeFormatError(SecretCacheHookError):
    """The cached value is not a recognized envelope."""


class SecretCacheKeyUnavailableError(SecretCacheHookError):
    """The key required to open a cached envelope is not available.

    This is raised when a wrapped value is still present in the cache but its
    key has been retired, so the value must be treated as unavailable.
    """


class SecretCacheEnvelopeIntegrityError(SecretCacheHookError):
    """A cached envelope failed authentication."""


_ENVELOPE_FORMAT_VERSION = 1
_NONCE_SIZE = 16
_KEY_ID_SIZE = 32
_BYTES_TAG = "__aws_secretsmanager_caching_bytes__"
_DATETIME_TAG = "__aws_secretsmanager_caching_datetime__"
_DICT_ESCAPE_TAG = "__aws_secretsmanager_caching_dict__"
_RESERVED_TAGS = (_BYTES_TAG, _DATETIME_TAG, _DICT_ESCAPE_TAG)


@dataclass(frozen=True)
class SecretCacheEnvelope:
    """An authenticated, key-identified envelope stored in the cache."""

    key_id: str
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    format_version: int = _ENVELOPE_FORMAT_VERSION


@dataclass(frozen=True)
class _EnvelopeKey:
    key_id: str
    encryption_key: bytes
    authentication_key: bytes


def _coerce_key_material(key_material):
    if isinstance(key_material, str):
        key_material = key_material.encode("utf-8")
    elif isinstance(key_material, (bytearray, memoryview)):
        key_material = bytes(key_material)
    if not isinstance(key_material, bytes):
        raise TypeError("Envelope key material must be bytes or str")
    if not key_material:
        raise ValueError("Envelope key material must not be empty")
    return key_material


def _build_envelope_key(key_material, key_id=None):
    key_material = _coerce_key_material(key_material)
    if key_id is None:
        key_id = hashlib.sha256(key_material).hexdigest()[:_KEY_ID_SIZE]
    if not isinstance(key_id, str) or not key_id:
        raise ValueError("Envelope key id must be a non-empty string")
    return _EnvelopeKey(
        key_id=key_id,
        encryption_key=hmac.new(
            key_material, b"secretsmanager-caching:encryption", hashlib.sha256
        ).digest(),
        authentication_key=hmac.new(
            key_material, b"secretsmanager-caching:authentication", hashlib.sha256
        ).digest(),
    )


def _split_key_spec(key_spec):
    if (
        isinstance(key_spec, (tuple, list))
        and len(key_spec) == 2
        and isinstance(key_spec[1], str)
    ):
        return key_spec[0], key_spec[1]
    return key_spec, None


def _encode_value(value):
    if isinstance(value, dict):
        if len(value) == 1 and next(iter(value)) in _RESERVED_TAGS:
            # Escape payload dictionaries that could be mistaken for a tag.
            return {_DICT_ESCAPE_TAG: [[key, _encode_value(item)] for key, item in value.items()]}
        encoded = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("Envelope payload dictionaries require string keys")
            encoded[key] = _encode_value(item)
        return encoded
    if isinstance(value, (list, tuple)):
        return [_encode_value(item) for item in value]
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {_BYTES_TAG: base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, datetime):
        return {_DATETIME_TAG: value.isoformat()}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise TypeError(f"Unsupported envelope payload type: {type(value).__name__}")


def _decode_value(value):
    if isinstance(value, list):
        return [_decode_value(item) for item in value]
    if isinstance(value, dict):
        if len(value) == 1 and _BYTES_TAG in value:
            return base64.b64decode(value[_BYTES_TAG])
        if len(value) == 1 and _DATETIME_TAG in value:
            return datetime.fromisoformat(value[_DATETIME_TAG])
        if len(value) == 1 and _DICT_ESCAPE_TAG in value:
            return {key: _decode_value(item) for key, item in value[_DICT_ESCAPE_TAG]}
        return {key: _decode_value(item) for key, item in value.items()}
    return value


def _apply_keystream(key, nonce, data):
    if not data:
        return b""
    stream = bytearray()
    counter = 0
    while len(stream) < len(data):
        stream.extend(hmac.new(key, nonce + struct.pack(">Q", counter), hashlib.sha256).digest())
        counter += 1
    return bytes(left ^ right for left, right in zip(data, stream))


def _tag_input(envelope):
    key_id = envelope.key_id.encode("utf-8")
    return b"".join((
        struct.pack(">I", envelope.format_version),
        struct.pack(">I", len(key_id)),
        key_id,
        struct.pack(">I", len(envelope.nonce)),
        envelope.nonce,
        envelope.ciphertext,
    ))


class RotatingSecretCacheHook(SecretCacheHook):
    """Cache hook that supports replacing the envelope key in place.

    New envelopes are always written with the primary key. During a rotation
    the previous key can be retained so envelopes written before the rotation
    remain readable. Call :meth:`retire_legacy_keys` to stop accepting them.
    :class:`~aws_secretsmanager_caching.cache.items.SecretCacheObject` rewrites
    a legacy envelope with the primary key after a successful read, per entry;
    a failed rewrite leaves the original envelope in place so the next read
    can retry it.
    """

    def __init__(self, primary_key, key_id=None, legacy_keys=None):
        """Construct a rotating envelope hook.

        :type primary_key: bytes or str
        :param primary_key: Material used to wrap newly cached values.

        :type key_id: str
        :param key_id: Optional identifier stored with each envelope. When
            omitted, it is derived from the key material.

        :type legacy_keys: iterable
        :param legacy_keys: Keys that may still be used to read existing
            envelopes. Each item is either key material or a
            ``(key_material, key_id)`` pair.
        """
        super().__init__()
        self._lock = threading.RLock()
        self._primary = _build_envelope_key(primary_key, key_id)
        self._legacy = {}
        for key_spec in legacy_keys or ():
            material, legacy_key_id = _split_key_spec(key_spec)
            self._add_legacy_key(_build_envelope_key(material, legacy_key_id))

    def __deepcopy__(self, memo):
        # The key ring is a live security boundary. Cache configuration copies
        # must observe rotations performed on this hook.
        return self

    @property
    def primary_key_id(self):
        """The identifier of the key used for new envelopes."""
        with self._lock:
            return self._primary.key_id

    @property
    def legacy_key_ids(self):
        """The identifiers of keys that are still accepted for reads."""
        with self._lock:
            return tuple(sorted(self._legacy))

    def _add_legacy_key(self, envelope_key):
        if envelope_key.key_id == self._primary.key_id:
            return
        self._legacy[envelope_key.key_id] = envelope_key

    def rotate(self, primary_key, key_id=None, retain_previous=True):
        """Replace the primary key.

        :type primary_key: bytes or str
        :param primary_key: Material for the new primary key.

        :type key_id: str
        :param key_id: Optional identifier for the new key.

        :type retain_previous: bool
        :param retain_previous: When True, keep the previous primary key (and
            any existing legacy keys) readable. When False, only the new key
            remains available.
        """
        new_key = _build_envelope_key(primary_key, key_id)
        with self._lock:
            previous = self._primary
            if retain_previous:
                self._legacy[previous.key_id] = previous
            else:
                self._legacy.clear()
            self._legacy.pop(new_key.key_id, None)
            self._primary = new_key

    def retire_legacy_keys(self):
        """Stop accepting every key except the primary key."""
        with self._lock:
            self._legacy.clear()

    def retire_key(self, key_id):
        """Stop accepting a specific legacy key.

        :type key_id: str
        :param key_id: Identifier of the key to retire.

        :rtype: bool
        :return: True if a legacy key was retired.
        """
        with self._lock:
            if key_id == self._primary.key_id:
                raise ValueError("The primary key cannot be retired")
            return self._legacy.pop(key_id, None) is not None

    def put(self, obj):
        """Wrap the object with the current primary key."""
        payload = json.dumps(
            _encode_value(obj), separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        with self._lock:
            envelope_key = self._primary
        nonce = os.urandom(_NONCE_SIZE)
        ciphertext = _apply_keystream(envelope_key.encryption_key, nonce, payload)
        unsigned = SecretCacheEnvelope(envelope_key.key_id, nonce, ciphertext, b"")
        tag = hmac.new(
            envelope_key.authentication_key, _tag_input(unsigned), hashlib.sha256
        ).digest()
        return SecretCacheEnvelope(envelope_key.key_id, nonce, ciphertext, tag)

    def get(self, cached_obj):
        """Open an envelope, including envelopes written with a legacy key."""
        if cached_obj is None:
            return None
        if not isinstance(cached_obj, SecretCacheEnvelope):
            raise SecretCacheEnvelopeFormatError("Cached value is not an envelope")
        if cached_obj.format_version != _ENVELOPE_FORMAT_VERSION:
            raise SecretCacheEnvelopeFormatError(
                f"Unsupported envelope format version: {cached_obj.format_version}"
            )

        with self._lock:
            if cached_obj.key_id == self._primary.key_id:
                envelope_key = self._primary
            else:
                envelope_key = self._legacy.get(cached_obj.key_id)
        if envelope_key is None:
            raise SecretCacheKeyUnavailableError(
                f"Envelope key {cached_obj.key_id!r} is no longer available"
            )

        expected_tag = hmac.new(
            envelope_key.authentication_key, _tag_input(cached_obj), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(expected_tag, cached_obj.tag):
            raise SecretCacheEnvelopeIntegrityError("Envelope authentication failed")

        payload = _apply_keystream(
            envelope_key.encryption_key, cached_obj.nonce, cached_obj.ciphertext
        )
        try:
            return _decode_value(json.loads(payload.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as error:
            raise SecretCacheEnvelopeFormatError("Envelope payload is invalid") from error

    def needs_rewrap(self, cached_obj):
        """Return True when an envelope is not using the primary key."""
        if not isinstance(cached_obj, SecretCacheEnvelope):
            return False
        with self._lock:
            return cached_obj.key_id != self._primary.key_id
