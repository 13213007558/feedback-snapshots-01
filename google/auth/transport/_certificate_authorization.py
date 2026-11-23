# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Call-scoped client certificate authorizations for mutual TLS.

A mutual TLS gateway accepts a client certificate for a limited time. To rotate
certificates without restarting an application, every *call* (the authentication
that produces its token plus every connection and retry it performs) must stay
on a single, explicitly identified certificate authorization. New calls are
free to pick up a freshly published certificate while calls that are already in
flight finish under the authorization they started with.

The bookkeeping is transport agnostic:

* :class:`CertificateAuthority` holds the currently published authorization and
  hands out reference counted leases.
* :class:`CertificateAuthorization` represents one published generation of
  client certificate material. The transport adapter (and therefore the TLS
  contexts used for direct connections and for connections through an existing
  proxy) is built lazily, exactly once, and only when a connection is
  established. The certificate material therefore never has to be passed around
  with individual requests or internal retries.

The active authorization for the call currently executing is exposed through
:mod:`google.auth._certificate_context` so credential refresh code can bind
tokens to the same certificate the call uses for its TLS connections.
"""

import hashlib
import logging
import os
import tempfile
import threading

from google.auth import _agent_identity_utils
from google.auth import _certificate_context
from google.auth import exceptions

_LOGGER = logging.getLogger(__name__)

get_active = _certificate_context.get_active
activate = _certificate_context.activate


def _fingerprint(cert):
    """Returns a stable fingerprint for ``cert`` without failing on odd input."""
    try:
        parsed = _agent_identity_utils.parse_certificate(cert)
        return _agent_identity_utils.calculate_certificate_fingerprint(parsed)
    except (ImportError, TypeError, ValueError):
        # Custom callbacks are allowed to supply material that is opaque to the
        # cryptography package. It can still be rotated and refcounted, so fall
        # back to a digest of the bytes themselves.
        return hashlib.sha256(cert).hexdigest()


def _create_private_temp_file(content):
    """Writes ``content`` to an owner-only temporary file and returns its path."""
    fd, path = tempfile.mkstemp(prefix="google-auth-cert-", suffix=".pem")
    try:
        with os.fdopen(fd, "wb") as file_obj:
            file_obj.write(content)
        try:
            os.chmod(path, 0o600)
        except OSError:  # pragma: NO COVER - not supported on every platform.
            pass
    except Exception:
        try:
            os.remove(path)
        except OSError:  # pragma: NO COVER
            pass
        raise
    return path


class CertificateAuthorization:
    """One published generation of client certificate material.

    Instances are created by :meth:`CertificateAuthority.publish` and are never
    mutated by callers. A generation is retired as soon as a newer generation is
    published, but it is only released once the last call holding a lease on it
    has finished.
    """

    def __init__(self, generation, cert, key, adapter_factory):
        self._generation = generation
        self._cert = cert
        self._key = key
        self._fingerprint = _fingerprint(cert)
        self._adapter_factory = adapter_factory
        self._adapter = None
        self._lock = threading.RLock()
        self._leases = 0
        self._retired = False
        self._released = False
        self._temp_paths = None

    def __repr__(self):
        return "CertificateAuthorization(generation={}, released={})".format(
            self._generation, self._released
        )

    @property
    def generation(self):
        """int: Monotonically increasing identifier of this authorization."""
        return self._generation

    @property
    def fingerprint(self):
        """str: Fingerprint of the published certificate."""
        return self._fingerprint

    @property
    def active_leases(self):
        """int: Number of calls currently using this authorization."""
        with self._lock:
            return self._leases

    @property
    def retired(self):
        """bool: Whether a newer authorization has been published."""
        with self._lock:
            return self._retired

    @property
    def released(self):
        """bool: Whether this authorization's resources were destroyed."""
        with self._lock:
            return self._released

    @property
    def cert(self):
        """bytes: The client certificate in PEM format."""
        with self._lock:
            self._check_available()
            return self._cert

    @property
    def key(self):
        """bytes: The client private key in PEM format."""
        with self._lock:
            self._check_available()
            return self._key

    @property
    def adapter(self):
        """The transport adapter carrying this generation's TLS contexts.

        The adapter is created at most once, when the session mounts the
        generation or when its first connection is established. Its direct and
        proxy TLS contexts are built from this generation's material only.
        """
        with self._lock:
            self._check_available()
            if self._adapter is None:
                _LOGGER.info(
                    "Building TLS connection contexts for client certificate "
                    "authorization generation %s.",
                    self._generation,
                )
                self._adapter = self._adapter_factory(self._cert, self._key)
            return self._adapter

    @property
    def adapter_if_built(self):
        """The adapter if it has already been built, otherwise ``None``."""
        with self._lock:
            return self._adapter

    def mtls_cert_and_key_paths(self):
        """Returns file paths for the pinned certificate and key.

        Certificate bound token exchanges and mTLS protected token endpoints
        need file paths rather than bytes. The files are created once per
        generation, are owner readable only, and are removed when the generation
        is released.
        """
        with self._lock:
            self._check_available()
            if self._temp_paths is None:
                self._temp_paths = (
                    _create_private_temp_file(self._cert),
                    _create_private_temp_file(self._key),
                )
            return self._temp_paths

    def matches(self, cert, key):
        """Returns whether ``cert``/``key`` are this generation's material."""
        with self._lock:
            if self._released:
                return False
            return self._key == key and self._fingerprint == _fingerprint(cert)

    def _check_available(self):
        if self._released:
            raise exceptions.MutualTLSChannelError(
                "Client certificate authorization generation {} has been "
                "released.".format(self._generation)
            )

    def _mark_retired(self):
        with self._lock:
            self._retired = True

    def _release_resources(self):
        with self._lock:
            if self._released:
                return
            self._released = True
            adapter = self._adapter
            self._adapter = None
            temp_paths = self._temp_paths
            self._temp_paths = None
            generation = self._generation
            # Drop the material so it cannot be reused after release.
            self._cert = None
            self._key = None
            self._fingerprint = None
        _LOGGER.info(
            "Releasing client certificate authorization generation %s; no calls "
            "are using it any more.",
            generation,
        )
        if adapter is not None:
            try:
                adapter.close()
            except Exception as exc:  # pragma: NO COVER - defensive cleanup.
                _LOGGER.warning(
                    "Failed to close TLS adapter for client certificate "
                    "authorization generation %s: %s",
                    generation,
                    exc,
                )
        if temp_paths is not None:
            for path in temp_paths:
                try:
                    os.remove(path)
                except OSError:  # pragma: NO COVER - already gone.
                    pass


class CertificateLease:
    """A reference on a :class:`CertificateAuthorization` for one API call."""

    def __init__(self, authority, authorization):
        self._authority = authority
        self.authorization = authorization
        self._released = False
        self._lock = threading.Lock()

    def __repr__(self):
        return "CertificateLease(generation={})".format(self.generation)

    @property
    def generation(self):
        """int: Generation number of the pinned authorization."""
        return self.authorization.generation

    @property
    def fingerprint(self):
        """str: Fingerprint of the pinned authorization."""
        return self.authorization.fingerprint

    def release(self):
        """Releases this call's reference on the authorization."""
        with self._lock:
            if self._released:
                return
            self._released = True
        self._authority._release(self.authorization)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.release()


class CertificateAuthority:
    """Publishes client certificate generations and leases them to calls."""

    def __init__(self):
        self._lock = threading.RLock()
        self._next_generation = 0
        self._current = None
        self._published = []
        self._closed = False

    @property
    def current(self):
        """Optional[CertificateAuthorization]: The latest published generation."""
        with self._lock:
            return self._current

    def publish(self, cert, key, adapter_factory):
        """Publishes a new certificate authorization.

        If the same certificate and key are already published, the existing
        generation is returned unchanged so repeated rotation checks do not
        churn TLS connections.

        Args:
            cert (bytes): The client certificate in PEM format.
            key (bytes): The client private key in PEM format.
            adapter_factory (Callable[[bytes, bytes], object]): Builds the
                transport adapter, and its direct and proxy TLS contexts, for
                this generation.

        Returns:
            CertificateAuthorization: The published authorization.
        """
        to_release = None
        with self._lock:
            if self._closed:
                raise exceptions.MutualTLSChannelError(
                    "The certificate authority has been closed."
                )
            current = self._current
            if current is not None and current.matches(cert, key):
                return current

            self._next_generation += 1
            authorization = CertificateAuthorization(
                self._next_generation, cert, key, adapter_factory
            )
            self._current = authorization
            self._published.append(authorization)
            if current is not None:
                current._mark_retired()
                _LOGGER.info(
                    "Published client certificate authorization generation %s. "
                    "Generation %s is retired and will be released once its %s "
                    "in-flight call(s) finish.",
                    authorization.generation,
                    current.generation,
                    current.active_leases,
                )
                if current.active_leases == 0:
                    self._published.remove(current)
                    to_release = current
            else:
                _LOGGER.info(
                    "Published client certificate authorization generation %s.",
                    authorization.generation,
                )
        if to_release is not None:
            to_release._release_resources()
        return authorization

    def owned_adapters(self):
        """Returns the adapters of every generation that is still alive.

        Callers that own a requests session need this to avoid closing TLS
        pools that in-flight calls are still using.
        """
        with self._lock:
            adapters = []
            for authorization in self._published:
                if authorization.released:
                    continue
                adapter = authorization.adapter_if_built
                if adapter is not None:
                    adapters.append(adapter)
            return adapters

    def acquire(self):
        """Pins the currently published authorization for one call.

        Returns:
            Optional[CertificateLease]: A lease, or ``None`` when no client
            certificate is configured.
        """
        with self._lock:
            if self._closed:
                raise exceptions.MutualTLSChannelError(
                    "The certificate authority has been closed."
                )
            authorization = self._current
            if authorization is None:
                return None
            authorization._leases += 1
            _LOGGER.debug(
                "Pinned client certificate authorization generation %s for a "
                "call (%s active lease(s)).",
                authorization.generation,
                authorization.active_leases,
            )
            return CertificateLease(self, authorization)

    def _release(self, authorization):
        to_release = None
        with self._lock:
            authorization._leases -= 1
            if authorization.retired and authorization.active_leases == 0:
                to_release = authorization
            generation = authorization.generation
            leases = authorization.active_leases
            if to_release is not None:
                self._published.remove(authorization)
        if to_release is not None:
            to_release._release_resources()
        else:
            _LOGGER.debug(
                "Call finished with client certificate authorization generation "
                "%s (%s active lease(s) for the retired generation).",
                generation,
                leases,
            )

    def close(self):
        """Retires the current authorization and releases what is unused.

        Calls still in flight keep their lease; the generation is released when
        the last of those calls finishes.
        """
        to_release = None
        with self._lock:
            if self._closed:
                return
            self._closed = True
            authorization = self._current
            if authorization is not None:
                authorization._mark_retired()
                if authorization.active_leases == 0:
                    to_release = authorization
                    self._published.remove(authorization)
        if to_release is not None:
            to_release._release_resources()
