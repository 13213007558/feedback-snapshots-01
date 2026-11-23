# Copyright 2016 Google LLC
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

"""Transport adapter for Requests."""

from __future__ import absolute_import

import functools
import http.client as http_client
import logging
import numbers
import time
from typing import Optional

try:
    import requests
except ImportError as caught_exc:  # pragma: NO COVER
    raise ImportError(
        "The requests library is not installed from please install the requests package to use the requests transport."
    ) from caught_exc
import requests.adapters  # pylint: disable=ungrouped-imports
import requests.exceptions  # pylint: disable=ungrouped-imports
from requests.packages.urllib3.util.ssl_ import (  # type: ignore
    create_urllib3_context,
)  # pylint: disable=ungrouped-imports

from google.auth import _certificate_context
from google.auth import _helpers
from google.auth import exceptions
from google.auth import transport
from google.auth.transport import _certificate_authorization
from google.auth.transport import _mtls_helper
import google.auth.transport._mtls_helper
from google.oauth2 import service_account

_LOGGER = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 120  # in seconds


class _Response(transport.Response):
    """Requests transport response adapter.

    Args:
        response (requests.Response): The raw Requests response.
    """

    def __init__(self, response):
        self._response = response

    @property
    def status(self):
        return self._response.status_code

    @property
    def headers(self):
        return self._response.headers

    @property
    def data(self):
        return self._response.content


class TimeoutGuard(object):
    """A context manager raising an error if the suite execution took too long.

    Args:
        timeout (Union[None, Union[float, Tuple[float, float]]]):
            The maximum number of seconds a suite can run without the context
            manager raising a timeout exception on exit. If passed as a tuple,
            the smaller of the values is taken as a timeout. If ``None``, a
            timeout error is never raised.
        timeout_error_type (Optional[Exception]):
            The type of the error to raise on timeout. Defaults to
            :class:`requests.exceptions.Timeout`.
    """

    def __init__(self, timeout, timeout_error_type=requests.exceptions.Timeout):
        self._timeout = timeout
        self.remaining_timeout = timeout
        self._timeout_error_type = timeout_error_type

    def __enter__(self):
        self._start = time.time()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_value:
            return  # let the error bubble up automatically

        if self._timeout is None:
            return  # nothing to do, the timeout was not specified

        elapsed = time.time() - self._start
        deadline_hit = False

        if isinstance(self._timeout, numbers.Number):
            self.remaining_timeout = self._timeout - elapsed
            deadline_hit = self.remaining_timeout <= 0
        else:
            self.remaining_timeout = tuple(x - elapsed for x in self._timeout)
            deadline_hit = min(self.remaining_timeout) <= 0

        if deadline_hit:
            raise self._timeout_error_type()


class Request(transport.Request):
    """Requests request adapter.

    This class is used internally for making requests using various transports
    in a consistent way. If you use :class:`AuthorizedSession` you do not need
    to construct or use this class directly.

    This class can be useful if you want to manually refresh a
    :class:`~google.auth.credentials.Credentials` instance::

        import google.auth.transport.requests
        import requests

        request = google.auth.transport.requests.Request()

        credentials.refresh(request)

    Args:
        session (requests.Session): An instance :class:`requests.Session` used
            to make HTTP requests. If not specified, a session will be created.

    .. automethod:: __call__
    """

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        if not session:
            session = requests.Session()

        self.session = session

    def __del__(self):
        try:
            if hasattr(self, "session") and self.session is not None:
                self.session.close()
        except TypeError:
            # NOTE: For certain Python binary built, the queue.Empty exception
            # might not be considered a normal Python exception causing
            # TypeError.
            pass

    def __call__(
        self,
        url,
        method="GET",
        body=None,
        headers=None,
        timeout=_DEFAULT_TIMEOUT,
        **kwargs
    ):
        """Make an HTTP request using requests.

        Args:
            url (str): The URI to be requested.
            method (str): The HTTP method to use for the request. Defaults
                to 'GET'.
            body (bytes): The payload or body in HTTP request.
            headers (Mapping[str, str]): Request headers.
            timeout (Optional[int]): The number of seconds to wait for a
                response from the server. If not specified or if None, the
                requests default timeout will be used.
            kwargs: Additional arguments passed through to the underlying
                requests :meth:`~requests.Session.request` method.

        Returns:
            google.auth.transport.Response: The HTTP response.

        Raises:
            google.auth.exceptions.TransportError: If any exception occurred.
        """
        try:
            _helpers.request_log(_LOGGER, method, url, body, headers)
            response = self.session.request(
                method, url, data=body, headers=headers, timeout=timeout, **kwargs
            )
            _helpers.response_log(_LOGGER, response)
            return _Response(response)
        except requests.exceptions.RequestException as caught_exc:
            new_exc = exceptions.TransportError(caught_exc)
            raise new_exc from caught_exc


class _MutualTlsAdapter(requests.adapters.HTTPAdapter):
    """
    A TransportAdapter that enables mutual TLS.

    The adapter carries one certificate authorization generation. Its direct
    connection pool and its proxy connection pools each get their own TLS
    context built from the same certificate and key, so both the direct and the
    existing-proxy paths present the same authorization.

    Args:
        cert (bytes): client certificate in PEM format
        key (bytes): client private key in PEM format

    Raises:
        ImportError: if certifi or pyOpenSSL is not installed
        OpenSSL.crypto.Error: if client cert or key is invalid
    """

    def __init__(self, cert, key):
        import certifi
        from OpenSSL import crypto
        import urllib3.contrib.pyopenssl  # type: ignore

        urllib3.contrib.pyopenssl.inject_into_urllib3()

        self._certifi = certifi
        # Validate and keep the parsed material. The direct TLS context is
        # created by ``init_poolmanager`` below and the proxy TLS context is
        # created only if an existing proxy is used, but both are built from
        # this generation's material and never from per-request arguments.
        self._pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
        self._x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        self._ctx_poolmanager = None
        self._ctx_proxymanager = None

        super(_MutualTlsAdapter, self).__init__()

    def _build_context(self):
        ctx = create_urllib3_context()
        ctx.load_verify_locations(cafile=self._certifi.where())
        ctx._ctx.use_certificate(self._x509)
        ctx._ctx.use_privatekey(self._pkey)
        return ctx

    def init_poolmanager(self, *args, **kwargs):
        if self._ctx_poolmanager is None:
            self._ctx_poolmanager = self._build_context()
        kwargs["ssl_context"] = self._ctx_poolmanager
        super(_MutualTlsAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        if self._ctx_proxymanager is None:
            self._ctx_proxymanager = self._build_context()
        kwargs["ssl_context"] = self._ctx_proxymanager
        return super(_MutualTlsAdapter, self).proxy_manager_for(*args, **kwargs)

    def close(self):
        super(_MutualTlsAdapter, self).close()
        self._ctx_poolmanager = None
        self._ctx_proxymanager = None
        self._x509 = None
        self._pkey = None


class _MutualTlsOffloadAdapter(requests.adapters.HTTPAdapter):
    """
    A TransportAdapter that enables mutual TLS and offloads the client side
    signing operation to the signing library.

    Args:
        enterprise_cert_file_path (str): the path to a enterprise cert JSON
            file. The file should contain the following field:

                {
                    "libs": {
                        "signer_library": "...",
                        "offload_library": "..."
                    }
                }

    Raises:
        ImportError: if certifi or pyOpenSSL is not installed
        google.auth.exceptions.MutualTLSChannelError: If mutual TLS channel
            creation failed for any reason.
    """

    def __init__(self, enterprise_cert_file_path):
        import certifi
        from google.auth.transport import _custom_tls_signer

        self.signer = _custom_tls_signer.CustomTlsSigner(enterprise_cert_file_path)
        self.signer.load_libraries()

        import urllib3.contrib.pyopenssl

        urllib3.contrib.pyopenssl.inject_into_urllib3()

        poolmanager = create_urllib3_context()
        poolmanager.load_verify_locations(cafile=certifi.where())
        self.signer.attach_to_ssl_context(poolmanager)
        self._ctx_poolmanager = poolmanager

        proxymanager = create_urllib3_context()
        proxymanager.load_verify_locations(cafile=certifi.where())
        self.signer.attach_to_ssl_context(proxymanager)
        self._ctx_proxymanager = proxymanager

        super(_MutualTlsOffloadAdapter, self).__init__()

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self._ctx_poolmanager
        super(_MutualTlsOffloadAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs["ssl_context"] = self._ctx_proxymanager
        return super(_MutualTlsOffloadAdapter, self).proxy_manager_for(*args, **kwargs)


class AuthorizedSession(requests.Session):
    """A Requests Session class with credentials.

    This class is used to perform requests to API endpoints that require
    authorization::

        from google.auth.transport.requests import AuthorizedSession

        authed_session = AuthorizedSession(credentials)

        response = authed_session.request(
            'GET', 'https://www.googleapis.com/storage/v1/b')


    The underlying :meth:`request` implementation handles adding the
    credentials' headers to the request and refreshing credentials as needed.

    This class also supports mutual TLS via :meth:`configure_mtls_channel`
    method. In order to use this method, the `GOOGLE_API_USE_CLIENT_CERTIFICATE`
    environment variable must be explicitly set to ``true``, otherwise it does
    nothing. Assume the environment is set to ``true``, the method behaves in the
    following manner:

    If client_cert_callback is provided, client certificate and private
    key are loaded using the callback; if client_cert_callback is None,
    application default SSL credentials will be used. Exceptions are raised if
    there are problems with the certificate, private key, or the loading process,
    so it should be called within a try/except block.

    First we set the environment variable to ``true``, then create an :class:`AuthorizedSession`
    instance and specify the endpoints::

        regular_endpoint = 'https://pubsub.googleapis.com/v1/projects/{my_project_id}/topics'
        mtls_endpoint = 'https://pubsub.mtls.googleapis.com/v1/projects/{my_project_id}/topics'

        authed_session = AuthorizedSession(credentials)

    Now we can pass a callback to :meth:`configure_mtls_channel`::

        def my_cert_callback():
            # some code to load client cert bytes and private key bytes, both in
            # PEM format.
            some_code_to_load_client_cert_and_key()
            if loaded:
                return cert, key
            raise MyClientCertFailureException()

        # Always call configure_mtls_channel within a try/except block.
        try:
            authed_session.configure_mtls_channel(my_cert_callback)
        except:
            # handle exceptions.

        if authed_session.is_mtls:
            response = authed_session.request('GET', mtls_endpoint)
        else:
            response = authed_session.request('GET', regular_endpoint)


    You can alternatively use application default SSL credentials like this::

        try:
            authed_session.configure_mtls_channel()
        except:
            # handle exceptions.

    Args:
        credentials (google.auth.credentials.Credentials): The credentials to
            add to the request.
        refresh_status_codes (Sequence[int]): Which HTTP status codes indicate
            that credentials should be refreshed and the request should be
            retried.
        max_refresh_attempts (int): The maximum number of times to attempt to
            refresh the credentials and retry the request.
        refresh_timeout (Optional[int]): The timeout value in seconds for
            credential refresh HTTP requests.
        auth_request (google.auth.transport.requests.Request):
            (Optional) An instance of
            :class:`~google.auth.transport.requests.Request` used when
            refreshing credentials. If not passed,
            an instance of :class:`~google.auth.transport.requests.Request`
            is created.
        default_host (Optional[str]): A host like "pubsub.googleapis.com".
            This is used when a self-signed JWT is created from service
            account credentials.
    """

    def __init__(
        self,
        credentials,
        refresh_status_codes=transport.DEFAULT_REFRESH_STATUS_CODES,
        max_refresh_attempts=transport.DEFAULT_MAX_REFRESH_ATTEMPTS,
        refresh_timeout=None,
        auth_request=None,
        default_host=None,
    ):
        super(AuthorizedSession, self).__init__()
        self.credentials = credentials
        self._refresh_status_codes = refresh_status_codes
        self._max_refresh_attempts = max_refresh_attempts
        self._refresh_timeout = refresh_timeout
        self._is_mtls = False
        self._cached_cert = None
        self._certificate_authority = _certificate_authorization.CertificateAuthority()
        self._default_host = default_host

        if auth_request is None:
            self._auth_request_session = requests.Session()

            # Using an adapter to make HTTP requests robust to network errors.
            # This adapter retrys HTTP requests when network errors occur
            # and the requests seems safely retryable.
            retry_adapter = requests.adapters.HTTPAdapter(max_retries=3)
            self._auth_request_session.mount("https://", retry_adapter)

            # Do not pass `self` as the session here, as it can lead to
            # infinite recursion.
            auth_request = Request(self._auth_request_session)
        else:
            self._auth_request_session = None

        # Request instance used by internal methods (for example,
        # credentials.refresh).
        self._auth_request = auth_request

        # https://google.aip.dev/auth/4111
        # Attempt to use self-signed JWTs when a service account is used.
        if isinstance(self.credentials, service_account.Credentials):
            self.credentials._create_self_signed_jwt(
                "https://{}/".format(self._default_host) if self._default_host else None
            )

    def configure_mtls_channel(self, client_cert_callback=None):
        """Configure the client certificate and key for SSL connection.

        The function does nothing unless `GOOGLE_API_USE_CLIENT_CERTIFICATE` is
        explicitly set to `true`. In this case if client certificate and key are
        successfully obtained (from the given client_cert_callback or from application
        default SSL credentials), the certificate is published as a new
        authorization generation. Calls that start afterwards use it; calls that
        are already in flight keep the generation they started with until they
        finish.

        Args:
            client_cert_callback (Optional[Callable[[], (bytes, bytes)]]):
                The optional callback returns the client certificate and private
                key bytes both in PEM format.
                If the callback is None, application default SSL credentials
                will be used.

        Raises:
            google.auth.exceptions.MutualTLSChannelError: If mutual TLS channel
                creation failed for any reason.
        """
        use_client_cert = google.auth.transport._mtls_helper.check_use_client_cert()
        if not use_client_cert:
            self._is_mtls = False
            return
        try:
            import OpenSSL
        except ImportError as caught_exc:
            new_exc = exceptions.MutualTLSChannelError(caught_exc)
            raise new_exc from caught_exc

        try:
            (
                found_cert_key,
                cert,
                key,
            ) = google.auth.transport._mtls_helper.get_client_cert_and_key(
                client_cert_callback
            )
        except (
            exceptions.ClientCertError,
            ImportError,
            OpenSSL.crypto.Error,
        ) as caught_exc:
            new_exc = exceptions.MutualTLSChannelError(caught_exc)
            raise new_exc from caught_exc

        if not found_cert_key:
            self._is_mtls = False
            return

        self._cached_cert = cert
        authorization = self._certificate_authority.publish(
            cert, key, _MutualTlsAdapter
        )
        # Keep ``adapters`` pointing at the newest generation for callers that
        # use ``Session.send`` directly. In-flight calls are unaffected: they
        # resolve the adapter through the authorization pinned for the call.
        self.mount("https://", authorization.adapter)
        self._is_mtls = True

    def _publish_rotated_certificate(self, authorization):
        """Publishes a newly discovered certificate for subsequent calls.

        The certificate source is only consulted after a 401, exactly like the
        pre-existing rotation check. An unchanged certificate, an unreadable
        source or an invalid certificate leaves the published authorization in
        place; the call that observed the 401 keeps its pinned generation.
        """
        if not self.is_mtls:
            return
        (
            call_cert_bytes,
            call_key_bytes,
            cached_fingerprint,
            current_cert_fingerprint,
        ) = _mtls_helper.check_parameters_for_unauthorized_response(self._cached_cert)
        if cached_fingerprint == current_cert_fingerprint:
            _LOGGER.info(
                "Skipping reconfiguration of mTLS channel because the client "
                "certificate has not changed."
            )
            return
        try:
            _LOGGER.info(
                "Client certificate has changed, publishing a new mTLS channel."
            )
            self.configure_mtls_channel(lambda: (call_cert_bytes, call_key_bytes))
        except Exception as e:
            _LOGGER.error("Failed to reconfigure mTLS channel: %s", e)
            raise exceptions.MutualTLSChannelError(
                "Failed to reconfigure mTLS channel"
            ) from e
        published = self._certificate_authority.current
        if published is not None and authorization is not None:
            _LOGGER.info(
                "Published client certificate authorization generation %s; the "
                "in-flight call keeps generation %s until it finishes.",
                published.generation,
                authorization.generation,
            )

    def get_adapter(self, url):
        """Returns the adapter to use for ``url``.

        While a call is in progress, the certificate authorization pinned at
        the start of that call wins for HTTPS URLs. This makes the call keep the
        TLS connection contexts it started with even if another thread publishes
        a new certificate in the middle of it. Redirects followed inside the
        call stay pinned for the same reason.
        """
        if url.lower().startswith("https://"):
            authorization = _certificate_context.get_active()
            if authorization is not None:
                return authorization.adapter
        return super(AuthorizedSession, self).get_adapter(url)

    def _send_with_authorization(self, authorization, *args, **kwargs):
        """Sends a request over the pinned authorization.

        The authorization is already active for the duration of the call, so
        ``get_adapter`` resolves HTTPS requests to its adapter. The method is a
        separate seam so transports and tests can observe or replace the send.
        """
        return super(AuthorizedSession, self).request(*args, **kwargs)

    def request(
        self,
        method,
        url,
        data=None,
        headers=None,
        max_allowed_time=None,
        timeout=_DEFAULT_TIMEOUT,
        **kwargs
    ):
        """Implementation of Requests' request.

        Args:
            timeout (Optional[Union[float, Tuple[float, float]]]):
                The amount of time in seconds to wait for the server response
                with each individual request. Can also be passed as a tuple
                ``(connect_timeout, read_timeout)``. See :meth:`requests.Session.request`
                documentation for details.
            max_allowed_time (Optional[float]):
                If the method runs longer than this, a ``Timeout`` exception is
                automatically raised. Unlike the ``timeout`` parameter, this
                value applies to the total method execution time, even if
                multiple requests are made under the hood.

                Mind that it is not guaranteed that the timeout error is raised
                at ``max_allowed_time``. It might take longer, for example, if
                an underlying request takes a lot of time, but the request
                itself does not timeout, e.g. if a large file is being
                transmitted. The timeout error will be raised after such
                request completes.
        Raises:
            google.auth.exceptions.MutualTLSChannelError: If mutual TLS
                channel creation fails for any reason.
            ValueError: If the client certificate is invalid.
        """
        # pylint: disable=arguments-differ
        # Requests has a ton of arguments to request, but only two
        # (method, url) are required. We pass through all of the other
        # arguments to super, so no need to exhaustively list them here.

        # Use a kwarg for this instead of an attribute to maintain
        # thread-safety. ``_certificate_lease`` is set on the first execution
        # and carried through the internal authentication retry so the whole
        # call stays on one certificate authorization.
        _credential_refresh_attempt = kwargs.pop("_credential_refresh_attempt", 0)
        certificate_lease = kwargs.pop("_certificate_lease", None)

        owns_lease = False
        if certificate_lease is None:
            certificate_lease = self._certificate_authority.acquire()
            owns_lease = True
        authorization = (
            certificate_lease.authorization if certificate_lease is not None else None
        )
        try:
            # Pinning the authorization for the whole call means credential
            # refresh, the TLS connection, redirects and the internal
            # authentication retry all observe the same certificate.
            with _certificate_authorization.activate(authorization):
                return self._request_with_certificate_lease(
                    certificate_lease,
                    method,
                    url,
                    data=data,
                    headers=headers,
                    max_allowed_time=max_allowed_time,
                    timeout=timeout,
                    _credential_refresh_attempt=_credential_refresh_attempt,
                    **kwargs
                )
        finally:
            if owns_lease and certificate_lease is not None:
                certificate_lease.release()

    def _request_with_certificate_lease(
        self,
        certificate_lease,
        method,
        url,
        data=None,
        headers=None,
        max_allowed_time=None,
        timeout=_DEFAULT_TIMEOUT,
        _credential_refresh_attempt=0,
        **kwargs
    ):
        authorization = (
            certificate_lease.authorization if certificate_lease is not None else None
        )
        _LOGGER.debug(
            "Starting call %s %s under client certificate authorization generation %s.",
            method,
            url,
            authorization.generation if authorization is not None else None,
        )

        # Make a copy of the headers. They will be modified by the credentials
        # and we want to pass the original headers if we recurse.
        request_headers = headers.copy() if headers is not None else {}

        # Do not apply the timeout unconditionally in order to not override the
        # _auth_request's default timeout.
        auth_request = (
            self._auth_request
            if timeout is None
            else functools.partial(self._auth_request, timeout=timeout)
        )

        remaining_time = max_allowed_time

        with TimeoutGuard(remaining_time) as guard:
            self.credentials.before_request(auth_request, method, url, request_headers)
        remaining_time = guard.remaining_timeout

        with TimeoutGuard(remaining_time) as guard:
            _helpers.request_log(_LOGGER, method, url, data, headers)
            response = self._send_with_authorization(
                authorization,
                method,
                url,
                data=data,
                headers=request_headers,
                timeout=timeout,
                **kwargs
            )
        remaining_time = guard.remaining_timeout

        # If the response indicated that the credentials needed to be
        # refreshed, then refresh the credentials and re-attempt the
        # request.
        # A stored token may expire between the time it is retrieved and
        # the time the request is made, so we may need to try twice.
        if (
            response.status_code in self._refresh_status_codes
            and _credential_refresh_attempt < self._max_refresh_attempts
        ):
            # Handle unauthorized permission error(401 status code)
            if response.status_code == http_client.UNAUTHORIZED and self.is_mtls:
                self._publish_rotated_certificate(authorization)
            _LOGGER.info(
                "Refreshing credentials due to a %s response. Attempt %s/%s.",
                response.status_code,
                _credential_refresh_attempt + 1,
                self._max_refresh_attempts,
            )

            # Do not apply the timeout unconditionally in order to not override the
            # _auth_request's default timeout.
            auth_request = (
                self._auth_request
                if timeout is None
                else functools.partial(self._auth_request, timeout=timeout)
            )

            with TimeoutGuard(remaining_time) as guard:
                self.credentials.refresh(auth_request)
            remaining_time = guard.remaining_timeout

            # Recurse on the same lease. Pass in the original headers, not our
            # modified set, but do pass the adjusted max allowed time (i.e. the
            # remaining total time).
            return self.request(
                method,
                url,
                data=data,
                headers=headers,
                max_allowed_time=remaining_time,
                timeout=timeout,
                _credential_refresh_attempt=_credential_refresh_attempt + 1,
                _certificate_lease=certificate_lease,
                **kwargs
            )

        return response

    @property
    def is_mtls(self):
        """Indicates if the created SSL channel is mutual TLS."""
        return self._is_mtls

    @property
    def certificate_authorization(self):
        """The certificate authorization used by calls that start now.

        Returns:
            Optional[CertificateAuthorization]: The currently published
            authorization, or ``None`` when mTLS is not configured.
        """
        return self._certificate_authority.current

    def close(self):
        if self._auth_request_session is not None:
            self._auth_request_session.close()
        # ``requests.Session.close`` closes every mounted adapter. That would
        # tear down the TLS pools of authorizations that still have calls in
        # flight, so close only adapters this session does not share with a
        # live generation. A generation closes its own adapter when the last
        # call using it finishes.
        generation_adapters = set(self._certificate_authority.owned_adapters())
        for adapter in set(self.adapters.values()):
            if adapter not in generation_adapters:
                adapter.close()
        self._certificate_authority.close()
