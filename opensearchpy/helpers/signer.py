# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.

from typing import Any, Callable, Dict, Optional, Union
from urllib.parse import parse_qs, urlencode, urlparse

import requests


class CredentialProviderError(RuntimeError):
    """
    Raised when a credential provider cannot supply credentials.

    The underlying provider failure is attached as the cause so applications
    can distinguish a temporarily unavailable provider from a configuration
    problem and decide whether to retry later.
    """


class CredentialProvider:
    """
    Supplies temporary AWS credentials, typically backed by an STS assume-role
    or web-identity session that the application refreshes once the current
    credentials expire.

    A provider only needs to implement ``get_credentials()`` and return an
    object exposing ``access_key``, ``secret_key`` and ``token`` attributes
    (for example a botocore credential object). Callable providers are also
    accepted directly, so a plain function or lambda can be used in tests and
    simple applications.
    """

    def get_credentials(self) -> Any:
        raise NotImplementedError(
            "CredentialProvider subclasses must implement get_credentials()"
        )


def _is_credential_provider(value: Any) -> bool:
    # Credential objects (and their mocks) expose the signing attributes.
    # Check those first so auto-created Mock attributes such as
    # ``get_credentials`` cannot make a credentials object look like a
    # provider.
    if hasattr(value, "access_key") and hasattr(value, "secret_key"):
        return False
    # A real provider exposes get_credentials(); plain callables
    # (functions/lambdas) are supported as providers too.
    return callable(getattr(value, "get_credentials", None)) or callable(value)


class AWSV4Signer:
    """
    Generic AWS V4 Request Signer.

    Credentials may be provided either directly as a credentials object or
    through a :class:`CredentialProvider` (or any callable returning
    credentials). When a provider is used, credentials are resolved once per
    signing call and immediately frozen, so a single outgoing request is
    always signed with one consistent credential view even if the provider
    rotates credentials mid-request.

    Set ``reuse_credentials_on_retry=False`` to take a fresh credential
    snapshot from the provider whenever a request is retried. By default the
    signer tracks the retry state and reuses the frozen credentials across
    retries of the same logical request, keeping every attempt identical.
    """

    def __init__(
        self,
        credentials: Union[Any, CredentialProvider, Callable[..., Any]],
        region: str,
        service: str = "es",
        reuse_credentials_on_retry: bool = True,
    ) -> Any:  # type: ignore
        if not credentials:
            raise ValueError("Credentials cannot be empty")
        self.credentials = credentials
        self._uses_provider = _is_credential_provider(credentials)

        if not region:
            raise ValueError("Region cannot be empty")
        self.region = region

        if not service:
            raise ValueError("Service name cannot be empty")
        self.service = service

        self.reuse_credentials_on_retry = reuse_credentials_on_retry
        # Frozen credentials reused across retries of the current request.
        self._frozen_credentials: Any = None
        # Number of signing attempts performed for the current logical request.
        self._sign_attempts = 0

    def _resolve_credentials(self, force_refresh: bool = False) -> Any:
        """
        Return a non-refreshing snapshot of the credentials.

        With a static credentials object the existing object is frozen. With a
        provider, ``get_credentials()`` is called lazily and its result frozen
        via ``get_frozen_credentials()`` when available. Provider failures are
        surfaced as :class:`CredentialProviderError` instead of leaking the
        underlying implementation exception.
        """
        if not self._uses_provider:
            return self._freeze(self.credentials)

        if (
            self.reuse_credentials_on_retry
            and self._frozen_credentials is not None
            and not force_refresh
        ):
            return self._frozen_credentials

        try:
            if hasattr(self.credentials, "get_credentials"):
                resolved = self.credentials.get_credentials()
            else:
                resolved = self.credentials()
        except CredentialProviderError:
            raise
        except Exception as error:
            raise CredentialProviderError(
                "Credential provider was unable to supply credentials"
            ) from error

        if not resolved:
            raise CredentialProviderError(
                "Credential provider returned empty credentials"
            )

        self._frozen_credentials = self._freeze(resolved)
        return self._frozen_credentials

    @staticmethod
    def _freeze(credentials: Any) -> Any:
        # credentials objects expose access_key, secret_key and token attributes
        # via @property annotations that call _refresh() on every access,
        # creating a race condition if the credentials expire before secret_key
        # is called but after access_key- the end result is the access_key doesn't
        # correspond to the secret_key used to sign the request. To avoid this,
        # get_frozen_credentials() which returns non-refreshing credentials is
        # called if it exists.
        if hasattr(credentials, "get_frozen_credentials") and callable(
            credentials.get_frozen_credentials
        ):
            return credentials.get_frozen_credentials()
        return credentials

    def reset_request(self) -> None:
        """
        Mark the start of a new logical request.

        Retry bookkeeping is otherwise advanced on every :meth:`sign` call.
        Transports that reuse one auth instance across several requests should
        call this before each new request so the first attempt of every
        request resolves credentials from the provider again.
        """
        self._sign_attempts = 0
        self._frozen_credentials = None

    def sign(
        self,
        method: str,
        url: str,
        body: Any,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """
        Sign the request and return the resulting headers.

        Each call counts as one attempt of the current logical request. The
        first call resolves and freezes the credentials; subsequent calls
        (retries) reuse that snapshot when
        ``reuse_credentials_on_retry`` is enabled, otherwise a fresh snapshot
        is taken from the provider before signing.
        """

        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest

        force_refresh = (
            self._sign_attempts > 0 and not self.reuse_credentials_on_retry
        )
        credentials = self._resolve_credentials(force_refresh=force_refresh)
        self._sign_attempts += 1

        signature_host = self._fetch_url(url, headers or dict())

        # create an AWS request object and sign it using SigV4Auth
        aws_request = AWSRequest(
            method=method.upper(), url=signature_host, data=body, headers=headers or {}
        )

        sig_v4_auth = SigV4Auth(credentials, self.service, self.region)

        # Set X-Amz-Content-SHA256 before signing so it is included in SignedHeaders.
        # Per the SigV4 spec, x-amz-* headers must be signed. Preserve any
        # caller-provided value (e.g., UNSIGNED-PAYLOAD or precomputed hashes).
        if "X-Amz-Content-SHA256" not in aws_request.headers:
            aws_request.headers["X-Amz-Content-SHA256"] = sig_v4_auth.payload(
                aws_request
            )

        sig_v4_auth.add_auth(aws_request)

        return dict(aws_request.headers.items())

    @staticmethod
    def _fetch_url(url: str, headers: Optional[Dict[str, str]]) -> str:
        """
        This is a util method that helps in reconstructing the request url.
        :param prepared_request: unsigned request
        :return: reconstructed url
        """
        parsed_url = urlparse(url)
        path = parsed_url.path or "/"

        # fetch the query string if present in the request
        querystring = ""
        if parsed_url.query:
            querystring = "?" + urlencode(
                parse_qs(parsed_url.query, keep_blank_values=True), doseq=True
            )

        # fetch the host information from headers
        headers = {key.lower(): value for key, value in (headers or dict()).items()}
        location = headers.get("host") or parsed_url.netloc

        # construct the url and return
        return parsed_url.scheme + "://" + location + path + querystring


class RequestsAWSV4SignerAuth(requests.auth.AuthBase):
    """
    AWS V4 Request Signer for Requests.

    :arg reuse_credentials_on_retry: when ``True`` (default) retries of a
        request reuse the frozen credentials resolved for its first attempt;
        when ``False`` every retry fetches a fresh snapshot from the
        credential provider.
    """

    def __init__(
        self,
        credentials,
        region,
        service: str = "es",
        reuse_credentials_on_retry: bool = True,
    ) -> None:  # type: ignore
        self.signer = AWSV4Signer(
            credentials,
            region,
            service,
            reuse_credentials_on_retry=reuse_credentials_on_retry,
        )
        self.service = service  # tools like LangChain rely on this, see https://github.com/opensearch-project/opensearch-py/issues/600

    def __call__(self, request):  # type: ignore
        return self._sign_request(request)  # type: ignore

    def reset_request(self) -> None:
        """Reset retry bookkeeping for the next logical request."""
        self.signer.reset_request()

    def _sign_request(self, prepared_request):  # type: ignore
        """
        This method helps in signing the request by injecting the required headers.
        :param prepared_request: unsigned request
        :return: signed request
        """

        updated_headers = self.signer.sign(
            method=prepared_request.method,
            url=prepared_request.url,
            body=prepared_request.body,
            headers=prepared_request.headers,
        )

        prepared_request.headers.update(updated_headers)

        return prepared_request


# Deprecated: use RequestsAWSV4SignerAuth
class AWSV4SignerAuth(RequestsAWSV4SignerAuth):
    pass


class Urllib3AWSV4SignerAuth(Callable):  # type: ignore
    def __init__(
        self,
        credentials,
        region,
        service: str = "es",
        reuse_credentials_on_retry: bool = True,
    ) -> None:  # type: ignore
        self.signer = AWSV4Signer(
            credentials,
            region,
            service,
            reuse_credentials_on_retry=reuse_credentials_on_retry,
        )
        self.service = service  # tools like LangChain rely on this, see https://github.com/opensearch-project/opensearch-py/issues/600

    def __call__(
        self, method: str, url: str, body: Any, headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        return self.signer.sign(method, url, body, headers)

    def reset_request(self) -> None:
        """Reset retry bookkeeping for the next logical request."""
        self.signer.reset_request()
