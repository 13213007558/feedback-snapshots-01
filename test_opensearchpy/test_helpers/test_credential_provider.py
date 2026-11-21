# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.

import uuid
from typing import Any, Dict, List, Optional
from unittest.mock import Mock

import pytest

from opensearchpy.helpers.signer import (
    AWSV4Signer,
    CredentialProvider,
    CredentialProviderError,
    RequestsAWSV4SignerAuth,
    Urllib3AWSV4SignerAuth,
)

REGION = "us-west-2"
SERVICE = "es"
URL = "http://localhost:9200/index/_search"


class FakeCredentials:
    """Static, non-refreshing credentials object used for deterministic tests."""

    def __init__(self, access_key: str, secret_key: str, token: str) -> None:
        self.access_key = access_key
        self.secret_key = secret_key
        self.token = token


class RefreshingCredentials(FakeCredentials):
    """Mimics a botocore credentials object whose properties self-refresh."""

    def __init__(
        self, provider: "FakeCredentialProvider", access_key: str, secret_key: str, token: str
    ) -> None:
        super().__init__(access_key, secret_key, token)
        self._provider = provider

    def get_frozen_credentials(self) -> FakeCredentials:
        return FakeCredentials(self.access_key, self.secret_key, self.token)


class FakeCredentialProvider(CredentialProvider):
    """In-memory provider the test can rotate or take offline."""

    def __init__(self, credentials: Optional[FakeCredentials] = None) -> None:
        self._credentials = credentials
        self.calls = 0
        self.offline = False
        self.offline_error: Optional[Exception] = None

    def set_credentials(self, credentials: FakeCredentials) -> None:
        self._credentials = credentials
        self.offline = False

    def get_credentials(self) -> FakeCredentials:
        self.calls += 1
        if self.offline:
            raise self.offline_error or RuntimeError("credential provider is unavailable")
        assert self._credentials is not None
        return self._credentials


def make_credentials(prefix: str = "AKIA") -> FakeCredentials:
    return FakeCredentials(f"{prefix}-{uuid.uuid4().hex}", uuid.uuid4().hex, uuid.uuid4().hex)


def credential_key_from_header(authorization: str) -> str:
    # AWS4-HMAC-SHA256 Credential=<access-key>/<date>/<region>/<service>/aws4_request, ...
    credential = authorization.split("Credential=", 1)[1].split(",", 1)[0]
    return credential.split("/", 1)[0]


def credential_scope(authorization: str) -> List[str]:
    credential = authorization.split("Credential=", 1)[1].split(",", 1)[0]
    # <access-key>/<date>/<region>/<service>/aws4_request
    return credential.split("/")


class TestCredentialProviderSigning:
    def test_signs_with_provider_credentials(self) -> None:
        credentials = make_credentials()
        provider = FakeCredentialProvider(credentials)
        signer = AWSV4Signer(provider, REGION, SERVICE)

        headers = signer.sign("GET", URL, None)

        assert provider.calls == 1
        authorization = headers["Authorization"]
        assert credential_key_from_header(authorization) == credentials.access_key
        scope = credential_scope(authorization)
        assert scope[2] == REGION
        assert scope[3] == SERVICE
        assert headers["X-Amz-Security-Token"] == credentials.token

    def test_callable_is_treated_as_provider(self) -> None:
        credentials = make_credentials()
        calls = []

        def provide() -> FakeCredentials:
            calls.append(1)
            return credentials

        signer = AWSV4Signer(provide, REGION, SERVICE)
        headers = signer.sign("GET", URL, None)

        assert len(calls) == 1
        assert credential_key_from_header(headers["Authorization"]) == credentials.access_key

    def test_static_credentials_still_supported(self) -> None:
        credentials = make_credentials()
        signer = AWSV4Signer(credentials, REGION, SERVICE)

        headers = signer.sign("GET", URL, None)

        assert credential_key_from_header(headers["Authorization"]) == credentials.access_key
        assert signer._uses_provider is False

    def test_provider_update_is_picked_up_on_new_request(self) -> None:
        first = make_credentials("AKIA-OLD")
        rotated = make_credentials("AKIA-NEW")
        provider = FakeCredentialProvider(first)
        signer = AWSV4Signer(provider, REGION, SERVICE)

        first_headers = signer.sign("GET", URL, None)
        assert credential_key_from_header(first_headers["Authorization"]) == first.access_key

        provider.set_credentials(rotated)
        signer.reset_request()
        rotated_headers = signer.sign("GET", URL, None)

        assert credential_key_from_header(rotated_headers["Authorization"]) == rotated.access_key
        assert provider.calls == 2

    def test_frozen_credentials_give_consistent_view_within_one_request(self) -> None:
        provider = FakeCredentialProvider()
        live = RefreshingCredentials(provider, "AKIA-LIVE", "live-secret", "live-token")
        provider.set_credentials(live)  # type: ignore
        signer = AWSV4Signer(provider, REGION, SERVICE)

        headers = signer.sign("POST", URL, b'{"query": "match_all"}')

        frozen = signer._frozen_credentials
        assert isinstance(frozen, FakeCredentials)
        assert credential_key_from_header(headers["Authorization"]) == "AKIA-LIVE"
        assert headers["X-Amz-Security-Token"] == "live-token"


class TestRetryCredentialBehavior:
    def test_retries_reuse_frozen_credentials_by_default(self) -> None:
        credentials = make_credentials()
        provider = FakeCredentialProvider(credentials)
        signer = AWSV4Signer(provider, REGION, SERVICE)

        first = signer.sign("GET", URL, None)
        rotated = make_credentials("AKIA-ROTATED")
        provider.set_credentials(rotated)
        retry = signer.sign("GET", URL, None)

        assert provider.calls == 1
        assert retry["Authorization"] == first["Authorization"]
        assert credential_key_from_header(retry["Authorization"]) == credentials.access_key

    def test_retries_fetch_fresh_credentials_when_refresh_enabled(self) -> None:
        first = make_credentials("AKIA-FIRST")
        second = make_credentials("AKIA-SECOND")
        provider = FakeCredentialProvider(first)
        signer = AWSV4Signer(
            provider, REGION, SERVICE, reuse_credentials_on_retry=False
        )

        first_headers = signer.sign("GET", URL, None)
        provider.set_credentials(second)
        retry_headers = signer.sign("GET", URL, None)

        assert provider.calls == 2
        assert credential_key_from_header(first_headers["Authorization"]) == first.access_key
        assert credential_key_from_header(retry_headers["Authorization"]) == second.access_key

    def test_reset_request_forces_resolution_even_in_reuse_mode(self) -> None:
        first = make_credentials("AKIA-ONE")
        second = make_credentials("AKIA-TWO")
        provider = FakeCredentialProvider(first)
        signer = AWSV4Signer(provider, REGION, SERVICE)

        signer.sign("GET", URL, None)
        provider.set_credentials(second)
        signer.reset_request()
        headers = signer.sign("GET", URL, None)

        assert provider.calls == 2
        assert credential_key_from_header(headers["Authorization"]) == second.access_key

    def test_auth_wrappers_expose_reset_and_option(self) -> None:
        provider = FakeCredentialProvider(make_credentials())

        urllib_auth = Urllib3AWSV4SignerAuth(
            provider, REGION, SERVICE, reuse_credentials_on_retry=False
        )
        urllib_auth("GET", URL, None)
        urllib_auth("GET", URL, None)
        assert provider.calls == 2
        urllib_auth.reset_request()
        urllib_auth("GET", URL, None)
        assert provider.calls == 3

        requests_auth = RequestsAWSV4SignerAuth(
            FakeCredentialProvider(make_credentials()), REGION, SERVICE
        )
        assert hasattr(requests_auth, "reset_request")


class TestProviderUnavailable:
    def test_provider_exception_surfaces_as_credential_provider_error(self) -> None:
        provider = FakeCredentialProvider()
        provider.offline = True
        provider.offline_error = RuntimeError("STS down")
        signer = AWSV4Signer(provider, REGION, SERVICE)

        with pytest.raises(CredentialProviderError) as exc_info:
            signer.sign("GET", URL, None)
        assert isinstance(exc_info.value.__cause__, RuntimeError)

    def test_empty_credentials_fail_explicitly(self) -> None:
        provider = FakeCredentialProvider()
        provider.set_credentials(None)  # type: ignore
        signer = AWSV4Signer(provider, REGION, SERVICE)

        with pytest.raises(CredentialProviderError):
            signer.sign("GET", URL, None)

    def test_failure_does_not_cache_credentials(self) -> None:
        provider = FakeCredentialProvider()
        provider.offline = True
        signer = AWSV4Signer(provider, REGION, SERVICE)

        with pytest.raises(CredentialProviderError):
            signer.sign("GET", URL, None)

        provider.offline = False
        provider.set_credentials(make_credentials())
        headers = signer.sign("GET", URL, None)
        assert "Authorization" in headers

    def test_urllib_auth_propagates_provider_failure(self) -> None:
        provider = FakeCredentialProvider()
        provider.offline = True
        auth = Urllib3AWSV4SignerAuth(provider, REGION, SERVICE)

        with pytest.raises(CredentialProviderError):
            auth("GET", URL, None)
