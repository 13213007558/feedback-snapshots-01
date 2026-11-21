# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.

from typing import Any, List, Optional

import pytest

from opensearchpy import AsyncOpenSearch
from opensearchpy._async.http_aiohttp import AsyncConnection
from opensearchpy.exceptions import ConnectionError as OpenSearchConnectionError
from opensearchpy.helpers.asyncsigner import AWSV4SignerAsyncAuth
from opensearchpy.helpers.signer import CredentialProvider, CredentialProviderError

pytestmark = pytest.mark.asyncio

REGION = "us-east-1"
SERVICE = "es"
HOST = "search-async.example.org"


class FakeCredentials:
    def __init__(self, access_key: str) -> None:
        self.access_key = access_key
        self.secret_key = f"secret-{access_key}"
        self.token = f"token-{access_key}"


class InMemoryProvider(CredentialProvider):
    def __init__(self, access_key: str) -> None:
        self._access_key = access_key
        self.calls = 0
        self.offline = False

    def rotate(self, access_key: str) -> None:
        self._access_key = access_key
        self.offline = False

    def get_credentials(self) -> FakeCredentials:
        self.calls += 1
        if self.offline:
            raise RuntimeError("temporary STS failure")
        return FakeCredentials(self._access_key)


def access_key_of(authorization: str) -> str:
    return authorization.split("Credential=", 1)[1].split("/", 1)[0]


def scope_of(authorization: str) -> List[str]:
    return authorization.split("Credential=", 1)[1].split(",", 1)[0].split("/")


class InMemoryAsyncConnection(AsyncConnection):
    def __init__(self, **kwargs: Any) -> None:
        self._auth = kwargs.pop("http_auth")
        self.fail_times = kwargs.pop("fail_times", 0)
        self.authorizations: List[str] = []
        self._attempt = 0
        super().__init__(**kwargs)

    def reset_auth_request(self) -> None:
        self._auth.reset_request()

    async def close(self) -> None:
        return None

    async def perform_request(
        self,
        method: str,
        url: str,
        params: Optional[Any] = None,
        body: Optional[Any] = None,
        timeout: Optional[Any] = None,
        ignore: Any = (),
        headers: Optional[Any] = None,
    ) -> Any:
        signed_headers = self._auth(method=method, url=self.host + url, body=body)
        authorization = signed_headers["Authorization"]
        self.authorizations.append(authorization)
        self._attempt += 1
        if self._attempt <= self.fail_times:
            raise OpenSearchConnectionError("N/A", "simulated node failure")
        return 200, {}, "{}"


def build_client(auth: Any, connection: InMemoryAsyncConnection, max_retries: int = 3) -> AsyncOpenSearch:
    return AsyncOpenSearch(
        hosts=[{"host": HOST, "port": 443, "use_ssl": True}],
        http_auth=auth,
        connection_class=lambda **kwargs: connection,
        max_retries=max_retries,
    )


class TestAsyncCredentialProvider:
    async def test_normal_request_signs_with_provider_identity(self) -> None:
        provider = InMemoryProvider("AKIA-ASYNC")
        auth = AWSV4SignerAsyncAuth(provider, REGION, SERVICE)
        connection = InMemoryAsyncConnection(http_auth=auth)
        client = build_client(auth, connection)

        await client.info()

        assert provider.calls == 1
        scope = scope_of(connection.authorizations[0])
        assert access_key_of(connection.authorizations[0]) == "AKIA-ASYNC"
        assert scope[2] == REGION
        assert scope[3] == SERVICE
        await client.close()

    async def test_rotation_is_used_by_the_next_request(self) -> None:
        provider = InMemoryProvider("AKIA-OLD")
        auth = AWSV4SignerAsyncAuth(provider, REGION, SERVICE)
        connection = InMemoryAsyncConnection(http_auth=auth)
        client = build_client(auth, connection)

        await client.info()
        provider.rotate("AKIA-NEW")
        await client.info()

        assert access_key_of(connection.authorizations[0]) == "AKIA-OLD"
        assert access_key_of(connection.authorizations[1]) == "AKIA-NEW"
        assert provider.calls == 2
        await client.close()

    async def test_retries_reuse_credentials_by_default(self) -> None:
        provider = InMemoryProvider("AKIA-STABLE")
        auth = AWSV4SignerAsyncAuth(provider, REGION, SERVICE)
        connection = InMemoryAsyncConnection(http_auth=auth, fail_times=2)
        client = build_client(auth, connection)

        await client.info()

        assert len(connection.authorizations) == 3
        assert provider.calls == 1
        assert len(set(connection.authorizations)) == 1
        await client.close()

    async def test_retries_refresh_credentials_when_configured(self) -> None:
        provider = InMemoryProvider("AKIA-FIRST")
        auth = AWSV4SignerAsyncAuth(
            provider, REGION, SERVICE, reuse_credentials_on_retry=False
        )
        connection = InMemoryAsyncConnection(http_auth=auth, fail_times=1)
        client = build_client(auth, connection)

        original_get_credentials = provider.get_credentials

        def rotate_on_retry() -> FakeCredentials:
            if provider.calls >= 1:
                provider.rotate("AKIA-SECOND")
            return original_get_credentials()

        provider.get_credentials = rotate_on_retry  # type: ignore

        await client.info()

        assert provider.calls == 2
        assert access_key_of(connection.authorizations[0]) == "AKIA-FIRST"
        assert access_key_of(connection.authorizations[1]) == "AKIA-SECOND"
        await client.close()

    async def test_unavailable_provider_fails_explicitly(self) -> None:
        provider = InMemoryProvider("AKIA-X")
        auth = AWSV4SignerAsyncAuth(provider, REGION, SERVICE)
        connection = InMemoryAsyncConnection(http_auth=auth)
        client = build_client(auth, connection)

        provider.offline = True
        with pytest.raises(CredentialProviderError):
            await client.info()
        assert connection.authorizations == []
        await client.close()
