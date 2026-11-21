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

import pytest

from opensearchpy import OpenSearch
from opensearchpy.connection import Connection
from opensearchpy.exceptions import ConnectionError as OpenSearchConnectionError
from opensearchpy.helpers.signer import (
    CredentialProvider,
    CredentialProviderError,
    Urllib3AWSV4SignerAuth,
)

REGION = "ap-southeast-2"
SERVICE = "aoss"
HOST = "search-test.example.org"


class FakeCredentials:
    def __init__(self, access_key: str) -> None:
        self.access_key = access_key
        self.secret_key = f"secret-{access_key}"
        self.token = f"token-{access_key}"


class RotatingCredentialProvider(CredentialProvider):
    """In-memory provider supporting rotation and an offline state."""

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


def credential_parts(authorization: str) -> Dict[str, str]:
    credential = authorization.split("Credential=", 1)[1].split(",", 1)[0]
    access_key, _date, region, service, _terminator = credential.split("/")
    return {"access_key": access_key, "region": region, "service": service}


class InMemorySigningConnection(Connection):
    """
    Connection that never touches the network. It runs the real SigV4 auth
    callable and records every signed Authorization header, optionally
    failing the first ``fail_times`` attempts to drive transport retries.
    """

    def __init__(self, **kwargs: Any) -> None:
        self._auth = kwargs.pop("http_auth")
        self.fail_times = kwargs.pop("fail_times", 0)
        self.authorizations: List[str] = []
        self._attempt = 0
        super().__init__(**kwargs)

    def reset_auth_request(self) -> None:
        reset_request = getattr(self._auth, "reset_request", None)
        if reset_request is not None:
            reset_request()

    def perform_request(
        self,
        method: str,
        url: str,
        params: Optional[Any] = None,
        body: Optional[Any] = None,
        timeout: Optional[Any] = None,
        ignore: Any = (),
        headers: Optional[Any] = None,
    ) -> Any:
        signed_headers = self._auth(method, self.host + url, body)
        self.authorizations.append(signed_headers["Authorization"])
        self._attempt += 1
        if self._attempt <= self.fail_times:
            raise OpenSearchConnectionError("N/A", "simulated node failure")
        return 200, {}, "{}"


def build_client(auth: Any, connection: InMemorySigningConnection, max_retries: int = 3) -> OpenSearch:
    return OpenSearch(
        hosts=[{"host": HOST, "port": 443, "use_ssl": True}],
        http_auth=auth,
        connection_class=lambda **kwargs: connection,
        max_retries=max_retries,
    )


class TestInMemoryTransportCredentialView:
    def test_normal_request_uses_current_credentials_region_and_service(self) -> None:
        access_key = f"AKIA-{uuid.uuid4().hex[:8]}"
        provider = RotatingCredentialProvider(access_key)
        auth = Urllib3AWSV4SignerAuth(provider, REGION, SERVICE)
        connection = InMemorySigningConnection(http_auth=auth)
        client = build_client(auth, connection)

        client.info()

        assert len(connection.authorizations) == 1
        assert provider.calls == 1
        parts = credential_parts(connection.authorizations[0])
        assert parts == {"access_key": access_key, "region": REGION, "service": SERVICE}

    def test_provider_update_used_by_next_request(self) -> None:
        old_key = "AKIA-OLD"
        new_key = "AKIA-NEW"
        provider = RotatingCredentialProvider(old_key)
        auth = Urllib3AWSV4SignerAuth(provider, REGION, SERVICE)
        connection = InMemorySigningConnection(http_auth=auth)
        client = build_client(auth, connection)

        client.info()
        provider.rotate(new_key)
        client.info()

        assert credential_parts(connection.authorizations[0])["access_key"] == old_key
        assert credential_parts(connection.authorizations[1])["access_key"] == new_key
        assert provider.calls == 2

    def test_retries_reuse_one_consistent_credential_view(self) -> None:
        access_key = "AKIA-STABLE"
        provider = RotatingCredentialProvider(access_key)
        auth = Urllib3AWSV4SignerAuth(provider, REGION, SERVICE)
        connection = InMemorySigningConnection(http_auth=auth, fail_times=2)
        client = build_client(auth, connection)

        client.info()

        assert len(connection.authorizations) == 3
        assert provider.calls == 1
        assert len(set(connection.authorizations)) == 1
        for authorization in connection.authorizations:
            assert credential_parts(authorization) == {
                "access_key": access_key,
                "region": REGION,
                "service": SERVICE,
            }

    def test_retry_can_refresh_credentials_explicitly(self) -> None:
        first_key = "AKIA-FIRST"
        rotated_key = "AKIA-ROTATED"
        provider = RotatingCredentialProvider(first_key)
        auth = Urllib3AWSV4SignerAuth(
            provider, REGION, SERVICE, reuse_credentials_on_retry=False
        )
        connection = InMemorySigningConnection(http_auth=auth, fail_times=1)
        client = build_client(auth, connection)

        def rotate_on_retry(*args: Any, **kwargs: Any) -> FakeCredentials:
            if provider.calls >= 1:
                provider.rotate(rotated_key)
            return RotatingCredentialProvider.get_credentials(provider)

        provider.get_credentials = rotate_on_retry  # type: ignore

        client.info()

        assert len(connection.authorizations) == 2
        assert provider.calls == 2
        assert credential_parts(connection.authorizations[0])["access_key"] == first_key
        assert credential_parts(connection.authorizations[1])["access_key"] == rotated_key

    def test_request_after_exhausted_retries_resolves_credentials_again(self) -> None:
        provider = RotatingCredentialProvider("AKIA-A")
        auth = Urllib3AWSV4SignerAuth(provider, REGION, SERVICE)
        connection = InMemorySigningConnection(http_auth=auth, fail_times=4)
        client = build_client(auth, connection, max_retries=1)

        with pytest.raises(OpenSearchConnectionError):
            client.info()
        first_request_calls = provider.calls
        assert first_request_calls == 1  # reused across the two attempts

        connection.fail_times = 0
        provider.rotate("AKIA-B")
        client.info()

        assert provider.calls == first_request_calls + 1
        assert credential_parts(connection.authorizations[-1])["access_key"] == "AKIA-B"

    def test_provider_unavailable_fails_the_request_explicitly(self) -> None:
        provider = RotatingCredentialProvider("AKIA-X")
        auth = Urllib3AWSV4SignerAuth(provider, REGION, SERVICE)
        connection = InMemorySigningConnection(http_auth=auth)
        client = build_client(auth, connection)

        provider.offline = True
        with pytest.raises(CredentialProviderError) as exc_info:
            client.info()
        assert isinstance(exc_info.value.__cause__, RuntimeError)
        assert connection.authorizations == []
