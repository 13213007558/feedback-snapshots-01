# Copyright 2021-2025 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0
import os
import threading
from collections.abc import Callable
from datetime import datetime, timedelta

import grpc
from grpc_status import rpc_status

from cerbos.cloud.apikey.v1 import apikey_pb2, apikey_pb2_grpc
from cerbos.sdk.hub.model import Credentials
from google.rpc import code_pb2


class InvalidCredentialsError(Exception):
    pass


class _AuthClient:
    _EARLY_EXPIRY: timedelta = timedelta(minutes=5)
    _client: apikey_pb2_grpc.ApiKeyServiceStub
    _client_id: str
    _client_secret: str
    _timeout_secs: float
    _expiry: datetime
    _lock: threading.Lock
    _token: str | None = None
    _invalid_credentials: bool = False

    def __init__(
        self,
        channel: grpc.Channel,
        timeout_secs: float,
        credentials: Credentials | None = None,
        credential_provider: Callable[[], Credentials] | None = None,
    ):
        self._credential_provider = credential_provider
        self._client_id = os.getenv("CERBOS_HUB_CLIENT_ID", "")
        self._client_secret = os.getenv("CERBOS_HUB_CLIENT_SECRET", "")
        self._apply_credentials(credentials)
        if credential_provider is not None:
            self._apply_credentials(credential_provider())
        self._client = apikey_pb2_grpc.ApiKeyServiceStub(channel)
        self._timeout_secs = timeout_secs
        self._lock = threading.Lock()

    def _apply_credentials(self, credentials: Credentials | None) -> None:
        if credentials is None:
            return
        if credentials.client_id != "":
            self._client_id = credentials.client_id
        if credentials.client_secret != "":
            self._client_secret = credentials.client_secret

    def refresh_credentials(
        self, credentials: Credentials | None = None
    ) -> None:
        """Rotate this client's credentials and force a new token request."""
        with self._lock:
            if credentials is not None:
                self._apply_credentials(credentials)
            elif self._credential_provider is not None:
                self._apply_credentials(self._credential_provider())
            self._token = None
            self._expiry = datetime.min
            self._invalid_credentials = False

    def refresh(self, credentials: Credentials | None = None) -> str:
        self.refresh_credentials(credentials)
        return self.authenticate()

    def authenticate(self) -> str:
        with self._lock:
            if self._invalid_credentials:
                raise InvalidCredentialsError("Invalid credentials")
            if self._token and self._expiry > datetime.now():
                return self._token
            req = apikey_pb2.IssueAccessTokenRequest(
                client_id=self._client_id, client_secret=self._client_secret
            )
            try:
                resp: apikey_pb2.IssueAccessTokenResponse = (
                    self._client.IssueAccessToken(req, timeout=self._timeout_secs)
                )
                self._token = resp.access_token
                expires_in = resp.expires_in.ToTimedelta()
                if expires_in > self._EARLY_EXPIRY:
                    expires_in = expires_in - self._EARLY_EXPIRY
                self._expiry = datetime.now() + expires_in
                return self._token
            except grpc.RpcError as rpc_error:
                status = rpc_status.from_call(rpc_error)
                if status and status.code == code_pb2.UNAUTHENTICATED:
                    self._invalid_credentials = True
                    raise InvalidCredentialsError("Invalid credentials")
                raise rpc_error  # noqa: TRY201
