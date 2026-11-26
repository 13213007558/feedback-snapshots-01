# Copyright 2021-2025 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0
import json
import os
from collections.abc import Callable
from typing import Any

import grpc

from cerbos.sdk._sync._hub._auth import _AuthClient
from cerbos.sdk._sync._hub._interceptors import _AuthInterceptor
from cerbos.sdk.hub.model import Credentials

_METHOD_CONFIG: dict[str, Any] = {
    "methodConfig": [
        {
            "name": [{}],
            "timeout": "5s",
            "maxRequestMessageBytes": 1048576,
            "retryPolicy": {
                "maxAttempts": 3,
                "initialBackoff": "0.2s",
                "maxBackoff": "5s",
                "backoffMultiplier": 2,
                "retryableStatusCodes": ["UNAVAILABLE"],
            },
        },
        {
            "name": [
                {
                    "service": "cerbos.cloud.store.v1.CerbosStoreService",
                    "method": "ReplaceFiles",
                },
                {
                    "service": "cerbos.cloud.store.v1.CerbosStoreService",
                    "method": "ModifyFiles",
                },
            ],
            "timeout": "10s",
            "maxRequestMessageBytes": 20971520,
        },
    ],
    "retryThrottling": {"maxTokens": 10, "tokenRatio": 0.5},
}
# Because grpc.aio is implemented differently, unasync can't do a direct translation. We need a second implementation here.


class _CerbosHubClientBase:
    _channel: grpc.Channel
    _timeout_secs: float = 5

    def __init__(
        self,
        credentials: Credentials | None = None,
        api_endpoint: str | None = None,
        timeout_secs: float | None = None,
        credential_provider: Callable[[], Credentials] | None = None,
    ):
        target = os.getenv("CERBOS_HUB_API_ENDPOINT", "dns:///api.cerbos.cloud")
        if api_endpoint:
            target = api_endpoint
        options = [
            ("grpc.enable_retries", 1),
            ("grpc.service_config_disable_resolution", 0),
            ("grpc.service_config", json.dumps(_METHOD_CONFIG)),
        ]
        if timeout_secs:
            self._timeout_secs = timeout_secs
        channel = grpc.secure_channel(
            target, credentials=grpc.ssl_channel_credentials(), options=options
        )
        self._auth_client = _AuthClient(
            channel,
            self._timeout_secs,
            credentials,
            credential_provider=credential_provider,
        )
        auth_interceptor = _AuthInterceptor(self._auth_client)
        self._channel = grpc.intercept_channel(channel, auth_interceptor)

    def refresh_credentials(self, credentials: Credentials | None = None) -> None:
        self._auth_client.refresh_credentials(credentials)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        self._channel.close()
