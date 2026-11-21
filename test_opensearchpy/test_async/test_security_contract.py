# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.


import base64
from typing import Any, Collection, Dict, List, Mapping, Optional, Tuple, Union

import pytest
from _pytest.mark.structures import MarkDecorator

from opensearchpy import AsyncOpenSearch, AsyncTransport

pytestmark: MarkDecorator = pytest.mark.asyncio

SECURITY_ADMIN_AUTH = ("security-admin", "security-secret")
PROXY_SEARCH_AUTH = ("search-reader", "search-secret")


def _basic_auth(auth: Tuple[str, str]) -> str:
    user, password = auth
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


class RecordingTransport(AsyncTransport):
    """Fake transport that records exactly what the client sends."""

    def __init__(self, hosts: Any, **kwargs: Any) -> None:
        self.hosts = hosts
        self.options = kwargs
        self.calls: List[Dict[str, Any]] = []

    async def perform_request(
        self,
        method: str,
        url: str,
        params: Optional[Mapping[str, Any]] = None,
        body: Optional[bytes] = None,
        timeout: Optional[Union[int, float]] = None,
        ignore: Collection[int] = (),
        headers: Optional[Mapping[str, str]] = None,
    ) -> Any:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "params": params,
                "body": body,
                "headers": headers,
                "timeout": timeout,
                "ignore": ignore,
            }
        )
        return {"acknowledged": True}

    async def close(self) -> None:
        pass


def _client(**kwargs: Any) -> AsyncOpenSearch:
    return AsyncOpenSearch(transport_class=RecordingTransport, **kwargs)


def _call(
    method: str,
    url: str,
    *,
    params: Optional[Mapping[str, Any]] = None,
    body: Any = None,
    headers: Optional[Mapping[str, str]] = None,
) -> Dict[str, Any]:
    return {
        "method": method,
        "url": url,
        "params": params if params is not None else {},
        "body": body,
        "headers": headers if headers is not None else {},
        "timeout": None,
        "ignore": (),
    }


def _transport(client: AsyncOpenSearch) -> RecordingTransport:
    transport = client.transport
    assert isinstance(transport, RecordingTransport)
    return transport


def _calls(client: AsyncOpenSearch) -> List[Dict[str, Any]]:
    return _transport(client).calls


class TestSecurityRoleReadOnlyContract:
    async def test_get_role_sends_encoded_role_path(self) -> None:
        client = _client()

        await client.security.get_role(role="logs:viewer")

        assert _calls(client) == [
            _call("GET", "/_plugins/_security/api/roles/logs%3Aviewer")
        ]

    async def test_get_roles_lists_roles_without_body(self) -> None:
        client = _client()

        await client.security.get_roles()

        assert _calls(client) == [_call("GET", "/_plugins/_security/api/roles")]

    async def test_get_role_mapping_targets_rolesmapping(self) -> None:
        client = _client()

        await client.security.get_role_mapping(role="logs:viewer")

        assert _calls(client) == [
            _call("GET", "/_plugins/_security/api/rolesmapping/logs%3Aviewer")
        ]

    async def test_get_role_mappings_lists_mappings_without_body(self) -> None:
        client = _client()

        await client.security.get_role_mappings()

        assert _calls(client) == [_call("GET", "/_plugins/_security/api/rolesmapping")]

    async def test_role_name_with_path_separator_is_escaped(self) -> None:
        client = _client()

        await client.security.get_role(role="../admin")

        assert _calls(client)[0]["url"] == "/_plugins/_security/api/roles/..%2Fadmin"

    async def test_authinfo_probes_current_identity(self) -> None:
        client = _client()

        await client.security.authinfo(verbose=True)

        assert _calls(client) == [
            _call(
                "GET",
                "/_plugins/_security/authinfo",
                params={"verbose": b"true"},
            )
        ]


class TestSecurityApprovedChangeContract:
    async def test_create_role_puts_body_to_role_path(self) -> None:
        client = _client()
        body = {
            "cluster_permissions": ["cluster_monitor"],
            "index_permissions": [],
        }

        await client.security.create_role(role="logs:writer", body=body)

        assert _calls(client) == [
            _call(
                "PUT",
                "/_plugins/_security/api/roles/logs%3Awriter",
                body=body,
            )
        ]

    async def test_patch_role_patches_individual_attributes(self) -> None:
        client = _client()
        body = {"cluster_permissions": ["cluster_all"]}

        await client.security.patch_role(role="logs:writer", body=body)

        assert _calls(client) == [
            _call(
                "PATCH",
                "/_plugins/_security/api/roles/logs%3Awriter",
                body=body,
            )
        ]

    async def test_delete_role_deletes_role_path(self) -> None:
        client = _client()

        await client.security.delete_role(role="logs:writer")

        assert _calls(client) == [
            _call("DELETE", "/_plugins/_security/api/roles/logs%3Awriter")
        ]

    async def test_create_role_mapping_puts_body_to_mapping_path(self) -> None:
        client = _client()
        body = {"backend_roles": ["logs-writers"]}

        await client.security.create_role_mapping(role="logs:writer", body=body)

        assert _calls(client) == [
            _call(
                "PUT",
                "/_plugins/_security/api/rolesmapping/logs%3Awriter",
                body=body,
            )
        ]

    async def test_empty_change_arguments_are_rejected_before_transport(self) -> None:
        client = _client()

        with pytest.raises(
            ValueError, match="Empty value passed for a required argument"
        ):
            await client.security.create_role(role="logs:writer", body="")
        with pytest.raises(
            ValueError, match="Empty value passed for a required argument"
        ):
            await client.security.delete_role(role="")

        assert _calls(client) == []


class TestSecurityIdentityAndPublicParamsContract:
    async def test_missing_auth_settings_do_not_add_identity_headers(self) -> None:
        client = _client()

        await client.security.get_roles()

        assert "http_auth" not in _transport(client).options
        assert _calls(client)[0]["headers"] == {}

    async def test_none_auth_setting_stays_unauthenticated(self) -> None:
        client = _client()

        await client.security.get_roles(http_auth=None)

        assert _calls(client)[0]["headers"] == {}

    async def test_explicit_auth_overrides_authorization_header(self) -> None:
        client = _client()

        await client.security.get_roles(
            headers={
                "Authorization": "Bearer caller-token",
                "X-Request-Origin": "proxy",
            },
            http_auth=SECURITY_ADMIN_AUTH,
        )

        assert _calls(client)[0]["headers"] == {
            "authorization": _basic_auth(SECURITY_ADMIN_AUTH),
            "x-request-origin": "proxy",
        }

    async def test_request_level_basic_auth_becomes_authorization_header(self) -> None:
        client = _client()

        await client.security.get_roles(http_auth=SECURITY_ADMIN_AUTH)

        assert _calls(client)[0]["headers"] == {
            "authorization": _basic_auth(SECURITY_ADMIN_AUTH)
        }

    async def test_request_level_api_key_becomes_authorization_header(self) -> None:
        client = _client()

        await client.security.get_roles(api_key=("name", "key"))

        assert _calls(client)[0]["headers"] == {"authorization": "ApiKey bmFtZTprZXk="}

    async def test_basic_auth_and_api_key_are_mutually_exclusive(self) -> None:
        client = _client()

        with pytest.raises(
            ValueError,
            match="Only one of 'http_auth' and 'api_key' may be passed at a time",
        ):
            await client.security.get_roles(
                http_auth=SECURITY_ADMIN_AUTH, api_key=("name", "key")
            )

        assert _calls(client) == []

    async def test_opaque_id_and_headers_are_forwarded_lowercased(self) -> None:
        client = _client()

        await client.security.get_roles(
            opaque_id="request-1", headers={"X-Request-Origin": "proxy"}
        )

        assert _calls(client)[0]["headers"] == {
            "x-request-origin": "proxy",
            "x-opaque-id": "request-1",
        }

    async def test_public_query_params_are_escaped_and_forwarded(self) -> None:
        client = _client()

        await client.security.get_roles(
            pretty=True,
            human=True,
            error_trace=True,
            filter_path="roles.*",
        )

        assert _calls(client)[0]["params"] == {
            "pretty": b"true",
            "human": b"true",
            "error_trace": b"true",
            "filter_path": b"roles.*",
        }

    async def test_caller_params_are_forwarded_without_mutation(self) -> None:
        client = _client()
        params = {"pretty": True, "custom": "value"}

        await client.security.get_roles(params=params)

        assert _calls(client)[0]["params"] == {"pretty": True, "custom": "value"}
        assert params == {"pretty": True, "custom": "value"}

    async def test_request_timeout_is_kept_in_public_params(self) -> None:
        client = _client()

        await client.security.get_role(role="logs:viewer", request_timeout=5)

        assert _calls(client)[0]["params"] == {"request_timeout": 5}

    async def test_unknown_public_parameter_is_rejected_without_request(self) -> None:
        client = _client()

        with pytest.raises(TypeError):
            await client.security.get_roles(unknown_parameter="value")

        assert _calls(client) == []


class TestSecurityClientIsolationContract:
    async def test_construction_auth_is_left_to_transport(self) -> None:
        client = _client(
            http_auth=("proxy-user", "proxy-secret"), opaque_id="proxy-app"
        )

        assert _transport(client).options["http_auth"] == (
            "proxy-user",
            "proxy-secret",
        )
        assert _transport(client).options["opaque_id"] == "proxy-app"
        assert _calls(client) == []

    async def test_regular_search_client_keeps_its_own_authorization(self) -> None:
        security_client = _client()
        search_client = _client()

        await security_client.security.get_roles(http_auth=SECURITY_ADMIN_AUTH)
        await search_client.search(
            index="orders",
            body={"query": {"match_all": {}}},
            http_auth=PROXY_SEARCH_AUTH,
        )

        security_call = _calls(security_client)[0]
        search_call = _calls(search_client)[0]
        assert security_call["headers"] == {
            "authorization": _basic_auth(SECURITY_ADMIN_AUTH)
        }
        assert search_call["headers"] == {
            "authorization": _basic_auth(PROXY_SEARCH_AUTH)
        }
        assert security_call["headers"] != search_call["headers"]
        assert _calls(search_client) == [
            _call(
                "POST",
                "/orders/_search",
                body={"query": {"match_all": {}}},
                headers={"authorization": _basic_auth(PROXY_SEARCH_AUTH)},
            )
        ]

    async def test_request_level_auth_does_not_leak_to_later_calls(self) -> None:
        client = _client()

        await client.security.get_roles(http_auth=SECURITY_ADMIN_AUTH)
        await client.security.get_roles()

        first_call, second_call = _calls(client)
        assert first_call["headers"] == {
            "authorization": _basic_auth(SECURITY_ADMIN_AUTH)
        }
        assert second_call["headers"] == {}
