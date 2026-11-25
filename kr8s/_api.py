# SPDX-FileCopyrightText: Copyright (c) 2023-2026, Kr8s Developers (See LICENSE for list)
# SPDX-License-Identifier: BSD 3-Clause License
from __future__ import annotations

import asyncio
import contextlib
import copy
import json
import logging
import ssl
import sys
import threading
import warnings
import weakref
from collections.abc import AsyncGenerator
from contextlib import contextmanager
from importlib.metadata import version as metadata_version
from typing import (
    TYPE_CHECKING,
)

import anyio
import httpx
import httpx_ws
from cachetools import TTLCache  # type: ignore
from cryptography import x509
from packaging.version import InvalidVersion
from packaging.version import parse as parse_version

from ._access import AccessDecision, AccessPolicy, split_api_version
from ._auth import KubeAuth
from ._constants import (
    KUBERNETES_MAXIMUM_SUPPORTED_VERSION,
    KUBERNETES_MINIMUM_SUPPORTED_VERSION,
)
from ._data_utils import dict_to_selector, sort_versions
from ._exceptions import AccessDeniedError, APITimeoutError, ServerError
from ._version import __version__

if TYPE_CHECKING:
    from ._objects import APIObject

if sys.version_info < (3, 11):
    from exceptiongroup import BaseExceptionGroup

ALL = "all"
logger = logging.getLogger(__name__)
_HTTPX_WS_VERSION = parse_version(metadata_version("httpx-ws"))


@contextmanager
def _httpx_ws_exception_fixer():
    try:
        yield
    except BaseException as exc:
        if _HTTPX_WS_VERSION < parse_version("0.9"):
            raise
        while isinstance(exc, BaseExceptionGroup) and len(exc.exceptions) == 1:
            exc = exc.exceptions[0]
        raise exc


class Api:
    """A kr8s object for interacting with the Kubernetes API.

    .. warning::
        This class is not intended to be instantiated directly. Instead, use the
        :func:`kr8s.api` function to get a singleton instance of the API.

        See https://docs.kr8s.org/en/stable/client.html#client-caching.

    """

    _asyncio = True
    _instances: dict[str, weakref.WeakValueDictionary] = {}

    def __init__(self, **kwargs) -> None:
        if not kwargs.pop("bypass_factory", False):
            raise ValueError(
                "Use kr8s.api() to get an instance of Api. "
                "See https://docs.kr8s.org/en/stable/client.html#client-caching."
            )

        self._url = kwargs.get("url")
        self._kubeconfig = kwargs.get("kubeconfig")
        self._serviceaccount = kwargs.get("serviceaccount")
        self._session: httpx.AsyncClient | None = None
        self._timeout = None
        self._api_resources_cache: TTLCache = TTLCache(maxsize=1, ttl=60 * 60 * 6)
        self._access_policy = AccessPolicy()
        self.auth = KubeAuth(
            url=self._url,
            kubeconfig=self._kubeconfig,
            serviceaccount=self._serviceaccount,
            namespace=kwargs.get("namespace"),
            context=kwargs.get("context"),
        )
        thread_id = threading.get_ident()
        try:
            loop_id = id(asyncio.get_running_loop())
        except RuntimeError:
            loop_id = 0
        thread_loop_id = f"{thread_id}.{loop_id}"
        if thread_loop_id not in Api._instances:
            Api._instances[thread_loop_id] = weakref.WeakValueDictionary()
        key = hash_kwargs(kwargs)
        Api._instances[thread_loop_id][key] = self

    def __await__(self):
        async def f():
            await self.auth
            await self._check_version()
            return self

        return f().__await__()

    @property
    def timeout(self):
        return self._timeout

    @timeout.setter
    def timeout(self, value):
        self._timeout = value
        if self._session:
            self._session.timeout = value

    async def _create_session(self) -> None:
        headers = {"User-Agent": self.__version__, "content-type": "application/json"}
        if self.auth.token:
            headers["Authorization"] = f"Bearer {self.auth.token}"
        if self._session:
            with contextlib.suppress(RuntimeError):
                await self._session.aclose()
            self._session = None
        self._session = httpx.AsyncClient(
            base_url=self.auth.server,
            headers=headers,
            verify=await self.auth.ssl_context(),
            timeout=self._timeout,
            follow_redirects=True,
            proxy=self.auth.proxy,
        )

    def _construct_url(
        self,
        version: str = "v1",
        base: str = "",
        namespace: str | None = None,
        url: str = "",
    ) -> str:
        if not base:
            if version == "v1":
                base = "/api"
            elif "/" in version:
                base = "/apis"
            else:
                raise ValueError("Unknown API version, base must be specified.")
        parts = [base]
        if version:
            parts.append(version)
        if namespace:
            parts.extend(["namespaces", namespace])
        parts.append(url)
        return "/".join(parts)

    @property
    def access_policy(self) -> AccessPolicy:
        """The access policy used for discovery and request preflight.

        The policy starts permissive so existing behaviour is unchanged. Adding
        the first rule turns it into an explicit allowlist: any resource version
        that is not granted visibility or request verbs is then denied. This is
        what prevents a newly discovered version from inheriting broad access.
        """
        return self._access_policy

    @access_policy.setter
    def access_policy(self, value: AccessPolicy) -> None:
        self._access_policy = value

    async def async_refresh_api_resources(self) -> list[dict]:
        """Refresh the discovery cache and return the visible resources.

        Only the raw server response is cached. Visibility is applied on every
        read, so the refreshed catalog still reflects the current approvals.

        Returns:
            The discovery entries that are currently visible.
        """
        raw = await self.async_api_resources_uncached()
        self._api_resources_cache[("resources",)] = raw
        return self._filter_api_resources(raw)

    async def refresh_api_resources(self) -> list[dict]:
        """Refresh the discovery cache and return the visible resources."""
        return await self.async_refresh_api_resources()

    async def async_api_resource_access(self) -> list[AccessDecision]:
        """Report the access decision for every discovered resource version.

        Unlike :meth:`async_api_resources`, this includes versions that are not
        visible, together with an explanation of why they are unavailable. It
        is the diagnostic surface for "this version exists but I may not use
        it yet".
        """
        key = ("resources",)
        try:
            raw = self._api_resources_cache[key]
        except KeyError:
            raw = await self.async_api_resources_uncached()
            self._api_resources_cache[key] = raw
        return self._access_decisions(raw)

    async def check_resource_access(
        self,
        verb: str,
        resource: str,
        *,
        group: str = "",
        version: str = "",
    ) -> AccessDecision:
        """Check a request verb against an exact resource version.

        Args:
            verb: The request verb (``get``, ``list``, ``create``, ...).
            resource: The plural resource name.
            group: The API group, empty for the core group.
            version: The API version.

        Returns:
            An :class:`AccessDecision` describing the outcome.
        """
        return await self.async_check_resource_access(
            verb, resource, group=group, version=version
        )

    async def async_check_resource_access(
        self,
        verb: str,
        resource: str,
        *,
        group: str = "",
        version: str = "",
    ) -> AccessDecision:
        """Check a request verb against an exact resource version."""
        return self._access_policy.check(verb, resource, group=group, version=version)

    def _filter_api_resources(self, resources: list[dict]) -> list[dict]:
        """Apply the current policy to cached discovery entries."""
        filtered = []
        for resource in self._access_policy.filter_resources(resources):
            entry = dict(resource)
            if self._access_policy.enabled:
                group, version = split_api_version(resource.get("version", ""))
                decision = self._access_policy.check_visibility(
                    resource.get("name", ""), group=group, version=version
                )
                entry["kr8sVisible"] = decision.visible
                entry["kr8sApprovedVerbs"] = sorted(decision.approved_verbs)
            filtered.append(entry)
        return filtered

    def _resource_visible(self, resource: dict) -> bool:
        """Return whether a raw discovery entry may be displayed."""
        group, version = split_api_version(resource.get("version", ""))
        return self._access_policy.is_visible(
            resource.get("name", ""), group=group, version=version
        )

    def _access_decisions(self, resources: list[dict]) -> list[AccessDecision]:
        """Build display decisions for every raw discovery entry."""
        decisions = []
        for resource in resources:
            group, version = split_api_version(resource.get("version", ""))
            decisions.append(
                self._access_policy.check_visibility(
                    resource.get("name", ""), group=group, version=version
                )
            )
        return decisions

    def _request_access(
        self,
        method: str,
        version: str,
        base: str,
        namespace: str | None,
        url: str,
        params: dict | None,
    ) -> AccessDecision | None:
        """Resolve the exact resource version targeted by a request and check it.

        Returns ``None`` when the request is not a resource request (for example
        discovery or version endpoints) or when the policy is permissive.
        Raises :class:`AccessDeniedError` when the request is not approved.
        """
        if not self._access_policy.enabled:
            return None
        path = self._construct_url(version, base, namespace, url)
        target = _parse_resource_path(path)
        if target is None:
            return None
        group, api_version, resource, has_name, subresource = target
        verb = _request_verb(method, has_name, subresource, params)
        decision = self._access_policy.check(
            verb, resource, group=group, version=api_version
        )
        if not decision.allowed:
            raise AccessDeniedError(
                f"Cannot send '{verb.upper()} {path}': {decision.explain()}",
                decision=decision,
            )
        return decision

    @contextlib.asynccontextmanager
    async def call_api(
        self,
        method: str = "GET",
        version: str = "v1",
        base: str = "",
        namespace: str | None = None,
        url: str = "",
        raise_for_status: bool = True,
        stream: bool = False,
        **kwargs,
    ) -> AsyncGenerator[httpx.Response]:
        """Make a Kubernetes API request."""
        self._request_access(
            method,
            version,
            base,
            namespace,
            url,
            kwargs.get("params"),
        )
        if not self._session or self._session.is_closed:
            await self._create_session()
        url = self._construct_url(version, base, namespace, url)
        kwargs.update(url=url, method=method)
        if self.auth.tls_server_name:
            kwargs["extensions"] = {"sni_hostname": self.auth.tls_server_name}
        auth_attempts = 0
        ssl_attempts = 0
        while True:
            try:
                if stream:
                    assert self._session
                    async with self._session.stream(**kwargs) as response:
                        if response.is_error and raise_for_status:
                            # NOTE: Avoid `httpx.ResponseNotRead` w/ streaming requests
                            # https://github.com/encode/httpx/discussions/1856#discussioncomment-1316674
                            await response.aread()
                            response.raise_for_status()
                        yield response
                else:
                    assert self._session
                    response = await self._session.request(**kwargs)
                    if raise_for_status:
                        response.raise_for_status()
                    yield response
            except httpx.HTTPStatusError as e:
                # If we get a 401 or 403 our credentials may have expired so we
                # reauthenticate and try again a few times before giving up.
                if e.response.status_code in (401, 403) and auth_attempts < 3:
                    logger.debug(
                        f"Unauthorized {e.response.status_code} error, reauthenticating attempt {auth_attempts}"
                    )
                    auth_attempts += 1
                    await self.auth.reauthenticate()
                    await self._create_session()
                    continue
                else:
                    if e.response.status_code >= 400 and e.response.status_code < 500:
                        try:
                            error = e.response.json()
                            error_message = error["message"]
                        except json.JSONDecodeError:
                            error = e.response.text
                            error_message = str(e)
                        raise ServerError(
                            error_message, status=error, response=e.response
                        ) from e
                    elif e.response.status_code >= 500:
                        raise ServerError(
                            str(e),
                            status=str(e.response.status_code),
                            response=e.response,
                        ) from e
                    raise
            except ssl.SSLCertVerificationError:
                # In some rare edge cases the SSL verification fails, so we try again
                # a few times before giving up.
                if ssl_attempts < 3:
                    ssl_attempts += 1
                    await self.auth.reauthenticate()
                    await self._create_session()
                    continue
                else:
                    raise
            except httpx.TimeoutException as e:
                raise APITimeoutError(
                    "Timeout while waiting for the Kubernetes API server"
                ) from e
            break

    @contextlib.asynccontextmanager
    async def open_websocket(
        self,
        version: str = "v1",
        base: str = "",
        namespace: str | None = None,
        url: str = "",
        **kwargs,
    ) -> AsyncGenerator[httpx_ws.AsyncWebSocketSession]:
        """Open a websocket connection to a Kubernetes API endpoint."""
        self._request_access(
            "GET",
            version,
            base,
            namespace,
            url,
            kwargs.get("params"),
        )
        if not self._session or self._session.is_closed:
            await self._create_session()
        url = self._construct_url(version, base, namespace, url)
        kwargs.update(url=url)
        if self.auth.tls_server_name:
            kwargs["extensions"] = {"sni_hostname": self.auth.tls_server_name}
        auth_attempts = 0
        while True:
            try:
                with _httpx_ws_exception_fixer():
                    async with httpx_ws.aconnect_ws(
                        client=self._session, **kwargs
                    ) as response:
                        yield response
            except httpx_ws.WebSocketDisconnect as e:
                if e.code and e.code != 1000:
                    if e.code in (401, 403) and auth_attempts < 3:
                        auth_attempts += 1
                        await self.auth.reauthenticate()
                        continue
                    else:
                        raise
            break

    async def version(self) -> dict:
        """Get the Kubernetes version information from the API.

        Returns:
            The Kubernetes version information.

        """
        return await self.async_version()

    async def async_version(self) -> dict:
        async with self.call_api(method="GET", version="", base="/version") as response:
            return response.json()

    async def _check_version(self) -> None:
        version = await self.async_version()
        git_version = version["gitVersion"]

        supported_message = (
            f"Supported versions for kr8s {__version__} are "
            f"{KUBERNETES_MINIMUM_SUPPORTED_VERSION}"
            " to "
            f"{KUBERNETES_MAXIMUM_SUPPORTED_VERSION}."
        )

        try:
            # Remove variant suffix if present before parsing, e.g v1.32.9-eks-113cf36 -> v1.32.9
            version = parse_version(git_version.split("-")[0])
        except InvalidVersion:
            warnings.warn(
                f"Unable to parse Kubernetes version {git_version}. {supported_message}",
                UserWarning,
                stacklevel=2,
            )
            return

        # We only care about major/minor version differences, so we truncate the patch version
        version = parse_version(f"{version.major}.{version.minor}")
        if (
            version < KUBERNETES_MINIMUM_SUPPORTED_VERSION
            or version > KUBERNETES_MAXIMUM_SUPPORTED_VERSION
        ):
            warnings.warn(
                f"Kubernetes version {git_version} is not supported. {supported_message}",
                UserWarning,
                stacklevel=2,
            )

    async def reauthenticate(self) -> None:
        """Reauthenticate the API."""
        return await self.async_reauthenticate()

    async def async_reauthenticate(self) -> None:
        await self.auth.reauthenticate()

    async def whoami(self):
        """Retrieve the subject that's currently authenticated.

        Inspired by `kubectl whoami`.

        Returns:
            str: The subject that's currently authenticated.
        """
        return await self.async_whoami()

    async def async_whoami(self):
        if self.auth.token:
            payload = {
                "apiVersion": "authentication.k8s.io/v1",
                "kind": "TokenReview",
                "spec": {"token": self.auth.token},
            }
            async with self.call_api(
                "POST",
                version="authentication.k8s.io/v1",
                url="tokenreviews",
                content=json.dumps(payload),
            ) as r:
                data = r.json()
                return data["status"]["user"]["username"]
        elif self.auth.client_cert_file:
            with open(self.auth.client_cert_file, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
                [name] = cert.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)
                return name.value

    async def lookup_kind(self, kind, verb: str = "list") -> tuple[str, str, bool]:
        """Lookup a Kubernetes resource kind.

        Check whether a resource kind exists on the remote server.

        Args:
            kind: The kind of resource to lookup.
            verb: The operation the caller is about to perform. Different
                versions of the same resource name can be approved for different
                verbs, so the version is selected for this exact operation.

        Returns:
            The kind of resource, the plural form and whether the resource is namespaced

        Raises:
            AccessDeniedError: If the kind was discovered but no version is
                approved for ``verb``.
            ValueError: If the kind is not found.
        """
        return await self.async_lookup_kind(kind, verb=verb)

    async def async_lookup_kind(
        self, kind, skip_cache: bool = False, verb: str = "list"
    ) -> tuple[str, str, bool]:
        """Lookup a Kubernetes resource kind.

        Args:
            kind: The kind, plural, singular, short name or qualified name.
            skip_cache: Bypass the discovery cache for this lookup.
            verb: The operation the caller is about to perform. Different
                versions of the same resource name may be approved for different
                verbs, so the version is selected for this exact operation.

        Returns:
            The qualified kind, plural form and whether the resource is namespaced.

        Raises:
            AccessDeniedError: If the only discovered versions of the kind are
                not approved for ``verb``.
            ValueError: If the kind was not discovered at all.
        """
        from ._objects import parse_kind

        requested_kind = kind
        if skip_cache:
            resources = await self.async_api_resources_uncached()
        else:
            resources = await self.async_api_resources()
        kind, group, version = parse_kind(kind)
        if group:
            version = f"{group}/{version}"

        def matches_version(resource_version: str) -> bool:
            if not version:
                return True
            if version.endswith("/"):
                # Only a group was given, so any version in that group matches.
                return resource_version.startswith(version)
            return version == resource_version

        def matches(resource: dict) -> bool:
            return matches_version(resource["version"]) and (
                kind == resource["name"]
                or kind == resource["kind"]
                or kind == resource["singularName"]
                or ("shortNames" in resource and kind in resource["shortNames"])
            )

        exact_version = bool(version) and not version.endswith("/")

        for resource in resources:
            if not self._resource_visible(resource):
                continue
            if matches(resource):
                resource_group, resource_version = split_api_version(
                    resource["version"]
                )
                approved = (
                    not self._access_policy.enabled
                    or self._access_policy.allows(
                        verb,
                        resource["name"],
                        group=resource_group,
                        version=resource_version,
                    )
                )
                if not approved and not exact_version:
                    # Only an unversioned lookup may fall through to another
                    # visible version of the same resource name that is approved
                    # for this operation. An explicitly requested version never
                    # silently changes.
                    continue
                if not approved:
                    decision = self._access_policy.check(
                        verb,
                        resource["name"],
                        group=resource_group,
                        version=resource_version,
                    )
                    raise AccessDeniedError(
                        f"Kind {kind} is discovered at {resource['version']} but cannot be requested: "
                        f"{decision.explain()}",
                        decision=decision,
                    )
                if "/" in resource["version"]:
                    return (
                        f"{resource['singularName']}.{resource['version']}",
                        resource["name"],
                        resource["namespaced"],
                    )
                return (
                    f"{resource['singularName']}/{resource['version']}",
                    resource["name"],
                    resource["namespaced"],
                )

        if not skip_cache:
            return await self.async_lookup_kind(
                requested_kind, skip_cache=True, verb=verb
            )

        # The version was discovered but is not visible or not requestable.
        # Surface that instead of pretending the kind does not exist.
        if self._access_policy.enabled:
            for resource in resources:
                if not matches(resource):
                    continue
                resource_group, resource_version = split_api_version(
                    resource["version"]
                )
                decision = self._access_policy.check(
                    verb,
                    resource["name"],
                    group=resource_group,
                    version=resource_version,
                )
                raise AccessDeniedError(
                    f"Kind {kind} is discovered at "
                    f"{resource['version']} but cannot be requested: "
                    f"{decision.explain()}",
                    decision=decision,
                )

        raise ValueError(f"Kind {kind} not found.")

    @contextlib.asynccontextmanager
    async def async_get_kind(
        self,
        kind: str | type[APIObject],
        namespace: str | None = None,
        label_selector: str | dict | None = None,
        field_selector: str | dict | None = None,
        params: dict | None = None,
        watch: bool = False,
        allow_unknown_type: bool = True,
        **kwargs,
    ) -> AsyncGenerator[tuple[type[APIObject], httpx.Response]]:
        """Get a Kubernetes resource."""
        from ._objects import get_class, new_class

        if not namespace:
            namespace = self.namespace
        if namespace is ALL:
            namespace = ""
        if params is None:
            params = {}
        if label_selector:
            if isinstance(label_selector, dict):
                label_selector = dict_to_selector(label_selector)
            params["labelSelector"] = label_selector
        if field_selector:
            if isinstance(field_selector, dict):
                field_selector = dict_to_selector(field_selector)
            params["fieldSelector"] = field_selector
        if watch:
            params["watch"] = "true" if watch else "false"
            kwargs["stream"] = True
        if isinstance(kind, type):
            obj_cls = kind
        else:
            namespaced: bool | None = None
            lookup_verb = "watch" if watch else "list"
            try:
                kind, plural, namespaced = await self.async_lookup_kind(
                    kind, verb=lookup_verb
                )
            except ServerError as e:
                warnings.warn(str(e), stacklevel=1)
            if isinstance(kind, str):
                try:
                    obj_cls = get_class(kind, _asyncio=self._asyncio)
                except KeyError as e:
                    if allow_unknown_type:
                        if namespaced is not None:
                            obj_cls = new_class(
                                kind,
                                namespaced=namespaced,
                                asyncio=self._asyncio,
                                plural=plural,
                            )
                        else:
                            obj_cls = new_class(
                                kind, asyncio=self._asyncio, plural=plural
                            )
                    else:
                        raise e
        params = params or None
        async with self.call_api(
            method="GET",
            url=obj_cls.endpoint,
            version=obj_cls.version,
            namespace=namespace if obj_cls.namespaced else None,
            params=params,
            **kwargs,
        ) as response:
            yield obj_cls, response

    async def get(
        self,
        kind: str | type,
        *names: str,
        namespace: str | None = None,
        label_selector: str | dict | None = None,
        field_selector: str | dict | None = None,
        as_object: type[APIObject] | None = None,
        allow_unknown_type: bool = True,
        raw: bool = False,
        **kwargs,
    ) -> AsyncGenerator[APIObject | dict]:
        """Get Kubernetes resources.

        Args:
            kind: The kind of resource to get.
            *names: The names of specific resources to get.
            namespace: The namespace to get the resource from.
            label_selector: The label selector to filter the resources by.
            field_selector: The field selector to filter the resources by.
            as_object: The object to return the resources as.
            allow_unknown_type: Automatically create a class for the resource if none exists, default True.
            raw: If True, return raw dictionaries instead of APIObject instances, default False.
            **kwargs: Additional keyword arguments to pass to the API call.

        Returns:
            The resources.
        """
        async for resource in self.async_get(
            kind,
            *names,
            namespace=namespace,
            label_selector=label_selector,
            field_selector=field_selector,
            as_object=as_object,
            allow_unknown_type=allow_unknown_type,
            raw=raw,
            **kwargs,
        ):
            yield resource

    async def async_get(
        self,
        kind: str | type,
        *names: str,
        namespace: str | None = None,
        label_selector: str | dict | None = None,
        field_selector: str | dict | None = None,
        as_object: type[APIObject] | None = None,
        allow_unknown_type: bool = True,
        raw: bool = False,
        **kwargs,
    ) -> AsyncGenerator[APIObject | dict]:
        names_list = [None] if not names else names
        for name in names_list:
            async for resource in self._async_get_single(
                kind,
                name,
                namespace=namespace,
                label_selector=label_selector,
                field_selector=field_selector,
                as_object=as_object,
                allow_unknown_type=allow_unknown_type,
                raw=raw,
                **kwargs,
            ):
                yield resource

    async def _async_get_single(
        self,
        kind: str | type,
        name: str | None = None,
        namespace: str | None = None,
        label_selector: str | dict | None = None,
        field_selector: str | dict | None = None,
        as_object: type[APIObject] | None = None,
        allow_unknown_type: bool = True,
        raw: bool = False,
        **kwargs,
    ) -> AsyncGenerator[APIObject | dict]:

        if name is not None:
            # Normalized field_selector to a string
            field_selector_str: str
            if isinstance(field_selector, dict):
                field_selector_str = dict_to_selector(field_selector)
            elif field_selector is None:
                field_selector_str = ""
            else:
                field_selector_str = field_selector
            field_selector = f"metadata.name={name},{field_selector_str}"

        headers = {}
        params = {}
        continue_paging = True
        if as_object:
            group, version = as_object.version.split("/")
            headers["Accept"] = (
                f"application/json;as={as_object.kind};v={version};g={group}"
            )
        else:
            params["limit"] = 100
        while continue_paging:
            async with self.async_get_kind(
                kind,
                namespace=namespace,
                label_selector=label_selector,
                field_selector=field_selector,
                headers=headers or None,
                allow_unknown_type=allow_unknown_type,
                params=params,
                **kwargs,
            ) as (obj_cls, response):
                resourcelist = response.json()
                if (
                    as_object
                    and "kind" in resourcelist
                    and resourcelist["kind"] == as_object.kind
                ):
                    if raw:
                        yield resourcelist
                    else:
                        yield as_object(resourcelist, api=self)
                else:
                    if "items" in resourcelist:
                        for item in resourcelist["items"]:
                            if name is None or item["metadata"]["name"] == name:
                                if raw:
                                    yield item
                                else:
                                    yield obj_cls(item, api=self)
                if (
                    "metadata" in resourcelist
                    and "continue" in resourcelist["metadata"]
                    and resourcelist["metadata"]["continue"]
                ):
                    continue_paging = True
                    params["continue"] = resourcelist["metadata"]["continue"]
                else:
                    continue_paging = False

    async def watch(
        self,
        kind: str,
        namespace: str | None = None,
        label_selector: str | dict | None = None,
        field_selector: str | dict | None = None,
        since: str | None = None,
    ) -> AsyncGenerator[tuple[str, APIObject]]:
        """Watch a Kubernetes resource."""
        async for t, object in self.async_watch(
            kind,
            namespace=namespace,
            label_selector=label_selector,
            field_selector=field_selector,
            since=since,
        ):
            yield t, object

    async def async_watch(
        self,
        kind: str,
        namespace: str | None = None,
        label_selector: str | dict | None = None,
        field_selector: str | dict | None = None,
        since: str | None = None,
        allow_unknown_type: bool = True,
    ) -> AsyncGenerator[tuple[str, APIObject]]:
        """Watch a Kubernetes resource."""
        while True:
            restart_watch = False
            async with self.async_get_kind(
                kind,
                namespace=namespace,
                label_selector=label_selector,
                field_selector=field_selector,
                params={"resourceVersion": since} if since else None,
                watch=True,
                timeout=None,
                allow_unknown_type=allow_unknown_type,
            ) as (obj_cls, response):
                logger.debug(
                    f"Starting watch of {kind}{' at resourceVersion ' + since if since else ''}"
                )
                async for line in response.aiter_lines():
                    event = json.loads(line)
                    if (
                        event["object"]["kind"] == "Status"
                        and event["object"].get("code") == 410
                    ):
                        restart_watch = True
                        logger.debug(
                            f"Got 410 Gone: Restarting watch of {kind} at resourceVersion {since}"
                        )
                        break
                    obj = obj_cls(event["object"], api=self)
                    since = obj.metadata.resourceVersion
                    yield event["type"], obj
            if not restart_watch:
                return

    async def api_resources(self) -> list[dict]:
        """Get the Kubernetes API resources."""
        return await self.async_api_resources()

    # Cache for 6 hours because kubectl does
    # https://github.com/kubernetes/cli-runtime/blob/980bedf450ab21617b33d68331786942227fe93a/pkg/genericclioptions/config_flags.go#L297
    async def async_api_resources(self) -> list[dict]:
        """Get the Kubernetes API resources visible under the access policy.

        The raw discovery response is cached for six hours. The access policy is
        applied on every read, so the cache keeps working while approvals change,
        and a newly discovered version is never displayed unless it is approved
        for display.
        """
        key = ("resources",)
        try:
            raw = self._api_resources_cache[key]
        except KeyError:
            raw = await self.async_api_resources_uncached()
            self._api_resources_cache[key] = raw
        return self._filter_api_resources(raw)

    async def async_api_resources_uncached(self) -> list[dict]:
        """Get the Kubernetes API resources."""
        resources = []
        async with self.call_api(method="GET", version="", base="/api") as response:
            core_api_list = response.json()

        for version in core_api_list["versions"]:
            async with self.call_api(
                method="GET", version="", base="/api", url=version
            ) as response:
                resource = response.json()
            resources.extend(
                [
                    {"version": version, **r}
                    for r in resource["resources"]
                    if "/" not in r["name"]
                ]
            )
        async with self.call_api(method="GET", version="", base="/apis") as response:
            api_list = response.json()
        for api in sorted(api_list["groups"], key=lambda d: d["name"]):
            for api_version in sort_versions(
                api["versions"], key=lambda x: x["groupVersion"]
            ):
                version = api_version["groupVersion"]
                async with self.call_api(
                    method="GET", version="", base="/apis", url=version
                ) as response:
                    resource = response.json()
                resources.extend(
                    [
                        {"version": version, **r}
                        for r in resource["resources"]
                        if "/" not in r["name"]
                    ]
                )
        return resources

    async def api_versions(self) -> AsyncGenerator[str]:
        """Get the Kubernetes API versions."""
        async for version in self.async_api_versions():
            yield version

    async def async_api_versions(self) -> AsyncGenerator[str]:
        async with self.call_api(method="GET", version="", base="/api") as response:
            core_api_list = response.json()
        for version in core_api_list["versions"]:
            yield version

        async with self.call_api(method="GET", version="", base="/apis") as response:
            api_list = response.json()
        for group in api_list["groups"]:
            for version in group["versions"]:
                yield version["groupVersion"]

    async def async_create(self, resources: list[APIObject]):
        async with anyio.create_task_group() as tg:
            for resource in resources:
                tg.start_soon(resource.async_create)

    async def create(self, resources: list[APIObject]):
        return await self.async_create(resources)

    @property
    def __version__(self) -> str:
        return f"kr8s/{__version__}"

    @property
    def namespace(self) -> str:
        """Get the default namespace."""
        assert self.auth.namespace
        return self.auth.namespace

    @namespace.setter
    def namespace(self, value):
        self.auth.namespace = value


def hash_kwargs(kwargs: dict):
    key_kwargs = copy.copy(kwargs)
    for key in key_kwargs:
        if isinstance(key_kwargs[key], dict):
            key_kwargs[key] = json.dumps(key_kwargs[key])
    return frozenset(key_kwargs.items())


_NAMESPACE_SUBRESOURCES = frozenset({"finalize", "status"})


def _parse_resource_path(
    path: str,
) -> tuple[str, str, str, bool, str | None] | None:
    """Resolve the exact resource version targeted by an API path.

    Args:
        path: A constructed Kubernetes API path such as
            ``/apis/apps/v1/namespaces/ns/deployments/name/scale``.

    Returns:
        A tuple of ``(group, version, resource, has_name, subresource)`` or
        ``None`` when the path is not a resource request (for example a
        discovery or version endpoint).
    """
    segments = [segment for segment in path.split("/") if segment]
    if not segments:
        return None
    if segments[0] == "api":
        if len(segments) < 2:
            return None
        group = ""
        version = segments[1]
        rest = segments[2:]
    elif segments[0] == "apis":
        if len(segments) < 3:
            return None
        group = segments[1]
        version = segments[2]
        rest = segments[3:]
    else:
        return None
    if not rest:
        return None

    if rest[0] == "namespaces":
        if len(rest) == 1:
            return group, version, "namespaces", False, None
        if len(rest) == 2:
            return group, version, "namespaces", True, None
        if len(rest) == 3 and rest[2] in _NAMESPACE_SUBRESOURCES:
            return group, version, "namespaces", True, rest[2]
        resource = rest[2]
        remainder = rest[3:]
    else:
        resource = rest[0]
        remainder = rest[1:]

    has_name = bool(remainder)
    subresource = remainder[1] if len(remainder) > 1 else None
    return group, version, resource, has_name, subresource


def _request_verb(
    method: str,
    has_name: bool,
    subresource: str | None,
    params: dict | None,
) -> str:
    """Derive the Kubernetes RBAC verb for a request."""
    method = method.upper()
    if subresource in ("exec", "attach", "portforward"):
        # Kubernetes authorizes these connections with the create verb.
        return "create"
    if method == "GET":
        if params and str(params.get("watch", "")).lower() == "true":
            return "watch"
        return "get" if has_name else "list"
    if method == "POST":
        return "create"
    if method == "PUT":
        return "update"
    if method == "PATCH":
        return "patch"
    if method == "DELETE":
        if has_name or subresource == "finalize":
            return "delete"
        return "deletecollection"
    return method.lower()
