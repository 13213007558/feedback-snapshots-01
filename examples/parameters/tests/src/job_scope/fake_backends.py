"""Two in-memory parameter backends that mimic the AWS SDK surface.

``FakeSSMClient`` exposes a ``get_parameters_by_path`` paginator like the SSM SDK;
``FakeSecretsClient`` exposes ``list_secrets`` + ``batch_get_secret_value`` like
Secrets Manager. Neither performs any network I/O, and every SDK call is recorded
so tests can prove that rejected requests never leave the provider layer.

Each backend can be put in ``inject_extra_entries`` mode: it then occasionally
returns entries that do not belong to the requested scope, simulating an
over-permissive or buggy upstream response that the job constraint must filter.
"""

from __future__ import annotations

from typing import Any

from aws_lambda_powertools.utilities.parameters.base import BaseProvider


class FakeSSMClient:
    """In-memory stand-in for the boto3 SSM client used by ``SSMProvider``."""

    def __init__(self, parameters: dict[str, str], *, page_size: int = 2, inject_extra_entries: bool = False):
        self._parameters = parameters
        self._page_size = page_size
        self._inject_extra_entries = inject_extra_entries
        self.calls: list[dict[str, Any]] = []

    def get_paginator(self, operation_name: str) -> FakeSSMPaginator:
        assert operation_name == "get_parameters_by_path"
        return FakeSSMPaginator(self)

    def get_parameter(self, *, Name: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append({"operation": "get_parameter", "Name": Name, **kwargs})
        if Name not in self._parameters:
            raise KeyError(Name)
        return {"Parameter": {"Name": Name, "Value": self._parameters[Name]}}

    def _list_by_path(self, path: str, recursive: bool) -> list[dict[str, str]]:
        entries = [
            {"Name": name, "Value": value}
            for name, value in sorted(self._parameters.items())
            if name == path
            or (
                name.startswith(f"{path.rstrip('/')}/")
                and (recursive or name.count("/") == path.rstrip("/").count("/") + 1)
            )
        ]
        if self._inject_extra_entries:
            # The upstream occasionally leaks a parameter from another team's scope.
            entries.append({"Name": "/team-admin/break-glass", "Value": "LEAKED-SSM"})
        return entries


class FakeSSMPaginator:
    """Splits a path query into pages, mirroring a paginator's ``NextToken`` flow."""

    def __init__(self, client: FakeSSMClient):
        self._client = client

    def paginate(self, **sdk_options: Any):
        path = sdk_options["Path"]
        recursive = sdk_options.get("Recursive", False)
        entries = self._client._list_by_path(path, recursive)
        self._client.calls.append({"operation": "get_parameters_by_path", **sdk_options})
        for start in range(0, len(entries), self._client._page_size):
            page_entries = entries[start : start + self._client._page_size]
            next_token = (
                str(start + self._client._page_size) if start + self._client._page_size < len(entries) else None
            )
            page = {"Parameters": page_entries}
            if next_token:
                page["NextToken"] = next_token
            yield page


class FakeSSMProvider(BaseProvider):
    """SSM-style provider: single reads by name, batch reads by path prefix."""

    def __init__(self, client: FakeSSMClient):
        super().__init__()
        self.client = client

    def _get(self, name: str, **sdk_options: Any) -> str:
        return self.client.get_parameter(Name=name, **sdk_options)["Parameter"]["Value"]

    def _get_multiple(self, path: str, **sdk_options: Any) -> dict[str, str]:
        sdk_options["Recursive"] = sdk_options.pop("recursive", False)
        parameters: dict[str, str] = {}
        for page in self.client.get_paginator("get_parameters_by_path").paginate(
            Path=path,
            **sdk_options,
        ):
            for parameter in page.get("Parameters", []):
                name = parameter["Name"]
                # Match on path segments, not a naive prefix: "/team-admin" must
                # not be treated as a child of "/team-a".
                if name == path or name.startswith(f"{path.rstrip('/')}/"):
                    # In-scope entries are reduced to the part after the requested
                    # path, matching the real SSM provider. Entries outside the
                    # path (an upstream leak) keep their full name so the job
                    # policy can recognize and reject them.
                    name = name[len(path) :].lstrip("/")
                parameters[name] = parameter["Value"]
        return parameters


class FakeSecretsClient:
    """In-memory stand-in for the boto3 Secrets Manager client."""

    def __init__(self, secrets: dict[str, str], *, page_size: int = 2, inject_extra_entries: bool = False):
        self._secrets = secrets
        self._page_size = page_size
        self._inject_extra_entries = inject_extra_entries
        self.calls: list[dict[str, Any]] = []

    def list_secrets(self, *, Path: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append({"operation": "list_secrets", "Path": Path, **kwargs})
        names = sorted(name for name in self._secrets if name == Path or name.startswith(f"{Path.rstrip('/')}/"))
        if self._inject_extra_entries:
            names.append("/team-admin/break-glass-secret")
        start = int(kwargs["NextToken"]) if kwargs.get("NextToken") else 0
        page = names[start : start + self._page_size]
        next_cursor = start + self._page_size
        next_token = str(next_cursor) if next_cursor < len(names) else None
        return {"SecretList": [{"Name": name} for name in page], "NextToken": next_token}

    def batch_get_secret_value(self, *, SecretIdList: list[str], **kwargs: Any) -> dict[str, Any]:
        self.calls.append({"operation": "batch_get_secret_value", "SecretIdList": list(SecretIdList), **kwargs})
        # No silent default for unknown names: a name outside the in-memory store
        # raises, like the real API reporting a missing secret. Enforcement itself
        # happens in JobScopedProvider, which removes out-of-scope names before
        # they ever reach this call.
        secret_values = [{"Name": name, "SecretString": self._secrets[name]} for name in SecretIdList]
        return {"SecretValues": secret_values, "Errors": []}


class FakeSecretsProvider(BaseProvider):
    """Secrets-Manager-style provider: batch reads are explicit secret names.

    The list and value-fetch steps are kept separate on purpose. A constrained
    wrapper can narrow the names between the two so a forbidden secret is never
    requested from the SDK, even when listing returns entries from another scope.
    """

    def __init__(self, client: FakeSecretsClient):
        super().__init__()
        self.client = client

    def _get(self, name: str, **sdk_options: Any) -> str:
        response = self.client.batch_get_secret_value(SecretIdList=[name], **sdk_options)
        return response["SecretValues"][0]["SecretString"]

    def list_names(self, path: str) -> list[str]:
        """Page through ``list_secrets`` and collect every visible secret name."""
        names: list[str] = []
        next_token: str | None = None
        while True:
            options = {"NextToken": next_token} if next_token else {}
            response = self.client.list_secrets(Path=path, **options)
            names.extend(item["Name"] for item in response["SecretList"])
            next_token = response.get("NextToken")
            if not next_token:
                return names

    def fetch_many(self, names: list[str]) -> dict[str, str]:
        if not names:
            return {}
        response = self.client.batch_get_secret_value(SecretIdList=names)
        return {item["Name"]: item["SecretString"] for item in response["SecretValues"]}

    def _get_multiple(self, names: list[str], **sdk_options: Any) -> dict[str, str]:
        return self.fetch_many(list(names), **sdk_options)
