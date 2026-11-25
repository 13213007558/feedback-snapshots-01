# SPDX-FileCopyrightText: Copyright (c) 2024-2026, Kr8s Developers (See LICENSE for list)
# SPDX-License-Identifier: BSD 3-Clause License
from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import yaml

from kr8s._api import Api
from kr8s._auth import AuthSnapshot, KubeAuth


def _kubeconfig(server: str, token: str, ca_name: str, tmp_path: Path) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Config",
        "current-context": "migration",
        "clusters": [
            {
                "name": "cluster",
                "cluster": {
                    "server": server,
                    "certificate-authority": str(tmp_path / ca_name),
                },
            }
        ],
        "contexts": [
            {
                "name": "migration",
                "context": {"cluster": "cluster", "user": "user"},
            }
        ],
        "users": [{"name": "user", "user": {"token": token}}],
    }


@pytest.fixture
def migration_configs(tmp_path: Path):
    path = tmp_path / "kubeconfig"
    old = _kubeconfig("https://old.example:6443", "old-token", "old-ca.pem", tmp_path)
    new = _kubeconfig("https://new.example:6443", "new-token", "new-ca.pem", tmp_path)
    path.write_text(yaml.safe_dump(old))
    return path, old, new


async def _ssl_context_without_cert_reads(self: AuthSnapshot) -> bool:
    return True


async def test_failed_reload_retains_last_good_snapshot(migration_configs):
    path, old, _ = migration_configs
    api = Api(bypass_factory=True, kubeconfig=path)
    await api.auth.reauthenticate()
    good_snapshot = api.auth.snapshot

    path.write_text("clusters: [unterminated\n")

    with pytest.raises(Exception):
        await api.auth.reauthenticate()

    assert api.auth.snapshot == good_snapshot
    assert api.auth.server == old["clusters"][0]["cluster"]["server"]
    assert api.auth.token == "old-token"
    ca_file = api.auth.server_ca_file
    assert ca_file is not None
    assert Path(ca_file).name == "old-ca.pem"


async def test_explicit_reauthenticate_replaces_session(migration_configs, monkeypatch):
    path, _, new = migration_configs
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((str(request.url), request.headers.get("authorization")))
        return httpx.Response(200, json={})

    class SpyClient(httpx.AsyncClient):
        def __init__(self, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", SpyClient)
    monkeypatch.setattr(AuthSnapshot, "ssl_context", _ssl_context_without_cert_reads)

    api = Api(bypass_factory=True, kubeconfig=path)
    await api.reauthenticate()
    old_session = api._session

    path.write_text(yaml.safe_dump(new))
    await api.reauthenticate()

    assert api._session is not old_session
    new_session = api._session
    assert new_session is not None
    assert str(new_session.base_url).startswith(new["clusters"][0]["cluster"]["server"])
    assert new_session.headers["authorization"] == "Bearer new-token"

    await api.async_version()
    assert requests[-1][0].startswith(new["clusters"][0]["cluster"]["server"])
    assert requests[-1][1] == "Bearer new-token"


async def test_session_snapshot_stays_coherent_during_interleaved_reload(
    migration_configs, monkeypatch
):
    path, _, new = migration_configs

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    class SpyClient(httpx.AsyncClient):
        def __init__(self, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(**kwargs)

    class ReloadDuringClose:
        is_closed = False

        def __init__(self, api: Api):
            self.api = api

        async def aclose(self):
            path.write_text(yaml.safe_dump(new))
            await self.api.auth.reauthenticate()

    monkeypatch.setattr(httpx, "AsyncClient", SpyClient)
    monkeypatch.setattr(AuthSnapshot, "ssl_context", _ssl_context_without_cert_reads)

    api = Api(bypass_factory=True, kubeconfig=path)
    await api.auth.reauthenticate()
    old_snapshot = api.auth.snapshot
    api._session = ReloadDuringClose(api)  # type: ignore[assignment]

    session = await api._create_session()

    new_ca_file = api.auth.snapshot.server_ca_file
    assert new_ca_file is not None
    assert api.auth.snapshot is not old_snapshot
    assert api.auth.snapshot.server == "https://new.example:6443"
    assert api.auth.snapshot.token == "new-token"
    assert Path(new_ca_file).name == "new-ca.pem"

    old_ca_file = api._auth_snapshot.server_ca_file
    assert old_ca_file is not None
    assert api._auth_snapshot == old_snapshot
    assert api._auth_snapshot is not api.auth.snapshot
    assert str(session.base_url).startswith("https://old.example:6443")
    assert session.headers["authorization"] == "Bearer old-token"
    assert Path(old_ca_file).name == "old-ca.pem"

    await api.async_version()


async def test_service_account_fallback_with_missing_kubeconfig(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    (tmp_path / "token").write_text("sa-token")
    (tmp_path / "namespace").write_text("sa-namespace")
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "kubernetes.example")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "443")

    auth = KubeAuth(
        kubeconfig=tmp_path / "missing-kubeconfig",
        serviceaccount=str(tmp_path),
    )
    await auth.reauthenticate()

    assert auth.server == "https://kubernetes.example:443"
    assert auth.token == "sa-token"
    assert auth.namespace == "sa-namespace"
    assert auth.snapshot.server == auth.server
    assert auth.snapshot.token == auth.token
