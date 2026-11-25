# SPDX-FileCopyrightText: Copyright (c) 2024-2026, Kr8s Developers (See LICENSE for list)
# SPDX-License-Identifier: BSD 3-Clause License
"""Repeatable local kubeconfig migration timing check.

The script uses ``httpx.MockTransport`` as a network double.  It proves that:

* a healthy client keeps using the old immutable session after the on-disk
  kubeconfig is atomically replaced;
* an explicit reload adopts the new server, CA and credential together;
* a reload interleaving with session construction exposes one complete
  revision, never a mixed server/CA/credential tuple;
* a failed candidate/reload leaves the last-known-good snapshot in service.

Run with the project virtualenv:

    .venv/bin/python scripts/verify_kubeconfig_migration.py
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import os
import shutil
import ssl
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from kr8s._api import Api

WORKDIR = Path(tempfile.gettempdir()) / "kr8s-migration"
CONFIG_PATH = WORKDIR / "kubeconfig"
CANDIDATE_PATH = WORKDIR / "kubeconfig.candidate"
GOOD_BACKUP = WORKDIR / "kubeconfig.last-good"
RECORDS_PATH = WORKDIR / "records.jsonl"

RECORDS: list[dict[str, Any]] = []
NETWORK_REQUESTS: list[dict[str, Any]] = []
CA_LOADS: list[str] = []
CLIENT_BUILDS: list[dict[str, Any]] = []


def record(event: str, **fields: Any) -> None:
    """Append and print one structured timeline event."""
    entry = {"step": len(RECORDS) + 1, "event": event, **fields}
    RECORDS.append(entry)
    print(json.dumps(entry, sort_keys=True, ensure_ascii=False))


def write_atomic(path: Path, data: str | dict[str, Any]) -> None:
    """Write a temporary file and atomically replace the target path."""
    if isinstance(data, dict):
        data = yaml.safe_dump(data)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(data)
    os.replace(temporary, path)


def make_ca(path: Path, common_name: str) -> None:
    """Create a short-lived self-signed CA PEM file for TLS snapshot checks."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def kubeconfig(server: str, token: str, ca_path: Path) -> dict[str, Any]:
    """Build one complete kubeconfig revision."""
    return {
        "apiVersion": "v1",
        "kind": "Config",
        "current-context": "migration",
        "clusters": [
            {
                "name": "migrate-cluster",
                "cluster": {
                    "server": server,
                    "certificate-authority": str(ca_path),
                },
            }
        ],
        "contexts": [
            {
                "name": "migration",
                "context": {
                    "cluster": "migrate-cluster",
                    "user": "migrate-user",
                    "namespace": "default",
                },
            }
        ],
        "users": [{"name": "migrate-user", "user": {"token": token}}],
    }


OLD_SERVER = "https://old.cluster.local:6443"
NEW_SERVER = "https://new.cluster.local:6443"
OLD_TOKEN = "token-old"
NEW_TOKEN = "token-new"


def classify_request(
    url: str, authorization: str | None
) -> tuple[str, str, bool, bool]:
    """Classify the server and credential revision carried by a request."""
    if url.startswith(OLD_SERVER):
        server_revision = "old"
    elif url.startswith(NEW_SERVER):
        server_revision = "new"
    else:
        server_revision = "unknown"

    if authorization == f"Bearer {OLD_TOKEN}":
        credential_revision = "old"
    elif authorization == f"Bearer {NEW_TOKEN}":
        credential_revision = "new"
    else:
        credential_revision = "invalid"

    mixed = (
        server_revision in {"old", "new"}
        and credential_revision in {"old", "new"}
        and server_revision != credential_revision
    )
    authorized = server_revision == credential_revision and not mixed
    return server_revision, credential_revision, mixed, authorized


def network_handler(request: httpx.Request) -> httpx.Response:
    """Record requests and accept only internally consistent revisions."""
    authorization = request.headers.get("authorization")
    server_revision, credential_revision, mixed, authorized = classify_request(
        str(request.url), authorization
    )
    status = 200 if authorized else 401
    entry = {
        "event": "network-request",
        "method": request.method,
        "url": str(request.url),
        "authorization": authorization,
        "server_revision": server_revision,
        "credential_revision": credential_revision,
        "mixed": mixed,
        "authorized": authorized,
        "status": status,
    }
    NETWORK_REQUESTS.append(entry)
    record(**entry)
    return httpx.Response(status, json={"gitVersion": "v1.37.0-migration-double"})


TRANSPORT = httpx.MockTransport(network_handler)
ORIGINAL_LOAD_VERIFY_LOCATIONS = ssl.SSLContext.load_verify_locations


def spy_load_verify_locations(
    self: ssl.SSLContext,
    cafile: str | os.PathLike[str] | None = None,
    capath: str | os.PathLike[str] | None = None,
    cadata: str | bytes | None = None,
) -> None:
    """Record which CA path is loaded into a client TLS context."""
    if cafile is not None:
        CA_LOADS.append(str(cafile))
        record("trust-store-load", cafile=str(cafile))
    return ORIGINAL_LOAD_VERIFY_LOCATIONS(
        self, cafile=cafile, capath=capath, cadata=cadata
    )


class SpyAsyncClient(httpx.AsyncClient):
    """HTTPX client that records construction arguments and uses MockTransport."""

    def __init__(self, **kwargs: Any) -> None:
        """Record the coherent session tuple and install the network double."""
        headers = httpx.Headers(kwargs.get("headers") or {})
        entry = {
            "event": "http-client-built",
            "base_url": str(kwargs.get("base_url") or ""),
            "authorization": headers.get("authorization"),
            "last_ca_load": CA_LOADS[-1] if CA_LOADS else None,
        }
        CLIENT_BUILDS.append(entry)
        record(**entry)
        kwargs["transport"] = TRANSPORT
        super().__init__(**kwargs)


class ReloadDuringClose:
    """Deterministically start a reload while an old session is closing."""

    is_closed = False

    def __init__(self, api: Api, new_config: dict[str, Any]) -> None:
        """Store the API and revision promoted during close."""
        self.api = api
        self.new_config = new_config

    async def aclose(self) -> None:
        """Promote and reload the new config at a deterministic yield point."""
        record("interleaving-close-yields")
        write_atomic(CONFIG_PATH, self.new_config)
        await self.api.auth.reauthenticate()
        record(
            "interleaving-reload-published",
            server=self.api.auth.snapshot.server,
            token=self.api.auth.snapshot.token,
        )


async def version_status(api: Api) -> int:
    """Request `/version` without raising so candidate 401s can be asserted."""
    async with api.call_api(
        "GET", version="", base="/version", raise_for_status=False
    ) as response:
        return response.status_code


async def main() -> int:
    """Run all migration timing scenarios and return a shell exit code."""
    WORKDIR.mkdir(parents=True, exist_ok=True)
    for path in WORKDIR.glob("*"):
        if path.is_file():
            path.unlink()

    old_ca = WORKDIR / "old-ca.pem"
    new_ca = WORKDIR / "new-ca.pem"
    make_ca(old_ca, "old-kr8s-ca")
    make_ca(new_ca, "new-kr8s-ca")
    old_config = kubeconfig(OLD_SERVER, OLD_TOKEN, old_ca)
    new_config = kubeconfig(NEW_SERVER, NEW_TOKEN, new_ca)
    write_atomic(CONFIG_PATH, old_config)
    write_atomic(GOOD_BACKUP, new_config)

    with (
        patch.object(httpx, "AsyncClient", SpyAsyncClient),
        patch.object(
            ssl.SSLContext, "load_verify_locations", spy_load_verify_locations
        ),
    ):
        api = Api(bypass_factory=True, kubeconfig=str(CONFIG_PATH))
        await api.reauthenticate()
        record(
            "initial-snapshot",
            server=api.auth.snapshot.server,
            token=api.auth.snapshot.token,
            ca=str(api.auth.snapshot.server_ca_file),
        )
        assert await version_status(api) == 200

        bad_candidate = kubeconfig(NEW_SERVER, "token-bad", new_ca)
        write_atomic(CANDIDATE_PATH, bad_candidate)
        candidate = Api(bypass_factory=True, kubeconfig=str(CANDIDATE_PATH))
        await candidate.reauthenticate()
        bad_status = await version_status(candidate)
        record("bad-candidate-validation", status=bad_status)
        assert bad_status == 401
        CANDIDATE_PATH.unlink()

        write_atomic(CANDIDATE_PATH, new_config)
        good_candidate = Api(bypass_factory=True, kubeconfig=str(CANDIDATE_PATH))
        await good_candidate.reauthenticate()
        good_status = await version_status(good_candidate)
        record("good-candidate-validation", status=good_status)
        assert good_status == 200

        shutil.copy2(CONFIG_PATH, WORKDIR / "kubeconfig.old-backup")
        os.replace(CANDIDATE_PATH, CONFIG_PATH)
        record("config-promoted-atomically", path=str(CONFIG_PATH))

        requests_before_healthy_call = len(NETWORK_REQUESTS)
        assert await version_status(api) == 200
        healthy_request = NETWORK_REQUESTS[requests_before_healthy_call]
        assert healthy_request["server_revision"] == "old"
        assert healthy_request["mixed"] is False
        record(
            "healthy-caller-still-uses-old-session",
            url=healthy_request["url"],
            authorization=healthy_request["authorization"],
        )

        await api.reauthenticate()
        record(
            "explicit-reload-complete",
            server=api.auth.snapshot.server,
            token=api.auth.snapshot.token,
            ca=str(api.auth.snapshot.server_ca_file),
        )
        assert await version_status(api) == 200

        write_atomic(CONFIG_PATH, old_config)
        await api.reauthenticate()
        api._session = ReloadDuringClose(api, new_config)  # type: ignore[assignment]
        record("begin-interleaved-session-creation")
        await api._create_session()
        assert await version_status(api) == 200
        interleaved_request = NETWORK_REQUESTS[-1]
        record(
            "interleaved-session-observed",
            server_revision=interleaved_request["server_revision"],
            credential_revision=interleaved_request["credential_revision"],
            mixed=interleaved_request["mixed"],
            url=interleaved_request["url"],
            authorization=interleaved_request["authorization"],
        )
        assert interleaved_request["server_revision"] == "old"
        assert interleaved_request["mixed"] is False

        await api.reauthenticate()
        assert await version_status(api) == 200
        record("late-reload-adopts-new-revision")

        write_atomic(CONFIG_PATH, "clusters: [this-write-is-invalid\n")
        try:
            await api.auth.reauthenticate()
        except Exception as exc:  # noqa: BLE001 - report any parser/loader failure
            record(
                "partial-promotion-reload-failed",
                error_type=type(exc).__name__,
                error=str(exc).splitlines()[0],
                retained_server=api.auth.snapshot.server,
                retained_token=api.auth.snapshot.token,
            )
        else:
            raise AssertionError("Corrupt kubeconfig unexpectedly loaded")

        assert api.auth.snapshot.server == NEW_SERVER
        assert api.auth.snapshot.token == NEW_TOKEN
        assert await version_status(api) == 200
        record("last-known-good-session-still-serves")

        shutil.copy2(GOOD_BACKUP, CONFIG_PATH)
        await api.reauthenticate()
        assert await version_status(api) == 200
        record("backup-restored-and-reloaded")

    mixed = [request for request in NETWORK_REQUESTS if request["mixed"]]
    new_requests = [
        request
        for request in NETWORK_REQUESTS
        if request["server_revision"] == "new" and request["authorized"]
    ]
    result = {
        "total_requests": len(NETWORK_REQUESTS),
        "mixed_requests": len(mixed),
        "old_observed_after_promotion": healthy_request["server_revision"] == "old",
        "new_request_count": len(new_requests),
        "ca_loads": CA_LOADS,
        "records": str(RECORDS_PATH),
    }
    record("verification-complete", **result)
    RECORDS_PATH.write_text("\n".join(json.dumps(entry) for entry in RECORDS) + "\n")
    if mixed or not new_requests:
        print("FAIL: mixed configuration observed")
        return 1
    print("PASS: old config is used only as a complete revision; new config is atomic")
    print(f"JSONL records: {RECORDS_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
