from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import pytest

from quart import Quart
from quart import abort
from quart import request
from quart.helpers import send_file
from quart.wrappers.response import FileBody

USER = "alice"
BEARER_TOKEN = "Bearer s3cr3t-token"
ASSET_NAME = "asset.bin"
LOGGER_NAME = "download_audit"


@dataclass
class DownloadHarness:
    app: Quart
    client: object
    asset: Path
    payload: bytes
    permissions: dict[str, bool]
    open_count: dict[str, int]


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> DownloadHarness:
    payload = bytes(range(256)) * 4
    asset = tmp_path / ASSET_NAME
    asset.write_bytes(payload)

    permissions: dict[str, bool] = {USER: True}
    open_count = {"opens": 0}
    audit = logging.getLogger(LOGGER_NAME)

    real_enter = FileBody.__aenter__

    async def counting_enter(self: FileBody) -> FileBody:
        open_count["opens"] += 1
        return await real_enter(self)

    monkeypatch.setattr(FileBody, "__aenter__", counting_enter)

    app = Quart(__name__)

    @app.route("/download/<name>")
    async def download(name: str):
        user = request.headers.get("X-User")
        audit.info("download decision user=%s resource=%s", user, name)
        if not permissions.get(user):
            abort(403)
        return await send_file(tmp_path / name, conditional=True)

    return DownloadHarness(
        app=app,
        client=app.test_client(),
        asset=asset,
        payload=payload,
        permissions=permissions,
        open_count=open_count,
    )


def _range_headers(range_: str, extra: dict[str, str] | None = None) -> dict[str, str]:
    headers = {"X-User": USER, "Authorization": BEARER_TOKEN, "Range": range_}
    if extra is not None:
        headers.update(extra)
    return headers


async def test_range_follows_authorization_lifecycle(
    harness: DownloadHarness, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)
    client = harness.client

    harness.open_count["opens"] = 0
    allowed = await client.get(
        f"/download/{ASSET_NAME}", headers=_range_headers("bytes=10-19")
    )
    assert allowed.status_code == 206
    assert allowed.headers["Accept-Ranges"] == "bytes"
    assert allowed.headers["Content-Range"] == "bytes 10-19/1024"
    assert allowed.headers["Content-Length"] == "10"
    allowed_etag = allowed.headers["ETag"]
    assert allowed_etag
    assert await allowed.get_data(as_text=False) == harness.payload[10:20]
    assert harness.open_count["opens"] == 1

    harness.permissions[USER] = False
    harness.open_count["opens"] = 0
    denied = await client.get(
        f"/download/{ASSET_NAME}",
        headers=_range_headers(
            "bytes=10-19", {"If-None-Match": allowed_etag}
        ),
    )
    assert denied.status_code == 403
    assert "Content-Range" not in denied.headers
    assert "ETag" not in denied.headers
    assert await denied.get_data(as_text=False) != harness.payload[10:20]
    assert harness.open_count["opens"] == 0

    harness.permissions[USER] = True
    harness.open_count["opens"] = 0
    regranted = await client.get(
        f"/download/{ASSET_NAME}", headers=_range_headers("bytes=0-99")
    )
    assert regranted.status_code == 206
    assert regranted.headers["Content-Range"] == "bytes 0-99/1024"
    assert regranted.headers["Content-Length"] == "100"
    assert await regranted.get_data(as_text=False) == harness.payload[0:100]
    assert harness.open_count["opens"] == 1

    decisions = [
        record.getMessage()
        for record in caplog.records
        if record.name == LOGGER_NAME
    ]
    assert decisions == [
        f"download decision user={USER} resource={ASSET_NAME}",
        f"download decision user={USER} resource={ASSET_NAME}",
        f"download decision user={USER} resource={ASSET_NAME}",
    ]
    joined = "\n".join(decisions)
    assert BEARER_TOKEN not in joined
    assert "s3cr3t" not in joined
    assert "Authorization" not in joined


async def test_authorized_not_modified_skips_file(
    harness: DownloadHarness,
) -> None:
    client = harness.client
    first = await client.get(
        f"/download/{ASSET_NAME}", headers=_range_headers("bytes=0-3")
    )
    etag = first.headers["ETag"]
    assert first.status_code == 206

    harness.open_count["opens"] = 0
    validated = await client.get(
        f"/download/{ASSET_NAME}",
        headers={
            "X-User": USER,
            "Authorization": BEARER_TOKEN,
            "If-None-Match": etag,
        },
    )
    assert validated.status_code == 304
    assert await validated.get_data(as_text=False) == b""
    assert harness.open_count["opens"] == 0


async def test_stale_if_range_returns_full_resource(
    harness: DownloadHarness,
) -> None:
    client = harness.client
    response = await client.get(
        f"/download/{ASSET_NAME}",
        headers=_range_headers("bytes=5-9", {"If-Range": '"stale-etag"'}),
    )
    assert response.status_code == 200
    assert "Content-Range" not in response.headers
    assert await response.get_data(as_text=False) == harness.payload
