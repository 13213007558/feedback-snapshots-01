from __future__ import annotations

import asyncio
from dataclasses import dataclass
from dataclasses import field
from enum import Enum

from hypercorn.typing import ASGIReceiveEvent
from hypercorn.typing import ASGISendEvent
from hypercorn.typing import HTTPScope

from quart import Quart
from quart.asgi import ASGIHTTPConnection


class UploadStatus(str, Enum):
    READING = "reading"
    READ_UNCOMMITTED = "read_uncommitted"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled_back"


@dataclass
class UploadRecord:
    upload_id: str
    status: UploadStatus
    data: bytearray = field(default_factory=bytearray)
    released: bool = False


class PausableUploadStore:
    """In-memory business persistence layer with pausable phases.

    The pauses let a test place a client disconnect at a precise point in
    the handler lifecycle. ``begin`` hands out an open handle that must be
    released in the request teardown, so leaked resources are observable.
    """

    def __init__(self) -> None:
        self._records: dict[str, UploadRecord] = {}
        self._open_handles: dict[str, UploadRecord] = {}
        self.released: list[str] = []
        self.teardown_seen: list[BaseException | None] = []
        # Signals raised by the handler as it reaches each phase.
        self.chunk_received = asyncio.Event()
        self.body_fully_read = asyncio.Event()
        self.record_committed = asyncio.Event()
        # Gates the handler waits on, controlled by the test.
        self.allow_commit = asyncio.Event()
        self.allow_response = asyncio.Event()

    def begin(self, upload_id: str) -> UploadRecord:
        record = UploadRecord(upload_id, UploadStatus.READING)
        self._records[upload_id] = record
        self._open_handles[upload_id] = record
        return record

    async def append(self, record: UploadRecord, chunk: bytes) -> None:
        record.data.extend(chunk)
        self.chunk_received.set()

    async def mark_fully_read(self, record: UploadRecord) -> None:
        record.status = UploadStatus.READ_UNCOMMITTED
        self.body_fully_read.set()
        # Pause with the whole body read but the transaction unconfirmed.
        await self.allow_commit.wait()

    async def commit(self, record: UploadRecord) -> None:
        record.status = UploadStatus.COMMITTED
        self.record_committed.set()
        # Pause after commit but before the response is produced.
        await self.allow_response.wait()

    def rollback_uncommitted(self, upload_id: str) -> None:
        record = self._records.get(upload_id)
        if record is None or record.status is UploadStatus.COMMITTED:
            return
        record.status = UploadStatus.ROLLED_BACK
        # Discard the uncommitted record so the same id remains retryable.
        self._records.pop(upload_id, None)

    def release(self, upload_id: str) -> None:
        record = self._open_handles.pop(upload_id, None)
        if record is not None:
            record.released = True
        self.released.append(upload_id)

    def get(self, upload_id: str) -> UploadRecord | None:
        return self._records.get(upload_id)

    @property
    def open_handle_ids(self) -> list[str]:
        return list(self._open_handles)


def _make_scope(method: str, path: str, query_string: bytes) -> HTTPScope:
    return {
        "type": "http",
        "asgi": {},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": query_string,
        "root_path": "",
        "headers": [(b"host", b"quart")],
        "client": ("127.0.0.1", 80),
        "server": None,
        "extensions": {},
        "state": {},  # type: ignore[typeddict-item]
    }


def _build_app(store: PausableUploadStore) -> Quart:
    app = Quart(__name__)

    @app.teardown_request
    async def _release_upload(exc: BaseException | None) -> None:
        upload_id = app.config["_current_upload_id"]
        store.teardown_seen.append(exc)
        store.rollback_uncommitted(upload_id)
        store.release(upload_id)

    @app.post("/uploads")
    async def upload() -> dict[str, object]:
        from quart import request

        upload_id = request.args["id"]
        app.config["_current_upload_id"] = upload_id
        record = store.begin(upload_id)

        async for chunk in request.body:
            if chunk:
                await store.append(record, chunk)

        full_body = bytes(record.data)
        await store.mark_fully_read(record)
        await store.commit(record)
        return {"id": upload_id, "length": len(full_body)}

    @app.get("/uploads/<upload_id>")
    async def fetch(upload_id: str) -> tuple[dict[str, object], int]:
        record = store.get(upload_id)
        if record is None:
            return {"found": False}, 404
        return (
            {
                "found": True,
                "status": record.status.value,
                "length": len(record.data),
            },
            200,
        )

    return app


class ASGIConnectionDriver:
    """Drives a single ASGI connection with scripted receive/send messages."""

    def __init__(self, app: Quart, method: str, path: str, query_string: bytes) -> None:
        self.inbox: asyncio.Queue[ASGIReceiveEvent] = asyncio.Queue()
        self.sent: list[ASGISendEvent] = []
        self.connection = ASGIHTTPConnection(
            app, _make_scope(method, path, query_string)
        )

    async def _receive(self) -> ASGIReceiveEvent:
        return await self.inbox.get()

    async def _send(self, message: ASGISendEvent) -> None:
        self.sent.append(message)

    async def run(self) -> None:
        await self.connection(self._receive, self._send)

    async def request(self, body: bytes, more_body: bool) -> None:
        await self.inbox.put(
            {"type": "http.request", "body": body, "more_body": more_body}
        )

    async def disconnect(self) -> None:
        await self.inbox.put({"type": "http.disconnect"})

    @property
    def sent_types(self) -> list[str]:
        return [message["type"] for message in self.sent]  # type: ignore[typeddict-item]


async def _wait(event: asyncio.Event) -> None:
    await asyncio.wait_for(event.wait(), timeout=3)


async def _wait_for_response(driver: ASGIConnectionDriver) -> None:
    async def _sent() -> None:
        while not any(
            message["type"] == "http.response.start" for message in driver.sent
        ):
            await asyncio.sleep(0)

    await asyncio.wait_for(_sent(), timeout=3)


# Body is delivered as three chunks so a disconnect can land between them.
UPLOAD_CHUNKS = [b"chunk-0", b"chunk-1", b"chunk-2"]
FULL_BODY = b"".join(UPLOAD_CHUNKS)


async def test_disconnect_while_still_reading_discards_uncommitted() -> None:
    store = PausableUploadStore()
    app = _build_app(store)
    driver = ASGIConnectionDriver(app, "POST", "/uploads", b"id=up1")
    task = asyncio.ensure_future(driver.run())

    await driver.request(UPLOAD_CHUNKS[0], more_body=True)
    await _wait(store.chunk_received)

    # Disconnect before the final chunk: the handler is still mid-read.
    await driver.disconnect()
    await asyncio.wait_for(task, timeout=3)
    assert task.done()  # reader and handler tasks are both reaped

    assert store.get("up1") is None  # uncommitted work rolled back, retryable
    assert store.open_handle_ids == []  # business handle released
    assert store.released == ["up1"]
    assert driver.sent_types == []  # no response reached the gone client
    # The real cancellation still reaches the request's teardown phase.
    assert [type(exc) for exc in store.teardown_seen] == [asyncio.CancelledError]


async def test_disconnect_after_full_read_before_commit_rolls_back() -> None:
    store = PausableUploadStore()
    app = _build_app(store)
    driver = ASGIConnectionDriver(app, "POST", "/uploads", b"id=up2")
    task = asyncio.ensure_future(driver.run())

    for index, chunk in enumerate(UPLOAD_CHUNKS):
        await driver.request(chunk, more_body=index < len(UPLOAD_CHUNKS) - 1)
    await _wait(store.body_fully_read)  # whole body read, paused before commit

    assert store.get("up2").status is UploadStatus.READ_UNCOMMITTED

    await driver.disconnect()
    await asyncio.wait_for(task, timeout=3)
    assert task.done()

    assert store.get("up2") is None  # fully read but never confirmed -> rollback
    assert store.open_handle_ids == []
    assert store.released == ["up2"]
    assert driver.sent_types == []
    assert [type(exc) for exc in store.teardown_seen] == [asyncio.CancelledError]


async def test_disconnect_after_commit_keeps_record_for_lookup() -> None:
    store = PausableUploadStore()
    app = _build_app(store)
    driver = ASGIConnectionDriver(app, "POST", "/uploads", b"id=up3")
    task = asyncio.ensure_future(driver.run())

    for index, chunk in enumerate(UPLOAD_CHUNKS):
        await driver.request(chunk, more_body=index < len(UPLOAD_CHUNKS) - 1)
    await _wait(store.body_fully_read)
    store.allow_commit.set()
    await _wait(store.record_committed)  # committed, paused before responding

    committed = store.get("up3")
    assert committed is not None
    assert committed.status is UploadStatus.COMMITTED
    assert bytes(committed.data) == FULL_BODY

    await driver.disconnect()
    store.allow_response.set()
    await asyncio.wait_for(task, timeout=3)
    assert task.done()

    # Committed work survives even though the response could not be sent.
    kept = store.get("up3")
    assert kept is not None
    assert kept.status is UploadStatus.COMMITTED
    assert kept.released is True  # handle still released
    assert store.open_handle_ids == []
    assert driver.sent_types == []
    # Even after commit the disconnect cancels the in-flight request task.
    assert type(store.teardown_seen[0]) is asyncio.CancelledError

    # The caller can reconcile the outcome through the lookup endpoint.
    lookup = ASGIConnectionDriver(app, "GET", "/uploads/up3", b"")
    lookup_task = asyncio.ensure_future(lookup.run())
    await lookup.request(b"", more_body=False)
    await _wait_for_response(lookup)
    await lookup.disconnect()
    await asyncio.wait_for(lookup_task, timeout=3)
    response_start = next(
        message for message in lookup.sent if message["type"] == "http.response.start"
    )
    assert response_start["status"] == 200  # type: ignore[typeddict-item]


async def test_cancelled_upload_can_be_retried_and_does_not_leak() -> None:
    store = PausableUploadStore()
    app = _build_app(store)

    # First attempt on up4 is cancelled mid-stream and rolled back.
    first = ASGIConnectionDriver(app, "POST", "/uploads", b"id=up4")
    first_task = asyncio.ensure_future(first.run())
    await first.request(UPLOAD_CHUNKS[0], more_body=True)
    await _wait(store.chunk_received)
    await first.disconnect()
    await asyncio.wait_for(first_task, timeout=3)
    assert store.get("up4") is None
    assert store.open_handle_ids == []

    # Retry the same id with a normal, fully-completed upload.
    retry = ASGIConnectionDriver(app, "POST", "/uploads", b"id=up4")
    retry_task = asyncio.ensure_future(retry.run())
    for index, chunk in enumerate(UPLOAD_CHUNKS):
        await retry.request(chunk, more_body=index < len(UPLOAD_CHUNKS) - 1)
    await _wait(store.body_fully_read)
    store.allow_commit.set()
    await _wait(store.record_committed)
    store.allow_response.set()

    # The message reader stays parked on receive() until the client closes;
    # deliver the disconnect once the full response has been sent.
    await _wait_for_response(retry)
    await retry.disconnect()
    await asyncio.wait_for(retry_task, timeout=3)

    retried = store.get("up4")
    assert retried is not None
    assert retried.status is UploadStatus.COMMITTED
    assert bytes(retried.data) == FULL_BODY
    assert retried.released is True
    assert store.open_handle_ids == []
    assert retry.sent_types[0] == "http.response.start"
    # First attempt was cancelled; the completed retry tears down without error.
    assert type(store.teardown_seen[0]) is asyncio.CancelledError
    assert store.teardown_seen[1] is None


async def test_second_normal_upload_uses_fresh_resources() -> None:
    store = PausableUploadStore()
    app = _build_app(store)

    # A disconnected, rolled-back upload leaves state behind to clean up.
    cancelled = ASGIConnectionDriver(app, "POST", "/uploads", b"id=up5")
    cancelled_task = asyncio.ensure_future(cancelled.run())
    await cancelled.request(UPLOAD_CHUNKS[0], more_body=True)
    await _wait(store.chunk_received)
    await cancelled.disconnect()
    await asyncio.wait_for(cancelled_task, timeout=3)
    assert store.released == ["up5"]
    assert store.open_handle_ids == []

    # A brand-new upload on a different id must not inherit any old resource.
    second = ASGIConnectionDriver(app, "POST", "/uploads", b"id=up6")
    second_task = asyncio.ensure_future(second.run())
    for index, chunk in enumerate(UPLOAD_CHUNKS):
        await second.request(chunk, more_body=index < len(UPLOAD_CHUNKS) - 1)
    await _wait(store.body_fully_read)
    store.allow_commit.set()
    await _wait(store.record_committed)
    store.allow_response.set()
    await _wait_for_response(second)
    await second.disconnect()
    await asyncio.wait_for(second_task, timeout=3)

    assert store.open_handle_ids == []
    assert store.released == ["up5", "up6"]
    # Old request was cancelled; the new request completed and tore down clean.
    assert type(store.teardown_seen[0]) is asyncio.CancelledError
    assert store.teardown_seen[1] is None
    new_record = store.get("up6")
    assert new_record is not None and new_record.status is UploadStatus.COMMITTED
    assert bytes(new_record.data) == FULL_BODY
    # The rolled-back record stays gone and never resurfaces via the new request.
    assert store.get("up5") is None
    assert second.sent_types[0] == "http.response.start"
