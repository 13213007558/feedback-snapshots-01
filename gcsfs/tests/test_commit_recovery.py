import json
from unittest import mock

import aiohttp
import pytest

from gcsfs.core import GCSFileSystem
from gcsfs.retry import CommitStatus, GenerationMismatchError, UnconfirmedCommitError


class FakeGenerationEndpoint:
    """In-memory conditional resumable-upload endpoint."""

    def __init__(self, initial_generation=7, lose_after_commit=True):
        self.generation = initial_generation
        self.initial_generation = initial_generation
        self.contents = b"old"
        self.objects = {}
        self.writes = []
        self.sessions = {}
        self.lose_after_commit = lose_after_commit
        self.disconnect_next_commit = True
        self.requests = []

    @property
    def write_count(self):
        return len(self.writes)

    def initiate(self, if_generation_match=None, **kwargs):
        session_id = f"session-{len(self.sessions) + 1}"
        self.sessions[session_id] = {
            "condition": if_generation_match,
            "committed": False,
            "metadata": None,
        }
        return f"https://fake.invalid/upload/{session_id}"

    def _session_id(self, path):
        return path.rstrip("/").rsplit("/", 1)[-1]

    def _commit(self, data, if_generation_match):
        if if_generation_match is not None and int(if_generation_match) != int(
            self.generation
        ):
            raise FileExistsError("412 Precondition Failed")
        self.generation += 1
        metadata = {
            "name": "conditional/object",
            "bucket": "bucket",
            "generation": str(self.generation),
            "size": len(data),
            "md5Hash": "",
            "crc32c": "",
        }
        self.contents = bytes(data)
        self.objects[metadata["generation"]] = self.contents
        self.writes.append(metadata)
        return metadata

    def approved_commit(self, data, expected_generation):
        return self._commit(data, expected_generation)

    def handle(self, method, path, headers=None, data=None, **kwargs):
        self.requests.append(
            {
                "method": method,
                "path": path,
                "headers": dict(headers or {}),
                "ifGenerationMatch": kwargs.get("ifGenerationMatch"),
            }
        )
        session_id = self._session_id(path)
        session = self.sessions.get(session_id)
        headers = headers or {}
        content_range = headers.get("Content-Range", "")

        if method == "DELETE":
            self.sessions.pop(session_id, None)
            return {}, b""

        # Empty body + bytes */N is the resumable session status query.
        if session is not None and data in (None, b"") and "*" in content_range:
            if session["committed"]:
                return {}, json.dumps(session["metadata"])
            return {"Range": "bytes=0-0"}, b""

        if session is not None and session["committed"]:
            # A repeated final POST to the same resumable session is idempotent.
            return {}, json.dumps(session["metadata"])

        if session is None:
            raise FileNotFoundError(path)

        if not self.lose_after_commit and self.disconnect_next_commit:
            self.disconnect_next_commit = False
            raise aiohttp.ServerDisconnectedError("connection lost before acceptance")

        condition = kwargs.get("ifGenerationMatch", session["condition"])
        payload = bytes(data) if data is not None else b""
        metadata = self._commit(payload, condition)
        session["committed"] = True
        session["metadata"] = metadata

        if self.lose_after_commit and self.disconnect_next_commit:
            self.disconnect_next_commit = False
            raise aiohttp.ServerDisconnectedError("final response lost")

        return {}, json.dumps(metadata)

    async def handle_async(self, *args, **kwargs):
        return self.handle(*args, **kwargs)


@pytest.fixture
def fs_and_endpoint():
    fs = GCSFileSystem(token="anon", skip_instance_cache=True)
    endpoint = FakeGenerationEndpoint()
    fs._call = endpoint.handle_async
    fs.call = endpoint.handle
    with mock.patch(
        "gcsfs.core._http_initiate_upload",
        new=mock.AsyncMock(
            side_effect=lambda fs_, bucket, key, *a, **kw: endpoint.initiate(**kw)
        ),
    ):
        yield fs, endpoint


def _open_write(fs, condition=7, data=b"first-update"):
    handle = fs.open(
        "bucket/conditional/object",
        "wb",
        if_generation_match=condition,
        consistency="none",
    )
    handle.write(data)
    return handle


def test_lost_response_after_commit_is_confirmed_without_second_write(fs_and_endpoint):
    fs, endpoint = fs_and_endpoint
    endpoint.lose_after_commit = True

    handle = _open_write(fs)
    with pytest.raises(UnconfirmedCommitError) as exc_info:
        handle.commit()

    unknown = exc_info.value.result
    assert unknown.state == CommitStatus.UNCONFIRMED
    assert unknown.condition_generation == 7
    assert unknown.location.endswith("/session-1")
    assert endpoint.write_count == 1

    # Another writer independently observed generation 8 and got approval for it.
    second = endpoint.approved_commit(b"second-update", expected_generation=8)
    assert second["generation"] == "9"

    confirmed = handle.confirm_commit()
    assert confirmed.state == CommitStatus.COMMITTED
    assert confirmed.committed is True
    assert confirmed.formally_committed is True
    assert confirmed.ever_committed is True
    assert confirmed.generation == "8"
    assert endpoint.write_count == 2
    assert endpoint.contents == b"second-update"

    # Recovery must not replay a confirmed original commit.
    recovered = handle.recover_commit()
    assert recovered.committed is True
    assert endpoint.write_count == 2
    assert endpoint.contents == b"second-update"


def test_unaccepted_commit_retry_conflicts_with_newer_writer(fs_and_endpoint):
    fs, endpoint = fs_and_endpoint
    endpoint.lose_after_commit = False

    handle = _open_write(fs)
    with pytest.raises(UnconfirmedCommitError):
        handle.commit()
    assert endpoint.write_count == 0

    endpoint.approved_commit(b"second-update", expected_generation=7)
    assert endpoint.generation == 8

    with pytest.raises(GenerationMismatchError) as exc_info:
        handle.recover_commit()

    # Recovery kept the original approval; it did not rebuild condition=8.
    assert exc_info.value.generation == 7
    assert handle.commit_result.state == CommitStatus.CONFLICT
    assert endpoint.write_count == 1
    assert endpoint.contents == b"second-update"

    replay_conditions = [
        request["ifGenerationMatch"]
        for request in endpoint.requests
        if request["path"].endswith("/session-1")
        and request["ifGenerationMatch"] is not None
    ]
    assert replay_conditions and set(replay_conditions) == {"7"}
    handle.discard()


def test_unaccepted_commit_can_safely_retry_with_original_generation():
    fs = GCSFileSystem(token="anon", skip_instance_cache=True)
    endpoint = FakeGenerationEndpoint(lose_after_commit=False)
    fs._call = endpoint.handle_async
    fs.call = endpoint.handle

    with mock.patch(
        "gcsfs.core._http_initiate_upload",
        new=mock.AsyncMock(
            side_effect=lambda fs_, bucket, key, *a, **kw: endpoint.initiate(**kw)
        ),
    ):
        handle = _open_write(fs, data=b"retryable-update")
        with pytest.raises(UnconfirmedCommitError):
            handle.commit()

        recovered = handle.recover_commit()

    assert recovered.state == CommitStatus.COMMITTED
    assert recovered.generation == "8"
    assert endpoint.write_count == 1
    assert endpoint.contents == b"retryable-update"
    conditions = [
        request["ifGenerationMatch"]
        for request in endpoint.requests
        if request["ifGenerationMatch"] is not None
    ]
    assert conditions and all(value == "7" for value in conditions)


def test_confirmation_transport_failure_remains_pending():
    fs = GCSFileSystem(token="anon", skip_instance_cache=True)

    async def unavailable(*args, **kwargs):
        raise aiohttp.ServerDisconnectedError("status query lost")

    fs._call = unavailable
    result = UnconfirmedCommitError(
        type(
            "Token",
            (),
            {
                "fs": fs,
                "path": "bucket/object",
                "location": "https://fake.invalid/upload/session-x",
                "if_generation_match": 11,
            },
        )()
    ).result

    confirmed = result.confirm(fs)
    assert confirmed.state == CommitStatus.UNCONFIRMED
    assert confirmed.condition_generation == 11
    with pytest.raises(UnconfirmedCommitError):
        confirmed.raise_for_state()


def test_pipe_file_lost_response_and_recovery_keeps_original_condition():
    fs = GCSFileSystem(token="anon", skip_instance_cache=True)
    endpoint = FakeGenerationEndpoint(lose_after_commit=True)
    fs._call = endpoint.handle_async

    with mock.patch(
        "gcsfs.core.initiate_upload",
        new=mock.AsyncMock(
            side_effect=lambda *args, **kwargs: endpoint.initiate(
                kwargs.get("if_generation_match")
            )
        ),
    ):
        with pytest.raises(UnconfirmedCommitError) as exc_info:
            fs.pipe_file(
                "bucket/object",
                b"pipe-update",
                chunksize=11,
                if_generation_match=7,
                consistency="none",
            )

        token = exc_info.value.result
        assert token.condition_generation == 7
        assert callable(token.retry_callback)
        assert endpoint.write_count == 1

        endpoint.approved_commit(b"second-update", expected_generation=8)
        confirmed = token.confirm(fs)
        assert confirmed.committed is True
        assert confirmed.generation == "8"
        assert endpoint.write_count == 2
        assert endpoint.contents == b"second-update"
