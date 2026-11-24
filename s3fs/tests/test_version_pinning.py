import asyncio
from io import BytesIO

import pytest
from botocore.exceptions import ClientError

from s3fs import S3FileSystem
from s3fs.utils import FileExpired, VersionUnavailable

BUCKET = "bucket"
KEY = "key"
PATH = f"{BUCKET}/{KEY}"


class Body:
    def __init__(self, data, version=None):
        self.stream = BytesIO(data)
        self.closed = False
        self.version = version

    async def read(self, size=-1):
        return self.stream.read(size)

    def close(self):
        self.closed = True
        self.stream.close()


def _etag(version):
    return f'"{version}"'


class MemoryVersionedClient:
    """Small in-memory S3 stand-in that records the version of every request.

    ``default`` is the bucket's current default version and can be changed at
    any point.  ``fail_once`` lists byte ranges that raise one transient
    transfer timeout before succeeding.
    """

    def __init__(self, data, default, fail_once=(), fail_always=()):
        self.data = dict(data)
        self.default = default
        self.fail_once = list(fail_once)
        self.fail_always = set(fail_always)
        self.failed_ranges = set()
        self.calls = []

    def versions_requested(self):
        return [c["version"] for c in self.calls if c["method"] == "get_object"]

    def _resolve(self, version):
        version = version or self.default
        if version not in self.data:
            raise ClientError(
                {
                    "Error": {
                        "Code": "NoSuchVersion",
                        "Message": f"version {version} no longer exists",
                    }
                },
                "GetObject",
            )
        return version, self.data[version]

    async def __call__(self, method, *args, **kwargs):
        params = {}
        for arg in args:
            if isinstance(arg, dict):
                params.update(arg)
        params.update(kwargs)

        version = params.get("VersionId")
        byte_range = params.get("Range")
        self.calls.append(
            {"method": method, "version": version, "range": byte_range}
        )

        if method == "head_object":
            resolved, content = self._resolve(version)
            return {
                "ContentLength": len(content),
                "VersionId": resolved,
                "ETag": _etag(resolved),
                "LastModified": "",
                "ContentType": "binary/octet-stream",
            }

        if method == "get_object":
            if byte_range in self.fail_always:
                raise TimeoutError("simulated transfer timeout")
            if byte_range in self.fail_once and byte_range not in self.failed_ranges:
                self.failed_ranges.add(byte_range)
                raise TimeoutError("simulated transfer timeout")

            resolved, content = self._resolve(version)
            if "IfMatch" in params and params["IfMatch"] != _etag(resolved):
                raise ClientError(
                    {
                        "Error": {
                            "Code": "PreconditionFailed",
                            "Message": "pre-conditions failed",
                        }
                    },
                    "GetObject",
                )

            if byte_range:
                start, _, end = byte_range.removeprefix("bytes=").partition("-")
                start = int(start)
                end = int(end) + 1 if end else len(content)
                content = content[start:end]

            return {
                "Body": Body(content, resolved),
                "ContentLength": len(content),
                "VersionId": resolved,
                "ETag": _etag(resolved),
                "ResponseMetadata": {
                    "HTTPHeaders": {"content-length": str(len(content))}
                },
            }

        raise AssertionError(f"unexpected method {method}")


def make_fs(**kwargs):
    fs = S3FileSystem(version_aware=True, skip_instance_cache=True, **kwargs)
    fs.invalidate_cache()
    return fs


def test_sync_open_uses_authorized_version_and_retries_segment():
    client = MemoryVersionedClient(
        {"v1": b"AAAA-BBBB-CCCC", "v2": b"1111-2222-3333"},
        default="v1",
        fail_once=["bytes=5-9"],
    )
    fs = make_fs()
    fs._call_s3 = client

    with fs.open(PATH, "rb", version_id="v1", block_size=5, cache_type="none") as f:
        assert f.version_id == "v1"
        assert f.seek(0) == 0
        assert f.read(5) == b"AAAA-"
        client.default = "v2"  # another writer publishes a new default version
        assert f.read(5) == b"BBBB-"  # first attempt times out, retry succeeds
        assert f.read(5) == b"CCCC"

    assert client.failed_ranges == {"bytes=5-9"}
    # HEAD bound v1, then each 5-byte segment was fetched from v1; the timed-out
    # second segment was retried against the same version, not the new default.
    assert client.versions_requested() == ["v1", "v1", "v1", "v1"]
    assert [c["range"] for c in client.calls if c["method"] == "get_object"] == [
        "bytes=0-4",
        "bytes=5-9",
        "bytes=5-9",
        "bytes=10-14",
    ]


def test_async_open_uses_authorized_version_and_retries_segment():
    client = MemoryVersionedClient(
        {"v1": b"AAAA-BBBB-CCCC", "v2": b"1111-2222-3333"},
        default="v1",
        fail_once=["bytes=5-9"],
    )
    fs = make_fs(asynchronous=True)
    fs._call_s3 = client

    chunks = []

    async def scenario():
        f = await fs.open_async(PATH, "rb", version_id="v1")
        try:
            assert f.version_id == "v1"
            chunks.append(await f.read(5))
            client.default = "v2"
            chunks.append(await f.read(5))
            chunks.append(await f.read(5))
        finally:
            await f.close()

    asyncio.run(scenario())

    assert b"".join(chunks) == b"AAAA-BBBB-CCCC"
    assert client.failed_ranges == {"bytes=5-9"}
    assert client.versions_requested() == ["v1", "v1", "v1", "v1"]
    assert [c["range"] for c in client.calls if c["method"] == "get_object"] == [
        "bytes=0-4",
        "bytes=5-9",
        "bytes=5-9",
        "bytes=10-13",
    ]


def test_async_open_pins_default_version_at_open_time():
    client = MemoryVersionedClient(
        {"v1": b"old-default", "v2": b"new-default"}, default="v1"
    )
    fs = make_fs(asynchronous=True)
    fs._call_s3 = client

    async def scenario():
        f = await fs.open_async(PATH)
        try:
            assert f.version_id == "v1"
            first = await f.read(3)
            client.default = "v2"
            rest = await f.read()
            return first + rest
        finally:
            await f.close()

    assert asyncio.run(scenario()) == b"old-default"
    # HEAD resolved the default once, every segment then names that version.
    assert client.versions_requested() == ["v1", "v1"]


def test_concurrent_range_read_uses_authorized_version():
    client = MemoryVersionedClient(
        {"v1": b"AAAA-BBBB-CCCC", "v2": b"1111-2222-3333"},
        default="v1",
        fail_once=["bytes=5-9"],
    )
    fs = make_fs(asynchronous=True)
    fs._call_s3 = client

    async def scenario():
        return await fs._cat_file(
            PATH, version_id="v1", chunksize=5, max_concurrency=2
        )

    client.default = "v2"
    assert asyncio.run(scenario()) == b"AAAA-BBBB-CCCC"
    assert client.failed_ranges == {"bytes=5-9"}
    assert set(client.versions_requested()) == {"v1"}


def test_concurrent_range_read_pins_default_version():
    client = MemoryVersionedClient(
        {"v1": b"AAAA-BBBB-CCCC", "v2": b"1111-2222-3333"}, default="v1"
    )
    fs = make_fs(asynchronous=True)
    fs._call_s3 = client

    async def scenario():
        result = await fs._cat_file(PATH, chunksize=5, max_concurrency=2)
        return result

    # HEAD resolves v1 before any segments are fetched; a replacement default
    # must not leak into the parallel range requests.
    original_call = client.__call__

    async def swap_after_head(method, *args, **kwargs):
        result = await original_call(method, *args, **kwargs)
        if method == "head_object":
            client.default = "v2"
        return result

    fs._call_s3 = swap_after_head
    assert asyncio.run(scenario()) == b"AAAA-BBBB-CCCC"
    assert set(client.versions_requested()) == {"v1"}


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_removed_version_ends_the_read(mode):
    client = MemoryVersionedClient({"v1": b"AAAA-BBBB-CCCC"}, default="v1")
    fs = make_fs(asynchronous=True) if mode == "async" else make_fs()
    fs._call_s3 = client

    if mode == "sync":
        with fs.open(PATH, "rb", version_id="v1", block_size=5, cache_type="none") as f:
            assert f.read(5) == b"AAAA-"
            del client.data["v1"]
            client.default = "v2"
            with pytest.raises(VersionUnavailable) as exc:
                f.read(5)
    else:

        async def scenario():
            f = await fs.open_async(PATH, "rb", version_id="v1")
            try:
                assert await f.read(5) == b"AAAA-"
                del client.data["v1"]
                client.default = "v2"
                with pytest.raises(VersionUnavailable) as exc:
                    await f.read(5)
                return exc
            finally:
                await f.close()

        exc = asyncio.run(scenario())

    assert isinstance(exc.value, FileNotFoundError)
    assert isinstance(exc.value, FileExpired)
    assert not isinstance(exc.value, TimeoutError)
    assert exc.value.version_id == "v1"
    # Still asked for the authorized version, not the replacement default.
    assert client.versions_requested()[-1] == "v1"


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_transient_timeout_stays_a_timeout(mode):
    client = MemoryVersionedClient(
        {"v1": b"AAAA-BBBB-CCCC"}, default="v1"
    )
    fs = (
        make_fs(asynchronous=True, retries=2)
        if mode == "async"
        else make_fs(retries=2)
    )
    fs._call_s3 = client

    if mode == "sync":
        with fs.open(PATH, "rb", version_id="v1", block_size=5, cache_type="none") as f:
            assert f.read(5) == b"AAAA-"
            client.fail_always.add("bytes=5-9")
            with pytest.raises(TimeoutError) as exc:
                f.read(5)
    else:

        async def scenario():
            f = await fs.open_async(PATH, "rb", version_id="v1")
            try:
                assert await f.read(5) == b"AAAA-"
                client.fail_always.add("bytes=5-9")
                with pytest.raises(TimeoutError) as exc:
                    await f.read(5)
                return exc
            finally:
                await f.close()

        exc = asyncio.run(scenario())

    assert not isinstance(exc.value, VersionUnavailable)
    assert set(client.versions_requested()) == {"v1"}


def test_unversioned_legacy_entries_keep_working():
    client = MemoryVersionedClient({"v1": b"hello legacy"}, default="v1")
    fs = S3FileSystem(skip_instance_cache=True)
    fs._call_s3 = client

    with fs.open(PATH, "rb") as f:
        assert f.version_id is None
        assert f.read() == b"hello legacy"

    async def scenario():
        afs = S3FileSystem(asynchronous=True, skip_instance_cache=True)
        afs._call_s3 = client
        f = await afs.open_async(PATH)
        try:
            return await f.read()
        finally:
            await f.close()

    assert asyncio.run(scenario()) == b"hello legacy"
    assert all(c["version"] is None for c in client.calls)



def test_missing_bucket_is_not_reported_as_version_gone():
    fs = make_fs(asynchronous=True)

    async def call(method, *args, **kwargs):
        raise ClientError(
            {"Error": {"Code": "NoSuchBucket", "Message": "bucket missing"}},
            "GetObject",
        )

    fs._call_s3 = call

    async def scenario():
        return await fs._cat_file(PATH, version_id="v1", start=0, end=4)

    with pytest.raises(FileNotFoundError) as exc:
        asyncio.run(scenario())
    assert not isinstance(exc.value, VersionUnavailable)


def test_removed_version_ends_a_plain_cat():
    client = MemoryVersionedClient({"v1": b"AAAA-BBBB"}, default="v1")
    fs = make_fs(asynchronous=True)
    original = client.__call__

    async def remove_before_read(method, *args, **kwargs):
        if method == "get_object":
            del client.data["v1"]
            client.default = "v2"
        return await original(method, *args, **kwargs)

    fs._call_s3 = remove_before_read

    async def scenario():
        return await fs._cat_file(PATH, version_id="v1", start=0, end=4)

    with pytest.raises(VersionUnavailable) as exc:
        asyncio.run(scenario())
    assert exc.value.version_id == "v1"
    assert exc.value.filename == PATH


def test_reopen_after_default_change_pins_the_new_version():
    client = MemoryVersionedClient(
        {"v1": b"old-version", "v2": b"newer-version"}, default="v1"
    )
    fs = make_fs(asynchronous=True)
    fs._call_s3 = client

    async def read_default():
        f = await fs.open_async(PATH)
        try:
            return f.version_id, await f.read()
        finally:
            await f.close()

    first = asyncio.run(read_default())
    client.default = "v2"  # replacement published between the two reads
    second = asyncio.run(read_default())

    assert first == ("v1", b"old-version")
    assert second == ("v2", b"newer-version")
    # Each read named one version: HEAD resolved it, the body used that same id.
    assert client.versions_requested() == ["v1", "v2"]
