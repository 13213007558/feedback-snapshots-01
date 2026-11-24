"""Offline regressions for transactional (``autocommit=False``) writes.

These tests never open a socket and never depend on ``moto``.  They drive the
real :class:`~s3fs.core.S3FileSystem` / :class:`~s3fs.core.S3File` code paths
against an in-memory, scriptable S3 endpoint (:class:`FakeS3`).

The property under test is *read-your-previously-committed-data*: an uploader
may stage bytes (multipart uploads and their parts) into the same bucket while
a transaction is open, but consumers looking through the directory listing,
``info``/``head_object`` or a direct ``get_object`` read must only ever observe
objects that were already delivered, or newly committed objects.  A cancelled
writer may only abort its own remote upload job.
"""

import datetime
import hashlib
import io
import itertools

import botocore.session
import pytest
from botocore.exceptions import ClientError

from s3fs.core import S3FileSystem
from s3fs.utils import ParamKwargsHelper

BUCKET = "test-bucket"
KEY = "ledger/state.bin"
PATH = f"{BUCKET}/{KEY}"
PARENT = f"{BUCKET}/ledger"
MIN_PART = 5 * 2**20  # S3's smallest legal multipart part
OLD_DATA = b"committed-v0"
NEW_DATA = b"committed-v1"
CANCEL_DATA = b"Z" * MIN_PART
NOW = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)


def s3_client_error(code, message, operation, status=404):
    return ClientError(
        {
            "Error": {"Code": code, "Message": message},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
        operation,
    )


class FakeBody:
    """Minimal async stream matching the surface used by ``_cat_file``."""

    def __init__(self, data):
        self._buffer = io.BytesIO(data)

    async def read(self, amount=-1):
        return self._buffer.read(amount)

    def close(self):
        self._buffer.close()


class FakeS3:
    """Scriptable, in-memory S3 endpoint covering the transactional API.

    State is split the way S3 itself separates it:

    * ``objects`` holds only *committed* objects, versioned so the fake can
      prove a staged upload never overwrites or hides the live object;
    * ``uploads`` holds in-progress multipart jobs and the part bytes that the
      uploader has already pushed, so tests can assert that partial data is
      held server-side yet invisible to readers.

    ``fail_once`` arms a one-shot, retryable ``ClientError`` for an API method,
    which lets the tests exercise s3fs's built-in retry loop deterministically.
    """

    def __init__(self, versioned=False):
        self.versioned = versioned
        self.objects = {}
        self.uploads = {}
        self.calls = []
        self._counter = itertools.count(1)
        self._fail_once = {}
        # The real botocore service description gives ParamKwargsHelper the
        # operation models it uses to filter kwargs; no network is involved.
        service_model = botocore.session.Session().get_service_model("s3")

        class _Meta:
            pass

        self.meta = _Meta()
        self.meta.service_model = service_model

    def arm_failure(self, method, code="SlowDown", message="retry me", status=503):
        self._fail_once[method] = s3_client_error(
            code, message, method.replace("_", " ").title().replace(" ", ""), status
        )

    def _record(self, method, **kwargs):
        self.calls.append((method, kwargs))
        failure = self._fail_once.pop(method, None)
        if failure is not None:
            raise failure

    @staticmethod
    def _etag(data):
        return '"%s"' % hashlib.md5(data).hexdigest()

    def _select_version(self, bucket, key, version_id):
        versions = self.objects.get((bucket, key))
        if not versions:
            return None
        if version_id is None:
            return versions[-1]
        return next(
            (version for version in versions if version["VersionId"] == version_id),
            None,
        )

    def _commit(self, bucket, key, data):
        version_id = (
            "version-%d" % next(self._counter) if self.versioned else "null"
        )
        self.objects.setdefault((bucket, key), []).append(
            {
                "data": data,
                "VersionId": version_id,
                "ETag": self._etag(data),
                "LastModified": NOW,
                "Size": len(data),
            }
        )
        return version_id

    async def create_multipart_upload(self, *, Bucket, Key, **kwargs):
        self._record("create_multipart_upload", Bucket=Bucket, Key=Key)
        upload_id = "upload-%d" % next(self._counter)
        self.uploads[upload_id] = {"bucket": Bucket, "key": Key, "parts": {}}
        return {"UploadId": upload_id, "Bucket": Bucket, "Key": Key}

    async def upload_part(
        self, *, Bucket, Key, PartNumber, UploadId, Body, **kwargs
    ):
        data = Body if isinstance(Body, bytes) else io.BytesIO(Body).read()
        self._record(
            "upload_part",
            Bucket=Bucket,
            Key=Key,
            PartNumber=PartNumber,
            UploadId=UploadId,
            bytes=len(data),
        )
        upload = self.uploads.get(UploadId)
        if upload is None:
            raise s3_client_error(
                "NoSuchUpload", "upload is gone", "UploadPart"
            )
        upload["parts"][PartNumber] = data
        return {"ETag": self._etag(data)}

    async def complete_multipart_upload(
        self, *, Bucket, Key, UploadId, MultipartUpload, **kwargs
    ):
        self._record(
            "complete_multipart_upload",
            Bucket=Bucket,
            Key=Key,
            UploadId=UploadId,
        )
        upload = self.uploads.get(UploadId)
        if upload is None:
            raise s3_client_error(
                "NoSuchUpload", "upload is gone", "CompleteMultipartUpload"
            )
        ordered = sorted(MultipartUpload["Parts"], key=lambda part: part["PartNumber"])
        data = b"".join(upload["parts"][part["PartNumber"]] for part in ordered)
        version_id = self._commit(Bucket, Key, data)
        del self.uploads[UploadId]
        return {
            "Location": f"/{Bucket}/{Key}",
            "Bucket": Bucket,
            "Key": Key,
            "ETag": self._etag(data),
            "VersionId": version_id,
        }

    async def abort_multipart_upload(self, *, Bucket, Key, UploadId, **kwargs):
        self._record(
            "abort_multipart_upload",
            Bucket=Bucket,
            Key=Key,
            UploadId=UploadId,
        )
        if UploadId not in self.uploads:
            raise s3_client_error(
                "NoSuchUpload", "upload is gone", "AbortMultipartUpload"
            )
        del self.uploads[UploadId]
        return {}

    async def list_multipart_uploads(self, *, Bucket, **kwargs):
        self._record("list_multipart_uploads", Bucket=Bucket)
        uploads = [
            {
                "Key": upload["key"],
                "UploadId": upload_id,
                "Initiated": NOW,
            }
            for upload_id, upload in self.uploads.items()
            if upload["bucket"] == Bucket
        ]
        return {"Uploads": uploads, "IsTruncated": False}

    async def put_object(self, *, Bucket, Key, Body, **kwargs):
        self._record("put_object", Bucket=Bucket, Key=Key)
        data = Body if isinstance(Body, bytes) else io.BytesIO(Body).read()
        return {
            "ETag": self._etag(data),
            "VersionId": self._commit(Bucket, Key, data),
        }

    async def head_object(self, *, Bucket, Key, VersionId=None, **kwargs):
        self._record(
            "head_object", Bucket=Bucket, Key=Key, VersionId=VersionId
        )
        version = self._select_version(Bucket, Key, VersionId)
        if version is None:
            raise s3_client_error("404", "Not Found", "HeadObject")
        return {
            "ContentLength": version["Size"],
            "ETag": version["ETag"],
            "LastModified": version["LastModified"],
            "VersionId": version["VersionId"],
            "ContentType": "binary/octet-stream",
            "StorageClass": "STANDARD",
            "AcceptRanges": "bytes",
        }

    async def get_object(self, *, Bucket, Key, VersionId=None, Range=None, **kwargs):
        self._record(
            "get_object",
            Bucket=Bucket,
            Key=Key,
            VersionId=VersionId,
            Range=Range,
        )
        version = self._select_version(Bucket, Key, VersionId)
        if version is None:
            raise s3_client_error("NoSuchKey", "Not Found", "GetObject")
        data = version["data"]
        if Range:
            start, end = Range.replace("bytes=", "").split("-")
            data = data[int(start) : int(end) + 1]
        return {
            "Body": FakeBody(data),
            "ContentLength": len(data),
            "ETag": version["ETag"],
            "VersionId": version["VersionId"],
            "LastModified": version["LastModified"],
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }

    async def list_objects_v2(self, *, Bucket, Prefix="", Delimiter="/", **kwargs):
        self._record("list_objects_v2", Bucket=Bucket, Prefix=Prefix)
        contents = []
        common_prefixes = set()
        for (bucket, key), versions in self.objects.items():
            if bucket != Bucket or not key.startswith(Prefix):
                continue
            latest = versions[-1]
            remainder = key[len(Prefix) :]
            if Delimiter and Delimiter in remainder:
                common_prefixes.add(Prefix + remainder.split(Delimiter)[0] + Delimiter)
            else:
                contents.append(
                    {
                        "Key": key,
                        "Size": latest["Size"],
                        "ETag": latest["ETag"],
                        "LastModified": latest["LastModified"],
                        "VersionId": latest["VersionId"],
                        "StorageClass": "STANDARD",
                    }
                )
        return {
            "Contents": contents,
            "CommonPrefixes": [
                {"Prefix": prefix} for prefix in sorted(common_prefixes)
            ],
            "IsTruncated": False,
            "Name": Bucket,
            "Prefix": Prefix,
            "KeyCount": len(contents),
        }

    async def list_object_versions(self, *, Bucket, Prefix="", Delimiter="", **kwargs):
        self._record("list_object_versions", Bucket=Bucket, Prefix=Prefix)
        versions_out = []
        for (bucket, key), versions in self.objects.items():
            if bucket != Bucket or not key.startswith(Prefix):
                continue
            latest_id = versions[-1]["VersionId"]
            for version in versions:
                versions_out.append(
                    {
                        "Key": key,
                        "VersionId": version["VersionId"],
                        "Size": version["Size"],
                        "ETag": version["ETag"],
                        "LastModified": version["LastModified"],
                        "IsLatest": version["VersionId"] == latest_id,
                        "StorageClass": "STANDARD",
                    }
                )
        return {
            "Versions": versions_out,
            "CommonPrefixes": [],
            "IsTruncated": False,
            "Name": Bucket,
            "Prefix": Prefix,
        }


@pytest.fixture
def fake_s3():
    return FakeS3(versioned=True)


def make_filesystem(fake, version_aware=True):
    """Build an S3FileSystem wired to the in-memory endpoint, no I/O at all."""
    fs = S3FileSystem(anon=False, version_aware=version_aware)
    fs._s3 = fake
    fs._kwargs_helper = ParamKwargsHelper(fake)
    return fs


def directory_entry(fs, path=PATH):
    entries = fs.ls(PARENT, detail=True, refresh=True)
    matches = [entry for entry in entries if entry["name"] == path]
    assert matches, f"{path} missing from fresh directory listing"
    return matches[0]


def assert_only_old_version_visible(fs, old_version):
    """The three read channels must all resolve to the previously committed object."""
    # direct object read (get_object)
    assert fs.cat_file(PATH) == OLD_DATA
    # metadata read (head_object), including its returned version
    assert fs.info(PATH, refresh=True)["VersionId"] == old_version
    # directory read (list_objects / list_object_versions), fresh from the server
    entry = directory_entry(fs)
    assert entry["VersionId"] == old_version
    # the old version itself stays addressable by version id
    assert fs.cat_file(f"{PATH}?versionId={old_version}") == OLD_DATA


def test_interleaved_writers_keep_partial_upload_invisible(fake_s3):
    fs = make_filesystem(fake_s3)
    fs.pipe_file(PATH, OLD_DATA)
    old_version = fs.info(PATH, refresh=True)["VersionId"]

    # Pre-warm the directory cache: a stale-but-safe listing must not be allowed
    # to leak an uncommitted key, and is also what most readers hit first.
    assert PATH in fs.ls(PARENT)
    assert PARENT in fs.dircache

    # Writer A opens a manual transaction and pushes one full part, then stalls
    # ("upload to half, then cancel").  The fake endpoint really does hold the
    # part bytes in an open multipart upload.
    cancelled = fs.open(PATH, "wb", autocommit=False, block_size=MIN_PART)
    cancelled.write(CANCEL_DATA)
    cancelled_upload = cancelled.mpu["UploadId"]
    assert fake_s3.uploads[cancelled_upload]["parts"]
    assert sum(
        call[0] == "upload_part"
        for call in fake_s3.calls
        if call[1].get("UploadId") == cancelled_upload
    ) == 1

    # Even though the fake has swallowed A's part bytes, the live object is
    # unchanged through the directory, info and direct-read channels.
    assert_only_old_version_visible(fs, old_version)
    pending = fs.list_multipart_uploads(BUCKET)
    assert any(upload["UploadId"] == cancelled_upload for upload in pending)

    # Writer B interleaves on the same key and commits a brand new version.
    committed = fs.open(PATH, "wb", autocommit=False, block_size=MIN_PART)
    committed.write(NEW_DATA)
    committed.flush(force=True)
    committed_upload = committed.mpu["UploadId"]
    assert committed_upload != cancelled_upload
    committed.commit()
    new_version = fs.info(PATH, refresh=True)["VersionId"]
    assert new_version != old_version

    # Before A is cancelled the old object must still be readable by version,
    # while the current version is B's commit.
    assert fs.cat_file(f"{PATH}?versionId={old_version}") == OLD_DATA
    assert fs.cat_file(PATH) == NEW_DATA

    # Cancelling A may only tear down A's own remote job - never B's.
    cancelled.close()
    cancelled.discard()
    aborted = [
        call[1]["UploadId"]
        for call in fake_s3.calls
        if call[0] == "abort_multipart_upload"
    ]
    assert aborted == [cancelled_upload]
    assert cancelled_upload not in fake_s3.uploads
    assert committed_upload not in fake_s3.uploads  # removed when B committed
    assert not fs.list_multipart_uploads(BUCKET)

    # Post-commit visibility through every channel.
    assert fs.cat_file(PATH) == NEW_DATA
    assert fs.info(PATH, refresh=True)["VersionId"] == new_version
    assert directory_entry(fs)["VersionId"] == new_version
    assert fs.cat_file(f"{PATH}?versionId={old_version}") == OLD_DATA


def test_warmed_directory_cache_does_not_publish_uncommitted_key(fake_s3):
    fs = make_filesystem(fake_s3)
    fs.pipe_file(PATH, OLD_DATA)
    old_version = fs.info(PATH, refresh=True)["VersionId"]

    # Warm the cache on both the bucket root and the parent prefix.
    fs.ls(BUCKET)
    fs.ls(PARENT)
    assert fs.dircache[PARENT]

    staged = fs.open(PATH, "wb", autocommit=False, block_size=MIN_PART)
    staged.write(CANCEL_DATA)
    staged_upload = staged.mpu["UploadId"]

    # Cached listing and a force-refreshed listing both still show only the old,
    # committed version; the open upload is not a directory entry.
    cached_names = fs.ls(PARENT)
    assert PATH in cached_names
    cached_entry = [
        entry
        for entry in fs.dircache[PARENT]
        if entry["name"] == PATH
    ][0]
    assert cached_entry["VersionId"] == old_version

    fresh_entry = directory_entry(fs)
    assert fresh_entry["VersionId"] == old_version

    # Direct reads and metadata likewise ignore the staged bytes.
    assert fs.cat_file(PATH) == OLD_DATA
    with fs.open(PATH, "rb") as handle:
        assert handle.read() == OLD_DATA
    assert fs.info(PATH)["VersionId"] == old_version

    staged.close()
    staged.discard()
    assert [
        call[1]["UploadId"]
        for call in fake_s3.calls
        if call[0] == "abort_multipart_upload"
    ] == [staged_upload]
    # After discard, the object is still the original committed one.
    assert fs.cat_file(PATH) == OLD_DATA


def test_cancelled_transaction_only_aborts_its_own_upload(fake_s3):
    fs = make_filesystem(fake_s3)
    fs.pipe_file(PATH, OLD_DATA)

    first = fs.open(PATH, "wb", autocommit=False, block_size=MIN_PART)
    second = fs.open(PATH, "wb", autocommit=False, block_size=MIN_PART)
    first.write(CANCEL_DATA)
    second.write(b"other-staged-bytes")
    second.flush(force=True)  # materialise the second remote multipart job
    first_id = first.mpu["UploadId"]
    second_id = second.mpu["UploadId"]
    assert set(fake_s3.uploads) == {first_id, second_id}

    first.close()
    first.discard()

    assert first_id not in fake_s3.uploads
    assert second_id in fake_s3.uploads  # the sibling job is untouched
    assert [
        call[1]["UploadId"]
        for call in fake_s3.calls
        if call[0] == "abort_multipart_upload"
    ] == [first_id]

    # The surviving writer can still commit cleanly.
    second.commit()
    assert fs.cat_file(PATH) == b"other-staged-bytes"
    assert not fake_s3.uploads


def test_transient_upload_part_failure_is_retried_without_publishing(fake_s3):
    fs = make_filesystem(fake_s3)
    fs.pipe_file(PATH, OLD_DATA)
    old_version = fs.info(PATH, refresh=True)["VersionId"]

    writer = fs.open(PATH, "wb", autocommit=False, block_size=MIN_PART)
    # Writing a full block flushes inside write(), so arm the failure first:
    # the first upload_part attempt fails with a retryable SlowDown and the
    # built-in retry loop must succeed on the second attempt.
    fake_s3.arm_failure("upload_part")
    writer.write(CANCEL_DATA)

    part_attempts = [
        call
        for call in fake_s3.calls
        if call[0] == "upload_part"
        and call[1]["UploadId"] == writer.mpu["UploadId"]
    ]
    assert len(part_attempts) == 2
    assert len(writer.parts) == 1
    # Retried staging still must not change the visible object.
    assert fs.cat_file(PATH) == OLD_DATA
    assert fs.info(PATH, refresh=True)["VersionId"] == old_version

    writer.close()
    writer.discard()


def test_transient_info_failure_is_retried_and_returns_committed_version(fake_s3):
    fs = make_filesystem(fake_s3)
    fs.pipe_file(PATH, OLD_DATA)
    old_version = fs.info(PATH, refresh=True)["VersionId"]

    writer = fs.open(PATH, "wb", autocommit=False, block_size=MIN_PART)
    writer.write(CANCEL_DATA)

    # One SlowDown on head_object, then the retry must return the live (old)
    # version rather than the staged upload.
    before = [call for call in fake_s3.calls if call[0] == "head_object"]
    fake_s3.arm_failure("head_object")
    info = fs.info(PATH, refresh=True)
    after = [call for call in fake_s3.calls if call[0] == "head_object"]
    assert len(after) - len(before) == 2
    assert info["VersionId"] == old_version

    # Same guarantee through a refreshed directory listing.
    before_ls = [call for call in fake_s3.calls if call[0] == "list_object_versions"]
    fake_s3.arm_failure("list_object_versions")
    entry = directory_entry(fs)
    after_ls = [
        call for call in fake_s3.calls if call[0] == "list_object_versions"
    ]
    assert len(after_ls) - len(before_ls) == 2
    assert entry["VersionId"] == old_version

    writer.close()
    writer.discard()


def test_non_versioned_bucket_never_exposes_staged_parts(fake_s3):
    fake = FakeS3(versioned=False)
    fs = make_filesystem(fake_s3, version_aware=False)
    fs.pipe_file(PATH, OLD_DATA)

    writer = fs.open(PATH, "wb", autocommit=False, block_size=MIN_PART)
    writer.write(CANCEL_DATA)
    upload_id = writer.mpu["UploadId"]
    assert fake_s3.uploads[upload_id]["parts"]

    # Without version awareness the same isolation holds across all channels.
    assert fs.cat_file(PATH) == OLD_DATA
    assert fs.info(PATH, refresh=True)["size"] == len(OLD_DATA)
    names = fs.ls(PARENT, refresh=True)
    assert PATH in names
    assert [
        name for name in names if name != PATH
    ] == []

    writer.close()
    writer.discard()
    assert not fake_s3.uploads
    assert fs.cat_file(PATH) == OLD_DATA

    # A committed transaction then becomes the new visible object.
    committed = fs.open(PATH, "wb", autocommit=False, block_size=MIN_PART)
    committed.write(NEW_DATA)
    committed.flush(force=True)
    committed.commit()
    assert fs.cat_file(PATH) == NEW_DATA
    assert fs.info(PATH, refresh=True)["size"] == len(NEW_DATA)


def test_partial_data_is_held_remotely_but_never_listed(fake_s3):
    fs = make_filesystem(fake_s3)
    fs.pipe_file(PATH, OLD_DATA)

    writer = fs.open(PATH, "wb", autocommit=False, block_size=MIN_PART)
    writer.write(CANCEL_DATA)
    upload_id = writer.mpu["UploadId"]

    # The fake uploader really has received part bytes ...
    staged = fake_s3.uploads[upload_id]
    assert staged and staged["parts"][1] == CANCEL_DATA
    # ... yet those bytes are not an object and cannot be read or listed.
    with pytest.raises(FileNotFoundError):
        fs.info(f"{BUCKET}/does-not-exist", refresh=True)
    listing = fs.ls(PARENT, detail=True, refresh=True)
    assert {entry["name"] for entry in listing} == {PATH}
    assert fs.cat_file(PATH) == OLD_DATA

    # And aborting drops the remote job without touching committed objects.
    writer.close()
    writer.discard()
    assert upload_id not in fake_s3.uploads
    assert fs.cat_file(PATH) == OLD_DATA
