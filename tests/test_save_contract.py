"""Caller-facing contract tests for archive-style saves.

The archive repository in these tests keeps every published version and logs
every backend call.  A save either publishes a replacement, is explicitly
rejected, or fails in transport with an unknown commit outcome.  The tests
state what a caller can observe in each case.

S3 is driven through its public streaming multipart entry point
(``storage.open(key, "wb")``) and Azure through the public direct save entry
point (``storage.save``).
"""

import io

import pytest
from azure.core.exceptions import HttpResponseError
from azure.core.exceptions import ResourceNotFoundError
from azure.core.exceptions import ServiceRequestError
from botocore.exceptions import ClientError
from botocore.exceptions import EndpointConnectionError
from django.core.files.base import ContentFile

from storages.backends import azure_storage
from storages.backends import s3

KEY = "archive/current.bin"
OLD = b"published-version-one"
NEW = b"replacement-two"


class PublishedVersion:
    def __init__(self, number, data, source):
        self.number = number
        self.data = data
        self.source = source


class ArchiveRepository:
    """A versioned archive plus a record of every backend call."""

    def __init__(self):
        self._versions = {}
        self._uploads = {}
        self._events = []
        self._commit_status = {}
        self._upload_seq = 0

    def seed(self, key, data):
        return self._publish(key, data, "seed")

    def _publish(self, key, data, source):
        versions = self._versions.setdefault(key, [])
        version = PublishedVersion(len(versions) + 1, data, source)
        versions.append(version)
        self.record("publish", key=key, version=version.number, source=source)
        return version

    def latest(self, key):
        versions = self._versions.get(key, [])
        return versions[-1] if versions else None

    def read(self, key):
        version = self.latest(key)
        if version is None:
            raise KeyError(key)
        return version.number, version.data

    def record(self, kind, **fields):
        self._events.append({"kind": kind, **fields})

    def events(self, kind, key=None):
        return [
            event
            for event in self._events
            if event["kind"] == kind and (key is None or event.get("key") == key)
        ]

    def mark_commit(self, key, status):
        self._commit_status[key] = status

    def commit_status(self, key):
        return self._commit_status.get(key)

    def begin_upload(self, key, parameters):
        self._upload_seq += 1
        upload_id = "upload-{}".format(self._upload_seq)
        self._uploads[upload_id] = {
            "upload_id": upload_id,
            "key": key,
            "parameters": parameters,
            "parts": {},
            "state": "pending",
        }
        self.record("initiate_multipart_upload", key=key, upload_id=upload_id)
        return upload_id

    def upload_part(self, upload_id, number, data):
        upload = self._uploads[upload_id]
        upload["parts"][number] = data
        self.record(
            "upload_part",
            key=upload["key"],
            upload_id=upload_id,
            part_number=number,
            size=len(data),
        )

    def parts_bytes(self, upload_id):
        parts = self._uploads[upload_id]["parts"]
        return b"".join(parts[number] for number in sorted(parts))

    def part_count(self, key):
        return sum(
            len(upload["parts"])
            for upload in self._uploads.values()
            if upload["key"] == key
        )

    def set_upload_state(self, upload_id, state):
        self._uploads[upload_id]["state"] = state

    def uploads(self, key):
        return [upload for upload in self._uploads.values() if upload["key"] == key]

    def upload_was_initiated(self, key):
        return bool(self.uploads(key))

    def cleanup_required(self, key):
        # Rejected or still-pending multipart uploads leave parts behind.  An
        # unknown outcome is deliberately excluded: no cleanup claim is made
        # for it here.
        return any(
            upload["state"] in ("pending", "rejected") for upload in self.uploads(key)
        )


class SaveAttempt:
    """The caller-visible result of one save call."""

    def __init__(self):
        self.returned = None
        self.error = None


def attempt_save(call):
    attempt = SaveAttempt()
    try:
        attempt.returned = call()
    except Exception as exc:  # callers see every exception
        attempt.error = exc
    return attempt


def caller_verdict(repo, key, before_version, attempt):
    """Classify what a caller has evidence for after a save attempt.

    A ``committed`` verdict requires both a newly published version and a
    recorded successful commit.  Returning a name without that evidence is a
    silent failure, whether the backend hid an explicit rejection or a
    transport error.
    """
    latest = repo.latest(key)
    status = repo.commit_status(key)
    if attempt.error is None:
        published = latest is not None and latest.number != before_version
        if status == "committed" and published:
            return "committed"
        return "silent_failure"
    if status == "rejected":
        return "rejected"
    if status == "unknown":
        return "unknown"
    if status == "not_attempted":
        return "failed_before_commit"
    return "failed_without_outcome"


def s3_error(status, operation="CompleteMultipartUpload"):
    return ClientError(
        {
            "Error": {"Code": "AccessDenied", "Message": "rejected"},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
        operation,
    )


class FakeS3Part:
    def __init__(self, repo, upload_id, key, number, mode):  # noqa: PLR0913
        self.repo = repo
        self.upload_id = upload_id
        self.key = key
        self.number = number
        self.mode = mode

    def upload(self, Body=b""):
        if self.mode == "part_failure":
            self.repo.mark_commit(self.key, "not_attempted")
            self.repo.record(
                "upload_part_failed", key=self.key, part_number=self.number
            )
            raise EndpointConnectionError(endpoint_url="https://s3.invalid")
        data = bytes(Body)
        self.repo.upload_part(self.upload_id, self.number, data)
        return {"ETag": "etag-{}".format(self.number)}


class FakeS3MultipartUpload:
    def __init__(self, repo, upload_id, key, mode, applied_on_unknown):  # noqa: PLR0913
        self.repo = repo
        self.upload_id = upload_id
        self.key = key
        self.mode = mode
        self.applied_on_unknown = applied_on_unknown

    def Part(self, number):
        return FakeS3Part(self.repo, self.upload_id, self.key, number, self.mode)

    def complete(self, MultipartUpload=None):
        parts = MultipartUpload["Parts"] if MultipartUpload else []
        self.repo.record(
            "complete_multipart_upload",
            key=self.key,
            upload_id=self.upload_id,
            parts=parts,
        )
        if self.mode == "reject":
            self.repo.mark_commit(self.key, "rejected")
            self.repo.set_upload_state(self.upload_id, "rejected")
            raise s3_error(403)
        if self.mode == "unknown":
            self.repo.mark_commit(self.key, "unknown")
            if self.applied_on_unknown:
                self.repo._publish(
                    self.key, self.repo.parts_bytes(self.upload_id), "s3"
                )
            self.repo.set_upload_state(self.upload_id, "unknown")
            raise EndpointConnectionError(endpoint_url="https://s3.invalid")
        self.repo._publish(self.key, self.repo.parts_bytes(self.upload_id), "s3")
        self.repo.mark_commit(self.key, "committed")
        self.repo.set_upload_state(self.upload_id, "committed")
        return {}

    def abort(self):
        self.repo.record(
            "abort_multipart_upload",
            key=self.key,
            upload_id=self.upload_id,
        )
        self.repo.set_upload_state(self.upload_id, "aborted")


class FakeS3Object:
    def __init__(self, repo, key, mode, applied_on_unknown):
        self.repo = repo
        self.key = key
        self.mode = mode
        self.applied_on_unknown = applied_on_unknown

    @property
    def content_length(self):
        version = self.repo.latest(self.key)
        return len(version.data) if version else 0

    @property
    def content_encoding(self):
        return None

    def load(self, **parameters):
        if self.repo.latest(self.key) is None:
            raise s3_error(404, operation="HeadObject")
        self.repo.record("head_object", key=self.key)

    def download_fileobj(self, fileobj, ExtraArgs=None, Config=None):
        version = self.repo.latest(self.key)
        if version is None:
            raise s3_error(404, operation="HeadObject")
        fileobj.write(version.data)
        self.repo.record("download_fileobj", key=self.key, version=version.number)

    def initiate_multipart_upload(self, **parameters):
        upload_id = self.repo.begin_upload(self.key, parameters)
        return FakeS3MultipartUpload(
            self.repo,
            upload_id,
            self.key,
            self.mode,
            self.applied_on_unknown,
        )


class FakeS3Bucket:
    def __init__(self, repo, mode="commit", applied_on_unknown=True):
        self.repo = repo
        self.mode = mode
        self.applied_on_unknown = applied_on_unknown

    def Object(self, key):
        return FakeS3Object(self.repo, key, self.mode, self.applied_on_unknown)


def make_s3_storage(repo, mode="commit", applied_on_unknown=True):
    storage = s3.S3Storage(bucket_name="archive")
    storage._bucket = FakeS3Bucket(repo, mode, applied_on_unknown)
    return storage


def stream_s3_save(storage, key, data, buffer_size=4):
    writer = storage.open(key, "wb")
    writer.buffer_size = buffer_size
    for offset in range(0, len(data), buffer_size):
        writer.write(data[offset : offset + buffer_size])
    writer.close()


def azure_error(status):
    response = type(
        "Response",
        (),
        {"status_code": status, "reason": "Forbidden", "headers": {}},
    )()
    return HttpResponseError("rejected", response=response)


class FakeAzureDownload:
    def __init__(self, data):
        self._stream = io.BytesIO(data)

    def readinto(self, target):
        return target.write(self._stream.read())


class FakeAzureContainer:
    def __init__(self, repo, mode="commit", applied_on_unknown=True):
        self.repo = repo
        self.mode = mode
        self.applied_on_unknown = applied_on_unknown

    def upload_blob(  # noqa: PLR0913
        self,
        name,
        data,
        content_settings=None,
        max_concurrency=None,
        timeout=None,
        overwrite=False,
    ):
        payload = data.read()
        self.repo.record(
            "upload_blob",
            key=name,
            size=len(payload),
            overwrite=overwrite,
        )
        if self.mode == "reject":
            self.repo.mark_commit(name, "rejected")
            self.repo.record("upload_rejected", key=name, status=403)
            raise azure_error(403)
        if self.mode == "unknown":
            self.repo.mark_commit(name, "unknown")
            if self.applied_on_unknown:
                self.repo._publish(name, payload, "azure")
            self.repo.record("upload_response_lost", key=name)
            raise ServiceRequestError("connection lost before response")
        self.repo._publish(name, payload, "azure")
        self.repo.mark_commit(name, "committed")
        return {"etag": "etag"}

    def download_blob(self, name, timeout=None):
        version = self.repo.latest(name)
        if version is None:
            raise ResourceNotFoundError("missing")
        self.repo.record("download_blob", key=name, version=version.number)
        return FakeAzureDownload(version.data)


def make_azure_storage(repo, mode="commit", applied_on_unknown=True):
    storage = azure_storage.AzureStorage(
        azure_container="archive", overwrite_files=True
    )
    storage._client = FakeAzureContainer(repo, mode, applied_on_unknown)
    return storage


@pytest.fixture
def repo():
    return ArchiveRepository()


def test_s3_parts_are_staged_until_complete_publishes(repo):
    repo.seed(KEY, OLD)
    storage = make_s3_storage(repo)

    writer = storage.open(KEY, "wb")
    writer.buffer_size = 4
    writer.write(NEW[:4])
    writer.write(NEW[4:8])

    assert repo.read(KEY) == (1, OLD)
    assert repo.part_count(KEY) == 1
    assert repo.commit_status(KEY) is None

    writer.write(NEW[8:])
    attempt = attempt_save(writer.close)

    assert attempt.error is None
    assert attempt.returned is None
    assert repo.read(KEY) == (2, NEW)
    assert repo.part_count(KEY) == 3
    assert repo.parts_bytes(repo.uploads(KEY)[0]["upload_id"]) == NEW
    assert repo.commit_status(KEY) == "committed"
    assert repo.cleanup_required(KEY) is False
    assert caller_verdict(repo, KEY, 1, attempt) == "committed"

    with storage.open(KEY, "rb") as reader:
        assert reader.read() == NEW


def test_s3_explicit_commit_rejection_keeps_published_version(repo):
    repo.seed(KEY, OLD)
    storage = make_s3_storage(repo, mode="reject")

    attempt = attempt_save(lambda: stream_s3_save(storage, KEY, NEW))

    assert isinstance(attempt.error, ClientError)
    assert attempt.error.response["ResponseMetadata"]["HTTPStatusCode"] == 403
    assert repo.read(KEY) == (1, OLD)
    assert repo.commit_status(KEY) == "rejected"
    assert repo.upload_was_initiated(KEY) is True
    assert repo.part_count(KEY) == 4
    assert repo.parts_bytes(repo.uploads(KEY)[0]["upload_id"]) == NEW
    assert repo.events("abort_multipart_upload", key=KEY) == []
    assert repo.cleanup_required(KEY) is True
    assert caller_verdict(repo, KEY, 1, attempt) == "rejected"

    with storage.open(KEY, "rb") as reader:
        assert reader.read() == OLD


@pytest.mark.parametrize("applied_on_unknown", [True, False])
def test_s3_unknown_commit_is_not_presented_as_rollback(repo, applied_on_unknown):
    repo.seed(KEY, OLD)
    storage = make_s3_storage(
        repo, mode="unknown", applied_on_unknown=applied_on_unknown
    )

    attempt = attempt_save(lambda: stream_s3_save(storage, KEY, NEW))

    assert isinstance(attempt.error, EndpointConnectionError)
    assert repo.commit_status(KEY) == "unknown"
    assert repo.upload_was_initiated(KEY) is True
    assert repo.part_count(KEY) == 4
    assert len(repo.events("complete_multipart_upload", key=KEY)) == 1
    assert repo.events("abort_multipart_upload", key=KEY) == []
    assert caller_verdict(repo, KEY, 1, attempt) == "unknown"
    # The server may or may not have applied the commit.  A read may therefore
    # return either complete version; the test must not claim a rollback.
    assert repo.read(KEY)[1] in (OLD, NEW)
    with storage.open(KEY, "rb") as reader:
        assert reader.read() in (OLD, NEW)


def test_s3_failure_before_complete_is_a_definite_failure(repo):
    repo.seed(KEY, OLD)
    storage = make_s3_storage(repo, mode="part_failure")

    attempt = attempt_save(lambda: stream_s3_save(storage, KEY, NEW))

    assert isinstance(attempt.error, EndpointConnectionError)
    assert repo.commit_status(KEY) == "not_attempted"
    assert repo.events("complete_multipart_upload", key=KEY) == []
    assert repo.read(KEY) == (1, OLD)
    assert caller_verdict(repo, KEY, 1, attempt) == "failed_before_commit"

    with storage.open(KEY, "rb") as reader:
        assert reader.read() == OLD


def test_azure_direct_save_publishes_replacement(repo):
    repo.seed(KEY, OLD)
    storage = make_azure_storage(repo)

    attempt = attempt_save(lambda: storage.save(KEY, ContentFile(NEW)))

    assert attempt.returned == KEY
    assert repo.read(KEY) == (2, NEW)
    assert repo.commit_status(KEY) == "committed"
    assert repo.events("upload_blob", key=KEY)[0]["size"] == len(NEW)
    assert repo.events("initiate_multipart_upload", key=KEY) == []
    assert repo.cleanup_required(KEY) is False
    assert caller_verdict(repo, KEY, 1, attempt) == "committed"

    with storage.open(KEY, "rb") as reader:
        assert reader.read() == NEW


def test_azure_explicit_commit_rejection_keeps_published_version(repo):
    repo.seed(KEY, OLD)
    storage = make_azure_storage(repo, mode="reject")

    attempt = attempt_save(lambda: storage.save(KEY, ContentFile(NEW)))

    assert isinstance(attempt.error, HttpResponseError)
    assert attempt.error.status_code == 403
    assert repo.read(KEY) == (1, OLD)
    assert repo.commit_status(KEY) == "rejected"
    assert repo.events("upload_rejected", key=KEY)
    assert repo.events("initiate_multipart_upload", key=KEY) == []
    assert repo.cleanup_required(KEY) is False
    assert caller_verdict(repo, KEY, 1, attempt) == "rejected"

    with storage.open(KEY, "rb") as reader:
        assert reader.read() == OLD


@pytest.mark.parametrize("applied_on_unknown", [True, False])
def test_azure_unknown_commit_is_not_presented_as_rollback(repo, applied_on_unknown):
    repo.seed(KEY, OLD)
    storage = make_azure_storage(
        repo, mode="unknown", applied_on_unknown=applied_on_unknown
    )

    attempt = attempt_save(lambda: storage.save(KEY, ContentFile(NEW)))

    assert isinstance(attempt.error, ServiceRequestError)
    assert repo.commit_status(KEY) == "unknown"
    assert repo.events("upload_response_lost", key=KEY)
    assert caller_verdict(repo, KEY, 1, attempt) == "unknown"
    # The server may or may not have applied the commit.  A read may therefore
    # return either complete version; the test must not claim a rollback.
    assert repo.read(KEY)[1] in (OLD, NEW)
    with storage.open(KEY, "rb") as reader:
        assert reader.read() in (OLD, NEW)


class SwallowingAzureStorage(azure_storage.AzureStorage):
    """Adapter that hides a definite rejection from its caller."""

    def _save(self, name, content):
        try:
            return super()._save(name, content)
        except HttpResponseError:
            return azure_storage.clean_name(name)


class OptimisticAzureStorage(azure_storage.AzureStorage):
    """Adapter that treats a lost response as a definite commit."""

    def _save(self, name, content):
        try:
            return super()._save(name, content)
        except ServiceRequestError:
            return azure_storage.clean_name(name)


def test_contract_check_detects_swallowed_commit_error(repo):
    repo.seed(KEY, OLD)
    storage = SwallowingAzureStorage(azure_container="archive", overwrite_files=True)
    storage._client = FakeAzureContainer(repo, mode="reject")

    attempt = attempt_save(lambda: storage.save(KEY, ContentFile(NEW)))

    assert attempt.error is None
    assert attempt.returned == KEY
    assert repo.read(KEY) == (1, OLD)
    assert repo.commit_status(KEY) == "rejected"
    assert caller_verdict(repo, KEY, 1, attempt) == "silent_failure"


def test_contract_check_detects_unknown_commit_claimed_as_success(repo):
    repo.seed(KEY, OLD)
    storage = OptimisticAzureStorage(azure_container="archive", overwrite_files=True)
    storage._client = FakeAzureContainer(repo, mode="unknown")

    attempt = attempt_save(lambda: storage.save(KEY, ContentFile(NEW)))

    assert attempt.error is None
    assert attempt.returned == KEY
    assert repo.commit_status(KEY) == "unknown"
    assert caller_verdict(repo, KEY, 1, attempt) == "silent_failure"
