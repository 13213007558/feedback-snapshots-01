"""Requester Pays authorization across region discovery, connection reuse and
multipart paths.

These tests use lightweight fakes so they run without a live (or mocked) S3
server. They model a single backend that serves two teams: one team is willing
to pay the Requester Pays fees, the other is not.
"""

import asyncio

import pytest
from botocore.exceptions import ClientError

import s3fs.core as core
from s3fs import S3FileSystem
from s3fs.core import S3File, _error_wrapper
from s3fs.utils import S3BucketRegionCache


REGION_HEADERS = {"x-amz-bucket-region": "eu-central-1"}
ENDPOINT = {"client_kwargs": {"endpoint_url": "http://127.0.0.1:9999/"}}
BILLING_DENIAL = {
    "Error": {"Code": "AccessDenied", "Message": "billing admission required"},
    "ResponseMetadata": {"HTTPHeaders": dict(REGION_HEADERS)},
}


class _FakeClient:
    def __init__(self, deny_head=False, deny_list=False):
        self.deny_head = deny_head
        self.deny_list = deny_list
        self.calls = []

    async def head_bucket(self, **kwargs):
        self.calls.append(("head_bucket", kwargs))
        if self.deny_head:
            raise ClientError(dict(BILLING_DENIAL), "HeadBucket")
        return {"ResponseMetadata": {"HTTPHeaders": dict(REGION_HEADERS)}}

    async def list_objects_v2(self, **kwargs):
        self.calls.append(("list_objects_v2", kwargs))
        if self.deny_list:
            raise ClientError(dict(BILLING_DENIAL), "ListObjectsV2")
        return {
            "ResponseMetadata": {"HTTPHeaders": dict(REGION_HEADERS)},
            "KeyCount": 0,
        }


class _ClientContext:
    def __init__(self, client):
        self._client = client

    async def __aenter__(self):
        return self._client

    async def __aexit__(self, *exc_args):
        return False


class _FakeSession:
    def __init__(self, **client_flags):
        self._client_flags = client_flags
        self.clients = []

    def create_client(self, service, **kwargs):
        client = _FakeClient(**self._client_flags)
        self.clients.append((kwargs.get("region_name"), client))
        return _ClientContext(client)

    @property
    def general_client(self):
        return self.clients[0][1]


def test_paying_team_warms_region_cache_with_billing_commitment():
    session = _FakeSession(deny_head=True)
    cache = S3BucketRegionCache(session, requester_pays=True)

    asyncio.run(cache.get_bucket_client("shared-bucket"))

    # HeadBucket cannot carry the fee commitment; the follow-up listing must.
    assert session.general_client.calls == [
        ("head_bucket", {"Bucket": "shared-bucket"}),
        (
            "list_objects_v2",
            {
                "Bucket": "shared-bucket",
                "MaxKeys": 1,
                "RequestPayer": "requester",
            },
        ),
    ]


def test_warmed_region_client_is_reused_for_later_access():
    session = _FakeSession(deny_head=True)
    cache = S3BucketRegionCache(session, requester_pays=True)

    first = asyncio.run(cache.get_bucket_client("shared-bucket"))
    second = asyncio.run(cache.get_bucket_client("shared-bucket"))

    assert first is second
    # Reuse means the discovery probe is not issued a second time.
    assert len(session.general_client.calls) == 2
    assert [region for region, _ in session.clients] == [None, "eu-central-1"]


def test_non_paying_team_keeps_head_bucket_and_does_not_commit_fees():
    session = _FakeSession(deny_head=True)
    cache = S3BucketRegionCache(session, requester_pays=False)

    asyncio.run(cache.get_bucket_client("shared-bucket"))

    # The non-billed path must not gain a fee-committing listing probe.
    assert session.general_client.calls == [
        ("head_bucket", {"Bucket": "shared-bucket"})
    ]
    assert all(
        "RequestPayer" not in kwargs for _, kwargs in session.general_client.calls
    )


def test_non_paying_team_billing_denial_is_reported_not_swallowed():
    session = _FakeSession(deny_head=True, deny_list=True)
    cache = S3BucketRegionCache(session, requester_pays=True)

    with pytest.raises(ClientError) as excinfo:
        asyncio.run(cache.get_bucket_client("shared-bucket"))

    assert excinfo.value.response["Error"]["Code"] == "AccessDenied"


def test_region_cache_receives_filesystem_billing_authorization(monkeypatch):
    captured = []

    class _RecordingCache:
        def __init__(self, session, requester_pays=False, **kwargs):
            captured.append(requester_pays)
            self.requester_pays = requester_pays

        async def get_client(self):
            return object()

    class _StubAioSession:
        def __init__(self, **kwargs):
            pass

        def create_client(self, *args, **kwargs):
            raise AssertionError("the region cache path must not create a client")

    monkeypatch.setattr(core, "S3BucketRegionCache", _RecordingCache)
    monkeypatch.setattr(core.aiobotocore.session, "AioSession", _StubAioSession)

    async def build(requester_pays):
        fs = S3FileSystem(
            asynchronous=True,
            requester_pays=requester_pays,
            cache_regions=True,
            skip_instance_cache=True,
            key="k",
            secret="s",
            region_name=None,
        )
        fs.session = _StubAioSession()
        await fs.set_session()
        return fs

    paying = asyncio.run(build(True))
    non_paying = asyncio.run(build(False))

    assert captured == [True, False]
    assert paying._s3creator.requester_pays is True
    assert non_paying._s3creator.requester_pays is False


_MPU_METHODS = (
    "create_multipart_upload",
    "upload_part",
    "complete_multipart_upload",
    "abort_multipart_upload",
)


def _multipart_kwargs(filesystem_pays, file_pays):
    fs = S3FileSystem(
        asynchronous=False,
        requester_pays=filesystem_pays,
        skip_instance_cache=True,
        key="k",
        secret="s",
        **ENDPOINT,
    )
    opened = S3File(fs, "shared-bucket/key", mode="rb", requester_pays=file_pays, size=0)
    return fs, opened


@pytest.mark.parametrize("method", _MPU_METHODS)
def test_multipart_path_preserves_paying_authorization(method):
    fs, opened = _multipart_kwargs(filesystem_pays=True, file_pays=True)

    kwargs = fs._get_s3_method_kwargs(
        getattr(fs.s3, method),
        opened.s3_additional_kwargs,
        opened._request_payer_kw,
        Bucket="shared-bucket",
        Key="key",
    )

    assert kwargs["RequestPayer"] == "requester"


@pytest.mark.parametrize("method", _MPU_METHODS[:3])
def test_multipart_path_honors_per_file_opt_out(method):
    fs, opened = _multipart_kwargs(filesystem_pays=True, file_pays=False)

    kwargs = fs._get_s3_method_kwargs(
        getattr(fs.s3, method),
        opened.s3_additional_kwargs,
        opened._request_payer_kw,
        Bucket="shared-bucket",
        Key="key",
    )

    assert "RequestPayer" not in kwargs


def test_billing_denial_is_not_retried_and_keeps_original_judgment():
    attempts = 0

    async def operation():
        nonlocal attempts
        attempts += 1
        raise ClientError(dict(BILLING_DENIAL), "ListObjectsV2")

    with pytest.raises(PermissionError):
        asyncio.run(_error_wrapper(operation, retries=5))

    # AccessDenied is a billing-admission decision, not a transient failure.
    assert attempts == 1


def test_retry_keeps_request_payer_commitment_on_each_attempt():
    attempts = []

    async def operation():
        attempts.append(dict(kwargs))
        if len(attempts) < 3:
            raise ClientError(
                {"Error": {"Code": "SlowDown", "Message": "reduce your request rate"}},
                "ListObjectsV2",
            )
        return {"KeyCount": 0}

    kwargs = {"Bucket": "shared-bucket", "RequestPayer": "requester"}

    result = asyncio.run(_error_wrapper(operation, retries=5))

    assert result == {"KeyCount": 0}
    assert len(attempts) == 3
    assert all(attempt["RequestPayer"] == "requester" for attempt in attempts)
