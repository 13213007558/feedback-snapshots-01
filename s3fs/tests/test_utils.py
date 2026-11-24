import asyncio

import pytest
from botocore.exceptions import ClientError

import s3fs.utils as utils
from s3fs.utils import S3BucketRegionCache


REGION_HEADERS = {"x-amz-bucket-region": "us-west-2"}


class _FakeClient:
    def __init__(self, region_name=None, deny_head=False, deny_list=False):
        self.region_name = region_name
        self.deny_head = deny_head
        self.deny_list = deny_list
        self.calls = []

    async def head_bucket(self, **kwargs):
        self.calls.append(("head_bucket", kwargs))
        if self.deny_head:
            raise ClientError(
                {
                    "Error": {"Code": "AccessDenied", "Message": "denied"},
                    "ResponseMetadata": {"HTTPHeaders": dict(REGION_HEADERS)},
                },
                "HeadBucket",
            )
        return {"ResponseMetadata": {"HTTPHeaders": dict(REGION_HEADERS)}}

    async def list_objects_v2(self, **kwargs):
        self.calls.append(("list_objects_v2", kwargs))
        if self.deny_list:
            raise ClientError(
                {
                    "Error": {
                        "Code": "AccessDenied",
                        "Message": "billing admission denied",
                    },
                    "ResponseMetadata": {"HTTPHeaders": dict(REGION_HEADERS)},
                },
                "ListObjectsV2",
            )
        return {"ResponseMetadata": {"HTTPHeaders": dict(REGION_HEADERS)}}


class _ClientContext:
    def __init__(self, client):
        self._client = client

    async def __aenter__(self):
        return self._client

    async def __aexit__(self, *exc_args):
        return False


class _FakeSession:
    def __init__(self, deny_head=False, deny_list=False):
        self.deny_head = deny_head
        self.deny_list = deny_list
        self.clients = []

    def create_client(self, service, **kwargs):
        client = _FakeClient(
            kwargs.get("region_name"),
            deny_head=self.deny_head,
            deny_list=self.deny_list,
        )
        self.clients.append(client)
        return _ClientContext(client)

    @property
    def general_client(self):
        return self.clients[0]


def test_get_brange():
    assert list(utils._get_brange(100, 24)) == [
        (0, 23),
        (24, 47),
        (48, 71),
        (72, 95),
        (96, 99),
    ]
    assert list(utils._get_brange(100, 25)) == [(0, 24), (25, 49), (50, 74), (75, 99)]
    assert list(utils._get_brange(100, 26)) == [(0, 25), (26, 51), (52, 77), (78, 99)]


def test_region_cache_reuses_bucket_client():
    session = _FakeSession()
    cache = S3BucketRegionCache(session)

    first = asyncio.run(cache.get_bucket_client("bucket"))
    second = asyncio.run(cache.get_bucket_client("bucket"))

    assert first is second
    # A warmed bucket does not trigger discovery again.
    assert session.general_client.calls == [("head_bucket", {"Bucket": "bucket"})]
    assert [client.region_name for client in session.clients] == [None, "us-west-2"]


def test_region_cache_non_payer_keeps_head_bucket_discovery():
    session = _FakeSession(deny_head=True)
    cache = S3BucketRegionCache(session, requester_pays=False)

    client = asyncio.run(cache.get_bucket_client("bucket"))

    # The billing-agnostic path still relies on HeadBucket alone and never
    # promises to pay; the denial's region header selects the regional client.
    assert session.general_client.calls == [("head_bucket", {"Bucket": "bucket"})]
    assert client.region_name == "us-west-2"


def test_region_cache_requester_pays_probes_with_billing_commitment():
    session = _FakeSession(deny_head=True)
    cache = S3BucketRegionCache(session, requester_pays=True)

    client = asyncio.run(cache.get_bucket_client("bucket"))

    assert session.general_client.calls == [
        ("head_bucket", {"Bucket": "bucket"}),
        (
            "list_objects_v2",
            {"Bucket": "bucket", "MaxKeys": 1, "RequestPayer": "requester"},
        ),
    ]
    assert client.region_name == "us-west-2"


def test_region_cache_requester_pays_denial_is_surfaced():
    session = _FakeSession(deny_head=True, deny_list=True)
    cache = S3BucketRegionCache(session, requester_pays=True)

    with pytest.raises(ClientError) as excinfo:
        asyncio.run(cache.get_bucket_client("bucket"))

    assert excinfo.value.response["Error"]["Code"] == "AccessDenied"
    # No regional client is cached for a bucket the team is not allowed to bill.
    assert [client.region_name for client in session.clients] == [None]
