"""
In-memory stand-ins for the S3 and Azure clients.

Both fakes emulate backends whose prefix matching does not respect
directory boundaries: a listing scoped to ``attachments/`` also returns
keys from the adjacent ``attachments-private`` namespace. This allows
tests to prove the storage backends enforce the root-directory contract
no matter what the backend hands back.
"""

from types import SimpleNamespace

from azure.core.exceptions import ResourceNotFoundError
from botocore.exceptions import ClientError


def _loose_prefix_match(key, prefix):
    """Match keys against a prefix ignoring the trailing slash boundary."""
    return key.startswith(prefix.rstrip("/"))


class FakeS3Object:
    content_encoding = None

    def __init__(self, objects, key):
        self._objects = objects
        self.key = key

    def load(self, **kwargs):
        if self.key not in self._objects:
            raise ClientError(
                {"Error": {}, "ResponseMetadata": {"HTTPStatusCode": 404}},
                "HeadObject",
            )

    def download_fileobj(self, fileobj, **kwargs):
        fileobj.write(self._objects[self.key])


class FakeS3Bucket:
    def __init__(self, objects):
        self._objects = objects

    def Object(self, key):
        return FakeS3Object(self._objects, key)


class FakeS3Paginator:
    def __init__(self, objects):
        self._objects = objects

    def paginate(self, Bucket, Delimiter, Prefix):
        directories = set()
        contents = []
        for key in sorted(self._objects):
            if key.startswith(Prefix):
                remainder = key[len(Prefix) :]
                if Delimiter and Delimiter in remainder:
                    head = remainder.split(Delimiter, 1)[0]
                    directories.add(Prefix + head + Delimiter)
                else:
                    contents.append({"Key": key})
            elif _loose_prefix_match(key, Prefix):
                # Boundary-ignoring backends leak adjacent namespaces flat.
                contents.append({"Key": key})
        page = {"Contents": contents}
        if directories:
            page["CommonPrefixes"] = [{"Prefix": name} for name in sorted(directories)]
        return [page]


class FakeS3Client:
    def __init__(self, objects):
        self._objects = objects

    def get_paginator(self, operation):
        assert operation == "list_objects"
        return FakeS3Paginator(self._objects)


class FakeS3Connection:
    """Stand-in for the boto3 S3 resource used by ``S3Storage``."""

    def __init__(self, objects):
        self._objects = dict(objects)
        self.meta = SimpleNamespace(client=FakeS3Client(self._objects))

    def Bucket(self, name):
        return FakeS3Bucket(self._objects)


class FakeAzureDownloadStream:
    def __init__(self, data):
        self._data = data

    def readinto(self, fileobj):
        fileobj.write(self._data)


class FakeAzureContainerClient:
    """Stand-in for the Azure ContainerClient used by ``AzureStorage``."""

    def __init__(self, blobs):
        self._blobs = dict(blobs)

    def list_blobs(self, name_starts_with="", timeout=None):
        return [
            SimpleNamespace(name=name)
            for name in sorted(self._blobs)
            if _loose_prefix_match(name, name_starts_with)
        ]

    def download_blob(self, name, timeout=None):
        if name not in self._blobs:
            raise ResourceNotFoundError("Blob not found: %s" % name)
        return FakeAzureDownloadStream(self._blobs[name])
