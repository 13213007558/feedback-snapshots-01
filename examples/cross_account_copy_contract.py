"""Run a synthetic cross-account encrypted copy without AWS credentials.

The script demonstrates both a regular copy and a multipart copy where the
middle fragment times out once and is safely retried.  Printed audit records
contain stage purposes and categories, but never synthetic key material.
"""

import json

from s3transfer.contracts import CrossAccountCopyContract, EncryptionProfile
from s3transfer.manager import TransferConfig, TransferManager
from s3transfer.utils import MIN_UPLOAD_CHUNKSIZE

SOURCE_KEY = "synthetic-source-key"
DESTINATION_KEY = "synthetic-destination-key"


class Events:
    def register_first(self, *args, **kwargs):
        pass

    def register_last(self, *args, **kwargs):
        pass


class Meta:
    events = Events()


class SyntheticS3Client:
    def __init__(self, size, timeout_part=None):
        self.meta = Meta()
        self.size = size
        self.timeout_part = timeout_part
        self.attempts = {}

    def head_object(self, **kwargs):
        return {"ContentLength": self.size, "ETag": "source-etag"}

    def copy_object(self, **kwargs):
        return {}

    def create_multipart_upload(self, **kwargs):
        return {"UploadId": "synthetic-upload-id"}

    def upload_part_copy(self, **kwargs):
        part_number = kwargs["PartNumber"]
        attempt = self.attempts.get(part_number, 0) + 1
        self.attempts[part_number] = attempt
        if part_number == self.timeout_part and attempt == 1:
            raise TimeoutError("synthetic fragment timeout")
        return {"CopyPartResult": {"ETag": f"etag-{part_number}"}}

    def complete_multipart_upload(self, **kwargs):
        return {"ETag": "destination-etag"}

    def abort_multipart_upload(self, **kwargs):
        return {}


def profiles():
    source = EncryptionProfile(
        name="source-account",
        category="source-sse-c",
        request_args={
            "SSECustomerAlgorithm": "AES256",
            "SSECustomerKey": SOURCE_KEY,
            "SSECustomerKeyMD5": "source-key-md5",
        },
    )
    destination = EncryptionProfile(
        name="destination-account",
        category="destination-sse-c",
        request_args={
            "SSECustomerAlgorithm": "AES256",
            "SSECustomerKey": DESTINATION_KEY,
            "SSECustomerKeyMD5": "destination-key-md5",
        },
    )
    return source, destination


def run(size, multipart):
    source_profile, destination_profile = profiles()
    contract = CrossAccountCopyContract(source_profile, destination_profile)
    source_client = SyntheticS3Client(size)
    destination_client = SyntheticS3Client(
        size, timeout_part=2 if multipart else None
    )
    config = TransferConfig(
        multipart_threshold=MIN_UPLOAD_CHUNKSIZE,
        multipart_chunksize=MIN_UPLOAD_CHUNKSIZE,
        max_request_concurrency=1,
        max_submission_concurrency=1,
    )
    manager = TransferManager(destination_client, config)
    future = manager.copy(
        {"Bucket": "source-bucket", "Key": "archive"},
        "destination-bucket",
        "archive",
        source_client=source_client,
        contract=contract,
    )
    future.result()
    manager.shutdown()
    return contract


def main():
    ordinary = run(size=1024, multipart=False)
    large = 2 * MIN_UPLOAD_CHUNKSIZE + MIN_UPLOAD_CHUNKSIZE // 2
    multipart = run(size=large, multipart=True)

    ordinary_records = ordinary.public_records()
    multipart_records = multipart.public_records()
    print("ordinary stages:")
    print(json.dumps(ordinary_records, indent=2, sort_keys=True))
    print("multipart stages:")
    print(json.dumps(multipart_records, indent=2, sort_keys=True))

    public_output = json.dumps(
        ordinary_records + multipart_records, sort_keys=True
    )
    assert SOURCE_KEY not in public_output
    assert DESTINATION_KEY not in public_output
    assert any(
        record["stage"] == "upload_part_copy" and record["status"] == "failed"
        for record in multipart_records
    )
    assert any(
        record["stage"] == "upload_part_copy"
        and record["status"] == "succeeded"
        and record["attempt"] == 2
        for record in multipart_records
    )


if __name__ == "__main__":
    main()
