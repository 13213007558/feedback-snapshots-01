# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
import json
import unittest

from s3transfer.contracts import (
    ContractStageTimeoutError,
    ContractViolationError,
    CrossAccountCopyContract,
    EncryptionProfile,
)
from s3transfer.manager import TransferConfig, TransferManager
from s3transfer.utils import MIN_UPLOAD_CHUNKSIZE

SOURCE_KEY = "source-synthetic-key-material"
DEST_KEY = "destination-synthetic-key-material"
SOURCE_MD5 = "source-synthetic-md5-material"
DEST_MD5 = "destination-synthetic-md5-material"


class FakeEvents:
    def register_first(self, *args, **kwargs):
        pass

    def register_last(self, *args, **kwargs):
        pass


class FakeClientMeta:
    events = FakeEvents()


class FakeCopyClient:
    def __init__(self, name, size=10, fail_part=None, fail_always=False):
        self.name = name
        self.meta = FakeClientMeta()
        self.size = size
        self.fail_part = fail_part
        self.fail_always = fail_always
        self.part_attempts = {}
        self.calls = []

    def _record(self, method, **kwargs):
        self.calls.append((method, kwargs))
        return {}

    def head_object(self, **kwargs):
        self.calls.append(("head_object", kwargs))
        return {"ContentLength": self.size, "ETag": "source-etag"}

    def copy_object(self, **kwargs):
        return self._record("copy_object", **kwargs)

    def create_multipart_upload(self, **kwargs):
        self.calls.append(("create_multipart_upload", kwargs))
        return {"UploadId": "upload-id"}

    def upload_part_copy(self, **kwargs):
        part_number = kwargs["PartNumber"]
        attempt = self.part_attempts.get(part_number, 0) + 1
        self.part_attempts[part_number] = attempt
        self.calls.append(("upload_part_copy", kwargs))
        if part_number == self.fail_part and (
            self.fail_always or attempt == 1
        ):
            raise TimeoutError(
                f"synthetic part timeout {SOURCE_KEY} {DEST_KEY}"
            )
        return {"CopyPartResult": {"ETag": f"etag-{part_number}"}}

    def complete_multipart_upload(self, **kwargs):
        return self._record("complete_multipart_upload", **kwargs)

    def abort_multipart_upload(self, **kwargs):
        return self._record("abort_multipart_upload", **kwargs)


def make_profiles():
    source = EncryptionProfile(
        name="source-account",
        category="source-customer-managed",
        request_args={
            "SSECustomerAlgorithm": "AES256",
            "SSECustomerKey": SOURCE_KEY,
            "SSECustomerKeyMD5": SOURCE_MD5,
        },
    )
    destination = EncryptionProfile(
        name="destination-account",
        category="destination-customer-managed",
        request_args={
            "SSECustomerAlgorithm": "AES256",
            "SSECustomerKey": DEST_KEY,
            "SSECustomerKeyMD5": DEST_MD5,
        },
    )
    return source, destination


class TestEncryptionProfile(unittest.TestCase):
    def test_copy_source_arguments_are_prefixed(self):
        source, _ = make_profiles()
        copy_source_args = source.copy_source_args()
        self.assertEqual(
            copy_source_args["CopySourceSSECustomerKey"], SOURCE_KEY
        )
        self.assertEqual(
            copy_source_args["CopySourceSSECustomerKeyMD5"], SOURCE_MD5
        )
        self.assertNotIn("SSECustomerKey", copy_source_args)

    def test_public_view_and_repr_do_not_expose_material(self):
        source, _ = make_profiles()
        public = source.public_view()
        rendered = json.dumps(public)
        self.assertNotIn(SOURCE_KEY, rendered)
        self.assertNotIn(SOURCE_MD5, rendered)
        self.assertNotIn(SOURCE_KEY, repr(source))
        self.assertIn(source.digest, repr(source))

    def test_contract_rejects_ambient_encryption_args(self):
        source, destination = make_profiles()
        contract = CrossAccountCopyContract(source, destination)
        with self.assertRaisesRegex(ValueError, "SSECustomerKey"):
            contract.prepare_copy_extra_args({"SSECustomerKey": "ambient"})

    def test_destination_stage_rejects_source_material_before_call(self):
        source, destination = make_profiles()
        contract = CrossAccountCopyContract(source, destination)
        destination_client = FakeCopyClient("destination")
        audited = contract.destination_client(destination_client)

        with self.assertRaises(ContractViolationError):
            audited.create_multipart_upload(
                Bucket="bucket",
                Key="key",
                SSECustomerKey=SOURCE_KEY,
            )

        self.assertEqual(destination_client.calls, [])
        rejected = [
            record
            for record in contract.public_records()
            if record["status"] == "rejected"
        ]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["stage"], "create_multipart_upload")
        self.assertNotIn(SOURCE_KEY, contract.audit.to_json())


class TestCrossAccountCopyIntegration(unittest.TestCase):
    def setUp(self):
        self.source_profile, self.dest_profile = make_profiles()
        self.large_size = 2 * MIN_UPLOAD_CHUNKSIZE + MIN_UPLOAD_CHUNKSIZE // 2
        self.config = TransferConfig(
            multipart_threshold=MIN_UPLOAD_CHUNKSIZE,
            multipart_chunksize=MIN_UPLOAD_CHUNKSIZE,
            max_request_concurrency=1,
            max_submission_concurrency=1,
        )

    def _manager(self, destination):
        return TransferManager(destination, self.config)

    def _copy(self, manager, source_client, contract):
        return manager.copy(
            {"Bucket": "source-bucket", "Key": "source-key"},
            "destination-bucket",
            "destination-key",
            extra_args={"ACL": "private"},
            source_client=source_client,
            contract=contract,
        )

    def _assert_public_records_are_redacted(self, contract):
        rendered = contract.audit.to_json()
        for secret in (SOURCE_KEY, DEST_KEY, SOURCE_MD5, DEST_MD5):
            self.assertNotIn(secret, rendered)

    def test_normal_copy_uses_each_material_only_in_its_scope(self):
        destination = FakeCopyClient("destination", size=10)
        source_client = FakeCopyClient("source", size=10)
        contract = CrossAccountCopyContract(
            self.source_profile, self.dest_profile
        )
        manager = self._manager(destination)
        future = self._copy(manager, source_client, contract)
        future.result()
        manager.shutdown()

        source_kwargs = source_client.calls[0][1]
        self.assertEqual(source_kwargs["SSECustomerKey"], SOURCE_KEY)
        self.assertNotIn("CopySourceSSECustomerKey", source_kwargs)

        method, copy_kwargs = next(
            call for call in destination.calls if call[0] == "copy_object"
        )
        self.assertEqual(copy_kwargs["CopySourceSSECustomerKey"], SOURCE_KEY)
        self.assertEqual(copy_kwargs["SSECustomerKey"], DEST_KEY)

        stages = [record.stage for record in contract.records]
        self.assertEqual(stages, ["head_object", "copy_object"])
        for record in contract.public_records():
            self.assertTrue(record["purpose"])
            self.assertTrue(record["category"])
        self._assert_public_records_are_redacted(contract)

    def test_multipart_timeout_retry_keeps_materials_separated(self):
        destination = FakeCopyClient(
            "destination", size=self.large_size, fail_part=2
        )
        source_client = FakeCopyClient("source", size=self.large_size)
        contract = CrossAccountCopyContract(
            self.source_profile, self.dest_profile
        )
        manager = self._manager(destination)
        future = self._copy(manager, source_client, contract)
        future.result()
        manager.shutdown()

        self.assertEqual(destination.part_attempts[2], 2)
        create_kwargs = next(
            kwargs
            for method, kwargs in destination.calls
            if method == "create_multipart_upload"
        )
        self.assertEqual(create_kwargs["SSECustomerKey"], DEST_KEY)
        self.assertNotIn("CopySourceSSECustomerKey", create_kwargs)

        part_calls = [
            kwargs
            for method, kwargs in destination.calls
            if method == "upload_part_copy"
        ]
        self.assertEqual(len(part_calls), 4)
        for kwargs in part_calls:
            self.assertEqual(kwargs["CopySourceSSECustomerKey"], SOURCE_KEY)
            self.assertEqual(kwargs["SSECustomerKey"], DEST_KEY)

        complete_kwargs = next(
            kwargs
            for method, kwargs in destination.calls
            if method == "complete_multipart_upload"
        )
        self.assertEqual(complete_kwargs["SSECustomerKey"], DEST_KEY)
        self.assertNotIn("CopySourceSSECustomerKey", complete_kwargs)

        records = contract.public_records()
        failed = [
            record
            for record in records
            if record["stage"] == "upload_part_copy"
            and record["status"] == "failed"
        ]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["part_number"], 2)
        self.assertEqual(failed[0]["attempt"], 1)
        self.assertTrue(failed[0]["purpose"])
        self.assertTrue(failed[0]["category"])
        self._assert_public_records_are_redacted(contract)

    def test_permanent_part_timeout_records_stage_and_cleans_job(self):
        destination = FakeCopyClient(
            "destination",
            size=self.large_size,
            fail_part=2,
            fail_always=True,
        )
        source_client = FakeCopyClient("source", size=self.large_size)
        contract = CrossAccountCopyContract(
            self.source_profile,
            self.dest_profile,
            part_attempts=2,
        )
        manager = self._manager(destination)
        future = self._copy(manager, source_client, contract)
        with self.assertRaises(ContractStageTimeoutError) as caught:
            future.result()
        manager.shutdown()

        self.assertIsInstance(caught.exception, TimeoutError)
        self.assertEqual(caught.exception.stage, "upload_part_copy")
        self.assertEqual(caught.exception.part_number, 2)
        diagnostic = str(caught.exception)
        self.assertIn("upload_part_copy", diagnostic)
        for secret in (SOURCE_KEY, DEST_KEY, SOURCE_MD5, DEST_MD5):
            self.assertNotIn(secret, diagnostic)

        abort_kwargs = next(
            kwargs
            for method, kwargs in destination.calls
            if method == "abort_multipart_upload"
        )
        self.assertEqual(abort_kwargs["UploadId"], "upload-id")
        self.assertNotIn("SSECustomerKey", abort_kwargs)
        self.assertNotIn("CopySourceSSECustomerKey", abort_kwargs)

        cleanup_records = [
            record
            for record in contract.public_records()
            if record["stage"] == "abort_multipart_upload"
        ]
        self.assertEqual(len(cleanup_records), 1)
        self.assertEqual(cleanup_records[0]["status"], "succeeded")
        self._assert_public_records_are_redacted(contract)


if __name__ == "__main__":
    unittest.main()
