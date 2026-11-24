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
import datetime
import json
import os
import tempfile

from botocore.exceptions import ClientError

from s3transfer.recovery import (
    MultipartUploadJournal,
    MultipartUploadRecoveryManager,
    OUTCOME_ABORTED,
    OUTCOME_MANUAL_REVIEW,
    OUTCOME_NO_ACTION,
    STATE_CANCELLED,
    STATE_COMPLETED,
    STATE_IN_PROGRESS,
    STATE_MANUAL_REVIEW,
    recover_multipart_uploads,
)
from tests import StubbedClientTest

BUCKET = 'archive-bucket'
KEY = 'nightly/2026-11-24.tar'
COMPLETED_UPLOAD_ID = 'upload-completed-lost-notification'
CANCELLED_UPLOAD_ID = 'upload-explicitly-cancelled'
IN_PROGRESS_UPLOAD_ID = 'upload-still-running'
UNOWNED_UPLOAD_ID = 'upload-owned-by-someone-else'


class JournalTest(StubbedClientTest):
    def setUp(self):
        super().setUp()
        self.tempdir = tempfile.mkdtemp()
        self.journal_path = os.path.join(self.tempdir, 'journal.json')

    def journal(self):
        return MultipartUploadJournal(self.journal_path)

    def test_missing_journal_loads_empty(self):
        journal = self.journal()
        self.assertEqual(journal.entries, [])

    def test_record_persists_and_reloads(self):
        journal = self.journal()
        journal.record_upload(
            BUCKET,
            KEY,
            CANCELLED_UPLOAD_ID,
            source='/var/archive/a.tar',
            parts=[{'PartNumber': 1, 'ETag': 'etag'}],
            initiated_at='2026-11-24T00:00:00+00:00',
        )

        reloaded = self.journal()
        self.assertEqual(len(reloaded.entries), 1)
        entry = reloaded.get(BUCKET, KEY, CANCELLED_UPLOAD_ID)
        self.assertEqual(entry['bucket'], BUCKET)
        self.assertEqual(entry['key'], KEY)
        self.assertEqual(entry['state'], STATE_IN_PROGRESS)
        self.assertEqual(entry['source'], '/var/archive/a.tar')
        self.assertEqual(
            entry['parts'], [{'PartNumber': 1, 'ETag': 'etag'}]
        )

    def test_same_object_name_keeps_distinct_upload_records(self):
        journal = self.journal()
        journal.record_upload(BUCKET, KEY, COMPLETED_UPLOAD_ID)
        journal.record_upload(BUCKET, KEY, CANCELLED_UPLOAD_ID)

        reloaded = self.journal()
        self.assertEqual(
            sorted(entry['upload_id'] for entry in reloaded.entries),
            sorted([COMPLETED_UPLOAD_ID, CANCELLED_UPLOAD_ID]),
        )
        self.assertIsNotNone(
            reloaded.get(BUCKET, KEY, COMPLETED_UPLOAD_ID)
        )
        self.assertIsNotNone(
            reloaded.get(BUCKET, KEY, CANCELLED_UPLOAD_ID)
        )

    def test_record_upload_replaces_existing_credential(self):
        journal = self.journal()
        journal.record_upload(BUCKET, KEY, CANCELLED_UPLOAD_ID)
        journal.record_upload(
            BUCKET, KEY, CANCELLED_UPLOAD_ID, state=STATE_CANCELLED
        )

        entries = self.journal().entries
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['state'], STATE_CANCELLED)

    def test_mark_state_and_remove(self):
        journal = self.journal()
        journal.record_upload(BUCKET, KEY, CANCELLED_UPLOAD_ID)
        journal.mark_state(BUCKET, KEY, CANCELLED_UPLOAD_ID, STATE_CANCELLED)
        self.assertEqual(
            self.journal().get(BUCKET, KEY, CANCELLED_UPLOAD_ID)['state'],
            STATE_CANCELLED,
        )

        journal.remove(BUCKET, KEY, CANCELLED_UPLOAD_ID)
        self.assertEqual(self.journal().entries, [])

    def test_mark_state_unknown_upload_raises(self):
        with self.assertRaises(KeyError):
            self.journal().mark_state(
                BUCKET, KEY, 'never-recorded', STATE_CANCELLED
            )

    def test_persist_writes_valid_json_document(self):
        self.journal().record_upload(BUCKET, KEY, CANCELLED_UPLOAD_ID)
        with open(self.journal_path, encoding='utf-8') as journal_file:
            document = json.load(journal_file)
        self.assertIn('uploads', document)


class RecoveryTest(StubbedClientTest):
    def setUp(self):
        super().setUp()
        self.tempdir = tempfile.mkdtemp()
        self.journal_path = os.path.join(self.tempdir, 'journal.json')
        self.now = datetime.datetime(2026, 11, 24, 12, 0, 0)
        self.clock = lambda: self.now.replace(
            tzinfo=datetime.timezone.utc
        )

    def journal(self):
        return MultipartUploadJournal(self.journal_path)

    def manager(self, retention_age=None):
        return MultipartUploadRecoveryManager(
            self.client,
            self.journal(),
            retention_age=retention_age,
            clock=self.clock,
        )

    def remote_upload(self, upload_id, key=KEY, initiated=None):
        if initiated is None:
            initiated = self.now - datetime.timedelta(hours=1)
        return {
            'UploadId': upload_id,
            'Key': key,
            'Initiated': initiated,
            'StorageClass': 'STANDARD',
        }

    def add_list_response(self, uploads, is_truncated=False, **expected):
        params = {'Bucket': BUCKET, 'Prefix': KEY}
        params.update(expected)
        self.stubber.add_response(
            'list_multipart_uploads',
            service_response={
                'Uploads': uploads,
                'IsTruncated': is_truncated,
            },
            expected_params=params,
        )

    def add_abort_response(self, upload_id):
        self.stubber.add_response(
            'abort_multipart_upload',
            service_response={},
            expected_params={
                'Bucket': BUCKET,
                'Key': KEY,
                'UploadId': upload_id,
            },
        )

    def add_abort_error(self, upload_id, code, status_code=403):
        self.stubber.add_client_error(
            'abort_multipart_upload',
            service_error_code=code,
            http_status_code=status_code,
            expected_params={
                'Bucket': BUCKET,
                'Key': KEY,
                'UploadId': upload_id,
            },
        )

    def record(self, upload_id, state, initiated_at=None, **kwargs):
        if initiated_at is None:
            initiated_at = (
                self.now - datetime.timedelta(hours=1)
            ).isoformat()
        self.journal().record_upload(
            BUCKET,
            KEY,
            upload_id,
            state=state,
            initiated_at=initiated_at,
            **kwargs,
        )

    def ids(self, records):
        return [record.upload_id for record in records]


class TestRecoveryScenario(RecoveryTest):
    def test_completed_lost_notification_and_cancelled_upload(self):
        # Two simulated uploads registered under the same object name.
        self.record(COMPLETED_UPLOAD_ID, STATE_COMPLETED)
        self.record(CANCELLED_UPLOAD_ID, STATE_CANCELLED)

        # The completed upload is gone server side. The cancelled upload is
        # still open, alongside an unrelated in progress upload.
        self.add_list_response(
            [
                self.remote_upload(CANCELLED_UPLOAD_ID),
                self.remote_upload(UNOWNED_UPLOAD_ID),
            ]
        )
        self.add_abort_response(CANCELLED_UPLOAD_ID)

        report = self.manager().recover(BUCKET, KEY)

        self.stubber.assert_no_pending_responses()
        # Only the explicitly cancelled, journal owned upload is cleaned up.
        self.assertEqual(self.ids(report.aborted), [CANCELLED_UPLOAD_ID])
        self.assertEqual(
            report.aborted[0].outcome, OUTCOME_ABORTED
        )
        # The completed upload whose notification was lost needs no call.
        self.assertEqual(
            self.ids(report.no_action), [COMPLETED_UPLOAD_ID]
        )
        self.assertEqual(
            report.no_action[0].outcome, OUTCOME_NO_ACTION
        )
        # The unrelated upload keeps running and is never terminated.
        self.assertEqual(
            [u['upload_id'] for u in report.unowned_uploads],
            [UNOWNED_UPLOAD_ID],
        )
        self.assertFalse(report.unowned_uploads[0]['expired'])

        remaining = self.journal().entries
        remaining_ids = [entry['upload_id'] for entry in remaining]
        self.assertNotIn(CANCELLED_UPLOAD_ID, remaining_ids)
        self.assertNotIn(COMPLETED_UPLOAD_ID, remaining_ids)

    def test_in_progress_owned_upload_is_left_untouched(self):
        self.record(IN_PROGRESS_UPLOAD_ID, STATE_IN_PROGRESS)
        self.add_list_response(
            [self.remote_upload(IN_PROGRESS_UPLOAD_ID)]
        )

        report = self.manager().recover(BUCKET, KEY)

        self.stubber.assert_no_pending_responses()
        self.assertEqual(self.ids(report.no_action), [IN_PROGRESS_UPLOAD_ID])
        self.assertEqual(report.aborted, [])
        # The credential is retained for a future run.
        self.assertIsNotNone(
            self.journal().get(BUCKET, KEY, IN_PROGRESS_UPLOAD_ID)
        )

    def test_other_in_progress_multipart_is_not_terminated(self):
        # The job only owns the cancelled upload; another job's upload under
        # the same object name must survive the recovery run untouched.
        self.record(CANCELLED_UPLOAD_ID, STATE_CANCELLED)
        self.add_list_response(
            [
                self.remote_upload(CANCELLED_UPLOAD_ID),
                self.remote_upload(UNOWNED_UPLOAD_ID),
            ]
        )
        self.add_abort_response(CANCELLED_UPLOAD_ID)

        report = self.manager().recover(BUCKET, KEY)

        self.stubber.assert_no_pending_responses()
        self.assertEqual(self.ids(report.aborted), [CANCELLED_UPLOAD_ID])
        self.assertEqual(
            [u['upload_id'] for u in report.unowned_uploads],
            [UNOWNED_UPLOAD_ID],
        )

    def test_completed_upload_still_open_goes_to_manual_review(self):
        self.record(COMPLETED_UPLOAD_ID, STATE_COMPLETED)
        self.add_list_response(
            [self.remote_upload(COMPLETED_UPLOAD_ID)]
        )

        report = self.manager().recover(BUCKET, KEY)

        self.stubber.assert_no_pending_responses()
        self.assertEqual(
            self.ids(report.manual_review), [COMPLETED_UPLOAD_ID]
        )
        self.assertEqual(
            report.manual_review[0].outcome, OUTCOME_MANUAL_REVIEW
        )
        self.assertEqual(report.aborted, [])
        self.assertEqual(
            self.journal().get(
                BUCKET, KEY, COMPLETED_UPLOAD_ID
            )['state'],
            STATE_MANUAL_REVIEW,
        )

    def test_in_progress_upload_vanished_goes_to_manual_review(self):
        self.record(IN_PROGRESS_UPLOAD_ID, STATE_IN_PROGRESS)
        self.add_list_response([])

        report = self.manager().recover(BUCKET, KEY)

        self.stubber.assert_no_pending_responses()
        self.assertEqual(
            self.ids(report.manual_review), [IN_PROGRESS_UPLOAD_ID]
        )
        self.assertEqual(report.aborted, [])

    def test_expired_credential_is_escalated_without_remote_mutation(self):
        old_timestamp = (
            self.now - datetime.timedelta(days=30)
        ).isoformat()
        self.record(
            CANCELLED_UPLOAD_ID,
            STATE_CANCELLED,
            initiated_at=old_timestamp,
        )
        self.add_list_response(
            [self.remote_upload(CANCELLED_UPLOAD_ID)]
        )

        report = self.manager(
            retention_age=datetime.timedelta(days=7)
        ).recover(BUCKET, KEY)

        self.stubber.assert_no_pending_responses()
        self.assertEqual(
            self.ids(report.manual_review), [CANCELLED_UPLOAD_ID]
        )
        self.assertEqual(report.aborted, [])

    def test_expired_unowned_upload_is_flagged_but_not_aborted(self):
        self.record(CANCELLED_UPLOAD_ID, STATE_CANCELLED)
        stale_initiated = self.now - datetime.timedelta(days=30)
        self.add_list_response(
            [
                self.remote_upload(CANCELLED_UPLOAD_ID),
                self.remote_upload(
                    UNOWNED_UPLOAD_ID, initiated=stale_initiated
                ),
            ]
        )
        self.add_abort_response(CANCELLED_UPLOAD_ID)

        report = self.manager(
            retention_age=datetime.timedelta(days=7)
        ).recover(BUCKET, KEY)

        self.stubber.assert_no_pending_responses()
        self.assertEqual(self.ids(report.aborted), [CANCELLED_UPLOAD_ID])
        unowned = report.unowned_uploads[0]
        self.assertEqual(unowned['upload_id'], UNOWNED_UPLOAD_ID)
        self.assertTrue(unowned['expired'])

    def test_abort_not_found_is_treated_as_already_finalized(self):
        self.record(CANCELLED_UPLOAD_ID, STATE_CANCELLED)
        self.add_list_response(
            [self.remote_upload(CANCELLED_UPLOAD_ID)]
        )
        self.add_abort_error(
            CANCELLED_UPLOAD_ID, 'NoSuchUpload', status_code=404
        )

        report = self.manager().recover(BUCKET, KEY)

        self.stubber.assert_no_pending_responses()
        self.assertEqual(report.aborted, [])
        self.assertEqual(
            self.ids(report.no_action), [CANCELLED_UPLOAD_ID]
        )
        # No terminal proof means the credential is retained, not deleted.
        self.assertIsNotNone(
            self.journal().get(BUCKET, KEY, CANCELLED_UPLOAD_ID)
        )

    def test_abort_failure_escalates_to_manual_review(self):
        self.record(CANCELLED_UPLOAD_ID, STATE_CANCELLED)
        self.add_list_response(
            [self.remote_upload(CANCELLED_UPLOAD_ID)]
        )
        self.add_abort_error(CANCELLED_UPLOAD_ID, 'AccessDenied')

        report = self.manager().recover(BUCKET, KEY)

        self.stubber.assert_no_pending_responses()
        self.assertEqual(
            self.ids(report.manual_review), [CANCELLED_UPLOAD_ID]
        )
        self.assertEqual(report.aborted, [])

    def test_cancelled_upload_already_gone_is_closed_out(self):
        self.record(CANCELLED_UPLOAD_ID, STATE_CANCELLED)
        self.add_list_response([])

        report = self.manager().recover(BUCKET, KEY)

        self.stubber.assert_no_pending_responses()
        self.assertEqual(
            self.ids(report.no_action), [CANCELLED_UPLOAD_ID]
        )
        self.assertEqual(self.journal().entries, [])

    def test_manual_review_entry_is_not_mutated_on_rerun(self):
        self.record(CANCELLED_UPLOAD_ID, STATE_MANUAL_REVIEW)
        self.add_list_response(
            [self.remote_upload(CANCELLED_UPLOAD_ID)]
        )

        first_run = self.manager().recover(BUCKET, KEY)
        self.assertEqual(
            self.ids(first_run.manual_review), [CANCELLED_UPLOAD_ID]
        )
        self.assertEqual(first_run.aborted, [])

        self.stubber.add_response(
            'list_multipart_uploads',
            service_response={
                'Uploads': [self.remote_upload(CANCELLED_UPLOAD_ID)],
                'IsTruncated': False,
            },
            expected_params={'Bucket': BUCKET, 'Prefix': KEY},
        )
        second_run = self.manager().recover(BUCKET, KEY)
        self.stubber.assert_no_pending_responses()
        self.assertEqual(
            self.ids(second_run.manual_review), [CANCELLED_UPLOAD_ID]
        )
        self.assertEqual(second_run.aborted, [])
        self.assertEqual(
            self.journal().get(
                BUCKET, KEY, CANCELLED_UPLOAD_ID
            )['state'],
            STATE_MANUAL_REVIEW,
        )

    def test_pagination_follows_upload_markers(self):
        self.record(CANCELLED_UPLOAD_ID, STATE_CANCELLED)
        first_page_upload = self.remote_upload(UNOWNED_UPLOAD_ID)
        second_page_upload = self.remote_upload(CANCELLED_UPLOAD_ID)
        self.stubber.add_response(
            'list_multipart_uploads',
            service_response={
                'Uploads': [first_page_upload],
                'IsTruncated': True,
                'NextKeyMarker': KEY,
                'NextUploadIdMarker': UNOWNED_UPLOAD_ID,
            },
            expected_params={'Bucket': BUCKET, 'Prefix': KEY},
        )
        self.stubber.add_response(
            'list_multipart_uploads',
            service_response={
                'Uploads': [second_page_upload],
                'IsTruncated': False,
            },
            expected_params={
                'Bucket': BUCKET,
                'Prefix': KEY,
                'KeyMarker': KEY,
                'UploadIdMarker': UNOWNED_UPLOAD_ID,
            },
        )
        self.add_abort_response(CANCELLED_UPLOAD_ID)

        report = self.manager().recover(BUCKET, KEY)

        self.stubber.assert_no_pending_responses()
        self.assertEqual(self.ids(report.aborted), [CANCELLED_UPLOAD_ID])
        self.assertEqual(
            [u['upload_id'] for u in report.unowned_uploads],
            [UNOWNED_UPLOAD_ID],
        )

    def test_prefix_filtering_keeps_only_exact_object_name(self):
        other_key = 'nightly/2026-11-24.tar.sidecar'
        self.record(CANCELLED_UPLOAD_ID, STATE_CANCELLED)
        self.add_list_response(
            [
                self.remote_upload(CANCELLED_UPLOAD_ID),
                self.remote_upload(UNOWNED_UPLOAD_ID, key=other_key),
            ]
        )
        self.add_abort_response(CANCELLED_UPLOAD_ID)

        report = self.manager().recover(BUCKET, KEY)

        self.stubber.assert_no_pending_responses()
        self.assertEqual(self.ids(report.aborted), [CANCELLED_UPLOAD_ID])
        self.assertEqual(report.unowned_uploads, [])

    def test_convenience_entry_point_recovers_from_disk(self):
        self.journal().record_upload(
            BUCKET,
            KEY,
            CANCELLED_UPLOAD_ID,
            state=STATE_CANCELLED,
            initiated_at=(
                self.now - datetime.timedelta(hours=1)
            ).isoformat(),
        )
        self.add_list_response(
            [self.remote_upload(CANCELLED_UPLOAD_ID)]
        )
        self.add_abort_response(CANCELLED_UPLOAD_ID)

        report = recover_multipart_uploads(
            self.client,
            self.journal_path,
            BUCKET,
            KEY,
            clock=self.clock,
        )

        self.stubber.assert_no_pending_responses()
        self.assertEqual(self.ids(report.aborted), [CANCELLED_UPLOAD_ID])
        self.assertEqual(self.journal().entries, [])

    def test_client_error_other_than_not_found_does_not_crash(self):
        self.record(IN_PROGRESS_UPLOAD_ID, STATE_IN_PROGRESS)
        self.stubber.add_client_error(
            'list_multipart_uploads',
            service_error_code='InternalError',
            http_status_code=500,
            expected_params={'Bucket': BUCKET, 'Prefix': KEY},
        )
        with self.assertRaises(ClientError):
            self.manager().recover(BUCKET, KEY)

    def test_records_for_other_buckets_are_ignored(self):
        self.journal().record_upload(
            'other-bucket', KEY, CANCELLED_UPLOAD_ID,
            state=STATE_CANCELLED,
        )
        self.add_list_response([])

        report = self.manager().recover(BUCKET, KEY)

        self.stubber.assert_no_pending_responses()
        self.assertEqual(report.records, [])
        self.assertIsNotNone(
            self.journal().get(
                'other-bucket', KEY, CANCELLED_UPLOAD_ID
            )
        )
