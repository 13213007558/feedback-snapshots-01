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
"""Recovery of multipart uploads left behind by a crashed process.

A long running archive job registers every multipart upload it creates in a
local journal. The journal is the only proof of ownership that survives a
restart: when the process comes back up it can distinguish its own uploads
from unrelated uploads sharing the same object name and reconcile each one
against the actual remote state instead of blindly aborting everything that
``ListMultipartUploads`` returns.

The decision for every journal entry is driven by the original job credential
recorded in the journal and the state of the upload in S3. Uploads that cannot
be reconciled safely are never mutated; they are handed off for manual review
so that in progress uploads owned by other jobs keep running undisturbed.
"""
import datetime
import json
import os
import tempfile

from botocore.exceptions import ClientError

# Terminal states written by the owning job while it is running.
STATE_IN_PROGRESS = 'in-progress'
STATE_COMPLETED = 'completed'
STATE_CANCELLED = 'cancelled'
# State written onto entries that need a human rather than an automatic call.
STATE_MANUAL_REVIEW = 'manual-review'

# Outcomes produced by the recovery run.
OUTCOME_ABORTED = 'aborted'
OUTCOME_NO_ACTION = 'no-action'
OUTCOME_MANUAL_REVIEW = 'manual-review'

_NOT_FOUND_CODES = {'404', 'NoSuchUpload', 'NotFound'}


class RecoveryRecord:
    """The reconciliation decision for a single multipart upload.

    :type bucket: str
    :param bucket: The bucket the upload belongs to.

    :type key: str
    :param key: The object name the upload targets.

    :type upload_id: str
    :param upload_id: The concrete multipart upload id. Multiple uploads can
        share the same object name, so the id is what makes a record unique.

    :type state: str
    :param state: The state the owning job recorded in its journal.

    :type outcome: str
    :param outcome: What the recovery run did with the upload.

    :type reason: str
    :param reason: Why the outcome was chosen.
    """

    def __init__(self, bucket, key, upload_id, state, outcome, reason):
        self.bucket = bucket
        self.key = key
        self.upload_id = upload_id
        self.state = state
        self.outcome = outcome
        self.reason = reason

    def __eq__(self, other):
        if not isinstance(other, RecoveryRecord):
            return NotImplemented
        return self.__dict__ == other.__dict__

    def __repr__(self):
        return (
            'RecoveryRecord(bucket={!r}, key={!r}, upload_id={!r}, '
            'state={!r}, outcome={!r}, reason={!r})'.format(
                self.bucket,
                self.key,
                self.upload_id,
                self.state,
                self.outcome,
                self.reason,
            )
        )


class RecoveryReport:
    """Summary of everything a recovery run observed and decided."""

    def __init__(self):
        self.records = []
        # Remote uploads that no journal entry claims ownership of. They are
        # reported but never touched.
        self.unowned_uploads = []

    @property
    def aborted(self):
        return [
            record
            for record in self.records
            if record.outcome == OUTCOME_ABORTED
        ]

    @property
    def manual_review(self):
        return [
            record
            for record in self.records
            if record.outcome == OUTCOME_MANUAL_REVIEW
        ]

    @property
    def no_action(self):
        return [
            record
            for record in self.records
            if record.outcome == OUTCOME_NO_ACTION
        ]

    def add(self, record):
        self.records.append(record)


class MultipartUploadJournal:
    """Persistent ownership ledger for the multipart uploads of one job.

    The journal is a JSON document. One entry maps a concrete
    ``(bucket, key, upload_id)`` triple to the credential the owning job used
    to create it, which is what makes cleanup precise when several uploads
    share an object name.
    """

    def __init__(self, journal_path):
        self.journal_path = journal_path
        self.entries = []
        self._load()

    def _load(self):
        if not os.path.exists(self.journal_path):
            self.entries = []
            return
        with open(self.journal_path, encoding='utf-8') as journal_file:
            document = json.load(journal_file)
        self.entries = document.get('uploads', [])

    def _persist(self):
        directory = os.path.dirname(os.path.abspath(self.journal_path))
        fd, tmp_path = tempfile.mkstemp(
            prefix='.multipart-journal-', dir=directory
        )
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as journal_file:
                json.dump(
                    {'uploads': self.entries},
                    journal_file,
                    indent=2,
                    sort_keys=True,
                )
            os.replace(tmp_path, self.journal_path)
        except Exception:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    def get(self, bucket, key, upload_id):
        for entry in self.entries:
            if (
                entry['bucket'] == bucket
                and entry['key'] == key
                and entry['upload_id'] == upload_id
            ):
                return entry
        return None

    def record_upload(
        self,
        bucket,
        key,
        upload_id,
        source=None,
        parts=None,
        state=STATE_IN_PROGRESS,
        initiated_at=None,
        extra_args=None,
    ):
        """Add or replace the entry for a concrete upload id."""
        entry = self.get(bucket, key, upload_id)
        if entry is None:
            entry = {}
            self.entries.append(entry)
        entry.update(
            {
                'bucket': bucket,
                'key': key,
                'upload_id': upload_id,
                'source': source,
                'parts': list(parts) if parts is not None else [],
                'state': state,
                'initiated_at': initiated_at,
                'extra_args': dict(extra_args) if extra_args else {},
            }
        )
        self._persist()
        return entry

    def mark_state(self, bucket, key, upload_id, state):
        entry = self.get(bucket, key, upload_id)
        if entry is None:
            raise KeyError(
                'No journal entry for upload {} on s3://{}/{}'.format(
                    upload_id, bucket, key
                )
            )
        entry['state'] = state
        self._persist()
        return entry

    def remove(self, bucket, key, upload_id):
        self.entries = [
            entry
            for entry in self.entries
            if not (
                entry['bucket'] == bucket
                and entry['key'] == key
                and entry['upload_id'] == upload_id
            )
        ]
        self._persist()


class MultipartUploadRecoveryManager:
    """Reconciles a journal against the multipart uploads still open in S3.

    The manager only ever acts on uploads that the journal proves the job
    created. Remote uploads without a matching ownership record are observed
    and reported but left alone, and any record that is expired or cannot be
    reconciled against the remote state is escalated instead of mutated.
    """

    def __init__(self, client, journal, retention_age=None, clock=None):
        """
        :type client: botocore.client.BaseClient
        :param client: The S3 client to query and reconcile with.

        :type journal: s3transfer.recovery.MultipartUploadJournal
        :param journal: The ownership ledger written before the restart.

        :type retention_age: datetime.timedelta
        :param retention_age: Entries older than this are considered expired
            and escalated without any remote mutation. ``None`` disables the
            expiration check.

        :type clock: callable
        :param clock: Returns the current timezone aware datetime. Defaults to
            ``datetime.datetime.now`` with UTC. Injected for testing.
        """
        self._client = client
        self._journal = journal
        self._retention_age = retention_age
        self._clock = clock or (
            lambda: datetime.datetime.now(datetime.timezone.utc)
        )

    def recover(self, bucket, key=None):
        """Run the recovery entry point and reconcile every owned upload.

        :type bucket: str
        :param bucket: The bucket the archive job uploaded into.

        :type key: str
        :param key: Optional object name to restrict the scan to.

        :rtype: s3transfer.recovery.RecoveryReport
        :returns: The decision and outcome for every upload considered.
        """
        report = RecoveryReport()
        remote_uploads = self._list_remote_uploads(bucket, key)
        remote_by_id = {
            upload['UploadId']: upload for upload in remote_uploads
        }
        # Snapshot ownership before reconciliation: entries that are resolved
        # and removed during this run must not be reclassified as unowned.
        owned_ids = {entry['upload_id'] for entry in self._journal.entries}

        for entry in list(self._journal.entries):
            if entry['bucket'] != bucket:
                continue
            if key is not None and entry['key'] != key:
                continue
            if entry.get('state') == STATE_MANUAL_REVIEW:
                # A previous run already escalated this credential. Do not
                # mutate it again; keep waiting for the human decision.
                report.add(
                    RecoveryRecord(
                        entry['bucket'],
                        entry['key'],
                        entry['upload_id'],
                        STATE_MANUAL_REVIEW,
                        OUTCOME_MANUAL_REVIEW,
                        'Already escalated for manual review in a previous '
                        'run',
                    )
                )
                continue
            self._reconcile_entry(entry, remote_by_id, report)

        self._report_unowned_uploads(
            bucket, remote_uploads, owned_ids, report
        )
        return report

    def _list_remote_uploads(self, bucket, key):
        uploads = []
        kwargs = {'Bucket': bucket}
        if key is not None:
            # An exact key match is applied after the prefix listing; an S3
            # prefix can return more than one upload when keys share prefixes.
            kwargs['Prefix'] = key
        while True:
            response = self._client.list_multipart_uploads(**kwargs)
            page = response.get('Uploads') or []
            if key is not None:
                page = [upload for upload in page if upload.get('Key') == key]
            uploads.extend(page)
            if not response.get('IsTruncated'):
                break
            kwargs['KeyMarker'] = response['NextKeyMarker']
            kwargs['UploadIdMarker'] = response['NextUploadIdMarker']
        return uploads

    def _reconcile_entry(self, entry, remote_by_id, report):
        bucket = entry['bucket']
        key = entry['key']
        upload_id = entry['upload_id']
        state = entry.get('state', STATE_IN_PROGRESS)

        if self._is_expired(entry):
            report.add(
                self._manual_review(
                    entry,
                    'Journal entry is older than the retention window and '
                    'cannot be reclaimed automatically',
                )
            )
            return

        remote_upload = remote_by_id.get(upload_id)
        if state == STATE_COMPLETED:
            self._recover_completed(entry, remote_upload, report)
            return
        if state == STATE_CANCELLED:
            self._recover_cancelled(entry, remote_upload, report)
            return
        self._recover_in_progress(entry, remote_upload, report)

    def _recover_completed(self, entry, remote_upload, report):
        bucket = entry['bucket']
        key = entry['key']
        upload_id = entry['upload_id']
        if remote_upload is None:
            # The upload is no longer open. It either completed server side
            # (the local completion notification was lost) or was otherwise
            # finalized. There is nothing left to abort, so trust the job's
            # own completion credential and close out its record.
            self._journal.remove(bucket, key, upload_id)
            report.add(
                RecoveryRecord(
                    bucket,
                    key,
                    upload_id,
                    STATE_COMPLETED,
                    OUTCOME_NO_ACTION,
                    'Upload is no longer open; the server side completion '
                    'succeeded but the local notification was lost',
                )
            )
            return

        # The job believed it completed while S3 still holds the upload open.
        # That contradiction is not safe to resolve with an abort, so the
        # record goes to a human with the remote evidence attached.
        report.add(
            self._manual_review(
                entry,
                'Journal marks the upload completed but it is still open in '
                'S3 (initiated {})'.format(
                    remote_upload.get('Initiated')
                ),
            )
        )

    def _recover_cancelled(self, entry, remote_upload, report):
        bucket = entry['bucket']
        key = entry['key']
        upload_id = entry['upload_id']
        if remote_upload is None:
            self._journal.remove(bucket, key, upload_id)
            report.add(
                RecoveryRecord(
                    bucket,
                    key,
                    upload_id,
                    STATE_CANCELLED,
                    OUTCOME_NO_ACTION,
                    'Cancel was already honored server side; no open upload '
                    'remains',
                )
            )
            return
        if self._abort_upload(entry, report):
            self._journal.remove(bucket, key, upload_id)

    def _recover_in_progress(self, entry, remote_upload, report):
        bucket = entry['bucket']
        key = entry['key']
        upload_id = entry['upload_id']
        if remote_upload is None:
            # The upload vanished without a terminal journal state. It may
            # have completed under another process or been aborted by a
            # bucket policy. Without ownership evidence of the outcome, do
            # not guess and do not delete the credential.
            report.add(
                self._manual_review(
                    entry,
                    'Owned upload is no longer open but the journal never '
                    'recorded a terminal state',
                )
            )
            return
        report.add(
            RecoveryRecord(
                bucket,
                key,
                upload_id,
                STATE_IN_PROGRESS,
                OUTCOME_NO_ACTION,
                'Upload is still in progress; leaving it and all of its '
                'parts untouched',
            )
        )

    def _abort_upload(self, entry, report):
        bucket = entry['bucket']
        key = entry['key']
        upload_id = entry['upload_id']
        try:
            self._client.abort_multipart_upload(
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
            )
        except ClientError as error:
            if self._is_not_found(error):
                # Another actor finalized it between listing and abort. The
                # remote state is now authoritative; nothing was terminated.
                report.add(
                    RecoveryRecord(
                        bucket,
                        key,
                        upload_id,
                        entry.get('state', STATE_IN_PROGRESS),
                        OUTCOME_NO_ACTION,
                        'Upload disappeared before abort ran; remote state '
                        'is now authoritative',
                    )
                )
                return False
            report.add(
                self._manual_review(
                    entry,
                    'AbortMultipartUpload failed: {}'.format(
                        self._error_message(error)
                    ),
                )
            )
            return False
        report.add(
            RecoveryRecord(
                bucket,
                key,
                upload_id,
                entry.get('state', STATE_IN_PROGRESS),
                OUTCOME_ABORTED,
                'Aborted per the cancelled credential recorded by the '
                'owning job',
            )
        )
        return True

    def _report_unowned_uploads(
        self, bucket, remote_uploads, owned_ids, report
    ):
        now = self._clock()
        for upload in remote_uploads:
            upload_id = upload['UploadId']
            if upload_id in owned_ids:
                continue
            # No journal entry proves this job created this upload, so it must
            # never be aborted. Only expired strangers are escalated; active
            # ones keep running and are simply reported for observability.
            initiated = self._coerce_datetime(upload.get('Initiated'))
            expired = (
                self._retention_age is not None
                and initiated is not None
                and self._elapsed(now, initiated) > self._retention_age
            )
            report.unowned_uploads.append(
                {
                    'bucket': bucket,
                    'key': upload.get('Key'),
                    'upload_id': upload_id,
                    'initiated': upload.get('Initiated'),
                    'expired': expired,
                }
            )

    def _manual_review(self, entry, reason):
        self._journal.mark_state(
            entry['bucket'],
            entry['key'],
            entry['upload_id'],
            STATE_MANUAL_REVIEW,
        )
        return RecoveryRecord(
            entry['bucket'],
            entry['key'],
            entry['upload_id'],
            STATE_MANUAL_REVIEW,
            OUTCOME_MANUAL_REVIEW,
            reason,
        )

    def _is_expired(self, entry):
        if self._retention_age is None:
            return False
        initiated = self._coerce_datetime(entry.get('initiated_at'))
        if initiated is None:
            # No timestamp means no proof of how old the credential is. Treat
            # the absence of evidence as ineligible for automatic cleanup.
            return False
        return (
            self._elapsed(self._clock(), initiated) > self._retention_age
        )

    @staticmethod
    def _elapsed(now, initiated):
        if now.tzinfo is None and initiated.tzinfo is not None:
            now = now.replace(tzinfo=datetime.timezone.utc)
        elif now.tzinfo is not None and initiated.tzinfo is None:
            initiated = initiated.replace(tzinfo=datetime.timezone.utc)
        return now - initiated

    @staticmethod
    def _coerce_datetime(value):
        if value is None or isinstance(value, datetime.datetime):
            return value
        try:
            parsed = datetime.datetime.fromisoformat(str(value))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
        return parsed

    @staticmethod
    def _is_not_found(error):
        code = error.response.get('Error', {}).get('Code', '')
        status = error.response.get('ResponseMetadata', {}).get(
            'HTTPStatusCode'
        )
        return code in _NOT_FOUND_CODES or str(status) in _NOT_FOUND_CODES

    @staticmethod
    def _error_message(error):
        return error.response.get('Error', {}).get('Message', str(error))


def recover_multipart_uploads(
    client,
    journal_path,
    bucket,
    key=None,
    retention_age=None,
    clock=None,
):
    """Convenience entry point for the post restart recovery run.

    :type client: botocore.client.BaseClient
    :param client: The S3 client for the archive job's own credentials.

    :type journal_path: str
    :param journal_path: Path to the journal the job wrote while running.

    :type bucket: str
    :param bucket: The bucket to reconcile.

    :type key: str
    :param key: Optional object name to restrict reconciliation to.

    :type retention_age: datetime.timedelta
    :param retention_age: Credentials older than this are escalated instead
        of being reclaimed automatically.

    :type clock: callable
    :param clock: Injected clock for deterministic expiration tests.

    :rtype: s3transfer.recovery.RecoveryReport
    """
    journal = MultipartUploadJournal(journal_path)
    manager = MultipartUploadRecoveryManager(
        client,
        journal,
        retention_age=retention_age,
        clock=clock,
    )
    return manager.recover(bucket, key)
