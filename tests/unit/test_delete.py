# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
import threading
import time

from botocore.awsrequest import AWSResponse
from botocore.exceptions import ReadTimeoutError

from s3transfer.delete import (
    NOT_SENT,
    OUTCOME_UNKNOWN,
    SUCCEEDED,
    DeleteAuthorization,
    DeleteObjectTask,
)
from s3transfer.exceptions import (
    DeleteExpiredError,
    DeleteOutcomeUnknownError,
    DeleteRevokedError,
    DeleteTargetMismatchError,
)
from s3transfer.manager import TransferConfig, TransferManager
from tests import BaseTaskTest, StubbedClientTest, unittest


class TestDeleteObjectTask(BaseTaskTest):
    def setUp(self):
        super().setUp()
        self.bucket = 'mybucket'
        self.key = 'mykey'
        self.extra_args = {}
        self.callbacks = []

    def get_delete_task(self, **kwargs):
        default_kwargs = {
            'client': self.client,
            'bucket': self.bucket,
            'key': self.key,
            'extra_args': self.extra_args,
        }
        default_kwargs.update(kwargs)
        return self.get_task(DeleteObjectTask, main_kwargs=default_kwargs)

    def test_main(self):
        self.stubber.add_response(
            'delete_object',
            service_response={},
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
            },
        )
        task = self.get_delete_task()
        task()

        self.stubber.assert_no_pending_responses()

    def test_extra_args(self):
        self.extra_args['MFA'] = 'mfa-code'
        self.extra_args['VersionId'] = '12345'
        self.stubber.add_response(
            'delete_object',
            service_response={},
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
                # These extra_args should be injected into the
                # expected params for the delete_object call.
                'MFA': 'mfa-code',
                'VersionId': '12345',
            },
        )
        task = self.get_delete_task()
        task()

        self.stubber.assert_no_pending_responses()


class _RawBody:
    def stream(self, **kwargs):
        yield b''


class Transport:
    """A transport-level stand-in for DeleteObject.

    It answers at ``before-send`` (the same point a real socket would be
    used), so it exercises the delegated delete's pre-send gate. Named
    versions can be held until released, and any version can be made to fail
    with an exception that simulates a hung or broken connection.
    """

    def __init__(self):
        self.sent = []
        self._releases = {}
        self._entered = {}
        self._errors = {}
        self._lock = threading.Lock()

    @staticmethod
    def _version_of(request):
        query = request.url.split('?', 1)[-1]
        for part in query.split('&'):
            if part.startswith('versionId='):
                return part.split('=', 1)[1]
        return None

    def install(self, client):
        def handler(request=None, **kwargs):
            version = self._version_of(request)
            with self._lock:
                self.sent.append(version)
                self._entered.setdefault(version, threading.Event()).set()
            release = self._releases.get(version)
            if release is not None:
                release.wait(10)
            error = self._errors.get(version)
            if error is not None:
                raise error
            return AWSResponse(request.url, 204, {}, _RawBody())

        client.meta.events.register('before-send.s3.DeleteObject', handler)
        return self

    def hold(self, version):
        self._releases[version] = threading.Event()
        self._entered[version] = threading.Event()

    def fail(self, version, error):
        self._errors[version] = error

    def wait_until_entered(self, version, timeout=5):
        return self._entered[version].wait(timeout)

    def release(self, version):
        self._releases[version].set()


class TestDeleteAuthorization(unittest.TestCase):
    def test_pins_exact_version(self):
        auth = DeleteAuthorization(version_id='v-1', delegate='team-a')
        self.assertEqual(auth.version_id, 'v-1')
        self.assertFalse(auth.creates_delete_marker)
        self.assertIsNone(auth.check())

    def test_pins_delete_marker(self):
        auth = DeleteAuthorization(creates_delete_marker=True)
        self.assertTrue(auth.creates_delete_marker)
        self.assertIsNone(auth.version_id)

    def test_requires_exactly_one_target_meaning(self):
        with self.assertRaises(ValueError):
            DeleteAuthorization()
        with self.assertRaises(ValueError):
            DeleteAuthorization(version_id='v-1', creates_delete_marker=True)

    def test_check_target_rejects_other_version(self):
        auth = DeleteAuthorization(version_id='v-1')
        auth.check_target('v-1')
        auth.check_target(None)
        with self.assertRaises(DeleteTargetMismatchError):
            auth.check_target('v-2')

    def test_marker_approval_rejects_explicit_version(self):
        auth = DeleteAuthorization(creates_delete_marker=True)
        auth.check_target(None)
        with self.assertRaises(DeleteTargetMismatchError):
            auth.check_target('v-1')

    def test_revoke_is_observed(self):
        auth = DeleteAuthorization(version_id='v-1')
        self.assertIsNone(auth.check())
        auth.revoke('approval pulled')
        self.assertIn('revoked', auth.check())


class _DelegatedDeleteTest(StubbedClientTest):
    """Base for tests that drive a real client through the request pipeline.

    ``StubbedClientTest`` gives a real botocore S3 client; these tests replace
    the transport rather than the API call, because delegation is enforced at
    ``before-send``.
    """

    def setUp(self):
        super().setUp()
        # Drop the stubber so requests reach the transport responder below.
        self.stubber.deactivate()
        self.bucket = 'mybucket'
        self.key = 'mykey'
        self.transport = Transport().install(self.client)
        self.manager = TransferManager(
            self.client,
            TransferConfig(
                max_request_concurrency=1, max_submission_concurrency=1
            ),
        )

    def tearDown(self):
        self.manager.shutdown()
        super().tearDown()

    def record_params(self):
        seen = []
        self.client.meta.events.register(
            'before-parameter-build.s3.DeleteObject',
            lambda model, params, context, **kwargs: seen.append(dict(params)),
        )
        return seen


class TestDelegatedDelete(_DelegatedDeleteTest):
    def test_sends_pinned_version_and_records_success(self):
        seen = self.record_params()
        auth = DeleteAuthorization(version_id='v-1', delegate='team-a')
        future = self.manager.delete(self.bucket, self.key, authorization=auth)
        future.result()

        self.assertEqual(seen[0]['VersionId'], 'v-1')
        attempt = auth.attempts[0]
        self.assertEqual(attempt.outcome, SUCCEEDED)
        self.assertTrue(attempt.request_sent)
        self.assertEqual(attempt.version_id, 'v-1')
        self.assertEqual(attempt.delegate, 'team-a')

    def test_marker_approval_sends_no_version(self):
        seen = self.record_params()
        auth = DeleteAuthorization(creates_delete_marker=True)
        self.manager.delete(self.bucket, self.key, authorization=auth).result()

        self.assertNotIn('VersionId', seen[0])
        self.assertTrue(auth.attempts[0].request_sent)
        self.assertTrue(auth.attempts[0].creates_delete_marker)

    def test_rejects_conflicting_version_before_enqueueing(self):
        auth = DeleteAuthorization(version_id='v-1')
        with self.assertRaises(DeleteTargetMismatchError):
            self.manager.delete(
                self.bucket,
                self.key,
                extra_args={'VersionId': 'v-2'},
                authorization=auth,
            )
        self.assertEqual(auth.attempts, [])
        self.assertEqual(self.transport.sent, [])

    def test_revoked_while_queued_is_not_sent(self):
        self.transport.hold('v-hold')
        blocker = self.manager.delete(
            self.bucket,
            self.key,
            authorization=DeleteAuthorization(version_id='v-hold'),
        )
        self.assertTrue(self.transport.wait_until_entered('v-hold'))

        queued_auth = DeleteAuthorization(
            version_id='v-queued', delegate='team-b'
        )
        queued = self.manager.delete(
            self.bucket, self.key, authorization=queued_auth
        )
        queued_auth.revoke('approval pulled for team-b')

        self.transport.release('v-hold')
        blocker.result()
        with self.assertRaises(DeleteRevokedError) as ctx:
            queued.result()

        exc = ctx.exception
        self.assertFalse(exc.request_sent)
        self.assertEqual(exc.version_id, 'v-queued')
        self.assertEqual(exc.delegate, 'team-b')
        attempt = queued_auth.attempts[0]
        self.assertEqual(attempt.outcome, NOT_SENT)
        self.assertFalse(attempt.request_sent)
        self.assertIsNone(attempt.sent_at)
        self.assertEqual(self.transport.sent, ['v-hold'])

    def test_sent_then_hung_and_cancelled_is_outcome_unknown(self):
        self.transport.hold('v-sent')
        auth = DeleteAuthorization(version_id='v-sent', delegate='team-a')
        future = self.manager.delete(self.bucket, self.key, authorization=auth)
        self.assertTrue(self.transport.wait_until_entered('v-sent'))
        attempt = auth.attempts[0]
        self.assertTrue(attempt.request_sent)

        # The caller gives up while the request is on the wire.
        future.cancel()
        with self.assertRaises(DeleteOutcomeUnknownError) as ctx:
            future.result()

        exc = ctx.exception
        self.assertTrue(exc.request_sent)
        self.assertEqual(exc.version_id, 'v-sent')
        self.assertEqual(exc.delegate, 'team-a')
        self.assertEqual(attempt.outcome, OUTCOME_UNKNOWN)
        self.assertTrue(attempt.request_sent)

        # Even if the hung connection later succeeds, the record must not be
        # rewritten to claim a definite success.
        self.transport.release('v-sent')
        self.manager.shutdown()
        self.assertEqual(attempt.outcome, OUTCOME_UNKNOWN)
        self.assertEqual(attempt.version_id, 'v-sent')
        # A second result() must keep reporting the ambiguous outcome rather
        # than flipping to success once the late response arrives.
        with self.assertRaises(DeleteOutcomeUnknownError):
            future.result()

    def test_send_failure_after_dispatch_is_outcome_unknown(self):
        self.transport.fail(
            'v-broken', ReadTimeoutError(endpoint_url='https://bucket.s3')
        )
        auth = DeleteAuthorization(version_id='v-broken')
        future = self.manager.delete(self.bucket, self.key, authorization=auth)
        with self.assertRaises(DeleteOutcomeUnknownError) as ctx:
            future.result()

        self.assertTrue(ctx.exception.request_sent)
        self.assertEqual(ctx.exception.version_id, 'v-broken')
        self.assertEqual(auth.attempts[0].outcome, OUTCOME_UNKNOWN)
        self.assertIn('v-broken', self.transport.sent)

    def test_expiry_before_send_is_not_sent(self):
        self.transport.hold('v-hold')
        blocker = self.manager.delete(
            self.bucket,
            self.key,
            authorization=DeleteAuthorization(version_id='v-hold'),
        )
        self.assertTrue(self.transport.wait_until_entered('v-hold'))

        now = [time.time()]
        expiring = DeleteAuthorization(
            version_id='v-expiring',
            expires_at=now[0] + 60,
            clock=lambda: now[0],
        )
        queued = self.manager.delete(
            self.bucket, self.key, authorization=expiring
        )
        now[0] += 120
        self.transport.release('v-hold')
        blocker.result()

        with self.assertRaises(DeleteExpiredError) as ctx:
            queued.result()
        self.assertFalse(ctx.exception.request_sent)
        self.assertEqual(expiring.attempts[0].outcome, NOT_SENT)


class TestDeleteWithoutAuthorization(StubbedClientTest):
    def test_non_delegated_delete_unchanged(self):
        self.stubber.add_response(
            'delete_object',
            service_response={},
            expected_params={'Bucket': 'b', 'Key': 'k', 'VersionId': 'v-9'},
        )
        manager = TransferManager(self.client)
        manager.delete('b', 'k', extra_args={'VersionId': 'v-9'}).result()
        self.stubber.assert_no_pending_responses()
        manager.shutdown()
