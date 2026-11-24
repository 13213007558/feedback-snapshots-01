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
import itertools
import logging
import threading
import time

from s3transfer.exceptions import (
    DeleteExpiredError,
    DeleteNotSentError,
    DeleteOutcomeUnknownError,
    DeleteRevokedError,
    DeleteTargetMismatchError,
)
from s3transfer.tasks import SubmissionTask, Task

logger = logging.getLogger(__name__)

# Outcomes recorded on a DeleteAttempt.
PENDING = 'pending'
SENT = 'sent'
NOT_SENT = 'not-sent'
SUCCEEDED = 'succeeded'
FAILED = 'failed'
OUTCOME_UNKNOWN = 'outcome-unknown'

_attempt_ids = itertools.count()


class DeleteAuthorization:
    """A single approval for one delegated object deletion.

    The approval fixes both *who* may delete (``delegate``) and *what* may be
    deleted. The target meaning is fixed by exactly one of:

    * ``version_id`` -- the exact object version approved for removal.
    * ``creates_delete_marker`` -- approval to only create a new delete
      marker (i.e. remove the current object without naming a version).

    An approval is valid between ``issued_at`` (if given) and ``expires_at``
    (if given) and until ``revoke()`` is called. Every check goes through a
    single lock so revocation is observed atomically with respect to the
    pre-send check.
    """

    def __init__(
        self,
        authorization_id=None,
        *,
        version_id=None,
        creates_delete_marker=False,
        delegate=None,
        expires_at=None,
        issued_at=None,
        clock=None,
    ):
        if version_id is not None and creates_delete_marker:
            raise ValueError(
                'A delete authorization must pin either an exact VersionId '
                'or the creation of a delete marker, not both.'
            )
        if version_id is None and not creates_delete_marker:
            raise ValueError(
                'A delete authorization must pin either an exact VersionId '
                'or the creation of a delete marker.'
            )
        if authorization_id is None:
            authorization_id = f'delete-auth-{next(_attempt_ids)}'
        self.authorization_id = authorization_id
        self.version_id = version_id
        self.creates_delete_marker = bool(creates_delete_marker)
        self.delegate = delegate
        self.issued_at = issued_at
        self.expires_at = expires_at
        self._clock = clock if clock is not None else time.time
        self._lock = threading.Lock()
        self._revoked = False
        self._revoked_reason = None
        self._attempts = []

    @property
    def target_version_id(self):
        """The VersionId value that must be sent, or None for a marker."""
        return self.version_id

    def revoke(self, reason=None):
        """Withdraw this authorization.

        A delete that has not been sent yet will be refused. A delete that is
        already on the wire is not affected; its caller receives
        :class:`DeleteOutcomeUnknownError` instead of a silent retry.
        """
        with self._lock:
            self._revoked = True
            if reason is not None:
                self._revoked_reason = reason

    @property
    def revoked(self):
        with self._lock:
            return self._revoked

    def register_attempt(self, attempt):
        with self._lock:
            self._attempts.append(attempt)

    @property
    def attempts(self):
        with self._lock:
            return list(self._attempts)

    def _check_locked(self):
        if self._revoked:
            reason = self._revoked_reason
            if reason:
                return f'authorization was revoked: {reason}'
            return 'authorization was revoked'
        now = self._clock()
        if self.issued_at is not None and now < self.issued_at:
            return 'authorization is not valid yet'
        if self.expires_at is not None and now >= self.expires_at:
            return 'authorization expired'
        return None

    def check(self):
        """Return None if still authorized, else a reason string."""
        with self._lock:
            return self._check_locked()

    def check_target(self, version_id=None):
        """Validate that an explicitly requested target matches approval.

        ``version_id`` is the caller-supplied target, or ``None`` when the
        caller relied on the approval alone. Raises
        :class:`DeleteTargetMismatchError` if the caller named a different
        version, or named any version for a marker-only approval.
        """
        if self.version_id is not None:
            if version_id is not None and version_id != self.version_id:
                raise DeleteTargetMismatchError(
                    f'Delete authorization {self.authorization_id} is pinned '
                    f'to version {self.version_id!r} but the request targets '
                    f'{version_id!r}.'
                )
        elif self.creates_delete_marker:
            if version_id is not None:
                raise DeleteTargetMismatchError(
                    f'Delete authorization {self.authorization_id} only '
                    'approves creating a delete marker, but the request '
                    f'targets version {version_id!r}.'
                )

    def refusal(self, attempt, reason):
        """Build the appropriate not-sent exception for this approval.

        The exception class reflects the actual withdrawal cause: revocation,
        expiry, or a local cancellation that never sent anything.
        """
        kwargs = {
            'bucket': attempt.bucket,
            'key': attempt.key,
            'version_id': self.version_id,
            'creates_delete_marker': self.creates_delete_marker,
            'authorization_id': self.authorization_id,
            'delegate': self.delegate,
            'attempt': attempt,
        }
        with self._lock:
            revoked = self._revoked
        if revoked:
            return DeleteRevokedError(reason, **kwargs)
        if self.expires_at is not None and self._clock() >= self.expires_at:
            return DeleteExpiredError(reason, **kwargs)
        return DeleteNotSentError(reason, **kwargs)


class DeleteAttempt:
    """A thread-safe audit record of one delegated delete attempt.

    This is the per-object record administrators and callers can reconcile
    against. It distinguishes, at the moment it is observed:

    * ``pending`` -- queued but no pre-send decision yet.
    * ``not-sent`` -- refused locally; no request left the process.
    * ``sent`` -- a request was handed to the HTTP layer, outcome not known.
    * ``succeeded`` / ``failed`` -- a definitive server outcome.

    ``sent_at`` is only set once a request has actually been dispatched, so
    ``request_sent`` is a durable fact rather than a guess derived from a
    cancelled future.
    """

    def __init__(self, authorization, *, bucket, key, clock=None):
        self.attempt_id = next(_attempt_ids)
        self.authorization = authorization
        self.authorization_id = authorization.authorization_id
        self.delegate = authorization.delegate
        self.bucket = bucket
        self.key = key
        # These are fixed by the approval so the record never drifts to a
        # different version than what was approved.
        self.version_id = authorization.version_id
        self.creates_delete_marker = authorization.creates_delete_marker
        self._clock = clock if clock is not None else time.time
        self._lock = threading.Lock()
        self._outcome = PENDING
        self._reason = None
        self._queued_at = self._clock()
        self._sent_at = None
        self._finished_at = None
        self._error = None
        authorization.register_attempt(self)

    @property
    def outcome(self):
        with self._lock:
            return self._outcome

    @property
    def reason(self):
        with self._lock:
            return self._reason

    @property
    def request_sent(self):
        with self._lock:
            return self._sent_at is not None

    @property
    def queued_at(self):
        return self._queued_at

    @property
    def sent_at(self):
        with self._lock:
            return self._sent_at

    @property
    def finished_at(self):
        with self._lock:
            return self._finished_at

    @property
    def error(self):
        with self._lock:
            return self._error

    def _transition(self, outcome, reason=None, error=None, mark_sent=False):
        with self._lock:
            # An ambiguous outcome is terminal. Once the caller has been told
            # the result is unknown, a request that resolves late (e.g. a hung
            # connection that eventually completes after cancel) must not
            # retroactively rewrite history to "succeeded".
            if self._outcome == OUTCOME_UNKNOWN:
                return
            if mark_sent and self._sent_at is None:
                self._sent_at = self._clock()
            if outcome in (SUCCEEDED, FAILED, NOT_SENT, OUTCOME_UNKNOWN):
                self._finished_at = self._clock()
            if reason is not None:
                self._reason = reason
            if error is not None:
                self._error = error
            self._outcome = outcome

    def mark_sent(self):
        """Record that a request was dispatched (outcome still unknown)."""
        self._transition(SENT, mark_sent=True)

    def mark_not_sent(self, reason):
        self._transition(NOT_SENT, reason=reason)

    def mark_succeeded(self):
        self._transition(SUCCEEDED, mark_sent=True)

    def mark_failed(self, error):
        self._transition(FAILED, error=error, mark_sent=True)

    def mark_outcome_unknown(self, error=None):
        self._transition(OUTCOME_UNKNOWN, error=error, mark_sent=True)

    def as_dict(self):
        with self._lock:
            return {
                'attempt_id': self.attempt_id,
                'authorization_id': self.authorization_id,
                'delegate': self.delegate,
                'bucket': self.bucket,
                'key': self.key,
                'version_id': self.version_id,
                'creates_delete_marker': self.creates_delete_marker,
                'outcome': self._outcome,
                'reason': self._reason,
                'request_sent': self._sent_at is not None,
                'queued_at': self._queued_at,
                'sent_at': self._sent_at,
                'finished_at': self._finished_at,
                'error': repr(self._error) if self._error else None,
            }

    def __repr__(self):
        data = self.as_dict()
        return (
            f'{self.__class__.__name__}(attempt_id={data["attempt_id"]}, '
            f'outcome={data["outcome"]!r}, request_sent={data["request_sent"]}, '
            f'bucket={data["bucket"]!r}, key={data["key"]!r}, '
            f'version_id={data["version_id"]!r})'
        )


class DeleteSubmissionTask(SubmissionTask):
    """Task for submitting tasks to execute an object deletion."""

    def _submit(self, client, request_executor, transfer_future, **kwargs):
        """
        :param client: The client associated with the transfer manager

        :type config: s3transfer.manager.TransferConfig
        :param config: The transfer config associated with the transfer
            manager

        :type osutil: s3transfer.utils.OSUtil
        :param osutil: The os utility associated to the transfer manager

        :type request_executor: s3transfer.futures.BoundedExecutor
        :param request_executor: The request executor associated with the
            transfer manager

        :type transfer_future: s3transfer.futures.TransferFuture
        :param transfer_future: The transfer future associated with the
            transfer request that tasks are being submitted for
        """
        call_args = transfer_future.meta.call_args

        authorization = getattr(call_args, 'authorization', None)
        if authorization is not None:
            delete_attempt = getattr(call_args, 'delete_attempt', None)
            if delete_attempt is None:
                delete_attempt = DeleteAttempt(
                    authorization,
                    bucket=call_args.bucket,
                    key=call_args.key,
                )
            self._transfer_coordinator.set_cancel_exception_factory(
                lambda default_exc: self._ambiguous_outcome(
                    delete_attempt, default_exc
                )
            )
            self._transfer_coordinator.submit(
                request_executor,
                DelegatedDeleteTask(
                    transfer_coordinator=self._transfer_coordinator,
                    authorization=authorization,
                    client=client,
                    bucket=call_args.bucket,
                    key=call_args.key,
                    attempt=delete_attempt,
                    extra_args=call_args.extra_args,
                    is_final=True,
                ),
            )
            return

        self._transfer_coordinator.submit(
            request_executor,
            DeleteObjectTask(
                transfer_coordinator=self._transfer_coordinator,
                main_kwargs={
                    'client': client,
                    'bucket': call_args.bucket,
                    'key': call_args.key,
                    'extra_args': call_args.extra_args,
                },
                is_final=True,
            ),
        )

    @staticmethod
    def _ambiguous_outcome(delete_attempt, default_exc):
        """Rewrite a cancellation that raced a send into an unknown outcome.

        Returns ``(exception, announce_now)``. When a request was already
        dispatched, ``announce_now`` is True so the caller waiting on the
        future is unblocked -- the local work is over even though the
        server-side result is unknown.
        """
        if not delete_attempt.request_sent:
            delete_attempt.mark_not_sent(
                'transfer cancelled before request was sent'
            )
            return default_exc, False
        delete_attempt.mark_outcome_unknown(default_exc)
        exception = DeleteOutcomeUnknownError(
            f'Delete request for {delete_attempt.bucket!r}/'
            f'{delete_attempt.key!r} (version {delete_attempt.version_id!r}) '
            'was sent before the transfer was cancelled; the server-side '
            'outcome is unknown.',
            bucket=delete_attempt.bucket,
            key=delete_attempt.key,
            version_id=delete_attempt.version_id,
            creates_delete_marker=delete_attempt.creates_delete_marker,
            authorization_id=delete_attempt.authorization_id,
            delegate=delete_attempt.delegate,
            attempt=delete_attempt,
        )
        return exception, True


class DeleteObjectTask(Task):
    def _main(self, client, bucket, key, extra_args):
        """

        :param client: The S3 client to use when calling DeleteObject

        :type bucket: str
        :param bucket: The name of the bucket.

        :type key: str
        :param key: The name of the object to delete.

        :type extra_args: dict
        :param extra_args: Extra arguments to pass to the DeleteObject call.

        """
        client.delete_object(Bucket=bucket, Key=key, **extra_args)


# Identifies the delegated delete currently executing on this thread so that
# per-task botocore event handlers never react to another task's request. The
# event emitter is shared by every transfer on a client, so a handler that did
# not check this would revalidate (or refuse) an unrelated delete.
_active_attempt = threading.local()


class DelegatedDeleteTask(Task):
    """A delete that revalidates its delegated approval right before sending.

    The approval is checked when the task actually runs, not just when it was
    queued, and it is checked again for every botocore retry. Two outcomes are
    kept distinct:

    * The approval was revoked (or expired) while the task waited for a free
      thread -- nothing is sent and the transfer fails with
      :class:`DeleteRevokedError` / :class:`DeleteExpiredError`, both of which
      are :class:`DeleteNotSentError` with ``request_sent == False``.
    * A request was already dispatched and then errored, hung, or the future
      was cancelled -- the transfer fails with
      :class:`DeleteOutcomeUnknownError` (``request_sent == True``) carrying
      the exact pinned target, so the caller cannot quietly re-delete a
      different version.

    The target meaning (exact ``VersionId`` vs. create-a-delete-marker) is
    fixed by the approval. The wire request is built from the approval, never
    from mutable ``extra_args`` supplied at execution time.
    """

    def __init__(
        self,
        transfer_coordinator,
        *,
        authorization,
        client,
        bucket,
        key,
        attempt=None,
        extra_args=None,
        is_final=False,
        **kwargs,
    ):
        super().__init__(
            transfer_coordinator=transfer_coordinator,
            is_final=is_final,
            **kwargs,
        )
        self._authorization = authorization
        self._client = client
        self._bucket = bucket
        self._key = key
        self._extra_args = dict(extra_args or {})
        self._attempt = attempt
        if self._attempt is None:
            self._attempt = DeleteAttempt(
                authorization, bucket=bucket, key=key
            )
        self._registered = False

    @property
    def authorization(self):
        return self._authorization

    @property
    def attempt(self):
        return self._attempt

    def _request_args(self):
        # Authorization and any caller-provided VersionId never reach the
        # wire. The version comes only from the fixed approval.
        request_args = {
            arg: value
            for arg, value in self._extra_args.items()
            if arg not in ('Authorization', 'VersionId')
        }
        version_id = self._authorization.version_id
        if version_id is not None:
            request_args['VersionId'] = version_id
        return request_args

    def _main(self):
        authorization = self._authorization
        attempt = self._attempt

        reason = self._pre_send_refusal()
        if reason is not None:
            attempt.mark_not_sent(reason)
            raise authorization.refusal(attempt, reason)

        self._send(attempt)

    def _pre_send_refusal(self):
        coordinator = self._transfer_coordinator
        if coordinator.done():
            # A cancelled queued transfer is a local refusal: nothing sent.
            return 'transfer cancelled before request was sent'
        return self._authorization.check()

    def _send(self, attempt):
        unique_id = f's3transfer-delegated-delete-{attempt.attempt_id}'
        events = self._client.meta.events
        events.register_first(
            'before-send.s3.DeleteObject',
            self._gate_before_send,
            unique_id=unique_id,
        )
        events.register(
            'needs-retry.s3.DeleteObject',
            self._gate_needs_retry,
            unique_id=unique_id,
        )
        self._registered = True
        _active_attempt.task = self
        try:
            self._client.delete_object(
                Bucket=self._bucket, Key=self._key, **self._request_args()
            )
        except DeleteNotSentError as e:
            if attempt.outcome != NOT_SENT:
                attempt.mark_not_sent(str(e) or 'authorization revoked')
            raise
        except DeleteOutcomeUnknownError:
            raise
        except Exception as e:
            if not attempt.request_sent:
                # The request never reached the transport. It is safe to
                # report a definite failure rather than an ambiguous outcome.
                attempt.mark_failed(e)
                raise
            attempt.mark_outcome_unknown(e)
            raise DeleteOutcomeUnknownError(
                f'Delete request for {self._bucket!r}/{self._key!r} '
                f'(version {attempt.version_id!r}) was sent but did not '
                f'complete: {e}',
                bucket=attempt.bucket,
                key=attempt.key,
                version_id=attempt.version_id,
                creates_delete_marker=attempt.creates_delete_marker,
                authorization_id=attempt.authorization_id,
                delegate=attempt.delegate,
                attempt=attempt,
            ) from e
        else:
            attempt.mark_succeeded()
        finally:
            _active_attempt.task = None
            self._unregister_gates(events, unique_id)

    def _gate_before_send(self, request=None, **kwargs):
        """Last check before the request is handed to the transport.

        Marking the attempt as sent happens here, immediately before the
        transport send, so ``request_sent`` reflects what actually left the
        process and not merely that a client method was entered.
        """
        if getattr(_active_attempt, 'task', None) is not self:
            return None
        reason = self._authorization.check()
        if reason is None and self._transfer_coordinator.done():
            if self._attempt.request_sent:
                reason = 'transfer was cancelled after the request was sent'
            else:
                reason = 'transfer cancelled before request was sent'
        if reason is None:
            if not self._attempt.request_sent:
                self._attempt.mark_sent()
            return None
        # A botocore retry reaching this point means an earlier attempt was
        # already dispatched, so the outcome is ambiguous, not "not sent".
        if self._attempt.request_sent:
            error = DeleteOutcomeUnknownError(
                f'Delete authorization {self._authorization.authorization_id} '
                f'became invalid ({reason}) after a request for '
                f'{self._bucket!r}/{self._key!r} (version '
                f'{self._attempt.version_id!r}) was sent.',
                bucket=self._attempt.bucket,
                key=self._attempt.key,
                version_id=self._attempt.version_id,
                creates_delete_marker=self._attempt.creates_delete_marker,
                authorization_id=self._attempt.authorization_id,
                delegate=self._attempt.delegate,
                attempt=self._attempt,
            )
            self._attempt.mark_outcome_unknown(error)
            raise error
        refusal = self._authorization.refusal(self._attempt, reason)
        self._attempt.mark_not_sent(reason)
        raise refusal

    def _gate_needs_retry(self, **kwargs):
        """Never resend a delegated delete whose approval was revoked."""
        if getattr(_active_attempt, 'task', None) is not self:
            return None
        if self._authorization.check() is None:
            return None
        return False

    def _unregister_gates(self, events, unique_id):
        if not self._registered:
            return
        events.unregister('before-send.s3.DeleteObject', unique_id=unique_id)
        events.unregister('needs-retry.s3.DeleteObject', unique_id=unique_id)
        self._registered = False
