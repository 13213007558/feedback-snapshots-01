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
from concurrent.futures import CancelledError


class RetriesExceededError(Exception):
    def __init__(self, last_exception, msg='Max Retries Exceeded'):
        super().__init__(msg)
        self.last_exception = last_exception


class S3UploadFailedError(Exception):
    pass


class S3DownloadFailedError(Exception):
    pass


class S3CopyFailedError(Exception):
    pass


class InvalidSubscriberMethodError(Exception):
    pass


class TransferNotDoneError(Exception):
    pass


class FatalError(CancelledError):
    """A CancelledError raised from an error in the TransferManager"""

    pass


class S3ValidationError(Exception):
    pass


class DeleteTargetMismatchError(ValueError):
    """Raised when a delete request conflicts with its pinned approval.

    A delegated delete approval fixes the target to one meaning: an exact
    object version, or the creation of a delete marker. Requesting any other
    target must be rejected before anything is sent.
    """

    pass


class DeleteNotSentError(CancelledError):
    """A delegated delete was refused before a request was sent.

    ``request_sent`` is always ``False``.  Callers may treat the target as
    untouched and reassign the deletion, because no request left the process.
    """

    request_sent = False

    def __init__(
        self,
        message='',
        *,
        bucket=None,
        key=None,
        version_id=None,
        creates_delete_marker=None,
        authorization_id=None,
        delegate=None,
        attempt=None,
    ):
        super().__init__(message)
        self.bucket = bucket
        self.key = key
        self.version_id = version_id
        self.creates_delete_marker = creates_delete_marker
        self.authorization_id = authorization_id
        self.delegate = delegate
        self.attempt = attempt


class DeleteRevokedError(DeleteNotSentError):
    """The delegate's authorization was revoked before the delete was sent."""

    pass


class DeleteExpiredError(DeleteNotSentError):
    """The delegate's authorization expired before the delete was sent."""

    pass


class DeleteOutcomeUnknownError(Exception):
    """A delegated delete was sent but no definitive outcome is known.

    ``request_sent`` is always ``True``.  The target may already have been
    deleted (or a delete marker may already have been created).  Callers must
    not silently retry a different version or a different target meaning.
    """

    request_sent = True

    def __init__(
        self,
        message='',
        *,
        bucket=None,
        key=None,
        version_id=None,
        creates_delete_marker=None,
        authorization_id=None,
        delegate=None,
        attempt=None,
    ):
        super().__init__(message)
        self.bucket = bucket
        self.key = key
        self.version_id = version_id
        self.creates_delete_marker = creates_delete_marker
        self.authorization_id = authorization_id
        self.delegate = delegate
        self.attempt = attempt
