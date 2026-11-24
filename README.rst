=====================================================
s3transfer - An Amazon S3 Transfer Manager for Python
=====================================================

S3transfer is a Python library for managing Amazon S3 transfers.
This project is maintained and published by Amazon Web Services.

.. note::

  This project is not currently GA. If you are planning to use this code in
  production, make sure to lock to a minor version as interfaces may break
  from minor version to minor version. For a basic, stable interface of
  s3transfer, try the interfaces exposed in `boto3 <https://docs.aws.amazon.com/boto3/latest/guide/s3.html>`__

Delegated deletes
-----------------

``TransferManager.delete`` accepts an optional ``authorization`` approving
one object deletion. The approval pins the target to either an exact
``VersionId`` or the creation of a delete marker, and is revalidated right
before the request is sent:

.. code-block:: python

    from s3transfer.delete import DeleteAuthorization

    authorization = DeleteAuthorization(
        version_id='version-id', delegate='cleanup-team'
    )
    future = transfer.delete('bucket', 'key', authorization=authorization)
    # Later, if the approval is withdrawn:
    authorization.revoke('cleanup window closed')

If the approval is revoked (or expires) while the delete is still queued,
nothing is sent and ``future.result()`` raises ``DeleteRevokedError`` /
``DeleteExpiredError`` with ``request_sent == False``. If the request was
already on the wire and then fails, hangs, or is cancelled, ``result()``
raises ``DeleteOutcomeUnknownError`` with ``request_sent == True`` and the
exact pinned target, so callers do not retry a different version by mistake.
``authorization.attempts`` exposes a ``DeleteAttempt`` record per approval.
