# -*- coding: utf-8 -*-
"""Adapter from :class:`minio.Minio` to the archive gateway protocol."""

from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING, Optional, Sequence

from .archive_retention import (ArchiveSource, PartToken, SourceRead,
                                SourceVersion, TargetCapabilities, TargetWrite)
from .error import S3Error
from .models import GetObjectResponse, Part, Retention, VersioningConfig

if TYPE_CHECKING:
    from .minio import Minio

# The archive orchestrator needs upload IDs and part tokens.  The MinIO SDK
# currently exposes those primitives through package-internal methods.
# pylint: disable=protected-access


class MinioArchiveGateway:
    """Implement archive storage operations with the MinIO Python SDK."""

    def __init__(self, client: Minio) -> None:
        self._client = client

    def target_capabilities(
            self, bucket_name: str,
    ) -> TargetCapabilities:
        """Read versioning and object-lock state from the target bucket."""
        versioning = self._client.get_bucket_versioning(
            bucket_name=bucket_name,
        )
        object_lock_enabled = True
        try:
            self._client.get_object_lock_config(bucket_name=bucket_name)
        except S3Error as exc:
            if exc.code != "NoSuchObjectLockConfiguration":
                raise
            object_lock_enabled = False

        return TargetCapabilities(
            versioning_enabled=(
                versioning.status == VersioningConfig.ENABLED
            ),
            object_lock_enabled=object_lock_enabled,
            supported_modes=frozenset(
                {Retention.GOVERNANCE, Retention.COMPLIANCE},
            ),
        )

    def stat_source(self, source: ArchiveSource) -> SourceVersion:
        """Stat an object version and read its retention configuration."""
        info = self._client.stat_object(
            bucket_name=source.bucket_name,
            object_name=source.object_name,
            version_id=source.version_id,
        )
        version_id = info.version_id or source.version_id or ""
        retention = self._client.get_object_retention(
            bucket_name=source.bucket_name,
            object_name=source.object_name,
            version_id=version_id or None,
        )
        return SourceVersion(
            bucket_name=source.bucket_name,
            object_name=source.object_name,
            version_id=version_id,
            requested_version_id=source.version_id,
            size=info.size,
            etag=info.etag or source.etag,
            retention=retention,
        )

    def read_source(self, source: ArchiveSource) -> SourceRead:
        """Read all bytes from one source and return its actual version ID."""
        response = self._client.get_object(
            bucket_name=source.bucket_name,
            object_name=source.object_name,
            version_id=source.version_id,
        )
        if not isinstance(response, GetObjectResponse):
            raise TypeError("get_object returned an inline buffer result")
        try:
            data = response.read()
        finally:
            response.close()

        etag = response.headers.get("etag")
        if etag:
            etag = etag.strip('"')
        version_id = (
            response.version_id
            or response.headers.get("x-amz-version-id")
            or source.version_id
            or ""
        )
        return SourceRead(
            version_id=version_id,
            data=data,
            etag=etag or source.etag,
        )

    def put_archive(
            self,
            *,
            bucket_name: str,
            object_name: str,
            data: bytes,
            retention: Optional[Retention],
    ) -> TargetWrite:
        """Put a small composed object in one request."""
        result = self._client.put_object(
            bucket_name=bucket_name,
            object_name=object_name,
            data=BytesIO(data),
            length=len(data),
            retention=retention,
        )
        return TargetWrite(
            version_id=result.version_id,
            etag=result.etag,
        )

    def create_multipart(
            self,
            *,
            bucket_name: str,
            object_name: str,
            retention: Optional[Retention],
    ) -> str:
        """Create the only multipart job owned by this archive transfer."""
        headers = self._client._gen_write_headers(retention=retention)
        response = self._client._create_multipart_upload(
            bucket_name=bucket_name,
            object_name=object_name,
            headers=headers,
        )
        return response.result.upload_id

    def upload_part(
            self,
            *,
            bucket_name: str,
            object_name: str,
            upload_id: str,
            part: PartToken,
            data: bytes,
    ) -> PartToken:
        """Upload one in-memory chunk as an S3 multipart part."""
        response = self._client._upload_part(
            bucket_name=bucket_name,
            object_name=object_name,
            data=data,
            upload_id=upload_id,
            part_number=part.part_number,
        )
        return PartToken(
            part_number=response.part.part_number,
            etag=response.part.etag,
        )

    def complete_multipart(
            self,
            *,
            bucket_name: str,
            object_name: str,
            upload_id: str,
            parts: Sequence[PartToken],
    ) -> TargetWrite:
        """Complete the multipart job using tokens from upload responses."""
        s3_parts = [
            Part(part_number=part.part_number, etag=part.etag)
            for part in parts
        ]
        result = self._client._complete_multipart_upload(
            bucket_name=bucket_name,
            object_name=object_name,
            upload_id=upload_id,
            parts=s3_parts,
        )
        return TargetWrite(
            version_id=result.version_id,
            etag=result.etag,
        )

    def abort_multipart(
            self,
            *,
            bucket_name: str,
            object_name: str,
            upload_id: str,
    ) -> None:
        """Abort an upload ID created by this composer."""
        self._client._abort_multipart_upload(
            bucket_name=bucket_name,
            object_name=object_name,
            upload_id=upload_id,
        )
