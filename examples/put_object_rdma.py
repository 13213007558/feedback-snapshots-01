# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) [2024] - [2026] MinIO, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Upload to MinIO over RDMA from a contiguous host buffer.

Requirements:
  * libminiocpp.so installed (or pointed at via MINIOCPP_LIB).
  * MinIO server reachable on the configured endpoint with RDMA enabled.
"""

import os

from minio import Minio
from minio.rdma import RDMACommitUnknown

client = Minio(
    endpoint=os.environ.get("MINIO_ENDPOINT", "coe01:9000"),
    access_key=os.environ.get("MINIO_ACCESS_KEY", "minioadmin"),
    secret_key=os.environ.get("MINIO_SECRET_KEY", "minioadmin"),
    secure=False,
    enable_rdma=True,
)

if not client.bucket_exists(bucket_name="rdma-test"):
    client.make_bucket(bucket_name="rdma-test")

payload = bytearray(b"x" * (1 << 20))  # 1 MiB

# If RDMA is unavailable or the upload has not started, the SDK falls back to
# HTTPS and sends the same bytes. A failure after the upload started is raised:
# the server may already have committed the object, so reconcile with
# stat_object instead of uploading again.
try:
    resp = client.put_object(
        bucket_name="rdma-test",
        object_name="hello-rdma",
        data=payload,         # buffer-protocol object selects RDMA path
        length=len(payload),
    )
except RDMACommitUnknown as exc:
    print(f"upload outcome unknown; etag seen: {exc.etag!r}")
    info = client.stat_object(bucket_name="rdma-test",
                              object_name="hello-rdma")
    print(f"object now present with etag={info.etag}")
else:
    print(f"etag={resp.etag} bucket={resp.bucket_name} "
          f"object={resp.object_name}")
