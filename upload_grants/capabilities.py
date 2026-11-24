"""Which approval conditions each issuance channel can actually encode.

The matrix is derived from this checkout of ``minio-py``:

* :meth:`minio.Minio.presigned_post_policy` builds a SigV4 POST policy whose
  condition document supports exact keys, ``starts-with`` prefixes,
  ``content-length-range`` and arbitrary equality conditions such as
  ``x-amz-tagging`` plus an absolute expiration.
* :meth:`minio.Minio.presigned_put_object` produces a query-presigned URL.
  In :func:`minio.signer.presign_v4` the signed headers are hard-coded to
  ``host`` and the URL path pins one object, so a prefix, a size interval
  and tag requirements cannot be forced by the resulting credential.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .model import GrantScope

POST_FORM = "post_form"
PUT_URL = "put_url"
CHANNELS = (POST_FORM, PUT_URL)

CHANNEL_TITLES = {
    POST_FORM: "上传表单（POST policy + 签名表单字段）",
    PUT_URL: "预签 PUT URL（query SigV4）",
}


@dataclass(frozen=True)
class MissingCondition:
    """A required condition the requested channel cannot express."""

    condition: str
    label: str
    detail: str
    expressible_in: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "condition": self.condition,
            "label": self.label,
            "detail": self.detail,
            "expressible_in": list(self.expressible_in),
        }


def missing_for_channel(
        scope: "GrantScope", channel: str,
) -> list[MissingCondition]:
    """List required scope conditions absent from the channel's encoding."""
    if channel not in CHANNELS:
        raise ValueError(f"unknown channel {channel!r}")

    missing: list[MissingCondition] = []
    if channel == POST_FORM:
        return missing

    if scope.key is None:
        missing.append(
            MissingCondition(
                condition="key_prefix",
                label="对象前缀限制（key starts-with）",
                detail=(
                    "预签 PUT 的路径只能锁定单个对象键，无法携带 "
                    "starts-with 前缀条件；需要先把目标收紧为单个对象，"
                    "或改用上传表单。"
                ),
                expressible_in=(POST_FORM,),
            ),
        )
    if scope.size_range is not None:
        missing.append(
            MissingCondition(
                condition="content_length_range",
                label="对象大小区间（content-length-range）",
                detail=(
                    "大小区间只能写进 POST policy 的 "
                    "content-length-range 条件；预签 PUT 不签名 "
                    "Content-Length 区间，无法限制上传字节数范围。"
                ),
                expressible_in=(POST_FORM,),
            ),
        )
    if scope.tags:
        missing.append(
            MissingCondition(
                condition="tags",
                label="数据标签（x-amz-tagging 精确条件）",
                detail=(
                    "minio-py 的预签 PUT 固定 "
                    "X-Amz-SignedHeaders=host，x-amz-tagging 不会被签名，"
                    "调用方可以省略或改写标签；标签条件只能由 POST policy "
                    "的 eq $x-amz-tagging 强制。"
                ),
                expressible_in=(POST_FORM,),
            ),
        )
    return missing


def available_methods(scope: "GrantScope") -> list[str]:
    """Channels able to encode every required condition."""
    return [
        channel for channel in CHANNELS
        if not missing_for_channel(scope, channel)
    ]
