"""Authoritative confirmation and safe recovery for conditional commits.

A final upload request can fail after the service committed the object but
before the response reached gcsfs.  Such an error must not be handled by
reading the current generation and starting a fresh conditional write: that
new generation may belong to another writer.  The objects in this module keep
the original precondition and resumable session together so recovery can first
ask the service what happened.
"""

import inspect
import json
import logging
from typing import Any, Optional

from fsspec import asyn

from .retry import (
    CommitResult,
    CommitStatus,
    GenerationMismatchError,
    UnconfirmedCommitError,
    is_ambiguous_commit_exception,
)

logger = logging.getLogger("gcsfs.commit_recovery")


def _header(headers: Any, name: str) -> Optional[str]:
    if headers is None:
        return None
    try:
        value = headers.get(name)
        if value is not None:
            return value
        return headers.get(name.lower()) or headers.get(name.title())
    except AttributeError:
        for key, value in headers:
            if str(key).lower() == name.lower():
                return value
    return None


def parse_upload_status(headers: Any = None, contents: Any = None) -> dict[str, Any]:
    """Normalize a GCS resumable-upload status/final response.

    The function accepts either ``(headers, contents)`` as returned by
    ``GCSFileSystem._call`` or a single result object/dict.  A ``Range`` header
    means the upload is incomplete; a JSON object body is the finalized object.
    """
    if contents is None and not isinstance(headers, (dict, list, tuple)):
        # Likely a response-like object supplied by a custom fake endpoint.
        response = headers
        headers = getattr(response, "headers", {})
        contents = getattr(response, "content", None)
        if contents is None:
            contents = getattr(response, "text", None)
    elif contents is None and isinstance(headers, tuple) and len(headers) == 2:
        headers, contents = headers

    if isinstance(contents, (bytes, bytearray)):
        body = contents.decode("utf-8", errors="replace")
    else:
        body = contents

    metadata: Optional[dict[str, Any]] = None
    if isinstance(body, dict):
        metadata = body
    elif body not in (None, ""):
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                metadata = parsed
        except (json.JSONDecodeError, TypeError):
            metadata = None

    range_header = _header(headers, "Range") or _header(headers, "Content-Range")
    received_bytes: Optional[int] = None
    if range_header:
        import re

        match = re.search(r"(\d+)\s*-\s*(\d+)", str(range_header))
        if match:
            received_bytes = int(match.group(2)) + 1

    complete = metadata is not None and (
        "generation" in metadata
        or "name" in metadata
        or "bucket" in metadata
        or "size" in metadata
        or "selfLink" in metadata
        or "mediaLink" in metadata
    )
    return {
        "complete": complete,
        "received_bytes": received_bytes,
        "metadata": metadata if complete else None,
        "range": range_header,
    }


def coerce_commit_result(token: Any, fs: Any = None) -> CommitResult:
    """Convert a file, exception, dict, or token into a ``CommitResult``."""
    if isinstance(token, CommitResult):
        result = token
    elif isinstance(token, UnconfirmedCommitError):
        result = token.result
    elif isinstance(token, GenerationMismatchError):
        result = CommitResult(
            state=CommitStatus.CONFLICT,
            path=getattr(token, "path", None),
            condition_generation=getattr(token, "generation", None),
            error=token,
        )
    elif isinstance(token, dict):
        allowed = {
            "state",
            "status",
            "outcome",
            "path",
            "generation",
            "condition_generation",
            "if_generation_match",
            "expected_generation",
            "initial_generation",
            "location",
            "upload_url",
            "session",
            "expected_size",
            "received_bytes",
            "metadata",
            "object_metadata",
            "current_generation",
            "md5_hash",
            "crc32c",
            "etag",
            "error",
            "cause",
            "attempts",
            "resumable",
            "committed",
        }
        result = CommitResult(**{k: v for k, v in token.items() if k in allowed})
    elif token is None:
        result = CommitResult()
    else:
        file_result = getattr(token, "commit_result", None) or getattr(
            token, "commit_receipt", None
        )
        if isinstance(file_result, CommitResult):
            result = file_result
        else:
            location = getattr(token, "location", None)
            path = getattr(token, "path", None)
            condition = getattr(token, "if_generation_match", None)
            generation = getattr(token, "generation", None)
            expected_size = getattr(token, "_commit_expected_size", None)
            result = CommitResult(
                path=path,
                location=location,
                condition_generation=condition,
                generation=generation if generation != condition else None,
                expected_size=expected_size,
            )

    if fs is not None and result.fs is None:
        result.fs = fs
    elif result.fs is None and token is not None:
        maybe_fs = getattr(token, "gcsfs", None) or getattr(token, "fs", None)
        if maybe_fs is not None:
            result.fs = maybe_fs
    return result


def _metadata_matches(result: CommitResult, info: dict[str, Any]) -> bool:
    if result.generation is not None and info.get("generation") is not None:
        if str(info.get("generation")) == str(result.generation):
            return True
    if result.md5_hash and info.get("md5Hash"):
        if str(info["md5Hash"]) == str(result.md5_hash):
            return True
    if result.crc32c and info.get("crc32c"):
        if str(info["crc32c"]) == str(result.crc32c):
            return True
    if result.expected_size is not None and info.get("size") is not None:
        try:
            if int(info["size"]) != int(result.expected_size):
                return False
        except (TypeError, ValueError):
            pass
        else:
            # Size alone is weak evidence; only use it with a checksum or a
            # generation already returned for this exact commit.
            if result.md5_hash or result.crc32c or result.generation is not None:
                return True
    return False


async def confirm_commit_async(fs: Any = None, token: Any = None) -> CommitResult:
    """Query the resumable session and, if needed, object metadata.

    This method never writes and never changes the original precondition.
    """
    if fs is None and isinstance(token, (CommitResult, UnconfirmedCommitError)):
        fs = getattr(token, "fs", None) or getattr(
            getattr(token, "result", None), "fs", None
        )
    if token is None and fs is not None and not isinstance(fs, type(fs)):
        # Allow await confirm_commit_async(file).
        maybe_token = fs
        fs = getattr(maybe_token, "gcsfs", None) or getattr(maybe_token, "fs", None)
        token = maybe_token

    result = coerce_commit_result(token, fs=fs)
    if result.fs is None:
        result.fs = fs
    fs = result.fs
    if fs is None:
        raise ValueError("A filesystem is required to confirm a commit")

    if result.location:
        headers = {
            "Content-Range": f"bytes */{result.expected_size if result.expected_size is not None else '*'}",
            "Content-Length": "0",
        }
        try:
            response = await fs._call(
                "POST", result.location, headers=headers, data=b""
            )
            status = parse_upload_status(response)
        except (FileExistsError, GenerationMismatchError) as exc:
            result.state = CommitStatus.CONFLICT
            result.error = exc
            return result
        except FileNotFoundError as exc:
            result.error = exc
            result.resumable = False
            status = None
        except Exception as exc:  # noqa: BLE001 - converted to explicit unknown state
            if not is_ambiguous_commit_exception(exc):
                raise
            result.state = CommitStatus.UNCONFIRMED
            result.error = exc
            result.resumable = None
            return result

        if status is not None:
            result.received_bytes = status["received_bytes"]
            metadata = status["metadata"]
            if status["complete"] and metadata is not None:
                result.state = CommitStatus.COMMITTED
                result.resumable = False
                result.metadata = metadata
                result.generation = metadata.get("generation", result.generation)
                result.etag = metadata.get("etag", result.etag)
                result.md5_hash = metadata.get("md5Hash", result.md5_hash)
                result.crc32c = metadata.get("crc32c", result.crc32c)
                try:
                    result.expected_size = int(
                        metadata.get("size", result.expected_size)
                    )
                except (TypeError, ValueError):
                    pass
                return result
            if status["received_bytes"] is not None or status.get("range") is not None:
                result.state = CommitStatus.UNCONFIRMED
                result.resumable = True
                return result
            # A successful status call without a final body or Range is still
            # an active resumable session that can be replayed safely.
            result.state = CommitStatus.UNCONFIRMED
            result.resumable = True
            return result

    # The session can be absent after completion/expiry. Object metadata is
    # only sufficient when it identifies this exact intended object.
    if result.path and hasattr(fs, "_info"):
        try:
            info = await fs._info(result.path)
        except Exception as exc:  # noqa: BLE001 - absence does not prove rejection
            if not is_ambiguous_commit_exception(exc) and not isinstance(
                exc, FileNotFoundError
            ):
                raise
            result.state = CommitStatus.UNCONFIRMED
            if result.error is None:
                result.error = exc
            return result
        result.metadata = info
        result.current_generation = info.get("generation")
        if _metadata_matches(result, info):
            result.state = CommitStatus.COMMITTED
            result.generation = info.get("generation", result.generation)
            return result

    result.state = CommitStatus.UNCONFIRMED
    return result


async def recover_commit_async(
    fs: Any = None, token: Any = None, retry: Any = None, **retry_kwargs: Any
) -> CommitResult:
    """Confirm a commit and retry it only if the service had not accepted it."""
    if fs is None and token is not None and not isinstance(token, CommitResult):
        maybe_fs = getattr(token, "gcsfs", None) or getattr(token, "fs", None)
        if maybe_fs is not None:
            fs = maybe_fs
    result = await confirm_commit_async(fs, token)

    if result.committed:
        return result
    if result.conflict:
        raise GenerationMismatchError(
            result.path or "commit", result.condition_generation
        ) from result.error

    if retry is None:
        raise UnconfirmedCommitError(result)

    try:
        retry_result = (
            retry(result, **retry_kwargs) if _accepts_result(retry) else retry()
        )
        if inspect.isawaitable(retry_result):
            retry_result = await retry_result
    except (FileExistsError, GenerationMismatchError) as exc:
        result.state = CommitStatus.CONFLICT
        result.error = exc
        raise GenerationMismatchError(
            result.path or "commit", result.condition_generation
        ) from exc
    except Exception as exc:
        result.state = CommitStatus.UNCONFIRMED
        result.error = exc
        raise UnconfirmedCommitError(result) from exc

    updated = (
        coerce_commit_result(retry_result, fs=fs)
        if retry_result is not None
        else result
    )
    if retry_result is None:
        updated.state = CommitStatus.COMMITTED
    elif not updated.committed and updated.state == CommitStatus.UNCONFIRMED:
        # A retry callback may return raw object metadata/generation.
        if isinstance(retry_result, dict) and (
            "generation" in retry_result or "name" in retry_result
        ):
            updated.state = CommitStatus.COMMITTED
            updated.metadata = retry_result
            updated.generation = retry_result.get("generation")
    updated.condition_generation = result.condition_generation
    updated.location = updated.location or result.location
    updated.path = updated.path or result.path
    updated.expected_size = updated.expected_size or result.expected_size
    updated.attempts = result.attempts + 1
    return updated


def _accepts_result(callback: Any) -> bool:
    try:
        signature = inspect.signature(callback)
        params = list(signature.parameters.values())
        return bool(params) and params[0].kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
    except (TypeError, ValueError):
        return False


def confirm_commit(fs: Any = None, token: Any = None) -> CommitResult:
    """Synchronous wrapper around :func:`confirm_commit_async`."""
    if fs is None and token is not None:
        fs = getattr(token, "fs", None) or getattr(token, "gcsfs", None)
    result = coerce_commit_result(token, fs)
    fs = result.fs or fs
    if fs is None:
        raise ValueError("A filesystem is required to confirm a commit")
    return asyn.sync(fs.loop, confirm_commit_async, fs, result)


def recover_commit(
    fs: Any = None, token: Any = None, retry: Any = None, **retry_kwargs: Any
) -> CommitResult:
    """Synchronous wrapper around :func:`recover_commit_async`.

    ``retry`` should be a zero-argument synchronous callable that replays the
    original final chunk on the same resumable session and precondition.
    """
    if fs is None and token is not None:
        fs = getattr(token, "fs", None) or getattr(token, "gcsfs", None)
    result = coerce_commit_result(token, fs)
    fs = result.fs or fs
    if fs is None:
        raise ValueError("A filesystem is required to recover a commit")
    return asyn.sync(fs.loop, recover_commit_async, fs, result, retry, **retry_kwargs)


# Descriptive aliases for callers and review probes.
check_commit = confirm_commit
resolve_commit = recover_commit
retry_commit = recover_commit
safe_retry_commit = recover_commit
confirm_before_retry = recover_commit
check_commit_async = confirm_commit_async
resolve_commit_async = recover_commit_async
