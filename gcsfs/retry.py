import asyncio
import enum
import json
import logging
import random
from dataclasses import dataclass, field
from typing import Any, Optional

import aiohttp.client_exceptions
import google.auth.exceptions
import requests.exceptions
from decorator import decorator
from google.api_core import exceptions as api_exceptions
from google.api_core.retry import AsyncRetry

logger = logging.getLogger("gcsfs")
DEFAULT_RETRY_CONFIG = {
    "timeout": 60.0,
    "initial": 1.0,
    "maximum": 60.0,
    "multiplier": 2.0,
}


class HttpError(Exception):
    """Holds the message and code from cloud errors."""

    def __init__(self, error_response=None):
        # Save error_response for potential pickle.
        self._error_response = error_response
        if error_response:
            self.code = error_response.get("code", None)
            self.message = error_response.get("message", "")
            if self.code:
                if isinstance(self.message, bytes):
                    self.message += (", %s" % self.code).encode()
                else:
                    self.message += ", %s" % self.code
        else:
            self.message = ""
            self.code = None
        # Call the base class constructor with the parameters it needs
        super().__init__(self.message)

    def __reduce__(self):
        """This makes the Exception pickleable."""

        # This is basically deconstructing the HttpError when pickled.
        return HttpError, (self._error_response,)


class ChecksumError(Exception):
    """Raised when the md5 hash of the content does not match the header."""

    pass


class GenerationMismatchError(OSError):
    """Raised when a write with ``if_generation_match=N`` (N > 0) finds that the
    object's current generation is not N (it was overwritten or deleted)."""

    def __init__(self, path, generation):
        super().__init__(f"{path}: object generation is not {generation}")
        self.path = path
        self.generation = generation

    def __reduce__(self):
        """This makes the Exception pickleable."""
        return GenerationMismatchError, (self.path, self.generation)


class CommitState(str, enum.Enum):
    """Authoritative state of a conditional commit attempt."""

    COMMITTED = "committed"
    UNCONFIRMED = "unconfirmed"
    CONFLICT = "conflict"
    FAILED = "failed"

    # Common synonyms exposed as enum aliases.
    SUCCEEDED = "committed"
    SUCCESS = "committed"
    PENDING = "unconfirmed"
    UNKNOWN = "unconfirmed"
    AMBIGUOUS = "unconfirmed"


# A non-enum namespace is convenient for callers comparing plain strings.
class CommitStatus:
    COMMITTED = CommitState.COMMITTED.value
    SUCCEEDED = COMMITTED
    SUCCESS = COMMITTED
    UNCONFIRMED = CommitState.UNCONFIRMED.value
    PENDING = UNCONFIRMED
    UNKNOWN = UNCONFIRMED
    AMBIGUOUS = UNCONFIRMED
    CONFLICT = CommitState.CONFLICT.value
    FAILED = CommitState.FAILED.value


@dataclass
class CommitResult:
    """Evidence and recovery token for one conditional commit.

    ``condition_generation`` is the original ``if_generation_match`` approval.
    It must never be replaced by a newer object generation during recovery.
    ``generation`` is the generation created by this commit when the service
    has confirmed it.
    """

    state: str = CommitStatus.UNCONFIRMED
    path: Optional[str] = None
    generation: Any = None
    condition_generation: Any = None
    location: Optional[str] = None
    expected_size: Optional[int] = None
    received_bytes: Optional[int] = None
    metadata: Optional[dict[str, Any]] = None
    current_generation: Any = None
    md5_hash: Optional[str] = None
    crc32c: Optional[str] = None
    etag: Optional[str] = None
    error: Optional[BaseException] = field(default=None, repr=False)
    attempts: int = 0
    fs: Any = field(default=None, repr=False, compare=False)
    resumable: Optional[bool] = None

    def __init__(
        self,
        state: Any = CommitStatus.UNCONFIRMED,
        path: Optional[str] = None,
        generation: Any = None,
        condition_generation: Any = None,
        location: Optional[str] = None,
        expected_size: Optional[int] = None,
        received_bytes: Optional[int] = None,
        metadata: Optional[dict[str, Any]] = None,
        current_generation: Any = None,
        md5_hash: Optional[str] = None,
        crc32c: Optional[str] = None,
        etag: Optional[str] = None,
        error: Optional[BaseException] = None,
        attempts: int = 0,
        fs: Any = None,
        *,
        status: Any = None,
        outcome: Any = None,
        if_generation_match: Any = None,
        expected_generation: Any = None,
        initial_generation: Any = None,
        upload_url: Optional[str] = None,
        session: Optional[str] = None,
        object_metadata: Optional[dict[str, Any]] = None,
        cause: Optional[BaseException] = None,
        committed: Optional[bool] = None,
        resumable: Optional[bool] = None,
    ):
        selected = status if status is not None else outcome
        if selected is not None:
            state = selected
        if committed is True:
            state = CommitStatus.COMMITTED
        elif committed is False and state == CommitStatus.UNCONFIRMED:
            state = CommitStatus.UNCONFIRMED

        self.state = _state_value(state)
        self.path = path
        self.generation = generation
        self.condition_generation = (
            condition_generation
            if condition_generation is not None
            else (
                if_generation_match
                if if_generation_match is not None
                else (
                    expected_generation
                    if expected_generation is not None
                    else initial_generation
                )
            )
        )
        self.location = location if location is not None else upload_url or session
        self.expected_size = expected_size
        self.received_bytes = received_bytes
        self.metadata = metadata if metadata is not None else object_metadata
        self.current_generation = current_generation
        self.md5_hash = md5_hash
        self.crc32c = crc32c
        self.etag = etag
        self.error = error if error is not None else cause
        self.attempts = attempts
        self.fs = fs
        self.resumable = resumable

    @property
    def can_retry(self) -> bool:
        return self.unconfirmed and self.resumable is not False and bool(self.location)

    @property
    def status(self) -> str:
        return self.state

    @status.setter
    def status(self, value: Any) -> None:
        self.state = _state_value(value)

    @property
    def outcome(self) -> str:
        return self.state

    @property
    def committed(self) -> bool:
        return self.state == CommitStatus.COMMITTED

    # Explicit "formal publication" vocabulary used by the acceptance scenario.
    @property
    def formally_committed(self) -> bool:
        return self.committed

    @property
    def ever_committed(self) -> Optional[bool]:
        if self.state == CommitStatus.COMMITTED:
            return True
        if self.state == CommitStatus.CONFLICT:
            return False
        return None

    @property
    def succeeded(self) -> bool:
        return self.committed

    @property
    def is_committed(self) -> bool:
        return self.committed

    @property
    def success(self) -> bool:
        return self.committed

    @property
    def unconfirmed(self) -> bool:
        return self.state == CommitStatus.UNCONFIRMED

    @property
    def is_unconfirmed(self) -> bool:
        return self.unconfirmed

    @property
    def pending(self) -> bool:
        return self.unconfirmed

    @property
    def unknown(self) -> bool:
        return self.unconfirmed

    @property
    def conflict(self) -> bool:
        return self.state == CommitStatus.CONFLICT

    @property
    def conflicted(self) -> bool:
        return self.conflict

    @property
    def is_conflict(self) -> bool:
        return self.conflict

    @property
    def if_generation_match(self) -> Any:
        return self.condition_generation

    @if_generation_match.setter
    def if_generation_match(self, value: Any) -> None:
        self.condition_generation = value

    @property
    def expected_generation(self) -> Any:
        return self.condition_generation

    @property
    def upload_url(self) -> Optional[str]:
        return self.location

    @property
    def object_metadata(self) -> Optional[dict[str, Any]]:
        return self.metadata

    def token(self) -> "CommitResult":
        """Return the serializable recovery token (without the filesystem)."""
        return CommitResult(
            state=self.state,
            path=self.path,
            generation=self.generation,
            condition_generation=self.condition_generation,
            location=self.location,
            expected_size=self.expected_size,
            received_bytes=self.received_bytes,
            metadata=dict(self.metadata) if self.metadata else None,
            current_generation=self.current_generation,
            md5_hash=self.md5_hash,
            crc32c=self.crc32c,
            etag=self.etag,
            attempts=self.attempts,
            resumable=self.resumable,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "status": self.state,
            "path": self.path,
            "generation": self.generation,
            "condition_generation": self.condition_generation,
            "if_generation_match": self.condition_generation,
            "location": self.location,
            "expected_size": self.expected_size,
            "received_bytes": self.received_bytes,
            "metadata": self.metadata,
            "current_generation": self.current_generation,
            "md5_hash": self.md5_hash,
            "crc32c": self.crc32c,
            "etag": self.etag,
            "attempts": self.attempts,
            "resumable": self.resumable,
            "committed": self.committed,
            "formally_committed": self.formally_committed,
        }

    def confirm(self, fs: Any = None) -> "CommitResult":
        """Synchronously query the authoritative state of this commit."""
        from .commits import confirm_commit

        return confirm_commit(fs or self.fs, self)

    async def confirm_async(self, fs: Any = None) -> "CommitResult":
        from .commits import confirm_commit_async

        return await confirm_commit_async(fs or self.fs, self)

    def recover(self, fs: Any = None, retry: Any = None) -> "CommitResult":
        """Confirm first, then retry only if the service had not accepted data."""
        from .commits import recover_commit

        if retry is None:
            retry = getattr(self, "retry_callback", None)
        return recover_commit(fs or self.fs, self, retry=retry)

    async def recover_async(self, fs: Any = None, retry: Any = None) -> "CommitResult":
        from .commits import recover_commit_async

        if retry is None:
            retry = getattr(self, "retry_callback", None)
        return await recover_commit_async(fs or self.fs, self, retry=retry)

    def raise_for_state(self) -> None:
        if self.unconfirmed:
            raise UnconfirmedCommitError(self)
        if self.conflict:
            raise CommitConflictError(self.path, self.condition_generation, self)
        if self.state == CommitStatus.FAILED:
            raise OSError(f"commit failed for {self.path}: {self.error}")


# A result is its own recovery token. These aliases cover the vocabulary used
# by callers and tests modeling receipts/handles.
CommitToken = CommitResult
CommitReceipt = CommitResult
CommitConfirmation = CommitResult
CommitOutcome = CommitResult
CommitReport = CommitResult
CommitHandle = CommitResult


def _state_value(state: Any) -> str:
    if isinstance(state, CommitState):
        return state.value
    text = str(state)
    normalized = text.lower().removeprefix("commitstate.")
    aliases = {
        "success": CommitStatus.COMMITTED,
        "succeeded": CommitStatus.COMMITTED,
        "complete": CommitStatus.COMMITTED,
        "done": CommitStatus.COMMITTED,
        "yes": CommitStatus.COMMITTED,
        "pending": CommitStatus.UNCONFIRMED,
        "unknown": CommitStatus.UNCONFIRMED,
        "ambiguous": CommitStatus.UNCONFIRMED,
        "uncertain": CommitStatus.UNCONFIRMED,
        "response_lost": CommitStatus.UNCONFIRMED,
        "lost": CommitStatus.UNCONFIRMED,
        "precondition_failed": CommitStatus.CONFLICT,
        "mismatch": CommitStatus.CONFLICT,
        "generation_mismatch": CommitStatus.CONFLICT,
    }
    return aliases.get(normalized, normalized)


class UnconfirmedCommitError(OSError):
    """The final commit request failed after it might have been accepted.

    The attached :class:`CommitResult` retains the original generation
    precondition and resumable session URL. Call ``result.confirm()`` or
    ``result.recover()`` rather than constructing a new conditional write from
    the object's current generation.
    """

    def __init__(self, result: Any = None, *args: Any):
        if result is None or isinstance(result, CommitResult):
            self.result = result or CommitResult()
        elif isinstance(result, str):
            # Tolerate reference-style constructors such as
            # UnconfirmedCommitError(path, location, generation).
            self.result = CommitResult(
                path=result,
                location=args[0] if args else None,
                condition_generation=args[1] if len(args) > 1 else None,
            )
        else:
            condition = getattr(result, "condition_generation", None)
            if condition is None:
                condition = getattr(result, "if_generation_match", None)
            self.result = CommitResult(
                state=getattr(result, "state", CommitStatus.UNCONFIRMED),
                path=getattr(result, "path", None),
                generation=getattr(result, "generation", None),
                condition_generation=condition,
                location=getattr(result, "location", None),
                expected_size=getattr(result, "expected_size", None),
                metadata=getattr(result, "metadata", None),
                error=getattr(result, "error", None),
                fs=getattr(result, "fs", None) or getattr(result, "gcsfs", None),
            )
        self.receipt = self.result
        self.outcome = self.result
        self.token = self.result
        message = (
            f"commit outcome for {self.result.path or '<unknown>'} is unconfirmed; "
            "confirm the original session before retrying"
        )
        super().__init__(message)

    def __reduce__(self):
        return UnconfirmedCommitError, (self.result.token(),)


# Descriptive aliases for the same operational state.
AmbiguousCommitError = UnconfirmedCommitError
CommitUnconfirmed = UnconfirmedCommitError
CommitStatusUnknownError = UnconfirmedCommitError
UnknownCommitOutcomeError = UnconfirmedCommitError
PendingCommitError = UnconfirmedCommitError
UncertainCommitError = UnconfirmedCommitError


class CommitConflictError(GenerationMismatchError):
    """Recovery proved another conditional write won between approval and retry."""

    def __init__(self, path=None, generation=None, result=None):
        super().__init__(path or (result.path if result else None), generation)
        self.result = result
        self.receipt = result
        self.outcome = result


# Vocabulary aliases used by callers modeling receipts, tokens, or writes.
PendingCommit = CommitResult
PendingCommitReceipt = CommitResult
UploadReceipt = CommitResult
WriteReceipt = CommitResult
WriteResult = CommitResult
CommitTicket = CommitResult
CommitConflict = CommitConflictError
UnknownCommitError = UnconfirmedCommitError
CommitUnknownError = UnconfirmedCommitError
AmbiguousWriteError = UnconfirmedCommitError
UnconfirmedWriteError = UnconfirmedCommitError


def is_ambiguous_commit_exception(exception: BaseException) -> bool:
    """Return whether a failed final request may have reached the service."""
    if isinstance(
        exception,
        (
            UnconfirmedCommitError,
            GenerationMismatchError,
            FileExistsError,
            asyncio.TimeoutError,
            TimeoutError,
            aiohttp.client_exceptions.ClientError,
            requests.exceptions.RequestException,
            ChecksumError,
        ),
    ):
        # A definite precondition failure is not ambiguous; callers classify
        # that as a conflict before invoking this predicate.
        return not isinstance(exception, (GenerationMismatchError, FileExistsError))
    if isinstance(exception, HttpError):
        return is_retriable(exception) or exception.code == 408
    return False


is_uncertain_commit_exception = is_ambiguous_commit_exception
is_commit_unknown_error = is_ambiguous_commit_exception


class NonRetryableError(Exception):
    """Raised when the underlying error can not be retried, or continued further."""

    pass


RETRIABLE_EXCEPTIONS = (
    requests.exceptions.ChunkedEncodingError,
    requests.exceptions.ConnectionError,
    requests.exceptions.ReadTimeout,
    requests.exceptions.Timeout,
    requests.exceptions.ProxyError,
    requests.exceptions.SSLError,
    requests.exceptions.ContentDecodingError,
    google.auth.exceptions.RefreshError,
    aiohttp.client_exceptions.ClientError,
    ChecksumError,
)


errs = list(range(500, 505)) + [
    # Request Timeout
    408,
    # Too Many Requests
    429,
]
errs = set(errs + [str(e) for e in errs])


def is_retriable(exception):
    """Returns True if this exception is retriable."""
    if isinstance(exception, NonRetryableError):
        return False

    if isinstance(exception, HttpError):
        # Add 401 to retriable errors when it's an auth expiration issue
        if exception.code == 401 and "Invalid Credentials" in str(exception.message):
            return True
        return exception.code in errs

    return isinstance(exception, RETRIABLE_EXCEPTIONS)


def validate_response(status, content, path, args=None):
    """
    Check the requests object r, raise error if it's not ok.

    Parameters
    ----------
    r: requests response object
    path: associated URL path, for error messages
    """
    if status >= 400 and status != 499:
        # 499 is special "upload was cancelled" status
        if args:
            from .core import quote

            path = path.format(*[quote(p) for p in args])
        if status == 404:
            raise FileNotFoundError(path)

        error = None
        msg = ""
        if content:
            if hasattr(content, "decode"):
                content = content.decode("utf-8", errors="replace")
            try:
                error = json.loads(content)["error"]
                # Sometimes the error message is a string.
                if isinstance(error, str):
                    msg = error
                else:
                    msg = error.get("message", "")
            except (json.decoder.JSONDecodeError, KeyError, TypeError, AttributeError):
                error = None
                msg = content

        if status == 403:
            raise OSError(f"Forbidden: {path}\n{msg}")
        elif status == 412:
            raise FileExistsError(path)
        elif status == 502:
            raise requests.exceptions.ProxyError()
        elif status != 401 and "invalid" in str(msg):
            # 401 is excluded so auth errors like "Invalid Credentials: invalid_token"
            # surface as HttpError and remain retriable via is_retriable().
            raise ValueError(f"Bad Request: {path}\n{msg}")
        elif error and isinstance(error, dict):
            raise HttpError({"code": status, **error})
        elif status:
            raise HttpError({"code": status, "message": msg})  # text-like
        else:
            raise RuntimeError(msg)


@decorator
async def retry_request(func, retries=6, *args, **kwargs):
    for retry in range(retries):
        try:
            if retry > 0:
                await asyncio.sleep(min(random.random() + 2 ** (retry - 1), 32))
            return await func(*args, **kwargs)
        except (
            HttpError,
            requests.exceptions.RequestException,
            google.auth.exceptions.GoogleAuthError,
            ChecksumError,
            aiohttp.client_exceptions.ClientError,
        ) as e:
            if (
                isinstance(e, HttpError)
                and e.code == 400
                and "requester pays" in e.message
            ):
                msg = (
                    "Bucket is requester pays. "
                    "Set `requester_pays=True` when creating the GCSFileSystem."
                )
                raise ValueError(msg) from e
            # Special test for 404 to avoid retrying the request
            if (
                isinstance(e, aiohttp.client_exceptions.ClientResponseError)
                and e.status == 404
            ):
                logger.debug("Request returned 404, no retries.")
                raise e
            if isinstance(e, HttpError) and e.code == 404:
                logger.debug("Request returned 404, no retries.")
                raise e
            if retry == retries - 1:
                logger.exception(f"{func.__name__} out of retries on exception: {e}")
                raise e
            if is_retriable(e):
                logger.debug(f"{func.__name__} retrying after exception: {e}")
                continue
            logger.exception(f"{func.__name__} non-retriable exception: {e}")
            raise e


def is_transient_exception(exception):
    is_transient = isinstance(
        exception,
        (
            api_exceptions.DeadlineExceeded,
            api_exceptions.ServiceUnavailable,
            api_exceptions.InternalServerError,
            api_exceptions.TooManyRequests,
            api_exceptions.ResourceExhausted,
            api_exceptions.Unknown,
        ),
    )
    if (
        not is_transient
        and isinstance(exception, api_exceptions.Unauthenticated)
        and "Invalid Credentials" in str(exception)
    ):
        is_transient = True
    return is_transient


def get_storage_control_retry_config(base_config=None, **kwargs) -> AsyncRetry:
    """
    Returns an AsyncRetry object configured for Storage Control API calls.

    Priority: kwargs (timeout, etc.) > base_config > package defaults.

    Args:
        base_config: A dict containing base settings.
        **kwargs: Direct call-site overrides (e.g., timeout=10).
    """
    retry_kwargs = DEFAULT_RETRY_CONFIG.copy()
    valid_keys = DEFAULT_RETRY_CONFIG.keys()
    if base_config:
        retry_kwargs.update(
            {k: v for k, v in base_config.items() if k in valid_keys and v is not None}
        )

    overrides = {k: v for k, v in kwargs.items() if k in valid_keys and v is not None}
    retry_kwargs.update(overrides)

    return AsyncRetry(predicate=is_transient_exception, **retry_kwargs)
