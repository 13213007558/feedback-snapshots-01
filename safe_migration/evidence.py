"""Evidence primitives for the bounded, approved-message migration tool.

The whole design rests on one rule: a migration is only *confirmed* on
server-issued identity evidence (UID / UIDVALIDITY / COPYUID), never on a
subjective match such as "a message with a similar body exists in the
destination".
"""
from __future__ import annotations

import email
import hashlib
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Sequence, Tuple


class MigrationStatus(str, Enum):
    """Lifecycle of a single approved UID.

    Only ``CONFIRMED`` is a success. ``FAILED`` means the server demonstrably
    refused the command. Every ambiguous outcome is ``REVIEW`` (manual
    handling required) rather than a guessed result.
    """

    PENDING = "PENDING"                      # approved, not attempted yet
    MOVE_SENT_UNKNOWN = "MOVE_SENT_UNKNOWN"  # MOVE on the wire, answer lost
    COPY_OK_DELETE_UNKNOWN = "COPY_OK_DELETE_UNKNOWN"
    CONFIRMED = "CONFIRMED"                  # success, evidence complete
    FAILED = "FAILED"                        # explicit server NO/BAD
    REVIEW = "REVIEW"                        # human threshold reached


# Terminal states: a worker must never mutate these records automatically.
TERMINAL_STATES = frozenset(
    {MigrationStatus.CONFIRMED, MigrationStatus.FAILED, MigrationStatus.REVIEW}
)


class ImapError(Exception):
    """Base class for gateway failures."""


class ImapDisconnected(ImapError):
    """The transport dropped while a command was in flight.

    aioimaplib does not fail the pending command on ``connection_lost``; it
    only invokes ``conn_lost_cb`` and the command later raises
    :class:`~aioimaplib.CommandTimeout`. We normalise both to this type so the
    state machine treats them as "answer unknown", never as failure or success.
    """


class ImapTimeout(ImapError):
    """No tagged completion arrived before the command timeout."""


class ImapRefused(ImapError):
    """The server returned an explicit tagged NO or BAD."""


@dataclass(frozen=True)
class MailboxAnchor:
    """Fixed identity of a mailbox across the whole job.

    ``uidvalidity`` is recorded up front and re-checked on every fresh
    connection. A mismatch means UIDs no longer name the same messages, so the
    job must stop for human review instead of acting on stale UIDs.
    """

    host: str
    mailbox: str
    uidvalidity: int


@dataclass(frozen=True)
class MessageFingerprint:
    """Strong, header-derived identity of one message.

    These fields come from a single FETCH of the *source* UID before any
    mutating command. They are evidence used to corroborate a later recheck;
    they are never a substitute for UID/COPYUID confirmation.
    """

    uid: int
    message_id: Optional[str]
    rfc822_size: int
    body_sha256: str
    internal_date: Optional[str]


@dataclass(frozen=True)
class CopyUid:
    """Parsed ``OK [COPYUID <uidvalidity> <src-uids> <dst-uids>]`` response."""

    uidvalidity: int
    source_uids: Tuple[int, ...]
    target_uids: Tuple[int, ...]

    def maps_single(self, source_uid: int) -> Optional[int]:
        """Return the target UID for a one-message COPY, else ``None``."""
        if (
            len(self.source_uids) == 1
            and len(self.target_uids) == 1
            and self.source_uids[0] == source_uid
        ):
            return self.target_uids[0]
        return None


def _flatten_lines(lines: Sequence[object]) -> bytes:
    chunks = []
    for line in lines:
        if isinstance(line, (bytes, bytearray)):
            chunks.append(bytes(line))
        else:  # pragma: no cover - defensive, aioimaplib always yields bytes
            chunks.append(str(line).encode())
    return b"\r\n".join(chunks)


def parse_uidvalidity(select_lines: Sequence[object]) -> Optional[int]:
    """Extract UIDVALIDITY from SELECT/EXAMINE untagged response lines."""
    blob = _flatten_lines(select_lines)
    marker = b"UIDVALIDITY "
    start = blob.find(marker)
    if start == -1:
        return None
    digits = []
    for char in blob[start + len(marker):]:
        if char < 0x30 or char > 0x39:
            break
        digits.append(chr(char))
    if not digits:
        return None
    return int("".join(digits))


def _uid_range(token: bytes) -> Tuple[int, ...]:
    if b":" not in token:
        return (int(token),)
    lo, hi = (int(part) for part in token.split(b":", 1))
    return tuple(range(lo, hi + 1))


def parse_copyuid(response_lines: Sequence[object]) -> Optional[CopyUid]:
    """Parse ``OK [COPYUID ...]`` expanding any ``a:b`` UID ranges."""
    blob = _flatten_lines(response_lines)
    match = re.search(rb"COPYUID\s+(\d+)\s+([0-9:]+)\s+([0-9:]+)", blob)
    if match is None:
        return None
    try:
        return CopyUid(int(match.group(1)),
                       _uid_range(match.group(2)),
                       _uid_range(match.group(3)))
    except ValueError:
        return None


def parse_search_uids(search_lines: Sequence[object]) -> Tuple[int, ...]:
    """Parse UIDs from a ``UID SEARCH`` response (``* SEARCH 437 438``)."""
    blob = _flatten_lines(search_lines)
    match = re.search(rb"SEARCH\s*([0-9 ]*)", blob)
    if match is None:
        return ()
    return tuple(int(token) for token in match.group(1).split() if token.isdigit())


def parse_fetch_uid(fetch_lines: Sequence[object]) -> Optional[int]:
    """Extract the message UID from ``UID FETCH`` response lines.

    Matches the standard ``... FETCH (UID <n> ...`` form as well as a bare
    ``* <n> FETCH (UID <n>)`` one.
    """
    blob = _flatten_lines(fetch_lines)
    match = re.search(rb"UID\s+(\d+)", blob)
    return int(match.group(1)) if match else None


def parse_fetch_size(fetch_lines: Sequence[object]) -> Optional[int]:
    blob = _flatten_lines(fetch_lines)
    marker = b"RFC822.SIZE "
    start = blob.find(marker)
    if start == -1:
        return None
    digits = []
    for char in blob[start + len(marker):]:
        if char < 0x30 or char > 0x39:
            break
        digits.append(chr(char))
    return int("".join(digits)) if digits else None


def parse_internal_date(fetch_lines: Sequence[object]) -> Optional[str]:
    blob = _flatten_lines(fetch_lines)
    marker = b"INTERNALDATE "
    start = blob.find(marker)
    if start == -1:
        return None
    rest = blob[start + len(marker):]
    quoted = rest.find(b'"')
    if quoted == -1:
        return None
    end = rest.find(b'"', quoted + 1)
    if end == -1:
        return None
    return rest[quoted + 1:end].decode("utf-8", "replace")


def extract_literal(fetch_lines: Sequence[object]) -> Optional[bytes]:
    """Return the literal payload announced by a ``{size}`` FETCH marker.

    aioimaplib delivers the literal as its own response line following the
    ``... BODY[] {size}`` header, so we locate that header and take the next
    line. Content is never guessed from brackets or other punctuation.
    """
    lines = list(fetch_lines)
    for index, line in enumerate(lines):
        if not isinstance(line, (bytes, bytearray)):
            continue
        if re.search(rb"\{\d+\}\s*$", bytes(line)) and index + 1 < len(lines):
            candidate = lines[index + 1]
            if isinstance(candidate, (bytes, bytearray)):
                return bytes(candidate)
    return None


def build_fingerprint(
    uid: int, fetch_lines: Sequence[object], literal: Optional[bytes]
) -> MessageFingerprint:
    """Build source-message identity evidence from one UID FETCH."""
    message_id = None
    internal_date = parse_internal_date(fetch_lines)
    if literal is not None:
        parsed = email.message_from_bytes(literal)
        raw_mid = parsed.get("Message-ID") or parsed.get("Message-Id")
        if raw_mid:
            message_id = raw_mid.strip()
        digest = hashlib.sha256(literal).hexdigest()
        size = len(literal)
    else:
        digest = ""
        size = parse_fetch_size(fetch_lines) or 0
    return MessageFingerprint(
        uid=uid,
        message_id=message_id,
        rfc822_size=size,
        body_sha256=digest,
        internal_date=internal_date,
    )
