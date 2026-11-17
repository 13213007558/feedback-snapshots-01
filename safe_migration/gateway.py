"""IMAP gateway boundary.

Two implementations share one narrow interface:

* :class:`AioimaplibGateway` wraps the real ``aioimaplib`` client and maps its
  exceptions onto the small hierarchy in :mod:`safe_migration.evidence`.
* :class:`ScriptedGateway` replays canned wire responses (including a
  mid-command disconnect) so the state machine can be tested deterministically
  without binding a TCP port.

All methods take and return only UIDs and raw response lines; the migration
state machine never touches a transport directly.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Set

from .evidence import (
    ImapDisconnected,
    ImapError,
    ImapRefused,
    ImapTimeout,
)


@dataclass
class RawResponse:
    """Result/status pair mirroring ``aioimaplib.Response``."""

    result: str
    lines: List[object]

    @property
    def ok(self) -> bool:
        return self.result == "OK"

    def require_ok(self) -> "RawResponse":
        if not self.ok:
            raise ImapRefused(f"server answered {self.result}: {self.lines!r}")
        return self


class ImapGateway:
    """The only surface the migration engine depends on."""

    capabilities: Set[str]

    async def open(self) -> None: ...
    async def close(self) -> None: ...
    async def select(self, mailbox: str) -> RawResponse: ...
    async def uid_search_message_id(self, message_id: str) -> RawResponse: ...
    async def uid_fetch(self, uid: int, parts: str) -> RawResponse: ...
    async def uid_move(self, uid: int, mailbox: str) -> RawResponse: ...
    async def uid_copy(self, uid: int, mailbox: str) -> RawResponse: ...
    async def uid_store_deleted(self, uid: int) -> RawResponse: ...
    async def uid_expunge(self, uid: int) -> RawResponse: ...


# --------------------------------------------------------------------------- #
# Real aioimaplib adapter
# --------------------------------------------------------------------------- #
class AioimaplibGateway(ImapGateway):
    """Thin adapter over :class:`aioimaplib.IMAP4`.

    The connection factory is injected so a fresh gateway can be created for
    each retry after a disconnect. Credentials and fixed mailbox names are
    supplied by the job configuration, never discovered from message content.
    """

    def __init__(self, client_factory, capabilities: Optional[Set[str]] = None):
        self._client_factory = client_factory
        self._client = None
        self.capabilities = set(capabilities or ())

    async def open(self) -> None:
        try:
            client = await self._client_factory()
            self._client = client
            self.capabilities = set(client.protocol.capabilities)
        except ImapError:
            raise
        except asyncio.TimeoutError as exc:
            raise ImapTimeout(str(exc)) from exc
        except (ConnectionError, OSError) as exc:
            raise ImapDisconnected(str(exc)) from exc

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.logout()
            except (ImapError, OSError, asyncio.TimeoutError):
                pass

    async def _run(self, coro):
        """Run an aioimaplib coroutine and normalise every failure mode."""
        try:
            response = await coro
        except ImapError:
            raise
        except asyncio.TimeoutError as exc:  # IMAP4 wrappers wait_for on timeout
            raise ImapTimeout(str(exc)) from exc
        except Exception as exc:  # aioimaplib.Abort / CommandTimeout / transport
            name = type(exc).__name__
            text = str(exc)
            if name in {"CommandTimeout"}:
                raise ImapTimeout(text) from exc
            if self._client is not None and self._client.protocol.transport is None:
                raise ImapDisconnected(text) from exc
            # An Abort raised before anything was sent (e.g. missing capability)
            # is a definite local refusal, not an unknown server outcome.
            raise ImapRefused(text) from exc
        return RawResponse(response.result, list(response.lines))

    async def select(self, mailbox: str) -> RawResponse:
        response = await self._run(self._client.select(mailbox))
        # Capabilities may be refreshed via untagged CAPABILITY on SELECT.
        if self._client is not None:
            self.capabilities = set(self._client.protocol.capabilities)
        return response

    async def uid_fetch(self, uid: int, parts: str) -> RawResponse:
        return await self._run(self._client.uid("fetch", str(uid), parts))

    async def uid_search_message_id(self, message_id: str) -> RawResponse:
        # Bounded server-side search on an exact header; the engine still
        # verifies the returned UID by full fingerprint before trusting it.
        return await self._run(
            self._client.uid_search("HEADER", "MESSAGE-ID", message_id)
        )

    async def uid_move(self, uid: int, mailbox: str) -> RawResponse:
        return await self._run(self._client.uid("move", str(uid), mailbox))

    async def uid_copy(self, uid: int, mailbox: str) -> RawResponse:
        return await self._run(self._client.uid("copy", str(uid), mailbox))

    async def uid_store_deleted(self, uid: int) -> RawResponse:
        return await self._run(
            self._client.uid("store", str(uid), "+FLAGS", "(\\Deleted)")
        )

    async def uid_expunge(self, uid: int) -> RawResponse:
        # aioimaplib itself refuses UID EXPUNGE without UIDPLUS; we rely on the
        # engine to never call this path unless the capability was advertised.
        return await self._run(self._client.uid("expunge", str(uid)))


# --------------------------------------------------------------------------- #
# Scripted gateway for deterministic, socket-free tests / transcripts
# --------------------------------------------------------------------------- #
@dataclass
class ScriptedStep:
    """One expected command and the canned behaviour that follows it."""

    expect: str                          # normalised command verb, e.g. "UID MOVE"
    result: str = "OK"                   # "OK" | "NO" | "BAD" | "DISCONNECT" | "TIMEOUT"
    lines: List[object] = field(default_factory=list)
    note: str = ""


class ScriptedGateway(ImapGateway):
    """Replays :class:`ScriptedStep` scripts and logs the wire conversation."""

    def __init__(
        self,
        capabilities: Sequence[str],
        select_lines: Optional[List[object]] = None,
        select_lines_by_mailbox: Optional[dict] = None,
        script: Optional[List[ScriptedStep]] = None,
    ):
        self.capabilities = set(capabilities)
        self._select_lines = select_lines or [
            b"FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)",
            b"OK [UIDVALIDITY 9001] UIDs valid",
            b"OK [UIDNEXT 42] Predicted next UID",
        ]
        self._select_lines_by_mailbox = select_lines_by_mailbox or {}
        self._script = list(script or [])
        self.opened = False
        self.transcript: List[str] = []

    async def open(self) -> None:
        self.opened = True
        self.transcript.append(
            "C: <connect>  S: * CAPABILITY IMAP4rev1 " + " ".join(sorted(self.capabilities))
        )

    async def close(self) -> None:
        self.transcript.append("C: <logout / connection closed>")
        self.opened = False

    def _consume(self, command: str) -> RawResponse:
        self.transcript.append(f"C: {command}")
        if not self._script:
            raise AssertionError(f"unexpected command with empty script: {command}")
        step = self._script.pop(0)
        if step.expect not in command:
            raise AssertionError(
                f"expected script step {step.expect!r}, got {command!r}"
            )
        if step.result == "DISCONNECT":
            self.opened = False
            self.transcript.append("S: <TCP connection reset by server; no tagged response>")
            raise ImapDisconnected(f"connection lost during {command}")
        if step.result == "TIMEOUT":
            self.opened = False
            self.transcript.append("S: <silence until client timeout; no tagged response>")
            raise ImapTimeout(f"timeout waiting for {command}")
        for line in step.lines:
            self.transcript.append(f"S: {line}")
        self.transcript.append(f"S: {step.result} ({step.note or command})")
        return RawResponse(step.result, list(step.lines))

    async def select(self, mailbox: str) -> RawResponse:
        lines = self._select_lines_by_mailbox.get(mailbox, self._select_lines)
        self.transcript.append(f"C: SELECT {mailbox}")
        for line in lines:
            self.transcript.append(f"S: {line}")
        self.transcript.append("S: OK SELECT completed")
        return RawResponse("OK", list(lines))

    async def uid_fetch(self, uid: int, parts: str) -> RawResponse:
        step = self._consume(f"UID FETCH {uid} {parts}")
        return step

    async def uid_search_message_id(self, message_id: str) -> RawResponse:
        return self._consume(f"UID SEARCH HEADER MESSAGE-ID {message_id}")

    async def uid_move(self, uid: int, mailbox: str) -> RawResponse:
        return self._consume(f"UID MOVE {uid} {mailbox}")

    async def uid_copy(self, uid: int, mailbox: str) -> RawResponse:
        return self._consume(f"UID COPY {uid} {mailbox}")

    async def uid_store_deleted(self, uid: int) -> RawResponse:
        return self._consume(f"UID STORE {uid} +FLAGS (\\Deleted)")

    async def uid_expunge(self, uid: int) -> RawResponse:
        return self._consume(f"UID EXPUNGE {uid}")
