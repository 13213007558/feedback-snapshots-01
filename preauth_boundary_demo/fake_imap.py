"""Scripted, in-memory IMAP peer for the demo and its tests.

This stands in for a real server *without opening any socket or TLS session*.
It drives the genuine :class:`aioimaplib.aioimaplib.IMAP4ClientProtocol`
through its normal ``connection_made`` / ``data_received`` callbacks, so the
library's real greeting handling (including its unconditional
``PREAUTH -> AUTH`` transition) is exercised. The only thing that is fake is
the byte transport and the scripted replies.

Everything here is explicitly labelled as test scaffolding:
:mod:`preauth_boundary_demo.transport` is what supplies the (fake) channel
evidence, and the policy module is what decides whether the scripted
PREAUTH is acceptable.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import List, Optional

from aioimaplib.aioimaplib import CONNECTED, IMAP4ClientProtocol

from .greeting import GreetingStatus


class _MemoryTransport(asyncio.Transport):
    """An asyncio transport that hands writes straight to the scripted peer."""

    def __init__(self, peer: "ScriptedImapPeer") -> None:
        super().__init__()
        self._peer = peer
        self._closed = False

    def write(self, data: bytes) -> None:
        if not self._closed:
            self._peer._on_client_bytes(data)

    def write_eof(self) -> None:
        self._closed = True

    def can_write_eof(self) -> bool:
        return True

    def close(self) -> None:
        self._closed = True

    def is_closing(self) -> bool:
        return self._closed

    def get_extra_info(self, name: str, default=None):
        if name == "peername":
            return None
        return default


@dataclass
class ScriptedImapPeer:
    """A minimal IMAP server: one greeting, then tag-aware canned replies."""

    greeting: str
    greeting_status: GreetingStatus
    protocol: IMAP4ClientProtocol
    accept_login: bool = True
    select_messages: int = 3
    sent_commands: List[str] = field(default_factory=list)
    _queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    _pump_task: Optional[asyncio.Task] = None

    def start(self) -> None:
        self.protocol.connection_made(_MemoryTransport(self))
        self.protocol.data_received(self.greeting.encode("utf-8") + b"\r\n")
        self._pump_task = asyncio.ensure_future(self._pump())

    def stop(self) -> None:
        if self._pump_task is not None and not self._pump_task.done():
            self._pump_task.cancel()
        self._pump_task = None

    def _on_client_bytes(self, data: bytes) -> None:
        self._queue.put_nowait(data)

    def _reply(self, line: str) -> None:
        self.protocol.data_received(line.encode("utf-8") + b"\r\n")

    async def _pump(self) -> None:
        while True:
            try:
                data = await self._queue.get()
            except asyncio.CancelledError:
                raise
            for raw_line in data.decode("utf-8").splitlines():
                parts = raw_line.split()
                if len(parts) < 2:
                    continue
                tag, command = parts[0], parts[1].upper()
                self.sent_commands.append(raw_line)
                await self._handle_command(tag, command, parts[2:])

    async def _handle_command(self, tag: str, command: str, args: List[str]) -> None:
        if command == "CAPABILITY":
            self._reply("* CAPABILITY IMAP4rev1")
            self._reply(f"{tag} OK CAPABILITY completed")
        elif command == "LOGIN":
            if self.accept_login:
                self._reply("* CAPABILITY IMAP4rev1 LOGINDISABLED")
                self._reply(f"{tag} OK LOGIN completed")
            else:
                self._reply(f"{tag} NO login refused by scripted peer")
        elif command == "AUTHENTICATE":
            self._reply(f"{tag} OK AUTHENTICATE completed" if self.accept_login
                        else f"{tag} NO authenticate refused")
        elif command in ("SELECT", "EXAMINE"):
            mailbox = args[0] if args else "INBOX"
            self._reply(f"* {self.select_messages} EXISTS")
            self._reply("* 0 RECENT")
            self._reply(f"{tag} OK [READ-WRITE] {mailbox} selected")
        elif command == "LOGOUT":
            self._reply("* BYE logging out")
            self._reply(f"{tag} OK LOGOUT completed")
        else:
            self._reply(f"{tag} OK {command} completed")


class RecordingProtocol(IMAP4ClientProtocol):
    """The real protocol, plus a capture of the raw greeting line.

    Capturing the greeting ourselves keeps the security decision independent
    of the library's state machine: even though aioimaplib flips to AUTH on
    PREAUTH, the policy gate still has to approve before any mailbox access
    happens.
    """

    def __init__(self, loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        super().__init__(loop or asyncio.get_running_loop())
        self.raw_greeting: Optional[bytes] = None
        # The library's welcome task raises on BYE/malformed greetings. We
        # keep the exception instead of letting it surface as an unretrieved
        # task error; the policy layer handles those greetings explicitly.
        self.greeting_error: Optional[Exception] = None

    def _handle_line(self, line: bytes, current_cmd):
        if self.state == CONNECTED and self.raw_greeting is None:
            self.raw_greeting = line
        return super()._handle_line(line, current_cmd)

    async def welcome(self, command: bytes) -> None:  # type: ignore[override]
        try:
            await super().welcome(command)
        except Exception as exc:  # noqa: BLE001 - surfaced via greeting_error
            self.greeting_error = exc


async def open_scripted_connection(
    greeting: str,
    greeting_status: GreetingStatus,
    *,
    accept_login: bool = True,
) -> tuple[RecordingProtocol, ScriptedImapPeer]:
    """Create a scripted in-memory connection and let the greeting settle.

    For OK/PREAUTH the library's welcome task drives the protocol to
    NONAUTH/AUTH (and runs its automatic CAPABILITY probe). For BYE or a
    malformed greeting the library never reaches those states, so we simply
    yield control until the raw greeting has been captured instead of waiting
    on a state that will never occur.
    """

    loop = asyncio.get_running_loop()
    protocol = RecordingProtocol(loop)
    peer = ScriptedImapPeer(
        greeting=greeting,
        greeting_status=greeting_status,
        protocol=protocol,
        accept_login=accept_login,
    )
    peer.start()

    if greeting_status in (GreetingStatus.BYE, GreetingStatus.MALFORMED):
        # The library never reaches AUTH/NONAUTH here. Wait until the raw
        # greeting is captured and the background welcome task (which raises
        # and is stored in greeting_error) has fully settled, so it is not
        # destroyed pending when the event loop closes.
        for _ in range(100):
            if protocol.raw_greeting is not None and not protocol.tasks:
                break
            await asyncio.sleep(0)
    else:
        await protocol.wait("AUTH|NONAUTH")

    return protocol, peer
