"""Policy-gated IMAP client built on top of aioimaplib.

aioimaplib's :meth:`IMAP4ClientProtocol.welcome` puts the protocol into
``AUTH`` as soon as it sees ``PREAUTH``. That is a reasonable interpretation
of the bytes, but it is *not* an authorization decision. This wrapper keeps
the library for protocol mechanics while forcing every privileged action
through :class:`~preauth_boundary_demo.policy.TrustPolicy` first.

The same wrapper is used two ways:

* :func:`connect_scripted` -- in-memory peer, no network (demo/tests);
* :func:`connect_tcp` -- a real asyncio connection, with transport evidence
  derived from the actual socket/TLS handshake (production path).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Optional

from aioimaplib.aioimaplib import IMAP4ClientProtocol

from .fake_imap import RecordingProtocol, ScriptedImapPeer, open_scripted_connection
from .greeting import Greeting, GreetingStatus, parse_greeting
from .policy import GateDecision, TrustPolicy
from .transport import (
    TransportEvidence,
    classify_asyncio_transport,
)


class PolicyError(RuntimeError):
    """Raised when an action is blocked by the trust policy."""

    def __init__(self, decision: GateDecision, action: str) -> None:
        super().__init__(f"[policy:{decision.code.value}] {action} blocked: {decision.reason}")
        self.decision = decision
        self.action = action


@dataclass
class ConnectionAudit:
    """What the backend should record for each connection attempt."""

    greeting: Greeting
    evidence: TransportEvidence
    decision: GateDecision

    def is_authenticated(self) -> bool:
        return self.decision.authenticated


class GuardedImapClient:
    def __init__(
        self,
        protocol: IMAP4ClientProtocol,
        evidence: TransportEvidence,
        policy: TrustPolicy,
        greeting: Greeting,
        peer: Optional[ScriptedImapPeer] = None,
    ) -> None:
        self._protocol = protocol
        self._evidence = evidence
        self._policy = policy
        self._greeting = greeting
        self._peer = peer
        self._decision = policy.evaluate_greeting(evidence, greeting)
        self.audit = ConnectionAudit(greeting, evidence, self._decision)

    # -- introspection ----------------------------------------------------
    @property
    def decision(self) -> GateDecision:
        return self._decision

    @property
    def library_state(self) -> str:
        """What aioimaplib thinks the state is (AUTH after PREAUTH, etc.)."""
        return self._protocol.state

    @property
    def authenticated(self) -> bool:
        """Whether *our policy* accepts an authenticated context."""
        return self._decision.authenticated

    # -- gated actions ----------------------------------------------------
    async def login(self, user: str, password: str) -> str:
        if not self._decision.may_send_credentials:
            raise PolicyError(self._decision, f"LOGIN for {user!r}")
        response = await self._protocol.login(user, password)
        if response.result != "OK":
            raise PolicyError(
                self._decision, f"LOGIN for {user!r} (server returned {response.result})"
            )
        return response.result

    async def select(self, mailbox: str = "INBOX") -> str:
        if not self._decision.may_select:
            raise PolicyError(self._decision, f"SELECT {mailbox!r}")
        response = await self._protocol.select(mailbox)
        return response.result

    async def logout(self) -> None:
        try:
            await self._protocol.logout()
        finally:
            if self._peer is not None:
                self._peer.stop()

    def close(self) -> None:
        if self._peer is not None:
            self._peer.stop()


async def _build_guarded(
    protocol: RecordingProtocol,
    evidence: TransportEvidence,
    policy: TrustPolicy,
    peer: Optional[ScriptedImapPeer],
) -> GuardedImapClient:
    # open_scripted_connection has already settled the welcome flow and
    # captured the raw greeting line, including for BYE / malformed greetings
    # where the library never reaches AUTH/NONAUTH.
    greeting = parse_greeting(protocol.raw_greeting or b"")
    return GuardedImapClient(protocol, evidence, policy, greeting, peer)


async def connect_scripted(
    greeting: str,
    greeting_status: GreetingStatus,
    evidence: TransportEvidence,
    policy: TrustPolicy,
    *,
    accept_login: bool = True,
) -> GuardedImapClient:
    """Open an in-memory scripted connection and run the policy gate (no network)."""

    protocol, peer = await open_scripted_connection(
        greeting, greeting_status, accept_login=accept_login
    )
    return await _build_guarded(protocol, evidence, policy, peer)


async def connect_tcp(
    host: str,
    port: int,
    expected_hostname: str,
    policy: TrustPolicy,
    *,
    ssl_context=None,
) -> GuardedImapClient:
    """Open a real connection. Transport evidence comes from the real channel.

    Pass a verifying ``ssl_context`` (or ``None`` to use a default
    SERVER_AUTH context) for TLS; the actual certificate/hostname validation
    result is read back from the completed handshake rather than assumed.
    """

    loop = asyncio.get_running_loop()
    protocol = RecordingProtocol(loop)

    def factory() -> RecordingProtocol:
        return protocol

    transport, _ = await loop.create_connection(
        factory, host, port, ssl=ssl_context
    )
    evidence = classify_asyncio_transport(transport, expected_hostname)
    await protocol.wait("AUTH|NONAUTH")
    greeting = parse_greeting(protocol.raw_greeting or b"")
    return GuardedImapClient(protocol, evidence, policy, greeting, peer=None)
