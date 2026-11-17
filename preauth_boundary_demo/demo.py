"""Runnable integration demo: PREAUTH trust boundary across channel types.

Run with::

    .venv/bin/python -m preauth_boundary_demo.demo

No network sockets are opened. Every connection is an in-memory scripted
transport (see :mod:`preauth_boundary_demo.fake_imap`) whose *channel
evidence* is supplied explicitly, so the same policy code can be exercised
against plaintext, unverified TLS, verified TLS and explicitly trusted local
channels.

The demo deliberately shows that:

* aioimaplib enters AUTH on any PREAUTH, even over plaintext;
* the policy gate still refuses mailbox access / credential transmission;
* identity is attributed to a configured source, never parsed from the
  welcome text.
"""

from __future__ import annotations

import asyncio

from .client import GuardedImapClient, PolicyError, connect_scripted
from .greeting import GreetingStatus
from .policy import DecisionCode, TrustPolicy, TrustedPreauthSource
from .transport import TransportKind, fake_evidence

# A PREAUTH greeting that *looks* like it names a user. The demo proves this
# text never becomes the authenticated identity.
PREAUTH_GREETING = "* PREAUTH authenticated as user=root do-not-trust-this-text"
OK_GREETING = "* OK IMAP4rev1 service ready"
BYE_GREETING = "* BYE shutting down"
MALFORMED_GREETING = "PREAUTH missing leading asterisk"


def build_policy() -> TrustPolicy:
    """Trusted configuration: only these channels may honour PREAUTH."""

    return TrustPolicy(
        trusted_preauth_sources=(
            TrustedPreauthSource(
                source_id="mail-edge-tls",
                kind=TransportKind.TLS_VERIFIED,
                channel_identity="mail.example.com",
                note="verified IMAP edge proxy that pre-authenticates sessions",
            ),
            TrustedPreauthSource(
                source_id="sidecar-unix-socket",
                kind=TransportKind.LOCAL_TRUSTED,
                channel_identity="imap-sidecar",
                local_credentials_allowed=True,
                note="co-located local sidecar reached over a protected channel",
            ),
        )
    )


async def _probe_mailbox_access(client: GuardedImapClient) -> str:
    if not client.decision.may_select:
        return "SELECT not attempted (gate forbids it)"
    try:
        result = await client.select("INBOX")
        return f"SELECT allowed -> {result}"
    except PolicyError as exc:
        return f"SELECT blocked -> {exc}"


async def _probe_credentials(client: GuardedImapClient, user: str, password: str) -> str:
    if not client.decision.may_send_credentials:
        return "credentials not sent (gate forbids it)"
    try:
        result = await client.login(user, password)
        return f"LOGIN allowed -> {result}"
    except PolicyError as exc:
        return f"LOGIN blocked -> {exc}"


async def run_case(
    label: str,
    greeting: str,
    greeting_status: GreetingStatus,
    evidence,
    policy: TrustPolicy,
) -> None:
    client = await connect_scripted(greeting, greeting_status, evidence, policy)
    decision = client.decision

    print("=" * 78)
    print(f"SCENARIO: {label}")
    print(f"  channel evidence : {evidence.describe()}")
    print(f"  server greeting  : {greeting!r}")
    print(f"  aioimaplib state : {client.library_state}  (library's own state machine)")
    print(f"  policy decision  : {decision.code.value}")
    print(f"  authenticated    : {decision.authenticated}")
    if decision.preauth_source_id:
        print(f"  identity source  : configured source {decision.preauth_source_id!r} "
              "(not parsed from greeting)")
    print(f"  may SELECT       : {decision.may_select}")
    print(f"  may send creds   : {decision.may_send_credentials}")
    print(f"  reason           : {decision.reason}")

    mailbox_outcome = await _probe_mailbox_access(client)
    print(f"  action           : {mailbox_outcome}")

    if greeting_status is GreetingStatus.OK:
        creds_outcome = await _probe_credentials(client, "alice", "hunter2")
        print(f"  action           : {creds_outcome}")

    client.close()


async def main() -> None:
    policy = build_policy()

    cases = [
        (
            "1. Plaintext connection, server sends PREAUTH",
            PREAUTH_GREETING,
            GreetingStatus.PREAUTH,
            fake_evidence(TransportKind.PLAINTEXT, peer_addr="10.0.0.5"),
        ),
        (
            "2. Verified-host TLS connection, server sends PREAUTH (trusted source)",
            PREAUTH_GREETING,
            GreetingStatus.PREAUTH,
            fake_evidence(
                TransportKind.TLS_VERIFIED,
                peer_identity="mail.example.com",
            ),
        ),
        (
            "3. Verified TLS to an UNLISTED host, server sends PREAUTH",
            PREAUTH_GREETING,
            GreetingStatus.PREAUTH,
            fake_evidence(
                TransportKind.TLS_VERIFIED,
                peer_identity="mail.attacker.example",
            ),
        ),
        (
            "4. Open TLS socket but peer NOT verified, server sends PREAUTH",
            PREAUTH_GREETING,
            GreetingStatus.PREAUTH,
            fake_evidence(TransportKind.TLS_UNVERIFIED, peer_addr="203.0.113.9"),
        ),
        (
            "5. Explicitly trusted local channel, server sends PREAUTH",
            PREAUTH_GREETING,
            GreetingStatus.PREAUTH,
            fake_evidence(
                TransportKind.LOCAL_TRUSTED,
                peer_identity="imap-sidecar",
                peer_addr="127.0.0.1",
            ),
        ),
        (
            "6. Plaintext connection, server sends OK (normal login path)",
            OK_GREETING,
            GreetingStatus.OK,
            fake_evidence(TransportKind.PLAINTEXT, peer_addr="10.0.0.5"),
        ),
        (
            "7. Verified TLS connection, server sends OK (login permitted)",
            OK_GREETING,
            GreetingStatus.OK,
            fake_evidence(
                TransportKind.TLS_VERIFIED,
                peer_identity="mail.example.com",
            ),
        ),
        (
            "8. Trusted local channel, server sends OK (credentials allowed here)",
            OK_GREETING,
            GreetingStatus.OK,
            fake_evidence(
                TransportKind.LOCAL_TRUSTED,
                peer_identity="imap-sidecar",
                peer_addr="127.0.0.1",
            ),
        ),
        (
            "9. Trusted local channel WITHOUT credential permission, server sends OK",
            OK_GREETING,
            GreetingStatus.OK,
            fake_evidence(
                TransportKind.LOCAL_TRUSTED,
                peer_identity="readonly-sidecar",
                peer_addr="127.0.0.1",
            ),
        ),
        (
            "10. Any channel, server sends BYE",
            BYE_GREETING,
            GreetingStatus.BYE,
            fake_evidence(TransportKind.TLS_VERIFIED, peer_identity="mail.example.com"),
        ),
        (
            "11. Malformed greeting (fail closed)",
            MALFORMED_GREETING,
            GreetingStatus.MALFORMED,
            fake_evidence(TransportKind.TLS_VERIFIED, peer_identity="mail.example.com"),
        ),
    ]

    for label, greeting, status, evidence in cases:
        await run_case(label, greeting, status, evidence, policy)

    print("=" * 78)
    print("SUMMARY OF ACCEPTANCE POLICY")
    print("  PREAUTH accepted only on a channel matching a trusted source;")
    print("  credentials sent only over verified TLS or an explicitly permitted")
    print("  trusted local channel; BYE and malformed greetings always rejected;")
    print("  greeting text is never used as a user identity.")


if __name__ == "__main__":
    asyncio.run(main())
