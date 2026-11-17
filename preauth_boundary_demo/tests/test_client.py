import pytest

from preauth_boundary_demo.client import PolicyError, connect_scripted
from preauth_boundary_demo.greeting import GreetingStatus
from preauth_boundary_demo.policy import DecisionCode, TrustPolicy, TrustedPreauthSource
from preauth_boundary_demo.transport import TransportKind, fake_evidence

PREAUTH = "* PREAUTH user=root do-not-trust"
OK = "* OK ready"
BYE = "* BYE off"
MALFORMED = "PREAUTH no-star"


def policy_factory():
    return TrustPolicy(
        trusted_preauth_sources=(
            TrustedPreauthSource(
                source_id="edge",
                kind=TransportKind.TLS_VERIFIED,
                channel_identity="mail.example.com",
            ),
            TrustedPreauthSource(
                source_id="sidecar",
                kind=TransportKind.LOCAL_TRUSTED,
                channel_identity="imap-sidecar",
                local_credentials_allowed=True,
            ),
        )
    )


@pytest.mark.asyncio
async def test_library_enters_auth_on_plaintext_preauth_but_gate_blocks_select():
    policy = policy_factory()
    evidence = fake_evidence(TransportKind.PLAINTEXT, peer_addr="10.0.0.5")
    client = await connect_scripted(PREAUTH, GreetingStatus.PREAUTH, evidence, policy)

    # The aioimaplib state machine alone would already allow SELECT here.
    assert client.library_state == "AUTH"
    assert client.authenticated is False
    assert client.decision.code is DecisionCode.REJECT_PREAUTH_PLAINTEXT

    with pytest.raises(PolicyError) as excinfo:
        await client.select("INBOX")
    assert excinfo.value.decision.code is DecisionCode.REJECT_PREAUTH_PLAINTEXT
    client.close()


@pytest.mark.asyncio
async def test_verified_tls_preauth_from_trusted_source_allows_select():
    policy = policy_factory()
    evidence = fake_evidence(
        TransportKind.TLS_VERIFIED, peer_identity="mail.example.com"
    )
    client = await connect_scripted(PREAUTH, GreetingStatus.PREAUTH, evidence, policy)

    assert client.library_state == "AUTH"
    assert client.authenticated is True
    result = await client.select("INBOX")
    assert result == "OK"
    # Pre-authenticated source must not be asked for a password.
    with pytest.raises(PolicyError):
        await client.login("anyone", "secret")
    client.close()


@pytest.mark.asyncio
async def test_credentials_refused_over_plaintext_ok_greeting():
    policy = policy_factory()
    evidence = fake_evidence(TransportKind.PLAINTEXT)
    client = await connect_scripted(OK, GreetingStatus.OK, evidence, policy)

    assert client.decision.code is DecisionCode.REJECT_CREDENTIALS
    with pytest.raises(PolicyError):
        await client.login("alice", "hunter2")
    # Prove the password never reached the scripted peer.
    assert not any("LOGIN" in line for line in client._peer.sent_commands)
    client.close()


@pytest.mark.asyncio
async def test_credentials_allowed_over_verified_tls():
    policy = policy_factory()
    evidence = fake_evidence(
        TransportKind.TLS_VERIFIED, peer_identity="mail.example.com"
    )
    client = await connect_scripted(OK, GreetingStatus.OK, evidence, policy)

    assert await client.login("alice", "hunter2") == "OK"
    assert any("LOGIN" in line for line in client._peer.sent_commands)
    # Not authenticated until login succeeds; SELECT before login is gated.
    client2 = await connect_scripted(OK, GreetingStatus.OK, evidence, policy)
    with pytest.raises(PolicyError):
        await client2.select("INBOX")
    client.close()
    client2.close()


@pytest.mark.asyncio
async def test_bye_and_malformed_are_rejected_without_state_wait_hang():
    policy = policy_factory()
    evidence = fake_evidence(
        TransportKind.TLS_VERIFIED, peer_identity="mail.example.com"
    )

    bye_client = await connect_scripted(BYE, GreetingStatus.BYE, evidence, policy)
    assert bye_client.decision.code is DecisionCode.REJECTED_BYE
    assert bye_client.library_state == "CONNECTED"
    # The library's own welcome task raised on BYE; we retain rather than leak it.
    assert bye_client._protocol.greeting_error is not None
    with pytest.raises(PolicyError):
        await bye_client.select("INBOX")
    bye_client.close()

    bad_client = await connect_scripted(
        MALFORMED, GreetingStatus.MALFORMED, evidence, policy
    )
    assert bad_client.decision.code is DecisionCode.REJECTED_MALFORMED
    bad_client.close()


@pytest.mark.asyncio
async def test_identity_never_parsed_from_greeting_text():
    policy = policy_factory()
    evidence = fake_evidence(
        TransportKind.TLS_VERIFIED, peer_identity="mail.example.com"
    )
    client = await connect_scripted(PREAUTH, GreetingStatus.PREAUTH, evidence, policy)
    assert client.audit.greeting.asserted_user is None
    assert client.decision.preauth_source_id == "edge"
    client.close()
