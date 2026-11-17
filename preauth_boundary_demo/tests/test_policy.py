import pytest

from preauth_boundary_demo.greeting import Greeting, GreetingStatus
from preauth_boundary_demo.policy import DecisionCode, TrustPolicy, TrustedPreauthSource
from preauth_boundary_demo.transport import TransportEvidence, TransportKind


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


def greet(status):
    return Greeting(status=status, raw=f"* {status.value} text")


@pytest.mark.parametrize(
    "kind,identity,expected",
    [
        (TransportKind.PLAINTEXT, None, DecisionCode.REJECT_PREAUTH_PLAINTEXT),
        (TransportKind.TLS_UNVERIFIED, None, DecisionCode.REJECT_PREAUTH_TLS_UNVERIFIED),
        (
            TransportKind.TLS_VERIFIED,
            "mail.attacker.example",
            DecisionCode.REJECT_PREAUTH_SOURCE_NOT_TRUSTED,
        ),
        (TransportKind.TLS_VERIFIED, "mail.example.com", DecisionCode.ACCEPT_PREAUTH),
        (TransportKind.LOCAL_TRUSTED, "imap-sidecar", DecisionCode.ACCEPT_PREAUTH),
    ],
)
def test_preauth_decisions(kind, identity, expected):
    policy = policy_factory()
    evidence = TransportEvidence(kind=kind, peer_identity=identity)
    decision = policy.evaluate_greeting(evidence, greet(GreetingStatus.PREAUTH))
    assert decision.code is expected


def test_accepted_preauth_allows_select_but_never_credentials():
    policy = policy_factory()
    evidence = TransportEvidence(
        kind=TransportKind.TLS_VERIFIED, peer_identity="mail.example.com"
    )
    decision = policy.evaluate_greeting(evidence, greet(GreetingStatus.PREAUTH))
    assert decision.authenticated is True
    assert decision.may_select is True
    assert decision.may_send_credentials is False
    assert decision.preauth_source_id == "edge"


def test_preauth_identity_is_attributed_to_source_not_greeting():
    policy = policy_factory()
    evidence = TransportEvidence(
        kind=TransportKind.TLS_VERIFIED, peer_identity="mail.example.com"
    )
    greeting = Greeting(
        status=GreetingStatus.PREAUTH, raw="* PREAUTH user=root welcome admin"
    )
    decision = policy.evaluate_greeting(evidence, greeting)
    assert decision.code is DecisionCode.ACCEPT_PREAUTH
    assert decision.preauth_source_id == "edge"
    assert "root" not in decision.reason


@pytest.mark.parametrize(
    "kind,identity,may_creds,expected",
    [
        (TransportKind.PLAINTEXT, None, False, DecisionCode.REJECT_CREDENTIALS),
        (TransportKind.TLS_UNVERIFIED, None, False, DecisionCode.REJECT_CREDENTIALS),
        (TransportKind.TLS_VERIFIED, "mail.example.com", True, DecisionCode.REQUIRE_LOGIN),
        (TransportKind.LOCAL_TRUSTED, "imap-sidecar", True, DecisionCode.REQUIRE_LOGIN),
        (
            TransportKind.LOCAL_TRUSTED,
            "readonly-sidecar",
            False,
            DecisionCode.REJECT_CREDENTIALS,
        ),
    ],
)
def test_ok_greeting_credential_policy(kind, identity, may_creds, expected):
    policy = policy_factory()
    evidence = TransportEvidence(kind=kind, peer_identity=identity)
    decision = policy.evaluate_greeting(evidence, greet(GreetingStatus.OK))
    assert decision.code is expected
    assert decision.may_send_credentials is may_creds
    assert decision.may_select is False
    assert decision.authenticated is False


def test_bye_and_malformed_always_rejected():
    policy = policy_factory()
    good = TransportEvidence(
        kind=TransportKind.TLS_VERIFIED, peer_identity="mail.example.com"
    )
    bye = policy.evaluate_greeting(good, greet(GreetingStatus.BYE))
    malformed = policy.evaluate_greeting(
        good, Greeting(status=GreetingStatus.MALFORMED, raw="garbage")
    )
    assert bye.code is DecisionCode.REJECTED_BYE
    assert malformed.code is DecisionCode.REJECTED_MALFORMED
    for decision in (bye, malformed):
        assert decision.may_select is False
        assert decision.may_send_credentials is False
        assert decision.authenticated is False


def test_default_policy_trusts_nothing():
    policy = TrustPolicy()
    evidence = TransportEvidence(
        kind=TransportKind.TLS_VERIFIED, peer_identity="mail.example.com"
    )
    decision = policy.evaluate_greeting(evidence, greet(GreetingStatus.PREAUTH))
    assert decision.code is DecisionCode.REJECT_PREAUTH_SOURCE_NOT_TRUSTED
