"""Acceptance policy: combine transport evidence with the greeting.

This is the single place where a trust decision is made. Everything above it
gathers facts (transport evidence, parsed greeting); nothing below it may
re-derive trust from a greeting string or from "the socket has SSL".

Acceptance policy (deliberately small and explicit)
---------------------------------------------------
``* BYE``
    the server is turning the connection away. No mailbox access, no
    credentials. Result: :data:`DecisionCode.REJECTED_BYE`.

malformed greeting
    we cannot tell what state the server is in. Fail closed. Result:
    :data:`DecisionCode.REJECTED_MALFORMED`.

``* OK`` (not pre-authenticated)
    a LOGIN/AUTHENTICATE exchange is required. Sending credentials is only
    allowed over a channel that protects them:

      * :data:`TransportKind.TLS_VERIFIED` -> allowed;
      * :data:`TransportKind.LOCAL_TRUSTED` -> allowed only when the trusted
        local source explicitly permits credentials;
      * plaintext / unverified TLS -> :data:`DecisionCode.REJECT_CREDENTIALS`.

``* PREAUTH`` (server claims pre-authentication)
    the claim is only honoured when the *transport it arrived on* matches a
    pre-authentication source that the operator listed in trusted
    configuration. The greeting text supplies no user, so the authenticated
    context is attributed to the configured source, never to words in the
    welcome message:

      * verified TLS whose hostname matches a trusted TLS source, or an
        explicitly trusted local channel -> :data:`DecisionCode.ACCEPT_PREAUTH`;
      * plaintext -> :data:`DecisionCode.REJECT_PREAUTH_PLAINTEXT`;
      * unverified TLS -> :data:`DecisionCode.REJECT_PREAUTH_TLS_UNVERIFIED`;
      * verified but unlisted peer ->
        :data:`DecisionCode.REJECT_PREAUTH_SOURCE_NOT_TRUSTED`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Tuple

from .greeting import Greeting, GreetingStatus
from .transport import TransportEvidence, TransportKind


class DecisionCode(str, Enum):
    ACCEPT_PREAUTH = "accept-preauth"
    REQUIRE_LOGIN = "require-login"
    REJECT_CREDENTIALS = "reject-credentials"
    REJECT_PREAUTH_PLAINTEXT = "reject-preauth-plaintext"
    REJECT_PREAUTH_TLS_UNVERIFIED = "reject-preauth-tls-unverified"
    REJECT_PREAUTH_SOURCE_NOT_TRUSTED = "reject-preauth-source-not-trusted"
    REJECTED_BYE = "rejected-bye"
    REJECTED_MALFORMED = "rejected-malformed"


_PREAUTH_REJECTIONS = {
    DecisionCode.REJECT_PREAUTH_PLAINTEXT,
    DecisionCode.REJECT_PREAUTH_TLS_UNVERIFIED,
    DecisionCode.REJECT_PREAUTH_SOURCE_NOT_TRUSTED,
    DecisionCode.REJECTED_BYE,
    DecisionCode.REJECTED_MALFORMED,
}


@dataclass(frozen=True)
class TrustedPreauthSource:
    """A pre-authentication source allowed by trusted configuration.

    ``channel_identity`` is matched against the channel-proven identity
    (verified TLS hostname, or explicit local channel id) -- never against
    greeting text. ``local_credentials_allowed`` only applies to local
    channels and says whether a credential exchange is permitted there.
    """

    source_id: str
    kind: TransportKind
    channel_identity: str
    local_credentials_allowed: bool = False
    note: str = ""


@dataclass(frozen=True)
class GateDecision:
    code: DecisionCode
    may_select: bool
    may_send_credentials: bool
    authenticated: bool
    reason: str
    preauth_source_id: Optional[str] = None

    @property
    def accepted(self) -> bool:
        return self.code not in _PREAUTH_REJECTIONS and self.code is not DecisionCode.REJECT_CREDENTIALS


@dataclass
class TrustPolicy:
    """Operator-provided trust configuration.

    Construct this from a real configuration file / secret store in
    production. The defaults trust nothing, which is the safe starting point.
    """

    trusted_preauth_sources: Tuple[TrustedPreauthSource, ...] = field(default_factory=tuple)
    require_verified_tls_for_credentials: bool = True

    def _match_source(self, evidence: TransportEvidence) -> Optional[TrustedPreauthSource]:
        if not evidence.proves_peer_identity:
            return None
        for source in self.trusted_preauth_sources:
            if source.kind is evidence.kind and source.channel_identity == evidence.peer_identity:
                return source
        return None

    def evaluate_greeting(self, evidence: TransportEvidence, greeting: Greeting) -> GateDecision:
        if greeting.status is GreetingStatus.BYE:
            return GateDecision(
                DecisionCode.REJECTED_BYE,
                may_select=False,
                may_send_credentials=False,
                authenticated=False,
                reason="server sent BYE and refused the connection",
            )

        if greeting.status is GreetingStatus.MALFORMED:
            return GateDecision(
                DecisionCode.REJECTED_MALFORMED,
                may_select=False,
                may_send_credentials=False,
                authenticated=False,
                reason=f"malformed greeting, failing closed: {greeting.raw!r}",
            )

        if greeting.status is GreetingStatus.PREAUTH:
            return self._evaluate_preauth(evidence, greeting)

        return self._evaluate_ok(evidence)

    def _evaluate_preauth(
        self, evidence: TransportEvidence, greeting: Greeting
    ) -> GateDecision:
        # Explicitly document the thing we refuse to do: the welcome text is
        # not a user identity regardless of what it contains.
        matched = self._match_source(evidence)

        if evidence.kind is TransportKind.PLAINTEXT:
            return GateDecision(
                DecisionCode.REJECT_PREAUTH_PLAINTEXT,
                may_select=False,
                may_send_credentials=False,
                authenticated=False,
                reason=(
                    "PREAUTH on a cleartext channel can be injected by anyone "
                    "on the path; greeting text proves no identity"
                ),
            )

        if evidence.kind is TransportKind.TLS_UNVERIFIED:
            return GateDecision(
                DecisionCode.REJECT_PREAUTH_TLS_UNVERIFIED,
                may_select=False,
                may_send_credentials=False,
                authenticated=False,
                reason=(
                    "TLS socket is open but the peer was not authenticated "
                    f"({evidence.detail}); PREAUTH cannot be attributed"
                ),
            )

        if matched is None:
            return GateDecision(
                DecisionCode.REJECT_PREAUTH_SOURCE_NOT_TRUSTED,
                may_select=False,
                may_send_credentials=False,
                authenticated=False,
                reason=(
                    "channel proves "
                    f"{evidence.peer_identity!r} but it is not listed as a trusted "
                    "PREAUTH source in configuration"
                ),
            )

        return GateDecision(
            DecisionCode.ACCEPT_PREAUTH,
            may_select=True,
            # A truly pre-authenticated source must not need a password.
            may_send_credentials=False,
            authenticated=True,
            reason=(
                f"PREAUTH accepted; identity guarantee attributed to configured "
                f"source {matched.source_id!r} via {evidence.kind.value}, not to "
                "greeting text"
            ),
            preauth_source_id=matched.source_id,
        )

    def _evaluate_ok(self, evidence: TransportEvidence) -> GateDecision:
        if evidence.kind is TransportKind.TLS_VERIFIED:
            return GateDecision(
                DecisionCode.REQUIRE_LOGIN,
                may_select=False,
                may_send_credentials=True,
                authenticated=False,
                reason="server requires login; channel is verified TLS, credentials may be sent",
            )

        if evidence.kind is TransportKind.LOCAL_TRUSTED:
            matched = self._match_source(evidence)
            allowed = bool(matched and matched.local_credentials_allowed)
            if allowed:
                return GateDecision(
                    DecisionCode.REQUIRE_LOGIN,
                    may_select=False,
                    may_send_credentials=True,
                    authenticated=False,
                    reason=f"explicitly trusted local channel {matched.source_id!r} permits a credential exchange",
                )
            return GateDecision(
                DecisionCode.REJECT_CREDENTIALS,
                may_select=False,
                may_send_credentials=False,
                authenticated=False,
                reason=(
                    "trusted local channel does not permit credentials; configure "
                    "local_credentials_allowed or use verified TLS"
                ),
            )

        return GateDecision(
            DecisionCode.REJECT_CREDENTIALS,
            may_select=False,
            may_send_credentials=False,
            authenticated=False,
            reason=(
                "refusing to send credentials over "
                f"{evidence.kind.value} ({evidence.detail})"
            ),
        )
