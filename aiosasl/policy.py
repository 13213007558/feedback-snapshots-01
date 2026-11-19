########################################################################
# File name: policy.py
# This file is part of: aiosasl
#
# LICENSE
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/>.
#
########################################################################
"""
Transport-aware SASL mechanism selection
========================================

The individual SASL mechanisms in :mod:`aiosasl` are deliberately
transport agnostic.  A mechanism such as :class:`~.PLAIN` will hand the
password to the server whenever it is asked to do so, even over an
unencrypted connection -- the mechanism itself cannot tell whether the
transport is safe for sending credentials.

This module closes that gap.  It keeps four pieces of information which
are otherwise easily conflated in separate places:

1. the mechanisms **advertised** by the server (untrusted input),
2. the mechanisms the **client is capable** of running
   (:class:`ClientCapabilities`),
3. whether the transport uses a **verified TLS** connection
   (:class:`TransportSecurity`), and
4. whether **channel binding** data is available on that transport
   (:class:`TransportSecurity`).

A :class:`SASLPolicy` combines those facts and decides which mechanisms
may be used.  Password-bearing mechanisms (:class:`~.PLAIN` and SCRAM)
are never selected on an untrusted transport, regardless of what the
server advertises.  SCRAM-PLUS is preferred over plain SCRAM whenever
channel binding is available; when the server does not advertise a
``-PLUS`` mechanism and the client falls back to plain SCRAM, the GS2
``y,,`` header is requested so that the downgrade remains detectable
(see :class:`~.SCRAM` and :rfc:`5802`).

The final choice can be overridden through the explicit
:data:`SASLMechanismSelector` hook, which only ever receives candidates
that already satisfy the trusted policy.  It can therefore reorder or
filter, but it can never re-enable a mechanism which the transport
policy rejected (PLAIN on a cleartext connection, for instance).

.. autoclass:: TransportSecurity

.. autoclass:: SASLPolicy

.. autoclass:: ClientCapabilities

.. autoclass:: MechanismCandidate

.. autoclass:: MechanismCandidates

.. autoclass:: NoAcceptableMechanism

.. autodata:: SASLMechanismSelector

.. autofunction:: select_mechanism

.. autofunction:: authenticate
"""
from __future__ import annotations

import dataclasses
import typing

from . import (
    anonymous,
    channel_binding,
    common,
    plain,
    scram,
    statemachine,
)


class NoAcceptableMechanism(common.SASLError):
    """
    Raised when none of the mechanisms advertised by the server is
    acceptable under the effective :class:`SASLPolicy` and the transport
    security state.

    This is a local, policy-driven rejection.  It is raised *before* any
    credential provider is consulted and before any data is sent to the
    server, so no password material can leak as a side effect.

    .. attribute:: advertised

       The mechanism names the server offered at the time of rejection.
    """

    def __init__(
            self,
            advertised: typing.Collection[str],
            text: typing.Optional[str] = None):
        super().__init__(
            None,
            "no acceptable SASL mechanism",
            text=text,
        )
        self.advertised = tuple(advertised)


@dataclasses.dataclass(frozen=True)
class TransportSecurity:
    """
    The security properties of the transport carrying the SASL exchange.

    These facts are established by the application from its own TLS
    stack; they are *not* derived from anything the server says during
    SASL.

    .. attribute:: tls_established

       Whether the transport is protected by TLS at all.

    .. attribute:: tls_verified

       Whether the TLS peer was authenticated (the certificate chain
       validated and the host name matched).  An encrypted but
       unauthenticated connection does not count as a trusted transport.

    .. attribute:: channel_binding

       A :class:`~.channel_binding.ChannelBindingProvider` if channel
       binding data can be extracted from the established TLS
       connection, or :data:`None` if channel binding is unavailable.

    A transport is considered *trusted* for password-bearing mechanisms
    only when :attr:`tls_established` and :attr:`tls_verified` are both
    true.  Channel binding additionally requires a working
    :attr:`channel_binding` provider.
    """

    tls_established: bool = False
    tls_verified: bool = False
    channel_binding: typing.Optional[
        channel_binding.ChannelBindingProvider
    ] = None

    @property
    def is_trusted(self) -> bool:
        """Authenticated TLS on which credentials may be sent."""
        return self.tls_established and self.tls_verified

    @property
    def channel_binding_available(self) -> bool:
        """:data:`True` if channel binding can be used."""
        return self.is_trusted and self.channel_binding is not None


@dataclasses.dataclass(frozen=True)
class SASLPolicy:
    """
    The trusted policy which governs mechanism selection and retries.

    The flags decide which *classes* of mechanisms the client is willing
    to use.  The transport state (:class:`TransportSecurity`) then
    further restricts this set: enabling a mechanism here is necessary
    but not sufficient for it to be selected.

    .. attribute:: allow_plain

       Permit :class:`~.PLAIN`.  Even when enabled, PLAIN is only used
       on a trusted transport.

    .. attribute:: allow_scram

       Permit the non-channel-binding SCRAM family (:class:`~.SCRAM`).

    .. attribute:: allow_scram_plus

       Permit the channel-binding SCRAM-PLUS family
       (:class:`~.SCRAMPLUS`).  It is only usable when channel binding
       data is available.

    .. attribute:: allow_anonymous

       Permit :class:`~.ANONYMOUS`.  ANONYMOUS never uses credentials
       and is therefore not gated on transport trust.

    .. attribute:: retry_on_protocol_failure

       Whether a failed attempt may be followed by another mechanism
       when the failure was unrelated to the credentials
       (:class:`~.SASLFailure`).  An
       :class:`~.AuthenticationFailure` never triggers another
       password-based attempt.

    .. attribute:: max_password_attempts

       The maximum number of times a password-bearing mechanism may be
       attempted during a single :func:`authenticate` call.  The
       default of one prevents repeatedly handing the password to
       alternative mechanisms after an authentication failure.
    """

    allow_plain: bool = True
    allow_scram: bool = True
    allow_scram_plus: bool = True
    allow_anonymous: bool = False
    retry_on_protocol_failure: bool = False
    max_password_attempts: int = 1

    def __post_init__(self) -> None:
        if self.max_password_attempts < 1:
            raise ValueError(
                "max_password_attempts must be at least 1")


@dataclasses.dataclass(frozen=True)
class ClientCapabilities:
    """
    The mechanisms and supporting objects the client is configured to
    use.

    This is distinct from the server advertisement: a capability here
    only means the client *can* run the mechanism, not that it is safe
    or permitted to do so on the current transport.

    .. attribute:: credential_provider

       Coroutine returning ``(username, password)`` for the
       password-based mechanisms.

    .. attribute:: anonymous_token

       Token used with :class:`~.ANONYMOUS`; required only when
       :attr:`SASLPolicy.allow_anonymous` is enabled.

    .. attribute:: enforce_minimum_iteration_count

       Forwarded to the constructed SCRAM mechanisms.
    """

    credential_provider: common.CredentialProvider
    anonymous_token: typing.Optional[str] = None
    enforce_minimum_iteration_count: bool = True


@dataclasses.dataclass(frozen=True)
class MechanismCandidate:
    """
    A single mechanism which passed the policy and transport checks.

    .. attribute:: mechanism

       The concrete :class:`~.SASLMechanism` instance to run.  Instances
       are created during selection but do not fetch credentials until
       :meth:`~.SASLMechanism.authenticate` is awaited.

    .. attribute:: name

       The mechanism name as advertised by the server (e.g.
       ``"SCRAM-SHA-256-PLUS"``).

    .. attribute:: token

       The opaque token produced by
       :meth:`~.SASLMechanism.any_supported` which must be passed to
       :meth:`~.SASLMechanism.authenticate`.

    .. attribute:: sends_password

       Whether the mechanism exchanges password-derived material.  Used
       by the retry bookkeeping to cap credential exposure.

    .. attribute:: channel_bound

       Whether the mechanism binds to the TLS channel (SCRAM-PLUS).

    .. attribute:: scram_downgrade

       :data:`True` when this is a plain SCRAM mechanism chosen while
       the client had SCRAM-PLUS capability.  The candidate is built
       with the GS2 ``y,,`` header so the downgrade is signalled to the
       server rather than silently accepted.
    """

    mechanism: statemachine.SASLMechanism
    name: str
    token: typing.Any
    sends_password: bool
    channel_bound: bool = False
    scram_downgrade: bool = False


class MechanismCandidates(typing.Sequence[MechanismCandidate]):
    """
    The ordered, policy-compliant candidates for one authentication.

    The order reflects preference (strongest first).  Instances are
    immutable and support the :class:`~typing.Sequence` protocol, so
    they can be inspected or reordered by a
    :data:`SASLMechanismSelector`.
    """

    def __init__(
            self,
            candidates: typing.Sequence[MechanismCandidate],
            advertised: typing.Collection[str]):
        self._candidates = tuple(candidates)
        self._advertised = tuple(advertised)

    @property
    def advertised(self) -> typing.Tuple[str, ...]:
        """The mechanism names as advertised by the server."""
        return self._advertised

    @typing.overload
    def __getitem__(self, index: int) -> MechanismCandidate:
        ...

    @typing.overload
    def __getitem__(self, index: slice) -> typing.Sequence[
            MechanismCandidate]:
        ...

    def __getitem__(self, index: typing.Any) -> typing.Any:
        return self._candidates[index]

    def __len__(self) -> int:
        return len(self._candidates)

    def __repr__(self) -> str:
        return "MechanismCandidates({!r})".format(self._candidates)


#: Explicit hook for choosing among the policy-compliant candidates.
#:
#: A selector receives the ordered :class:`MechanismCandidates` together
#: with the transport and policy context and returns the candidate to
#: use, or :data:`None` to abort selection.  It only ever sees
#: candidates which already satisfy the trusted policy, so it cannot
#: resurrect a mechanism which the transport rejected.
SASLMechanismSelector = typing.Callable[
    [
        MechanismCandidates,
        TransportSecurity,
        SASLPolicy,
    ],
    typing.Optional[MechanismCandidate],
]


def _preference_rank(candidate: MechanismCandidate) -> int:
    # Strongest channel protection first, then other password
    # mechanisms, ANONYMOUS last.  Within one family any_supported() has
    # already picked the strongest available hash.
    if candidate.channel_bound:
        return 3
    if isinstance(candidate.mechanism, scram.SCRAM):
        return 2
    if isinstance(candidate.mechanism, plain.PLAIN):
        return 1
    return 0


def _scram_plus_candidate(
        capabilities: ClientCapabilities,
        transport: TransportSecurity,
        advertised: typing.Collection[str],
        ) -> typing.Optional[MechanismCandidate]:
    mechanism = scram.SCRAMPLUS(
        capabilities.credential_provider,
        typing.cast(
            channel_binding.ChannelBindingProvider,
            transport.channel_binding),
        enforce_minimum_iteration_count=(
            capabilities.enforce_minimum_iteration_count),
    )
    token = mechanism.any_supported(advertised)
    if token is None:
        return None
    name, _ = token
    return MechanismCandidate(
        mechanism=mechanism,
        name=name,
        token=token,
        sends_password=True,
        channel_bound=True,
    )


def _scram_candidate(
        capabilities: ClientCapabilities,
        after_scram_plus: bool,
        advertised: typing.Collection[str],
        ) -> typing.Optional[MechanismCandidate]:
    mechanism = scram.SCRAM(
        capabilities.credential_provider,
        after_scram_plus=after_scram_plus,
        enforce_minimum_iteration_count=(
            capabilities.enforce_minimum_iteration_count),
    )
    token = mechanism.any_supported(advertised)
    if token is None:
        return None
    name, _ = token
    return MechanismCandidate(
        mechanism=mechanism,
        name=name,
        token=token,
        sends_password=True,
        scram_downgrade=after_scram_plus,
    )


def _plain_candidate(
        capabilities: ClientCapabilities,
        advertised: typing.Collection[str],
        ) -> typing.Optional[MechanismCandidate]:
    mechanism = plain.PLAIN(capabilities.credential_provider)
    token = mechanism.any_supported(advertised)
    if token is None:
        return None
    return MechanismCandidate(
        mechanism=mechanism,
        name="PLAIN",
        token=token,
        sends_password=True,
    )


def _anonymous_candidate(
        capabilities: ClientCapabilities,
        advertised: typing.Collection[str],
        ) -> typing.Optional[MechanismCandidate]:
    if capabilities.anonymous_token is None:
        return None
    mechanism = anonymous.ANONYMOUS(capabilities.anonymous_token)
    token = mechanism.any_supported(advertised)
    if token is None:
        return None
    return MechanismCandidate(
        mechanism=mechanism,
        name="ANONYMOUS",
        token=token,
        sends_password=False,
    )


def _ordered_candidates(
        advertised: typing.Collection[str],
        capabilities: ClientCapabilities,
        transport: TransportSecurity,
        policy: SASLPolicy,
        ) -> typing.List[MechanismCandidate]:
    candidates: typing.List[MechanismCandidate] = []

    plus_capable = (
        policy.allow_scram_plus and
        transport.channel_binding_available
    )

    if plus_capable:
        candidate = _scram_plus_candidate(
            capabilities, transport, advertised)
        if candidate is not None:
            candidates.append(candidate)

    if policy.allow_scram and transport.is_trusted:
        # Plain SCRAM after the client could have used SCRAM-PLUS keeps
        # the GS2 "y,," downgrade signal.
        candidate = _scram_candidate(
            capabilities,
            after_scram_plus=plus_capable,
            advertised=advertised,
        )
        if candidate is not None:
            candidates.append(candidate)

    if policy.allow_plain and transport.is_trusted:
        candidate = _plain_candidate(capabilities, advertised)
        if candidate is not None:
            candidates.append(candidate)

    if policy.allow_anonymous:
        candidate = _anonymous_candidate(
            capabilities, advertised)
        if candidate is not None:
            candidates.append(candidate)

    candidates.sort(key=_preference_rank, reverse=True)
    return candidates


def _resolve(
        advertised: typing.Collection[str],
        capabilities: ClientCapabilities,
        transport: TransportSecurity,
        policy: SASLPolicy,
        selector: typing.Optional[SASLMechanismSelector],
        ) -> typing.Tuple[
            MechanismCandidates,
            typing.List[MechanismCandidate]]:
    ordered = _ordered_candidates(
        advertised, capabilities, transport, policy)
    candidates = MechanismCandidates(ordered, advertised)

    if not ordered:
        raise NoAcceptableMechanism(
            advertised,
            text=(
                "advertised mechanisms {} are not permitted under the "
                "effective transport policy".format(
                    sorted(advertised))),
        )

    if selector is None:
        return candidates, list(ordered)

    chosen = selector(candidates, transport, policy)
    if chosen is None:
        raise NoAcceptableMechanism(
            advertised,
            text="mechanism selector rejected all candidates",
        )
    if chosen not in candidates:
        raise ValueError(
            "selector returned a candidate which it was not given")

    attempt_order = [chosen]
    attempt_order.extend(
        candidate
        for candidate in ordered
        if candidate != chosen
    )
    return candidates, attempt_order


def select_mechanism(
        advertised: typing.Collection[str],
        capabilities: ClientCapabilities,
        transport: TransportSecurity,
        policy: SASLPolicy,
        selector: typing.Optional[SASLMechanismSelector] = None,
        ) -> MechanismCandidate:
    """
    Choose a mechanism from `advertised` under the given policy.

    Server advertisement, client capability, verified-TLS state and
    channel-binding availability are evaluated independently.  No
    credential provider is invoked and no network traffic is generated
    by this synchronous function.

    :raises NoAcceptableMechanism: if no advertised mechanism is
       permitted by the policy and transport state.
    """
    _, attempt_order = _resolve(
        advertised, capabilities, transport, policy, selector)
    return attempt_order[0]


async def authenticate(
        interface: statemachine.SASLInterface,
        advertised: typing.Collection[str],
        capabilities: ClientCapabilities,
        transport: TransportSecurity,
        policy: typing.Optional[SASLPolicy] = None,
        selector: typing.Optional[SASLMechanismSelector] = None,
        ) -> MechanismCandidate:
    """
    Select and run a mechanism on `interface`.

    A fresh :class:`~.SASLStateMachine` is created for every attempt.
    Retries are governed by `policy`: an
    :class:`~.AuthenticationFailure` always terminates the exchange and
    never leads to another password-based attempt, while a
    :class:`~.SASLFailure` only allows another mechanism when
    :attr:`~.SASLPolicy.retry_on_protocol_failure` is enabled.  The
    number of password-bearing mechanisms used is bounded by
    :attr:`~.SASLPolicy.max_password_attempts`.

    The returned candidate identifies the mechanism which succeeded.

    :raises NoAcceptableMechanism: if selection produces no candidate.
    :raises SASLError: the final mechanism error when the policy does
       not permit another attempt.
    """
    effective_policy = policy or SASLPolicy()
    _, attempt_order = _resolve(
        advertised,
        capabilities,
        transport,
        effective_policy,
        selector,
    )

    password_attempts = 0
    last_error: typing.Optional[common.SASLFailure] = None

    for candidate in attempt_order:
        if candidate.sends_password:
            if password_attempts >= effective_policy.max_password_attempts:
                break
            password_attempts += 1

        state_machine = statemachine.SASLStateMachine(interface)
        try:
            await candidate.mechanism.authenticate(
                state_machine, candidate.token)
        except common.AuthenticationFailure:
            # Credentials were rejected; never try the password against
            # another password-bearing mechanism.
            raise
        except common.SASLFailure as err:
            if not effective_policy.retry_on_protocol_failure:
                raise
            last_error = err
            continue
        else:
            return candidate

    if last_error is None:
        # All candidates were skipped by the password-attempt cap.
        raise NoAcceptableMechanism(advertised)
    raise last_error
