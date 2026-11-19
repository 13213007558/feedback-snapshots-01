"""
Regression tests for receive-side forgery handling.

An attacker can copy the header of a legitimate (possibly late or out-of-order)
message and send it together with a different ciphertext or different
associated data.  The receiver must authenticate every part of the message
before it commits any ratchet state, otherwise the forged message can consume
the skipped message key that the genuine message still needs.

The tests cover three classes of genuine messages:

* a late message on the current receiving chain,
* a message from the chain that was replaced by a Diffie-Hellman ratchet step,
* the next, normally numbered message of the current chain.

Everything is observed through the public API only: ``decrypt_message`` for
plaintext delivery, ``sending_chain_length`` / ``receiving_chain_length`` for
the chains, and ``json`` for the exported state.  Exception types alone are
never considered sufficient: state, chain lengths, skipped-key presence and
delivered plaintext are all compared as well.
"""

from __future__ import annotations

import asyncio
import copy
import types
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, FrozenSet, List, Mapping, Optional, Tuple, Type

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey

from doubleratchet import (
    AuthenticationFailedException,
    DecryptionFailedException,
    DuplicateMessageException,
    EncryptedMessage
)

from .test_double_ratchet import AEAD as TestAEAD
from .test_double_ratchet import DoubleRatchet, drc


pytestmark = pytest.mark.asyncio


SHARED_SECRET = bytes(range(32))
BOB_RATCHET_PRIV = bytes(range(56))
INITIAL_MESSAGE = b"initial message"
ASSOCIATED_DATA = b"receive-forgery-regression associated data"
WRONG_ASSOCIATED_DATA = b"receive-forgery-regression associated data (forged)"

REJECTION_EXCEPTIONS: Tuple[Type[BaseException], ...] = (
    AuthenticationFailedException,
    DecryptionFailedException,
    DuplicateMessageException
)

MessageKey = Tuple[bytes, int]


class ReceiveSequenceFailure(AssertionError):
    """
    Raised when the forged/genuine/replay receive sequence does not behave as required.  ``lost_keys``
    identifies the skipped message keys that were consumed, which allows a failure to name the message that
    would no longer be deliverable.
    """

    def __init__(self, message: str, lost_keys: FrozenSet[MessageKey] = frozenset()) -> None:
        self.lost_keys = frozenset(lost_keys)
        super().__init__(message)


@dataclass(frozen=True)
class MessageRecord:
    """
    A message together with the plaintext it genuinely carries.
    """

    encrypted: EncryptedMessage
    plaintext: bytes


@dataclass(frozen=True)
class AttemptOutcome:
    """
    The observable outcome of a single public ``decrypt_message`` call.
    """

    exception: Optional[BaseException]
    plaintext: Optional[bytes]
    state: Mapping[str, Any]
    skipped: FrozenSet[MessageKey]
    lengths: Tuple[Optional[int], Optional[int]]


@dataclass(frozen=True)
class SequenceOutcome:
    """
    The observable outcome of the full forged/genuine/replay sequence.
    """

    before: AttemptOutcome
    forged: AttemptOutcome
    genuine: AttemptOutcome
    replay: AttemptOutcome

    @property
    def keys_consumed_by_forgery(self) -> FrozenSet[MessageKey]:
        return self.before.skipped - self.forged.skipped

    @property
    def keys_missing_after_genuine(self) -> FrozenSet[MessageKey]:
        return self.before.skipped - self.genuine.skipped


@dataclass(frozen=True)
class Scenario:
    """
    A prepared receiver state plus the genuine message to protect and its observable expectations.
    """

    name: str
    receiver: DoubleRatchet
    target: MessageRecord
    sibling_ciphertext: bytes
    expects_skipped_key: bool
    chain_lengths_before: Tuple[Optional[int], Optional[int]]
    chain_lengths_after: Tuple[Optional[int], Optional[int]]
    messages: Mapping[MessageKey, MessageRecord]

    @property
    def target_key(self) -> MessageKey:
        return _message_key(self.target.encrypted)

    def describe(self, key: MessageKey) -> str:
        record = self.messages.get(key)
        ratchet_pub = f"{key[0].hex()[:16]}..."
        if record is None:
            return f"ratchet_pub={ratchet_pub} index={key[1]} plaintext=<unknown>"
        return f"ratchet_pub={ratchet_pub} index={key[1]} plaintext={record.plaintext!r}"

    @property
    def message_id(self) -> str:
        return f"{self.name}: {self.describe(self.target_key)}"


###############
# observation #
###############

def _message_key(message: EncryptedMessage) -> MessageKey:
    return (message.header.ratchet_pub, message.header.sending_chain_length)


def _skipped_keys(serialized: Mapping[str, Any]) -> FrozenSet[MessageKey]:
    return frozenset(
        (bytes(map(ord, entry["ratchet_pub"])), int(entry["index"]))
        for entry in serialized["skipped_message_keys"]
    )


def _chain_lengths(receiver: DoubleRatchet) -> Tuple[Optional[int], Optional[int]]:
    return (receiver.sending_chain_length, receiver.receiving_chain_length)


def _snapshot(
    receiver: DoubleRatchet
) -> Tuple[Mapping[str, Any], FrozenSet[MessageKey], Tuple[Optional[int], Optional[int]]]:
    state = copy.deepcopy(receiver.json)
    return state, _skipped_keys(state), _chain_lengths(receiver)


async def _attempt(
    receiver: DoubleRatchet,
    message: EncryptedMessage,
    associated_data: bytes
) -> AttemptOutcome:
    try:
        plaintext = await receiver.decrypt_message(message, associated_data)
    except asyncio.CancelledError:
        raise
    except (Exception, KeyboardInterrupt, SystemExit) as error:
        state, skipped, lengths = _snapshot(receiver)
        return AttemptOutcome(error, None, state, skipped, lengths)
    state, skipped, lengths = _snapshot(receiver)
    return AttemptOutcome(None, plaintext, state, skipped, lengths)


async def _run_sequence(
    receiver: DoubleRatchet,
    forged: EncryptedMessage,
    forged_associated_data: bytes,
    genuine: MessageRecord
) -> SequenceOutcome:
    state, skipped, lengths = _snapshot(receiver)
    before = AttemptOutcome(None, None, state, skipped, lengths)
    rejected = await _attempt(receiver, forged, forged_associated_data)
    delivered = await _attempt(receiver, genuine.encrypted, ASSOCIATED_DATA)
    replayed = await _attempt(receiver, genuine.encrypted, ASSOCIATED_DATA)
    return SequenceOutcome(before, rejected, delivered, replayed)


####################
# scenario builders #
####################

def _corrupt_ciphertext(ciphertext: bytes) -> bytes:
    if not ciphertext:
        raise ValueError("Can not corrupt an empty ciphertext.")
    corrupted = bytearray(ciphertext)
    corrupted[-1] ^= 0x01
    return bytes(corrupted)


async def _make_pair() -> Tuple[DoubleRatchet, DoubleRatchet]:
    bob_ratchet_priv = X448PrivateKey.from_private_bytes(BOB_RATCHET_PRIV)
    bob_ratchet_pub = bob_ratchet_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    alice, initial_message = await DoubleRatchet.encrypt_initial_message(
        shared_secret=SHARED_SECRET,
        recipient_ratchet_pub=bob_ratchet_pub,
        message=INITIAL_MESSAGE,
        associated_data=ASSOCIATED_DATA,
        **drc
    )
    bob, plaintext = await DoubleRatchet.decrypt_initial_message(
        shared_secret=SHARED_SECRET,
        own_ratchet_priv=BOB_RATCHET_PRIV,
        message=initial_message,
        associated_data=ASSOCIATED_DATA,
        **drc
    )
    assert plaintext == INITIAL_MESSAGE
    return alice, bob


async def _record(sender: DoubleRatchet, plaintext: bytes) -> MessageRecord:
    return MessageRecord(await sender.encrypt_message(plaintext, ASSOCIATED_DATA), plaintext)


def _index_messages(records: List[MessageRecord]) -> Dict[MessageKey, MessageRecord]:
    return {_message_key(record.encrypted): record for record in records}


async def _build_same_chain_late() -> Scenario:
    """
    A message that arrived out of order on the current receiving chain, so its key is a skipped message key
    of that chain.
    """

    alice, bob = await _make_pair()
    records = [await _record(bob, f"same-chain-{index}".encode("ASCII")) for index in range(5)]
    assert await alice.decrypt_message(records[4].encrypted, ASSOCIATED_DATA) == records[4].plaintext
    assert _chain_lengths(alice) == (0, 5)
    scenario = Scenario(
        "same-chain-late",
        alice,
        records[2],
        records[1].encrypted.ciphertext,
        True,
        (0, 5),
        (0, 5),
        _index_messages(records)
    )
    assert scenario.target_key in _skipped_keys(alice.json)
    return scenario


async def _build_pre_switch_late() -> Scenario:
    """
    A message from the chain that was already replaced by a Diffie-Hellman ratchet step.  Its key is kept as
    a skipped message key even though the chain itself is gone.
    """

    alice, bob = await _make_pair()
    old_chain = [await _record(bob, f"old-chain-{index}".encode("ASCII")) for index in range(6)]
    assert await alice.decrypt_message(old_chain[2].encrypted, ASSOCIATED_DATA) == old_chain[2].plaintext

    post_switch_a = await _record(alice, b"post-switch-a0")
    assert await bob.decrypt_message(post_switch_a.encrypted, ASSOCIATED_DATA) == post_switch_a.plaintext
    post_switch_b = await _record(bob, b"post-switch-b0")
    assert await alice.decrypt_message(post_switch_b.encrypted, ASSOCIATED_DATA) == post_switch_b.plaintext

    assert _chain_lengths(alice) == (0, 1)
    scenario = Scenario(
        "pre-switch-late",
        alice,
        old_chain[4],
        old_chain[3].encrypted.ciphertext,
        True,
        (0, 1),
        (0, 1),
        _index_messages(old_chain + [post_switch_a, post_switch_b])
    )
    assert scenario.target_key in _skipped_keys(alice.json)
    return scenario


async def _build_current() -> Scenario:
    """
    The next, normally numbered message of the current receiving chain, for which no skipped key exists yet.
    """

    alice, bob = await _make_pair()
    first = await _record(bob, b"current-0")
    assert await alice.decrypt_message(first.encrypted, ASSOCIATED_DATA) == first.plaintext
    second = await _record(bob, b"current-1")
    assert _chain_lengths(alice) == (0, 1)

    scenario = Scenario(
        "current-next",
        alice,
        second,
        first.encrypted.ciphertext,
        False,
        (0, 1),
        (0, 2),
        _index_messages([first, second])
    )
    assert scenario.target_key not in _skipped_keys(alice.json)
    return scenario


SCENARIO_BUILDERS: Dict[str, Callable[[], Awaitable[Scenario]]] = {
    "same-chain-late": _build_same_chain_late,
    "pre-switch-late": _build_pre_switch_late,
    "current-next": _build_current
}

FORGERY_VARIANTS: Tuple[str, ...] = (
    "corrupt-ciphertext",
    "wrong-ciphertext",
    "wrong-associated-data"
)


def _impostor_ciphertext(sibling_ciphertext: bytes, target_ciphertext: bytes) -> bytes:
    """
    Build a shape-correct ciphertext that is the genuine ciphertext of a different message.  Its body has the
    target's length so rejection is decided by authentication, not by a length/format error.
    """

    body = sibling_ciphertext[:-64]
    if len(body) < len(target_ciphertext) - 64:
        body = body.ljust(len(target_ciphertext) - 64, b"\x00")
    else:
        body = body[:len(target_ciphertext) - 64]
    return body + sibling_ciphertext[-64:]


def _select_forged_variant(scenario: Scenario, variant: str) -> Tuple[EncryptedMessage, bytes]:
    target = scenario.target.encrypted
    if variant == "corrupt-ciphertext":
        return (EncryptedMessage(target.header, _corrupt_ciphertext(target.ciphertext)), ASSOCIATED_DATA)
    if variant == "wrong-ciphertext":
        return (
            EncryptedMessage(
                target.header,
                _impostor_ciphertext(scenario.sibling_ciphertext, target.ciphertext)
            ),
            ASSOCIATED_DATA
        )
    if variant == "wrong-associated-data":
        return (target, WRONG_ASSOCIATED_DATA)
    raise ValueError(f"Unknown forgery variant: {variant}")


#############
# assertions #
###############

def _lost_description(scenario: Scenario, keys: FrozenSet[MessageKey]) -> str:
    if not keys:
        return "receive state changed without an observable skipped-key consumption"
    consumed = ", ".join(scenario.describe(key) for key in sorted(keys))
    return f"skipped key(s) required by the genuine message were consumed: {consumed}"


async def assert_secure_receive_sequence(scenario: Scenario, variant: str) -> SequenceOutcome:
    """
    Send a forged copy of the genuine message, then the untouched genuine message, then the genuine message
    again.  The required observable result is rejection, successful delivery, rejection.

    Raises:
        ReceiveSequenceFailure: naming the genuine message that was lost, if the sequence is insecure.
    """

    forged, forged_associated_data = _select_forged_variant(scenario, variant)
    outcome = await _run_sequence(scenario.receiver, forged, forged_associated_data, scenario.target)

    def fail(message: str, keys: FrozenSet[MessageKey] = frozenset()) -> None:
        raise ReceiveSequenceFailure(f"{message} [{scenario.message_id}]", keys)

    # 0. The scenario must be in the state its expectations were derived from.
    if outcome.before.lengths != scenario.chain_lengths_before:
        fail(
            f"prepared chains are {outcome.before.lengths}, expected {scenario.chain_lengths_before}"
        )
    if scenario.expects_skipped_key != (scenario.target_key in outcome.before.skipped):
        fail("prepared skipped-key state does not match the expectation")

    # 1. The forged message must be rejected without delivering plaintext.
    if outcome.forged.plaintext is not None:
        fail(f"forged message ({variant}) was accepted and delivered plaintext")
    if outcome.forged.exception is None:
        fail(f"forged message ({variant}) did not raise")
    if isinstance(outcome.forged.exception, asyncio.CancelledError):
        raise outcome.forged.exception
    if not isinstance(outcome.forged.exception, REJECTION_EXCEPTIONS):
        fail(
            f"forged message ({variant}) raised unexpected {type(outcome.forged.exception).__name__}:"
            f" {outcome.forged.exception}"
        )

    # 2. Rejection must not have committed any state, chain step or skipped-key consumption.
    if outcome.forged.state != outcome.before.state or outcome.forged.lengths != outcome.before.lengths:
        fail(
            "the forged message changed the committed receive state before authentication:"
            f" {_lost_description(scenario, outcome.keys_consumed_by_forgery)}",
            outcome.keys_consumed_by_forgery
        )
    if scenario.expects_skipped_key and scenario.target_key not in outcome.forged.skipped:
        fail(
            "the skipped key for the genuine message is missing after rejecting the forgery",
            frozenset({scenario.target_key})
        )

    # 3. The untouched genuine message must now be deliverable.
    if outcome.genuine.exception is not None or outcome.genuine.plaintext != scenario.target.plaintext:
        details = ""
        if outcome.genuine.exception is not None:
            details = f" ({type(outcome.genuine.exception).__name__}: {outcome.genuine.exception})"
        fail(
            "the genuine message was not delivered after the forgery was rejected"
            f"{details}; {_lost_description(scenario, outcome.keys_missing_after_genuine)}",
            outcome.keys_missing_after_genuine
        )
    if outcome.genuine.lengths != scenario.chain_lengths_after:
        fail(
            f"genuine delivery advanced the chains to {outcome.genuine.lengths}, expected"
            f" {scenario.chain_lengths_after}"
        )
    expected_skipped = (
        outcome.before.skipped - {scenario.target_key}
        if scenario.expects_skipped_key
        else outcome.before.skipped
    )
    if outcome.genuine.skipped != expected_skipped:
        fail(
            "genuine delivery changed skipped keys unexpectedly:"
            f" {sorted(outcome.genuine.skipped)} != {sorted(expected_skipped)}"
        )

    # 4. Replaying the now-consumed message must be rejected without further state changes.
    if outcome.replay.plaintext is not None:
        fail("replayed message was accepted and delivered plaintext")
    if outcome.replay.exception is None:
        fail("replayed message did not raise")
    if isinstance(outcome.replay.exception, asyncio.CancelledError):
        raise outcome.replay.exception
    if not isinstance(outcome.replay.exception, REJECTION_EXCEPTIONS):
        fail(
            f"replayed message raised unexpected {type(outcome.replay.exception).__name__}:"
            f" {outcome.replay.exception}"
        )
    if outcome.replay.state != outcome.genuine.state or outcome.replay.lengths != outcome.genuine.lengths:
        fail("replaying the genuine message changed the receive state")

    return outcome


#################
# AEAD failures #
#################

def _decryption_failure() -> BaseException:
    return DecryptionFailedException("injected AEAD decryption failure")


def _unexpected_failure() -> BaseException:
    return RuntimeError("injected AEAD crash")


AEAD_FAILURE_FACTORIES: Dict[str, Callable[[], BaseException]] = {
    "decryption-failed": _decryption_failure,
    "unexpected-error": _unexpected_failure
}


def _make_fault_injecting_aead(failure: BaseException) -> Type[TestAEAD]:
    """
    Return an AEAD that raises ``failure`` on its first decryption attempt and behaves normally afterwards.
    """

    class FaultInjectingAEAD(TestAEAD):
        _pending: List[BaseException] = [failure]

        @classmethod
        async def decrypt(cls, ciphertext: bytes, key: bytes, associated_data: bytes) -> bytes:
            if cls._pending:
                raise cls._pending.pop(0)
            return await super().decrypt(ciphertext, key, associated_data)

    return FaultInjectingAEAD


def _make_hanging_aead() -> Tuple[Type[TestAEAD], asyncio.Event]:
    """
    Return an AEAD that signals ``started`` and then suspends in decryption until the calling task is
    cancelled.  Clearing ``hang`` makes all later decryptions behave normally.
    """

    started = asyncio.Event()

    class HangingAEAD(TestAEAD):
        hang = True

        @classmethod
        async def decrypt(cls, ciphertext: bytes, key: bytes, associated_data: bytes) -> bytes:
            if cls.hang:
                started.set()
                await asyncio.Event().wait()
            return await super().decrypt(ciphertext, key, associated_data)

    return HangingAEAD, started


async def _build_receiver_with_aead(scenario: Scenario, aead: Type[TestAEAD]) -> DoubleRatchet:
    return DoubleRatchet.from_json(scenario.receiver.json, **{**drc, "aead": aead})


###########
# the bug #
###########

def _install_pre_auth_key_deletion(receiver: DoubleRatchet) -> None:
    """
    Temporarily move the skipped-key deletion in front of authentication, reproducing the regression this
    module is meant to catch.  The genuine message must then be reported as lost by name.
    """

    original = type(receiver).decrypt_message

    async def decrypt_message_with_early_deletion(
        self: DoubleRatchet,
        message: EncryptedMessage,
        associated_data: bytes
    ) -> bytes:
        key = (message.header.ratchet_pub, message.header.sending_chain_length)
        getattr(self, "_DoubleRatchet__skipped_message_keys").pop(key, None)
        return await original(self, message, associated_data)

    setattr(receiver, "decrypt_message", types.MethodType(decrypt_message_with_early_deletion, receiver))


##########
# tests  #
#########

@pytest.mark.parametrize("scenario_name", list(SCENARIO_BUILDERS))
@pytest.mark.parametrize("variant", FORGERY_VARIANTS)
async def test_forgery_rejected_then_genuine_delivered_then_replay_rejected(
    scenario_name: str,
    variant: str
) -> None:
    scenario = await SCENARIO_BUILDERS[scenario_name]()
    outcome = await assert_secure_receive_sequence(scenario, variant)

    assert outcome.forged.exception is not None
    assert outcome.forged.plaintext is None
    assert outcome.genuine.exception is None
    assert outcome.genuine.plaintext == scenario.target.plaintext
    assert outcome.replay.exception is not None
    assert outcome.replay.plaintext is None


@pytest.mark.parametrize("scenario_name", list(SCENARIO_BUILDERS))
@pytest.mark.parametrize("failure_name", list(AEAD_FAILURE_FACTORIES))
async def test_aead_failure_before_commit_is_rolled_back(
    scenario_name: str,
    failure_name: str
) -> None:
    scenario = await SCENARIO_BUILDERS[scenario_name]()
    failure = AEAD_FAILURE_FACTORIES[failure_name]()
    receiver = await _build_receiver_with_aead(scenario, _make_fault_injecting_aead(failure))

    state_before = copy.deepcopy(receiver.json)
    skipped_before = _skipped_keys(state_before)
    lengths_before = _chain_lengths(receiver)

    forged = EncryptedMessage(
        scenario.target.encrypted.header,
        _corrupt_ciphertext(scenario.target.encrypted.ciphertext)
    )
    with pytest.raises(type(failure)) as excinfo:
        await receiver.decrypt_message(forged, ASSOCIATED_DATA)
    assert excinfo.value is failure

    # The failure must leave every observable part of the receive state untouched.
    assert receiver.json == state_before
    assert _chain_lengths(receiver) == lengths_before
    assert _skipped_keys(receiver.json) == skipped_before
    if scenario.expects_skipped_key:
        assert scenario.target_key in _skipped_keys(receiver.json)

    # The genuine message is still deliverable and a replay is still rejected.
    assert await receiver.decrypt_message(scenario.target.encrypted, ASSOCIATED_DATA) \
        == scenario.target.plaintext
    assert _chain_lengths(receiver) == scenario.chain_lengths_after
    state_after_genuine = copy.deepcopy(receiver.json)
    with pytest.raises(REJECTION_EXCEPTIONS):
        await receiver.decrypt_message(scenario.target.encrypted, ASSOCIATED_DATA)
    assert receiver.json == state_after_genuine


@pytest.mark.parametrize("scenario_name", list(SCENARIO_BUILDERS))
async def test_cancelled_decryption_does_not_consume_key(scenario_name: str) -> None:
    scenario = await SCENARIO_BUILDERS[scenario_name]()
    hanging_aead, started = _make_hanging_aead()
    receiver = await _build_receiver_with_aead(scenario, hanging_aead)

    state_before = copy.deepcopy(receiver.json)
    skipped_before = _skipped_keys(state_before)
    lengths_before = _chain_lengths(receiver)

    forged = EncryptedMessage(
        scenario.target.encrypted.header,
        _corrupt_ciphertext(scenario.target.encrypted.ciphertext)
    )
    task = asyncio.create_task(receiver.decrypt_message(forged, ASSOCIATED_DATA))
    try:
        await asyncio.wait_for(started.wait(), timeout=5.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert task.cancelled()
    finally:
        setattr(hanging_aead, "hang", False)
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    # Cancellation happened after key selection but before authentication committed anything.
    assert receiver.json == state_before
    assert _chain_lengths(receiver) == lengths_before
    assert _skipped_keys(receiver.json) == skipped_before
    if scenario.expects_skipped_key:
        assert scenario.target_key in _skipped_keys(receiver.json)

    assert await receiver.decrypt_message(scenario.target.encrypted, ASSOCIATED_DATA) \
        == scenario.target.plaintext
    assert _chain_lengths(receiver) == scenario.chain_lengths_after
    state_after_genuine = copy.deepcopy(receiver.json)
    with pytest.raises(REJECTION_EXCEPTIONS):
        await receiver.decrypt_message(scenario.target.encrypted, ASSOCIATED_DATA)
    assert receiver.json == state_after_genuine


@pytest.mark.parametrize("scenario_name", ["same-chain-late", "pre-switch-late"])
async def test_pre_auth_key_deletion_failure_names_the_lost_message(scenario_name: str) -> None:
    scenario = await SCENARIO_BUILDERS[scenario_name]()
    _install_pre_auth_key_deletion(scenario.receiver)

    with pytest.raises(ReceiveSequenceFailure) as excinfo:
        await assert_secure_receive_sequence(scenario, "corrupt-ciphertext")

    failure = excinfo.value
    assert failure.lost_keys == frozenset({scenario.target_key})
    assert scenario.message_id in str(failure)
    assert repr(scenario.target.plaintext) in str(failure)
