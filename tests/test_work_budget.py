"""
Tests for the per-message work budget protecting the receiver against malicious message headers that would
otherwise trigger an unbounded amount of KDF/Diffie-Hellman work.

The tests use a *counting* KDF and a *counting* Diffie-Hellman ratchet together with very small DoS
protection thresholds, so the exact number of cryptographic operations caused by a single message can be
asserted and the boundary between "just allowed" and "one too many" is visible.
"""
from typing import Any, Dict, Tuple
from warnings import catch_warnings

from doubleratchet import (
    AuthenticationFailedException,
    DoSProtectionException,
    EncryptedMessage,
    Header,
    KDF,
    MessageWorkBudget,
    OldChainSkipPolicy
)
from doubleratchet.recommended import diffie_hellman_ratchet_curve25519 as dhr25519

from .test_double_ratchet import DoubleRatchet, drc


__all__ = [
    "test_work_budget_dhr_unit",
    "test_work_budget_double_ratchet"
]


try:
    import pytest
except ImportError:
    pass
else:
    pytestmark = pytest.mark.asyncio


class CountingKDF(KDF):
    """
    A deterministic KDF test double that counts every :meth:`derive` call. The output is a reproducible
    expansion of the key, so chain steps remain independent without invoking a real hash function. Subclasses
    keep their own counter, which :func:`_counts` aggregates.
    """

    counter = 0

    @classmethod
    async def derive(cls, key: bytes, data: bytes, length: int) -> bytes:
        cls.counter += 1
        # Deterministic, length-accurate output derived solely from the inputs, so two parties holding the
        # same key and data agree on the result. The counter is only used for counting, never as input.
        accumulator = 0x01
        for byte in key + data:
            accumulator = ((accumulator + byte) * 31) & 0xFF
        seed = bytes([accumulator or 0x01])
        return (seed * (length + 1))[:length]


class CountingRootChainKDF(CountingKDF):
    """The counting KDF used for the root chain."""

    counter = 0


class CountingMessageChainKDF(CountingKDF):
    """The counting KDF used for the sending and receiving chains."""

    counter = 0


class CountingDiffieHellmanRatchet(dhr25519.DiffieHellmanRatchet):
    """
    A Diffie-Hellman ratchet that counts the number of Diffie-Hellman key exchanges performed.
    """

    dh_counter = 0

    @staticmethod
    def _perform_diffie_hellman(own_priv: bytes, other_pub: bytes) -> bytes:
        CountingDiffieHellmanRatchet.dh_counter += 1
        return dhr25519.DiffieHellmanRatchet._perform_diffie_hellman(own_priv, other_pub)


def _reset_counters() -> None:
    CountingRootChainKDF.counter = 0
    CountingMessageChainKDF.counter = 0
    CountingDiffieHellmanRatchet.dh_counter = 0


def _counts() -> Tuple[int, int]:
    return (
        CountingRootChainKDF.counter + CountingMessageChainKDF.counter,
        CountingDiffieHellmanRatchet.dh_counter
    )


async def _paired_ratchets(
    threshold: int,
    budget: MessageWorkBudget,
    policy: OldChainSkipPolicy = OldChainSkipPolicy.WARN
) -> Tuple[CountingDiffieHellmanRatchet, CountingDiffieHellmanRatchet, bytes]:
    """
    Create a freshly paired pair of counting ratchets (Alice initiates, Bob accepts the initial message) and
    return them together with the shared root chain key.
    """

    root_chain_key = b"\x42" * 32
    constant = b"work-budget-test constant"
    bob_priv = CountingDiffieHellmanRatchet._generate_priv()
    alice = await CountingDiffieHellmanRatchet.create(
        None,
        CountingDiffieHellmanRatchet._derive_pub(bob_priv),
        CountingRootChainKDF,
        root_chain_key,
        CountingMessageChainKDF,
        constant,
        threshold,
        budget,
        policy
    )
    initial_key, initial_header = await alice.next_encryption_key()
    bob = await CountingDiffieHellmanRatchet.create(
        bob_priv,
        initial_header.ratchet_pub,
        CountingRootChainKDF,
        root_chain_key,
        CountingMessageChainKDF,
        constant,
        threshold,
        budget,
        policy
    )
    decrypted_key, _ = await bob.next_decryption_key(initial_header)
    assert decrypted_key == initial_key
    # A reply establishes Bob's current ratchet pub as Alice's peer and gives Alice a receiving chain, so
    # later same-chain (non-ratchet) messages are recognized as such.
    reply_key, reply_header = await bob.next_encryption_key()
    assert (await alice.next_decryption_key(reply_header))[0] == reply_key
    return alice, bob, root_chain_key


async def test_work_budget_dhr_unit() -> None:
    """
    Exercise the two cost branches (same-chain large jump and ratchet step with a long previous chain)
    directly on the Diffie-Hellman ratchet, asserting exact KDF/Diffie-Hellman call counts at the boundary.
    """

    # A tiny threshold makes the "just allowed" vs. "one too many" boundary easy to observe.
    threshold = 2
    # Generous budget by default here; individual cases tighten it explicitly.
    generous = MessageWorkBudget(kdf_derivations=2 ** 31, diffie_hellman_operations=2)

    # --- Same-chain (no ratchet step): skips are message-chain KDF steps only -----------------------------
    alice, bob, _ = await _paired_ratchets(threshold, generous)
    # After the handshake reply, Alice's receiving chain is at length 1 and Bob is on the same ratchet pub.
    assert alice._DiffieHellmanRatchet__symmetric_key_ratchet.receiving_chain_length == 1
    same_chain_pub = alice._DiffieHellmanRatchet__other_ratchet_pub

    # A jump of exactly `threshold` skipped keys is just allowed: threshold skipped KDF steps + the final
    # message key = threshold + 1 message-chain KDF derivations, no Diffie-Hellman operations.
    _reset_counters()  # exclude the KDF/DH work spent establishing the paired ratchets
    just_allowed = Header(
        ratchet_pub=same_chain_pub,
        previous_sending_chain_length=0,
        sending_chain_length=1 + threshold  # current length is 1 -> exactly `threshold` skips
    )
    key, skipped = await alice.next_decryption_key(just_allowed)
    kdf_calls, dh_calls = _counts()
    assert len(skipped) == threshold
    assert dh_calls == 0
    assert kdf_calls == threshold + 1
    assert len(key) == 32

    # One more skipped key crosses both the hard threshold and any tight budget of exactly the allowed work.
    alice2, bob2, _ = await _paired_ratchets(threshold, generous)
    tight = MessageWorkBudget(kdf_derivations=threshold + 1, diffie_hellman_operations=0)
    alice2_tight = CountingDiffieHellmanRatchet.from_json(
        alice2.json,
        CountingRootChainKDF,
        CountingMessageChainKDF,
        b"work-budget-test constant",
        threshold,
        tight
    )
    one_too_many = Header(
        ratchet_pub=alice2_tight._DiffieHellmanRatchet__other_ratchet_pub,
        previous_sending_chain_length=0,
        sending_chain_length=1 + threshold + 1
    )
    state_before = alice2_tight.json
    _reset_counters()
    with pytest.raises(DoSProtectionException):
        await alice2_tight.next_decryption_key(one_too_many)
    # Rejected before any cryptographic work and without touching the state.
    assert _counts() == (0, 0)
    assert alice2_tight.json == state_before

    # --- Ratchet step with a long previous chain: a small new-chain number must not bypass the total budget
    # The paired helper already established Bob's chain as Alice's receiving chain. Let Bob accumulate a long
    # chain, then both sides ratchet forward so it becomes the "previous" chain.
    alice3, bob3, _ = await _paired_ratchets(threshold, generous)
    long_chain_length = 20
    for _ in range(long_chain_length):
        await bob3.next_encryption_key()
    # Both sides ratchet forward so Bob's long chain becomes the "previous" chain.
    step_key, step_header = await alice3.next_encryption_key()
    await bob3.next_decryption_key(step_header)
    recovery_key, recovery_header = await bob3.next_encryption_key()
    assert recovery_header.previous_sending_chain_length > threshold
    # The malicious header keeps the *new* chain number tiny but the previous chain very long.
    assert recovery_header.sending_chain_length == 0

    # Under WARN (default) with a generous budget: recovery proceeds, only threshold previous-chain keys are
    # calculated (capped with a warning), plus two root-chain KDF steps and two Diffie-Hellman operations.
    _reset_counters()
    with catch_warnings(record=True) as warning_list:
        recovered_key, recovered_skipped = await alice3.next_decryption_key(recovery_header)
    assert len(warning_list) == 1
    assert "DoS" in str(warning_list[0].message)
    kdf_calls, dh_calls = _counts()
    assert dh_calls == 2
    # threshold capped previous-chain message KDFs + 2 root KDFs + 1 final message KDF
    assert kdf_calls == threshold + 3
    assert len(recovered_skipped) == threshold
    assert recovered_key == recovery_key

    # The same long-previous-chain header cannot bypass a tight *total* budget, even though the new chain
    # number is 0. Build a fresh receiver holding the same pre-recovery state.
    alice4, bob4, _ = await _paired_ratchets(threshold, generous)
    for _ in range(long_chain_length):
        await bob4.next_encryption_key()
    sk4, sh4 = await alice4.next_encryption_key()
    await bob4.next_decryption_key(sh4)
    rk4, rh4 = await bob4.next_encryption_key()
    # Budget only covers a normal ratchet (2 root KDFs + 1 message KDF), none of the previous-chain skips.
    tight_step_budget = MessageWorkBudget(kdf_derivations=3, diffie_hellman_operations=2)
    alice4_tight = CountingDiffieHellmanRatchet.from_json(
        alice4.json,
        CountingRootChainKDF,
        CountingMessageChainKDF,
        b"work-budget-test constant",
        threshold,
        tight_step_budget
    )
    state_before = alice4_tight.json
    _reset_counters()
    with pytest.raises(DoSProtectionException):
        await alice4_tight.next_decryption_key(rh4)
    assert _counts() == (0, 0)
    assert alice4_tight.json == state_before

    # Under the RAISE policy the same header is rejected at the previous-chain check, preserving the session.
    alice5, bob5, _ = await _paired_ratchets(
        threshold, generous, OldChainSkipPolicy.RAISE
    )
    for _ in range(long_chain_length):
        await bob5.next_encryption_key()
    sk5, sh5 = await alice5.next_encryption_key()
    await bob5.next_decryption_key(sh5)
    rk5, rh5 = await bob5.next_encryption_key()
    state_before = alice5.json
    _reset_counters()
    with pytest.raises(DoSProtectionException):
        await alice5.next_decryption_key(rh5)
    assert _counts() == (0, 0)
    assert alice5.json == state_before


async def test_work_budget_double_ratchet() -> None:
    """
    End-to-end checks through the DoubleRatchet: normal loss recovery stays within budget, over-budget and
    authentication-failed messages leave the whole session (including skipped keys) unchanged, and the budget
    is plumbed through the public constructors.
    """

    threshold = 2
    max_skipped = 5
    # The default-derived budget for this threshold: 2 * threshold + 3 KDFs, 2 DH operations.
    default_budget = MessageWorkBudget.from_dos_protection_threshold(threshold)
    assert default_budget == MessageWorkBudget(kdf_derivations=7, diffie_hellman_operations=2)

    config: Dict[str, Any] = {
        **drc,
        "diffie_hellman_ratchet_class": dhr25519.DiffieHellmanRatchet,
        "dos_protection_threshold": threshold,
        "max_num_skipped_message_keys": max_skipped,
        "message_work_budget": default_budget,
        "old_chain_skip_policy": OldChainSkipPolicy.WARN
    }

    shared_secret = b"\x55" * 32
    bob_priv = dhr25519.DiffieHellmanRatchet._generate_priv()
    bob_pub = dhr25519.DiffieHellmanRatchet._derive_pub(bob_priv)
    associated_data = b"work-budget e2e"

    alice_dr, initial = await DoubleRatchet.encrypt_initial_message(
        shared_secret=shared_secret,
        recipient_ratchet_pub=bob_pub,
        message=b"hello",
        associated_data=associated_data,
        **config
    )
    bob_dr, plaintext = await DoubleRatchet.decrypt_initial_message(
        shared_secret=shared_secret,
        own_ratchet_priv=bob_priv,
        message=initial,
        associated_data=associated_data,
        **config
    )
    assert plaintext == b"hello"

    # --- Normal, bounded loss recovery remains fully functional within the budget --------------------------
    lost_1 = await alice_dr.encrypt_message(b"lost1", associated_data)
    lost_2 = await alice_dr.encrypt_message(b"lost2", associated_data)
    in_order = await alice_dr.encrypt_message(b"in-order", associated_data)
    assert await bob_dr.decrypt_message(in_order, associated_data) == b"in-order"
    assert await bob_dr.decrypt_message(lost_2, associated_data) == b"lost2"
    assert await bob_dr.decrypt_message(lost_1, associated_data) == b"lost1"

    # --- A same-chain jump beyond the budget is rejected and leaves the session untouched -------------------
    for _ in range(threshold + 5):
        await alice_dr.encrypt_message(b"flood", associated_data)
    malicious = await alice_dr.encrypt_message(b"flood-last", associated_data)
    bob_state_before = bob_dr.json
    with pytest.raises(DoSProtectionException):
        await bob_dr.decrypt_message(malicious, associated_data)
    assert bob_dr.json == bob_state_before

    # --- An authentication failure also leaves the session untouched ----------------------------------------
    # Use an independent, in-sync session and corrupt only the ciphertext so the AEAD tag check fails.
    auth_secret = b"\x66" * 32
    auth_priv = dhr25519.DiffieHellmanRatchet._generate_priv()
    auth_pub = dhr25519.DiffieHellmanRatchet._derive_pub(auth_priv)
    auth_alice, auth_initial = await DoubleRatchet.encrypt_initial_message(
        shared_secret=auth_secret,
        recipient_ratchet_pub=auth_pub,
        message=b"auth-hello",
        associated_data=associated_data,
        **config
    )
    auth_bob, _ = await DoubleRatchet.decrypt_initial_message(
        shared_secret=auth_secret,
        own_ratchet_priv=auth_priv,
        message=auth_initial,
        associated_data=associated_data,
        **config
    )
    good = await auth_alice.encrypt_message(b"good", associated_data)
    tampered = EncryptedMessage(header=good.header, ciphertext=good.ciphertext[:-1] + b"\x00")
    auth_state_before = auth_bob.json
    with pytest.raises(AuthenticationFailedException):
        await auth_bob.decrypt_message(tampered, associated_data)
    assert auth_bob.json == auth_state_before
    # The untampered message still decrypts, proving the failure did not advance the ratchet.
    assert await auth_bob.decrypt_message(good, associated_data) == b"good"

    # --- The long-previous-chain / tiny-new-chain attack cannot bypass the total budget ---------------------
    strict_config = {
        **config,
        "message_work_budget": MessageWorkBudget(kdf_derivations=3, diffie_hellman_operations=2),
        "old_chain_skip_policy": OldChainSkipPolicy.WARN
    }
    # Build a real back-and-forth session so the victim actually holds a receiving chain; otherwise the
    # previous-chain branch would be skipped rather than charged against the budget.
    victim_priv = dhr25519.DiffieHellmanRatchet._generate_priv()
    victim_pub = dhr25519.DiffieHellmanRatchet._derive_pub(victim_priv)
    sender_dr, victim_initial = await DoubleRatchet.encrypt_initial_message(
        shared_secret=shared_secret,
        recipient_ratchet_pub=victim_pub,
        message=b"seed",
        associated_data=associated_data,
        **strict_config
    )
    victim_dr, _ = await DoubleRatchet.decrypt_initial_message(
        shared_secret=shared_secret,
        own_ratchet_priv=victim_priv,
        message=victim_initial,
        associated_data=associated_data,
        **strict_config
    )
    # One reply establishes the sender's current pub as the victim's peer and a receiving chain.
    reply = await victim_dr.encrypt_message(b"reply", associated_data)
    await sender_dr.decrypt_message(reply, associated_data)
    assert victim_dr.receiving_chain_length is not None

    # Forge a header with a very long previous chain but a new-chain number of zero. Even though the new
    # chain number is tiny, the previous-chain work alone exhausts the total budget.
    forged_header = Header(
        ratchet_pub=dhr25519.DiffieHellmanRatchet._derive_pub(
            dhr25519.DiffieHellmanRatchet._generate_priv()
        ),
        previous_sending_chain_length=50,
        sending_chain_length=0
    )
    forged_message = EncryptedMessage(header=forged_header, ciphertext=b"\x00" * 32)
    victim_state_before = victim_dr.json
    with pytest.raises(DoSProtectionException):
        await victim_dr.decrypt_message(forged_message, associated_data)
    assert victim_dr.json == victim_state_before

    # --- Serialization round-trip preserves the configured budget and policy --------------------------------
    restored = DoubleRatchet.from_json(bob_dr.json, **config)
    assert restored.json == bob_dr.json

    # A negative threshold passed to the budget factory is rejected.
    with pytest.raises(ValueError):
        MessageWorkBudget.from_dos_protection_threshold(-1)
