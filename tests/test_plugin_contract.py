from __future__ import annotations

import itertools
import json
from typing import Any, Dict, List, Optional, Tuple, Type

from doubleratchet import (
    AEAD,
    AuthenticationFailedException,
    DoubleRatchet as DR,
    EncryptedMessage,
    Header,
    KDF,
    KDFChain
)
from doubleratchet.recommended import (
    aead_aes_hmac,
    diffie_hellman_ratchet_curve25519 as dhr25519,
    HashFunction,
    kdf_hkdf,
    kdf_separate_hmacs
)


__all__ = [
    "test_two_party_conversation_transcript_is_deterministic",
    "test_serialization_roundtrip_preserves_transcript",
    "test_plugin_call_site_invariants",
    "test_kdf_failure_propagates_and_preserves_state",
    "test_aead_failure_propagates_and_preserves_state",
    "test_authentication_failure_preserves_state",
    "test_malformed_kdf_output_rejected",
    "test_malformed_aead_output_rejected",
    "test_silent_failure_contrast"
]


try:
    import pytest
except ImportError:
    pass
else:
    pytestmark = pytest.mark.asyncio


################################
# deterministic test scaffolding #
################################


class DeterministicDiffieHellmanRatchet(dhr25519.DiffieHellmanRatchet):
    """
    A Curve25519 Diffie-Hellman ratchet with deterministic key generation, such that conversations produce
    reproducible transcripts that can be compared item by item.
    """

    _priv_counter = itertools.count(1)

    @staticmethod
    def _generate_priv() -> bytes:
        return next(DeterministicDiffieHellmanRatchet._priv_counter).to_bytes(32, "big")

    @classmethod
    def reset(cls) -> None:
        cls._priv_counter = itertools.count(1)


class DoubleRatchet(DR):
    """
    The Double Ratchet to use while testing.
    """

    @staticmethod
    def _build_associated_data(associated_data: bytes, header: Header) -> bytes:
        return (
            associated_data
            + header.ratchet_pub
            + header.sending_chain_length.to_bytes(8, "big")
            + header.previous_sending_chain_length.to_bytes(8, "big")
        )


###############################
# real recommended implementations, combination A (HKDF everywhere, AEAD with SHA-256) #
###############################


class RootChainKDFA(kdf_hkdf.KDF):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_256

    @staticmethod
    def _get_info() -> bytes:
        return "test_plugin_contract Root Chain KDF A info".encode("ASCII")


class MessageChainKDFA(kdf_hkdf.KDF):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512_256

    @staticmethod
    def _get_info() -> bytes:
        return "test_plugin_contract Message Chain KDF A info".encode("ASCII")


class AEADA(aead_aes_hmac.AEAD):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_256

    @staticmethod
    def _get_info() -> bytes:
        return "test_plugin_contract AEAD A info".encode("ASCII")


#########################################################
# real recommended implementations, combination B:      #
# HKDF root chain, separate-HMACs message chain,        #
# AEAD with SHA-512                                     #
#########################################################


class RootChainKDFB(kdf_hkdf.KDF):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return "test_plugin_contract Root Chain KDF B info".encode("ASCII")


class MessageChainKDFB(kdf_separate_hmacs.KDF):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_256


class AEADB(aead_aes_hmac.AEAD):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return "test_plugin_contract AEAD B info".encode("ASCII")


CONFIG_A: Dict[str, Any] = {
    "diffie_hellman_ratchet_class": DeterministicDiffieHellmanRatchet,
    "root_chain_kdf": RootChainKDFA,
    "message_chain_kdf": MessageChainKDFA,
    # Any constant works with the HKDF-based message chain KDF
    "message_chain_constant": "test_plugin_contract Message Chain constant A".encode("ASCII"),
    "dos_protection_threshold": 10,
    "max_num_skipped_message_keys": 15,
    "aead": AEADA
}

CONFIG_B: Dict[str, Any] = {
    "diffie_hellman_ratchet_class": DeterministicDiffieHellmanRatchet,
    "root_chain_kdf": RootChainKDFB,
    "message_chain_kdf": MessageChainKDFB,
    # The separate-HMACs KDF requires len(constant) * hash_size == 64, i.e. a two-byte constant with SHA-256
    "message_chain_constant": b"\xaa\xbb",
    "dos_protection_threshold": 10,
    "max_num_skipped_message_keys": 15,
    "aead": AEADB
}

ALL_CONFIGS = [CONFIG_A, CONFIG_B]

SHARED_SECRET = bytes(range(32))
ASSOCIATED_DATA = b"test_plugin_contract associated data"


#####################
# conversation script #
#####################


async def run_conversation(
    config: Dict[str, Any],
    restore_after: Optional[int] = None
) -> List[Tuple[str, ...]]:
    """
    Run a scripted two-party conversation between Alice and Bob and return a transcript of all events. The
    script covers in-order messages, out-of-order messages (skipped message keys) and a final exchange after
    the out-of-order delivery. Optionally, both parties are serialized and restored via
    :meth:`DoubleRatchet.from_json` once the transcript has reached a certain length.

    Args:
        config: The plugin configuration to use for both parties.
        restore_after: Restore both parties from their JSON serialization once the transcript has reached
            this many events, or ``None`` to run without restoration.

    Returns:
        The transcript as a list of string tuples, one per event, suitable for item-by-item comparison.
    """

    DeterministicDiffieHellmanRatchet.reset()
    events: List[Tuple[str, ...]] = []
    restored = False

    bob_priv = DeterministicDiffieHellmanRatchet._generate_priv()
    bob_pub = DeterministicDiffieHellmanRatchet._derive_pub(bob_priv)

    alice, initial_message = await DoubleRatchet.encrypt_initial_message(
        shared_secret=SHARED_SECRET,
        recipient_ratchet_pub=bob_pub,
        message=b"initial a2b",
        associated_data=ASSOCIATED_DATA,
        **config
    )
    events.append(("enc", "alice", b"initial a2b".hex(), initial_message.ciphertext.hex()))

    bob, plaintext = await DoubleRatchet.decrypt_initial_message(
        shared_secret=SHARED_SECRET,
        own_ratchet_priv=bob_priv,
        message=initial_message,
        associated_data=ASSOCIATED_DATA,
        **config
    )
    assert plaintext == b"initial a2b"
    events.append(("dec", "bob", plaintext.hex()))

    async def maybe_restore() -> None:
        nonlocal alice, bob, restored
        if restore_after is not None and not restored and len(events) >= restore_after:
            alice = DoubleRatchet.from_json(json.loads(json.dumps(alice.json)), **config)
            bob = DoubleRatchet.from_json(json.loads(json.dumps(bob.json)), **config)
            restored = True

    await maybe_restore()

    # Bob -> Alice, three messages delivered in order
    for i in range(3):
        message = f"b2a-{i}".encode("ASCII")
        encrypted = await bob.encrypt_message(message, ASSOCIATED_DATA)
        events.append(("enc", "bob", message.hex(), encrypted.ciphertext.hex()))
        await maybe_restore()
        plaintext = await alice.decrypt_message(encrypted, ASSOCIATED_DATA)
        assert plaintext == message
        events.append(("dec", "alice", plaintext.hex()))
        await maybe_restore()

    # Alice -> Bob, four messages delivered out of order
    pending: List[Tuple[bytes, EncryptedMessage]] = []
    for i in range(4):
        message = f"a2b-{i}".encode("ASCII")
        encrypted = await alice.encrypt_message(message, ASSOCIATED_DATA)
        events.append(("enc", "alice", message.hex(), encrypted.ciphertext.hex()))
        pending.append((message, encrypted))
        await maybe_restore()
    for i in (2, 0, 3, 1):
        plaintext = await bob.decrypt_message(pending[i][1], ASSOCIATED_DATA)
        assert plaintext == pending[i][0]
        events.append(("dec", "bob", plaintext.hex()))
        await maybe_restore()

    # One final exchange after the out-of-order delivery
    for sender, recipient, name in ((alice, bob, "alice"), (bob, alice, "bob")):
        message = f"final-{name}".encode("ASCII")
        encrypted = await sender.encrypt_message(message, ASSOCIATED_DATA)
        events.append(("enc", name, message.hex(), encrypted.ciphertext.hex()))
        await maybe_restore()
        plaintext = await recipient.decrypt_message(encrypted, ASSOCIATED_DATA)
        assert plaintext == message
        events.append(("dec", "bob" if name == "alice" else "alice", plaintext.hex()))
        await maybe_restore()

    events.append(("state", "alice", json.dumps(alice.json, sort_keys=True)))
    events.append(("state", "bob", json.dumps(bob.json, sort_keys=True)))

    return events


############################################
# transcript comparison: compliant implementations #
############################################


async def test_two_party_conversation_transcript_is_deterministic() -> None:
    """
    Run the scripted conversation with both combinations of real recommended implementations. The
    transcript must be reproducible run over run, which allows comparing the behavior item by item before
    and after replacing or refactoring a plugin.
    """

    for config in ALL_CONFIGS:
        transcript_run1 = await run_conversation(config)
        transcript_run2 = await run_conversation(config)
        assert len(transcript_run1) > 0
        for event_run1, event_run2 in zip(transcript_run1, transcript_run2, strict=True):
            assert event_run1 == event_run2


async def test_serialization_roundtrip_preserves_transcript() -> None:
    """
    Serializing and restoring both parties mid-conversation must not change any subsequent event of the
    transcript, for both combinations of real recommended implementations.
    """

    for config in ALL_CONFIGS:
        baseline = await run_conversation(config)
        # Restore right after the initial exchange, in the middle of the in-order phase and in the middle
        # of the out-of-order phase
        for restore_after in (2, 5, 11):
            transcript = await run_conversation(config, restore_after=restore_after)
            for baseline_event, event in zip(baseline, transcript, strict=True):
                assert baseline_event == event


async def test_plugin_call_site_invariants() -> None:
    """
    Record every call the library makes into the plugins during the scripted conversation and verify the
    call-site contract: 32-byte keys everywhere, positive derivation lengths, 64-byte derivations for the
    root and message chains, and bytes-typed associated data.
    """

    kdf_calls: List[Tuple[int, int, int]] = []
    aead_calls: List[Tuple[str, int, int, int]] = []

    class RecordingRootChainKDF(KDF):
        @staticmethod
        async def derive(key: bytes, data: bytes, length: int) -> bytes:
            kdf_calls.append((len(key), len(data), length))
            return await RootChainKDFA.derive(key, data, length)

    class RecordingMessageChainKDF(KDF):
        @staticmethod
        async def derive(key: bytes, data: bytes, length: int) -> bytes:
            kdf_calls.append((len(key), len(data), length))
            return await MessageChainKDFA.derive(key, data, length)

    class RecordingAEAD(AEAD):
        @staticmethod
        async def encrypt(plaintext: bytes, key: bytes, associated_data: bytes) -> bytes:
            assert isinstance(associated_data, bytes)
            aead_calls.append(("enc", len(plaintext), len(key), len(associated_data)))
            return await AEADA.encrypt(plaintext, key, associated_data)

        @staticmethod
        async def decrypt(ciphertext: bytes, key: bytes, associated_data: bytes) -> bytes:
            assert isinstance(associated_data, bytes)
            aead_calls.append(("dec", len(ciphertext), len(key), len(associated_data)))
            return await AEADA.decrypt(ciphertext, key, associated_data)

    config = dict(
        CONFIG_A,
        root_chain_kdf=RecordingRootChainKDF,
        message_chain_kdf=RecordingMessageChainKDF,
        aead=RecordingAEAD
    )
    await run_conversation(config)

    assert len(kdf_calls) > 0
    for key_length, _data_length, requested_length in kdf_calls:
        assert key_length == 32
        assert requested_length == 64

    assert len(aead_calls) > 0
    for _operation, _data_length, key_length, _ad_length in aead_calls:
        assert key_length == 32


##################################################
# controlled failure implementations #
##################################################


class PluginBoomException(Exception):
    """
    Raised by the controlled failure implementations.
    """


def make_failing_kdf(wrapped: Type[KDF], fail_at_call: int) -> Type[KDF]:
    """
    Build a KDF that delegates to a real recommended implementation but raises
    :class:`PluginBoomException` once, on the given 1-based call number.
    """

    class FailingKDF(KDF):
        calls = 0

        @staticmethod
        async def derive(key: bytes, data: bytes, length: int) -> bytes:
            FailingKDF.calls += 1
            if FailingKDF.calls == fail_at_call:
                raise PluginBoomException("controlled KDF failure")
            return await wrapped.derive(key, data, length)

    return FailingKDF


def make_failing_aead(wrapped: Type[AEAD], fail_at_call: int) -> Type[AEAD]:
    """
    Build an AEAD that delegates to a real recommended implementation but raises
    :class:`PluginBoomException` once, on the given 1-based encrypt call number.
    """

    class FailingAEAD(AEAD):
        calls = 0

        @staticmethod
        async def encrypt(plaintext: bytes, key: bytes, associated_data: bytes) -> bytes:
            FailingAEAD.calls += 1
            if FailingAEAD.calls == fail_at_call:
                raise PluginBoomException("controlled AEAD failure")
            return await wrapped.encrypt(plaintext, key, associated_data)

        @staticmethod
        async def decrypt(ciphertext: bytes, key: bytes, associated_data: bytes) -> bytes:
            return await wrapped.decrypt(ciphertext, key, associated_data)

    return FailingAEAD


async def make_alice_and_bob(
    alice_config: Dict[str, Any],
    bob_config: Dict[str, Any]
) -> Tuple[DoubleRatchet, DoubleRatchet]:
    """
    Set up a conversation between Alice and Bob with potentially different plugin configurations.
    """

    DeterministicDiffieHellmanRatchet.reset()
    bob_priv = DeterministicDiffieHellmanRatchet._generate_priv()
    bob_pub = DeterministicDiffieHellmanRatchet._derive_pub(bob_priv)

    alice, initial_message = await DoubleRatchet.encrypt_initial_message(
        shared_secret=SHARED_SECRET,
        recipient_ratchet_pub=bob_pub,
        message=b"initial a2b",
        associated_data=ASSOCIATED_DATA,
        **alice_config
    )
    bob, plaintext = await DoubleRatchet.decrypt_initial_message(
        shared_secret=SHARED_SECRET,
        own_ratchet_priv=bob_priv,
        message=initial_message,
        associated_data=ASSOCIATED_DATA,
        **bob_config
    )
    assert plaintext == b"initial a2b"

    return alice, bob


async def test_kdf_failure_propagates_and_preserves_state() -> None:
    """
    A KDF that fails must let its exception propagate unchanged, and the ratchet state must remain
    untouched, such that the operation can be retried and the conversation can continue as if the failure
    never happened.
    """

    failing_kdf = make_failing_kdf(MessageChainKDFA, fail_at_call=2)
    alice, bob = await make_alice_and_bob(dict(CONFIG_A, message_chain_kdf=failing_kdf), CONFIG_A)

    state_before = alice.json
    try:
        await alice.encrypt_message(b"message that triggers the failure", ASSOCIATED_DATA)
        assert False
    except PluginBoomException as e:
        assert "controlled KDF failure" in str(e)
    assert alice.json == state_before

    # The failure happened exactly once; retrying the same operation succeeds and the conversation
    # continues normally.
    encrypted = await alice.encrypt_message(b"message that triggers the failure", ASSOCIATED_DATA)
    assert await bob.decrypt_message(encrypted, ASSOCIATED_DATA) == b"message that triggers the failure"


async def test_aead_failure_propagates_and_preserves_state() -> None:
    """
    Same as above, but with a failing AEAD implementation on the encryption path.
    """

    failing_aead = make_failing_aead(AEADA, fail_at_call=2)
    alice, bob = await make_alice_and_bob(dict(CONFIG_A, aead=failing_aead), CONFIG_A)

    state_before = alice.json
    try:
        await alice.encrypt_message(b"message that triggers the failure", ASSOCIATED_DATA)
        assert False
    except PluginBoomException as e:
        assert "controlled AEAD failure" in str(e)
    assert alice.json == state_before

    encrypted = await alice.encrypt_message(b"message that triggers the failure", ASSOCIATED_DATA)
    assert await bob.decrypt_message(encrypted, ASSOCIATED_DATA) == b"message that triggers the failure"


async def test_authentication_failure_preserves_state() -> None:
    """
    A tampered ciphertext must surface as :class:`AuthenticationFailedException`, the exception must not be
    converted into an authentication success or empty plaintext, and the ratchet state must remain
    untouched, such that the legitimate message can still be decrypted afterwards.
    """

    alice, bob = await make_alice_and_bob(CONFIG_A, CONFIG_A)

    message = b"authentic message"
    encrypted = await alice.encrypt_message(message, ASSOCIATED_DATA)
    tampered = EncryptedMessage(
        header=encrypted.header,
        ciphertext=encrypted.ciphertext[:-1] + bytes([encrypted.ciphertext[-1] ^ 1])
    )

    state_before = bob.json
    try:
        await bob.decrypt_message(tampered, ASSOCIATED_DATA)
        assert False
    except AuthenticationFailedException:
        pass
    assert bob.json == state_before

    assert await bob.decrypt_message(encrypted, ASSOCIATED_DATA) == message


##############################################
# contract-violating implementations #
##############################################


class ShortOutputKDF(KDF):
    """
    Violates the contract: returns fewer bytes than requested.
    """

    @staticmethod
    async def derive(key: bytes, data: bytes, length: int) -> bytes:
        return (await MessageChainKDFA.derive(key, data, length))[:-1]


class NonBytesKDF(KDF):
    """
    Violates the contract: returns a bytearray instead of bytes.
    """

    @staticmethod
    async def derive(key: bytes, data: bytes, length: int) -> bytes:
        return bytearray(await MessageChainKDFA.derive(key, data, length))  # type: ignore[return-value]


class BytearrayAEAD(AEADA):
    """
    Violates the contract: returns a bytearray instead of bytes.
    """

    @classmethod
    async def encrypt(cls, plaintext: bytes, key: bytes, associated_data: bytes) -> bytes:
        return bytearray(await super().encrypt(plaintext, key, associated_data))  # type: ignore[return-value]


class SilentFailureAEAD(AEADA):
    """
    Violates the contract: converts authentication failures into empty plaintext instead of raising
    :class:`AuthenticationFailedException`.
    """

    @classmethod
    async def decrypt(cls, ciphertext: bytes, key: bytes, associated_data: bytes) -> bytes:
        try:
            return await super().decrypt(ciphertext, key, associated_data)
        except AuthenticationFailedException:
            return b""


async def test_malformed_kdf_output_rejected() -> None:
    """
    A KDF that violates the return value contract must be rejected by the KDF chain before any state
    change is applied.
    """

    for kdf_class in (ShortOutputKDF, NonBytesKDF):
        chain = KDFChain.create(kdf_class, b"\x00" * 32)
        try:
            await chain.step(b"data", 32)
            assert False
        except ValueError as e:
            assert "Plugin contract violation" in str(e)
        assert chain.length == 0


async def test_malformed_aead_output_rejected() -> None:
    """
    An AEAD that violates the return value contract must be rejected by the Double Ratchet.
    """

    try:
        await make_alice_and_bob(dict(CONFIG_A, aead=BytearrayAEAD), CONFIG_A)
        assert False
    except TypeError as e:
        assert "Plugin contract violation" in str(e)


async def test_silent_failure_contrast() -> None:
    """
    Contrast a compliant AEAD with one that violates the contract by converting authentication failures
    into empty plaintext: the compliant implementation raises and leaves the state untouched, while the
    violating implementation returns empty plaintext and lets the ratchet state advance. This demonstrates
    why the contract forbids silently converting failures into successful results.
    """

    message = b"authentic message"

    # Compliant implementation: failure surfaces as an exception, state untouched
    alice, bob = await make_alice_and_bob(CONFIG_A, CONFIG_A)
    encrypted = await alice.encrypt_message(message, ASSOCIATED_DATA)
    tampered = EncryptedMessage(
        header=encrypted.header,
        ciphertext=encrypted.ciphertext[:-1] + bytes([encrypted.ciphertext[-1] ^ 1])
    )
    state_before = bob.json
    try:
        await bob.decrypt_message(tampered, ASSOCIATED_DATA)
        assert False
    except AuthenticationFailedException:
        pass
    assert bob.json == state_before

    # Violating implementation: failure is converted into empty plaintext, state advances
    alice, bob = await make_alice_and_bob(CONFIG_A, dict(CONFIG_A, aead=SilentFailureAEAD))
    encrypted = await alice.encrypt_message(message, ASSOCIATED_DATA)
    tampered = EncryptedMessage(
        header=encrypted.header,
        ciphertext=encrypted.ciphertext[:-1] + bytes([encrypted.ciphertext[-1] ^ 1])
    )
    state_before = bob.json
    plaintext = await bob.decrypt_message(tampered, ASSOCIATED_DATA)
    assert plaintext == b""
    assert bob.json != state_before
