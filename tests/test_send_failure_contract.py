import asyncio
import copy
from typing import Any, ClassVar, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from doubleratchet import DoubleRatchet as DR, EncryptedMessage, Header
from doubleratchet.recommended import (
    aead_aes_hmac,
    diffie_hellman_ratchet_curve25519 as dhr25519,
    HashFunction,
    kdf_hkdf
)


__all__ = [
    "test_kdf_failure_keeps_sending_chain_unchanged",
    "test_malformed_kdf_output_is_rejected_without_state_change",
    "test_kdf_cancellation_keeps_sending_chain_unchanged",
    "test_aead_failure_before_ciphertext_consumes_one_key",
    "test_aead_failure_after_ciphertext_allows_late_delivery",
    "test_cancellation_after_ciphertext_consumes_one_key",
    "test_concurrent_sends_do_not_reuse_message_keys",
    "test_concurrent_receive_does_not_roll_back_sending_chain"
]


try:
    import pytest
except ImportError:
    pass
else:
    pytestmark = pytest.mark.asyncio


AD = b"send-failure-contract associated data"
SHARED_SECRET = b"send-failure shared secret 32b!!"


class RootChainKDF(kdf_hkdf.KDF):
    """
    The root chain KDF to use while testing.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_256

    @staticmethod
    def _get_info() -> bytes:
        return b"send-failure-contract root chain"


class MessageChainKDF(kdf_hkdf.KDF):
    """
    The message chain KDF to use while testing, with optional failure injection.
    """

    fail_next_call: ClassVar[bool] = False
    short_output: ClassVar[bool] = False
    gate: ClassVar[Optional[asyncio.Event]] = None
    entered: ClassVar[Optional[asyncio.Event]] = None
    calls: ClassVar[int] = 0

    @classmethod
    def reset(cls) -> None:
        cls.fail_next_call = False
        cls.short_output = False
        cls.gate = None
        cls.entered = None
        cls.calls = 0

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512_256

    @staticmethod
    def _get_info() -> bytes:
        return b"send-failure-contract message chain"

    @classmethod
    async def derive(cls, key: bytes, data: bytes, length: int) -> bytes:
        cls.calls += 1

        # Force a suspension point so that concurrent callers actually interleave. The recommended KDF
        # implementations do not suspend internally, which would hide concurrency bugs.
        await asyncio.sleep(0)

        if cls.gate is not None:
            assert cls.entered is not None
            cls.entered.set()
            await cls.gate.wait()

        if cls.fail_next_call:
            cls.fail_next_call = False
            raise RuntimeError("scripted KDF failure")

        output = await super().derive(key, data, length)
        return output[:-1] if cls.short_output else output


class AEAD(aead_aes_hmac.AEAD):
    """
    The AEAD to use while testing, with failure injection and call recording.
    """

    failure: ClassVar[Optional[str]] = None
    seen_keys: ClassVar[List[bytes]] = []
    seen_plaintexts: ClassVar[List[bytes]] = []
    last_ciphertext: ClassVar[Optional[bytes]] = None
    encrypt_gate: ClassVar[Optional[asyncio.Event]] = None
    encrypt_entered: ClassVar[Optional[asyncio.Event]] = None
    decrypt_gate: ClassVar[Optional[asyncio.Event]] = None
    decrypt_entered: ClassVar[Optional[asyncio.Event]] = None

    @classmethod
    def reset(cls) -> None:
        cls.failure = None
        cls.seen_keys = []
        cls.seen_plaintexts = []
        cls.last_ciphertext = None
        cls.encrypt_gate = None
        cls.encrypt_entered = None
        cls.decrypt_gate = None
        cls.decrypt_entered = None

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return b"send-failure-contract aead"

    @classmethod
    async def encrypt(cls, plaintext: bytes, key: bytes, associated_data: bytes) -> bytes:
        cls.seen_keys.append(key)
        cls.seen_plaintexts.append(plaintext)

        if cls.failure == "before":
            raise RuntimeError("scripted AEAD failure before ciphertext")

        ciphertext = await super().encrypt(plaintext, key, associated_data)
        cls.last_ciphertext = ciphertext

        if cls.encrypt_gate is not None:
            assert cls.encrypt_entered is not None
            cls.encrypt_entered.set()
            await cls.encrypt_gate.wait()

        if cls.failure == "transport":
            raise RuntimeError("scripted transport failure after ciphertext")

        if cls.failure == "cancel":
            raise asyncio.CancelledError()

        return ciphertext

    @classmethod
    async def decrypt(cls, ciphertext: bytes, key: bytes, associated_data: bytes) -> bytes:
        if cls.decrypt_gate is not None:
            assert cls.decrypt_entered is not None
            cls.decrypt_entered.set()
            await cls.decrypt_gate.wait()

        return await super().decrypt(ciphertext, key, associated_data)


class RecordingDiffieHellmanRatchet(dhr25519.DiffieHellmanRatchet):
    """
    A Diffie-Hellman ratchet that records the header of the last produced encryption key.
    """

    last_header: ClassVar[Optional[Header]] = None

    @classmethod
    def reset(cls) -> None:
        cls.last_header = None

    async def next_encryption_key(self) -> Tuple[bytes, Header]:
        key, header = await super().next_encryption_key()
        type(self).last_header = header
        return key, header


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


DR_CONFIGURATION: Dict[str, Any] = {
    "diffie_hellman_ratchet_class": RecordingDiffieHellmanRatchet,
    "root_chain_kdf": RootChainKDF,
    "message_chain_kdf": MessageChainKDF,
    "message_chain_constant": b"send-failure-contract constant",
    "dos_protection_threshold": 10,
    "max_num_skipped_message_keys": 15,
    "aead": AEAD
}


def reset_plugins() -> None:
    """
    Reset all failure injection and recording state.
    """

    MessageChainKDF.reset()
    AEAD.reset()
    RecordingDiffieHellmanRatchet.reset()


async def make_pair() -> Tuple[DoubleRatchet, DoubleRatchet]:
    """
    Create Alice' and Bob's Double Ratchets with a decrypted initial message.
    """

    reset_plugins()

    bob_ratchet_priv = X25519PrivateKey.generate()
    bob_ratchet_priv_bytes = bob_ratchet_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    bob_ratchet_pub_bytes = bob_ratchet_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    alice, initial_message = await DoubleRatchet.encrypt_initial_message(
        shared_secret=SHARED_SECRET,
        recipient_ratchet_pub=bob_ratchet_pub_bytes,
        message=b"initial",
        associated_data=AD,
        **DR_CONFIGURATION
    )
    bob, plaintext = await DoubleRatchet.decrypt_initial_message(
        shared_secret=SHARED_SECRET,
        own_ratchet_priv=bob_ratchet_priv_bytes,
        message=initial_message,
        associated_data=AD,
        **DR_CONFIGURATION
    )
    assert plaintext == b"initial"

    # Ignore the calls made while establishing the session in the per-test recordings.
    AEAD.reset()
    RecordingDiffieHellmanRatchet.reset()

    return alice, bob


def skipped_indices(dr: DoubleRatchet) -> List[int]:
    """
    Return the indices of the skipped message keys stored in the given Double Ratchet.
    """

    return [entry.index for entry in dr.model.skipped_message_keys]


async def test_kdf_failure_keeps_sending_chain_unchanged() -> None:
    """
    A KDF failure happens before the message key exists, so the send can be retried at the same index.
    """

    alice, bob = await make_pair()
    before = copy.deepcopy(alice.json)
    next_index = alice.sending_chain_length

    MessageChainKDF.fail_next_call = True
    try:
        await alice.encrypt_message(b"failed", AD)
        assert False
    except RuntimeError as e:
        assert "KDF" in str(e)

    assert alice.json == before
    assert alice.sending_chain_length == next_index

    message = await alice.encrypt_message(b"retried", AD)
    assert message.header.sending_chain_length == next_index
    assert await bob.decrypt_message(message, AD) == b"retried"
    assert skipped_indices(bob) == []


async def test_malformed_kdf_output_is_rejected_without_state_change() -> None:
    """
    A KDF whose output has the wrong length is rejected before the chain advances.
    """

    alice, _ = await make_pair()
    before = copy.deepcopy(alice.json)
    next_index = alice.sending_chain_length

    MessageChainKDF.short_output = True
    try:
        await alice.encrypt_message(b"malformed", AD)
        assert False
    except ValueError as e:
        assert "bytes" in str(e)
    finally:
        MessageChainKDF.short_output = False

    assert alice.json == before
    assert AEAD.seen_keys == []

    message = await alice.encrypt_message(b"retried", AD)
    assert message.header.sending_chain_length == next_index


async def test_kdf_cancellation_keeps_sending_chain_unchanged() -> None:
    """
    Cancelling a send while the KDF is still running also leaves the sending chain unchanged.
    """

    alice, bob = await make_pair()
    before = copy.deepcopy(alice.json)
    next_index = alice.sending_chain_length

    gate = asyncio.Event()
    entered = asyncio.Event()
    calls_before = MessageChainKDF.calls
    MessageChainKDF.gate = gate
    MessageChainKDF.entered = entered

    task = asyncio.create_task(alice.encrypt_message(b"cancelled", AD))
    await entered.wait()
    task.cancel()
    try:
        await task
        assert False
    except asyncio.CancelledError:
        pass
    finally:
        MessageChainKDF.gate = None
        MessageChainKDF.entered = None

    assert alice.json == before
    assert MessageChainKDF.calls == calls_before + 1

    message = await alice.encrypt_message(b"retried", AD)
    assert message.header.sending_chain_length == next_index
    assert await bob.decrypt_message(message, AD) == b"retried"


async def test_aead_failure_before_ciphertext_consumes_one_key() -> None:
    """
    Once the message key is derived, an AEAD failure cannot be rolled back. The retry uses the next index.
    """

    alice, bob = await make_pair()
    failed_index = alice.sending_chain_length

    AEAD.failure = "before"
    try:
        await alice.encrypt_message(b"failed", AD)
        assert False
    except RuntimeError as e:
        assert "AEAD" in str(e)
    finally:
        AEAD.failure = None

    assert alice.sending_chain_length == failed_index + 1
    assert len(AEAD.seen_keys) == 1
    assert AEAD.seen_plaintexts == [b"failed"]

    message = await alice.encrypt_message(b"retried", AD)
    assert message.header.sending_chain_length == failed_index + 1
    assert AEAD.seen_keys[0] != AEAD.seen_keys[1]
    assert await bob.decrypt_message(message, AD) == b"retried"
    assert skipped_indices(bob) == [failed_index]


async def test_aead_failure_after_ciphertext_allows_late_delivery() -> None:
    """
    A ciphertext that was produced before the failure can still be delivered later, from the skipped key.
    """

    alice, bob = await make_pair()
    failed_index = alice.sending_chain_length

    AEAD.failure = "transport"
    try:
        await alice.encrypt_message(b"late", AD)
        assert False
    except RuntimeError as e:
        assert "transport" in str(e)
    finally:
        AEAD.failure = None

    failed_ciphertext = AEAD.last_ciphertext
    failed_header = RecordingDiffieHellmanRatchet.last_header
    assert failed_ciphertext is not None
    assert failed_header is not None
    assert failed_header.sending_chain_length == failed_index

    retried = await alice.encrypt_message(b"retried", AD)
    assert retried.header.sending_chain_length == failed_index + 1
    assert await bob.decrypt_message(retried, AD) == b"retried"
    assert skipped_indices(bob) == [failed_index]

    # The failed send was never confirmed, but its ciphertext did leave the process. Delivering it late
    # still works, without reusing the retried message key.
    late_message = EncryptedMessage(header=failed_header, ciphertext=failed_ciphertext)
    assert await bob.decrypt_message(late_message, AD) == b"late"
    assert AEAD.seen_keys[0] != AEAD.seen_keys[1]


async def test_cancellation_after_ciphertext_consumes_one_key() -> None:
    """
    Cancellation after the ciphertext exists consumes the message key and keeps the ciphertext recoverable.
    """

    alice, bob = await make_pair()
    failed_index = alice.sending_chain_length

    gate = asyncio.Event()
    entered = asyncio.Event()
    AEAD.encrypt_gate = gate
    AEAD.encrypt_entered = entered

    task = asyncio.create_task(alice.encrypt_message(b"cancelled", AD))
    await entered.wait()

    assert AEAD.last_ciphertext is not None
    failed_ciphertext = AEAD.last_ciphertext
    failed_header = RecordingDiffieHellmanRatchet.last_header
    assert failed_header is not None

    task.cancel()
    try:
        await task
        assert False
    except asyncio.CancelledError:
        pass
    finally:
        AEAD.encrypt_gate = None
        AEAD.encrypt_entered = None

    assert alice.sending_chain_length == failed_index + 1
    assert len(AEAD.seen_keys) == 1

    retried = await alice.encrypt_message(b"retried", AD)
    assert retried.header.sending_chain_length == failed_index + 1
    assert await bob.decrypt_message(retried, AD) == b"retried"
    assert skipped_indices(bob) == [failed_index]

    late_message = EncryptedMessage(header=failed_header, ciphertext=failed_ciphertext)
    assert await bob.decrypt_message(late_message, AD) == b"cancelled"


async def test_concurrent_sends_do_not_reuse_message_keys() -> None:
    """
    Concurrent sends are serialized and therefore get distinct chain indices and message keys.
    """

    alice, bob = await make_pair()
    first_index = alice.sending_chain_length

    messages = await asyncio.gather(
        alice.encrypt_message(b"one", AD),
        alice.encrypt_message(b"two", AD)
    )

    assert sorted(message.header.sending_chain_length for message in messages) == [
        first_index,
        first_index + 1
    ]
    assert len(AEAD.seen_keys) == 2
    assert AEAD.seen_keys[0] != AEAD.seen_keys[1]

    for message, plaintext in zip(sorted(messages, key=lambda item: item.header.sending_chain_length),
                                  [b"one", b"two"]):
        assert await bob.decrypt_message(message, AD) == plaintext


async def test_concurrent_receive_does_not_roll_back_sending_chain() -> None:
    """
    A receive must not replace the Diffie-Hellman ratchet with a clone that misses a concurrent send.
    """

    alice, bob = await make_pair()

    # Advance the ratchets so that Bob has a sending chain that Alice has already ratcheted to. The second
    # message from Bob then arrives on the same chain and does not trigger another Diffie-Hellman step.
    first = await alice.encrypt_message(b"a1", AD)
    assert await bob.decrypt_message(first, AD) == b"a1"
    reply = await bob.encrypt_message(b"b1", AD)
    assert await alice.decrypt_message(reply, AD) == b"b1"
    second = await alice.encrypt_message(b"a2", AD)
    assert await bob.decrypt_message(second, AD) == b"a2"
    decrypt_me = await bob.encrypt_message(b"b2", AD)
    assert await alice.decrypt_message(decrypt_me, AD) == b"b2"
    in_flight = await bob.encrypt_message(b"b3", AD)
    same_chain = await bob.encrypt_message(b"b4", AD)

    gate = asyncio.Event()
    entered = asyncio.Event()
    AEAD.decrypt_gate = gate
    AEAD.decrypt_entered = entered

    decrypt_task = asyncio.create_task(alice.decrypt_message(same_chain, AD))
    await entered.wait()

    send_task = asyncio.create_task(alice.encrypt_message(b"racing", AD))
    await asyncio.sleep(0.05)
    assert not send_task.done()  # the send waits for the receive to commit

    gate.set()
    assert await decrypt_task == b"b4"
    racing = await send_task
    following = await alice.encrypt_message(b"following", AD)

    AEAD.decrypt_gate = None
    AEAD.decrypt_entered = None

    # The message produced while the receive was in flight and the following message use the same new
    # sending chain, with consecutive indices and distinct keys.
    assert following.header.ratchet_pub == racing.header.ratchet_pub
    assert following.header.sending_chain_length == racing.header.sending_chain_length + 1
    assert AEAD.seen_keys[-1] != AEAD.seen_keys[-2]

    assert await alice.decrypt_message(in_flight, AD) == b"b3"
    assert await bob.decrypt_message(racing, AD) == b"racing"
    assert await bob.decrypt_message(following, AD) == b"following"
