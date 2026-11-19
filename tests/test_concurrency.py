import asyncio
import os
from typing import Dict, Optional, Set, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from doubleratchet import (
    AuthenticationFailedException,
    DoubleRatchet as DR,
    DoubleRatchetSession,
    DuplicateMessageException,
    EncryptedMessage,
    Header
)
from doubleratchet.recommended import (
    aead_aes_hmac,
    diffie_hellman_ratchet_curve25519 as dhr25519,
    HashFunction,
    kdf_hkdf
)


__all__ = [
    "test_serialized_interleaving",
    "test_duplicate_ciphertext_delivered_once",
    "test_failed_decryption_does_not_overwrite_state",
    "test_cancellation_leaves_state_untouched",
    "test_session_is_reentrant_and_exclusive",
    "test_concurrent_sends_advance_once_each",
    "test_out_of_order_messages_use_skipped_keys"
]


try:
    import pytest
except ImportError:
    pass
else:
    pytestmark = pytest.mark.asyncio


class RootChainKDF(kdf_hkdf.KDF):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_256

    @staticmethod
    def _get_info() -> bytes:
        return "test_concurrency Root Chain KDF info".encode("ASCII")


class MessageChainKDF(kdf_hkdf.KDF):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_256

    @staticmethod
    def _get_info() -> bytes:
        return "test_concurrency Message Chain KDF info".encode("ASCII")


class _Gate:
    """
    A one-shot asynchronous gate: entering sets ``entered`` and waits until ``open`` is called.
    """

    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.released = asyncio.Event()

    async def wait(self) -> None:
        self.entered.set()
        await self.released.wait()

    def open(self) -> None:
        self.released.set()


class _Probe:
    """
    Tracks how many operations are simultaneously inside a pausable primitive.
    """

    active = 0
    max_active = 0

    @classmethod
    def reset(cls) -> None:
        cls.active = 0
        cls.max_active = 0

    @classmethod
    def enter(cls) -> None:
        cls.active += 1
        cls.max_active = max(cls.max_active, cls.active)

    @classmethod
    def exit(cls) -> None:
        cls.active -= 1


class PausableAEAD(aead_aes_hmac.AEAD):
    """
    The recommended AEAD implementation, with an optional test-controlled pause before decryption.
    """

    decrypt_gate: Optional[Tuple[bytes, _Gate]] = None
    started: Set[bytes] = set()

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_256

    @staticmethod
    def _get_info() -> bytes:
        return "test_concurrency AEAD info".encode("ASCII")

    @classmethod
    def reset(cls) -> None:
        cls.decrypt_gate = None
        cls.started = set()

    @classmethod
    async def decrypt(cls, ciphertext: bytes, key: bytes, associated_data: bytes) -> bytes:
        cls.started.add(ciphertext)
        _Probe.enter()
        try:
            gate = cls.decrypt_gate
            if gate is not None and gate[0] == ciphertext:
                await gate[1].wait()
            return await super().decrypt(ciphertext, key, associated_data)
        finally:
            _Probe.exit()


class PausableMessageChainKDF(kdf_hkdf.KDF):
    """
    The message chain KDF, with an optional test-controlled pause on the next derivation.
    """

    gate: Optional[_Gate] = None

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_256

    @staticmethod
    def _get_info() -> bytes:
        return "test_concurrency Message Chain KDF info".encode("ASCII")

    @classmethod
    def reset(cls) -> None:
        cls.gate = None

    @classmethod
    async def derive(cls, key: bytes, data: bytes, length: int) -> bytes:
        _Probe.enter()
        try:
            gate = cls.gate
            if gate is not None:
                cls.gate = None
                await gate.wait()
            return await super().derive(key, data, length)
        finally:
            _Probe.exit()


class DoubleRatchet(DR):
    @staticmethod
    def _build_associated_data(associated_data: bytes, header: Header) -> bytes:
        return (
            associated_data
            + header.ratchet_pub
            + header.sending_chain_length.to_bytes(8, "big")
            + header.previous_sending_chain_length.to_bytes(8, "big")
        )


CONFIG: Dict[str, object] = {
    "diffie_hellman_ratchet_class": dhr25519.DiffieHellmanRatchet,
    "root_chain_kdf": RootChainKDF,
    "message_chain_kdf": PausableMessageChainKDF,
    "message_chain_constant": "test_concurrency Message Chain constant".encode("ASCII"),
    "dos_protection_threshold": 10,
    "max_num_skipped_message_keys": 15,
    "aead": PausableAEAD
}

AD = "test_concurrency associated data".encode("ASCII")


def _reset_harness() -> None:
    _Probe.reset()
    PausableAEAD.reset()
    PausableMessageChainKDF.reset()


async def _make_pair() -> Tuple[DoubleRatchet, DoubleRatchet]:
    bob_priv = X25519PrivateKey.generate()
    bob_pub = bob_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    shared_secret = os.urandom(32)

    alice, initial = await DoubleRatchet.encrypt_initial_message(
        shared_secret=shared_secret,
        recipient_ratchet_pub=bob_pub,
        message=b"initial",
        associated_data=AD,
        **CONFIG  # type: ignore[arg-type]
    )
    bob, plaintext = await DoubleRatchet.decrypt_initial_message(
        shared_secret=shared_secret,
        own_ratchet_priv=bob_priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        message=initial,
        associated_data=AD,
        **CONFIG  # type: ignore[arg-type]
    )
    assert plaintext == b"initial"

    return alice, bob


async def _send(alice: DoubleRatchet, plaintext: bytes) -> EncryptedMessage:
    return await alice.encrypt_message(plaintext, AD)


async def test_serialized_interleaving() -> None:
    """
    Interleave two decryptions, one send and one export while a KDF step is paused. With serialization, the
    paused operation owns the instance until it completes, exports observe a completed boundary, and the
    receiver keeps working both directly and after restoring from the exported state.
    """

    _reset_harness()
    alice, bob = await _make_pair()
    m1 = await _send(alice, b"m1")
    m2 = await _send(alice, b"m2")

    gate = _Gate()
    PausableMessageChainKDF.gate = gate

    boundary_before = bob.json
    decrypt_1 = asyncio.create_task(bob.decrypt_message(m1, AD))
    await asyncio.wait_for(gate.entered.wait(), 1)

    decrypt_2 = asyncio.create_task(bob.decrypt_message(m2, AD))
    send_task = asyncio.create_task(bob.encrypt_message(b"reply", AD))
    export_task = asyncio.create_task(bob.export_json())

    await asyncio.sleep(0.05)
    assert not decrypt_1.done()
    assert not decrypt_2.done()
    assert not send_task.done()
    assert not export_task.done()

    # While the AEAD/KDF primitive is paused, the committed state is still the previous operation boundary:
    # no partial derivation is visible, neither via the synchronous property nor via a state export.
    assert bob.json == boundary_before

    # The second decryption never reached the AEAD layer: it is waiting for the lock.
    assert m2.ciphertext not in PausableAEAD.started
    assert _Probe.max_active == 1

    gate.open()

    assert await decrypt_1 == b"m1"
    assert await decrypt_2 == b"m2"
    reply = await send_task
    snapshot = await export_task
    assert _Probe.max_active == 1

    # The original receiver continues to communicate.
    assert await alice.decrypt_message(reply, AD) == b"reply"
    m3 = await _send(alice, b"m3")
    m4 = await _send(alice, b"m4")
    assert await bob.decrypt_message(m3, AD) == b"m3"

    # The exported snapshot corresponds to a completed operation boundary and can be restored; the restored
    # receiver independently decrypts a later message of the same sending chain.
    restored = DoubleRatchet.from_json(snapshot, **CONFIG)  # type: ignore[arg-type]
    assert await restored.decrypt_message(m4, AD) == b"m4"

    # The snapshot includes the send performed before the export.
    assert snapshot["diffie_hellman_ratchet"]["symmetric_key_ratchet"]["sending_chain"] is not None


async def test_duplicate_ciphertext_delivered_once() -> None:
    """
    Submit the same ciphertext twice from the same starting state. Only one submission may deliver the
    plaintext; the other must fail deterministically, and the receiver must continue afterwards.
    """

    _reset_harness()
    alice, bob = await _make_pair()
    m1 = await _send(alice, b"m1")
    m2 = await _send(alice, b"m2")
    m3 = await _send(alice, b"m3")

    gate = _Gate()
    PausableAEAD.decrypt_gate = (m1.ciphertext, gate)

    first = asyncio.create_task(bob.decrypt_message(m1, AD))
    await asyncio.wait_for(gate.entered.wait(), 1)
    second = asyncio.create_task(bob.decrypt_message(m1, AD))
    await asyncio.sleep(0.02)
    assert not second.done()

    gate.open()
    assert await first == b"m1"
    with pytest.raises((DuplicateMessageException, AuthenticationFailedException)):
        await second

    # The duplicate attempt must not have consumed or re-created any state: the following messages still
    # decrypt normally.
    assert await bob.decrypt_message(m2, AD) == b"m2"
    assert await bob.decrypt_message(m3, AD) == b"m3"

    # A third submission of the same ciphertext fails again and still does not disturb the receiver.
    with pytest.raises((DuplicateMessageException, AuthenticationFailedException)):
        await bob.decrypt_message(m1, AD)


async def test_failed_decryption_does_not_overwrite_state() -> None:
    """
    An authentication failure must leave the committed state untouched, and an older out-of-order message
    that was waiting behind it must still be delivered.
    """

    _reset_harness()
    alice, bob = await _make_pair()
    m1 = await _send(alice, b"m1")
    m2 = await _send(alice, b"m2")
    m3 = await _send(alice, b"m3")

    snapshot_before = await bob.export_json()

    tampered = m2._replace(ciphertext=m2.ciphertext[:-1] + bytes([m2.ciphertext[-1] ^ 0x01]))

    # Sequentially: the failed request must not change the exported state at all.
    with pytest.raises(AuthenticationFailedException):
        await bob.decrypt_message(tampered, AD)
    assert await bob.export_json() == snapshot_before

    # Concurrently: the failing request is paused in the AEAD layer, an older legal message waits behind it.
    gate = _Gate()
    PausableAEAD.decrypt_gate = (tampered.ciphertext, gate)
    failing = asyncio.create_task(bob.decrypt_message(tampered, AD))
    await asyncio.wait_for(gate.entered.wait(), 1)

    old_message = asyncio.create_task(bob.decrypt_message(m1, AD))
    await asyncio.sleep(0.02)
    assert not old_message.done()
    assert _Probe.max_active == 1

    gate.open()
    with pytest.raises(AuthenticationFailedException):
        await failing
    assert await old_message == b"m1"

    # The successful state was not overwritten by the failure, and skipped keys still work.
    assert await bob.decrypt_message(m2, AD) == b"m2"
    assert await bob.decrypt_message(m3, AD) == b"m3"

    # An additional export equals the state that a receiver which only saw the successful messages would
    # reach, in terms of the receiving chain and the (empty) skipped key set.
    final = await bob.export_json()
    symmetric_key_ratchet = final["diffie_hellman_ratchet"]["symmetric_key_ratchet"]
    assert symmetric_key_ratchet["receiving_chain"]["length"] == 4
    assert symmetric_key_ratchet["sending_chain"]["length"] == 0
    assert final["skipped_message_keys"] == []


async def test_cancellation_leaves_state_untouched() -> None:
    """
    Cancelling a paused decryption (and cancelling a task waiting for the lock) must leave the committed
    state untouched. The same ciphertext can be submitted afterwards and is delivered once.
    """

    _reset_harness()
    alice, bob = await _make_pair()
    m1 = await _send(alice, b"m1")
    m2 = await _send(alice, b"m2")

    snapshot_before = await bob.export_json()

    gate = _Gate()
    PausableMessageChainKDF.gate = gate
    cancelled = asyncio.create_task(bob.decrypt_message(m1, AD))
    await asyncio.wait_for(gate.entered.wait(), 1)

    cancelled.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancelled
    assert await bob.export_json() == snapshot_before

    # Cancelling while waiting for the lock of another operation must not run the decoder at all.
    gate = _Gate()
    PausableMessageChainKDF.gate = gate
    holder = asyncio.create_task(bob.decrypt_message(m1, AD))
    await asyncio.wait_for(gate.entered.wait(), 1)
    waiter = asyncio.create_task(bob.decrypt_message(m2, AD))
    await asyncio.sleep(0.02)
    assert not waiter.done()
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter

    gate.open()
    assert await holder == b"m1"

    # The cancelled-and-retried ciphertext is still deliverable exactly once; the cancelled waiter did not
    # consume m2.
    assert await bob.decrypt_message(m2, AD) == b"m2"


async def test_session_is_reentrant_and_exclusive() -> None:
    """
    The explicit session entry point groups operations into one critical section. Calls inside the session
    are reentrant, while other tasks wait until the session exits.
    """

    _reset_harness()
    alice, bob = await _make_pair()
    m1 = await _send(alice, b"m1")

    _Probe.reset()
    async with bob.session() as session:
        assert isinstance(session, DoubleRatchetSession)
        assert await bob.decrypt_message(m1, AD) == b"m1"
        inside = await bob.export_json()

        outside = asyncio.create_task(bob.export_json())
        await asyncio.sleep(0.02)
        assert not outside.done()

    after = await outside
    assert after == inside
    assert _Probe.max_active == 1

    # A cancelled session waiter does not disturb the instance.
    gate = _Gate()
    PausableMessageChainKDF.gate = gate
    holder = asyncio.create_task(bob.encrypt_message(b"held", AD))
    await asyncio.wait_for(gate.entered.wait(), 1)

    async def _session_waiter() -> None:
        async with bob.session():
            pass

    session_waiter = asyncio.create_task(_session_waiter())
    await asyncio.sleep(0.02)
    assert not session_waiter.done()
    session_waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await session_waiter

    gate.open()
    await holder
    assert await bob.export_json() is not None


async def test_out_of_order_messages_use_skipped_keys() -> None:
    """
    Legal out-of-order messages must still be decryptable using stored skipped message keys, including after
    restoring an exported state that contains them.
    """

    _reset_harness()
    alice, bob = await _make_pair()
    m1 = await _send(alice, b"m1")
    m2 = await _send(alice, b"m2")
    m3 = await _send(alice, b"m3")

    assert await bob.decrypt_message(m3, AD) == b"m3"
    snapshot = await bob.export_json()
    skipped = snapshot["skipped_message_keys"]
    assert {entry["index"] for entry in skipped} == {1, 2}

    restored = DoubleRatchet.from_json(snapshot, **CONFIG)  # type: ignore[arg-type]
    assert await restored.decrypt_message(m1, AD) == b"m1"
    assert await restored.decrypt_message(m2, AD) == b"m2"

    # Each skipped key is single-use, also across the restored instance and the original one.
    with pytest.raises((DuplicateMessageException, AuthenticationFailedException)):
        await restored.decrypt_message(m1, AD)
    assert await bob.decrypt_message(m1, AD) == b"m1"
    assert await bob.decrypt_message(m2, AD) == b"m2"

    remaining = await bob.export_json()
    assert remaining["skipped_message_keys"] == []


async def test_concurrent_sends_advance_once_each() -> None:
    """
    Concurrent sends on one instance must each advance the sending chain exactly once, producing distinct
    headers that the peer can decrypt (in any order, using skipped keys).
    """

    _reset_harness()
    alice, bob = await _make_pair()

    messages = [asyncio.create_task(alice.encrypt_message(f"m{i}".encode("ASCII"), AD)) for i in range(5)]
    encrypted = await asyncio.gather(*messages)

    assert len({message.header.sending_chain_length for message in encrypted}) == 5
    assert alice.sending_chain_length == 6

    # Deliver in reverse order: every message except the newest uses a skipped key.
    for index in reversed(range(5)):
        assert await bob.decrypt_message(encrypted[index], AD) == f"m{index}".encode("ASCII")

    final = await bob.export_json()
    assert final["skipped_message_keys"] == []
    assert final["diffie_hellman_ratchet"]["symmetric_key_ratchet"]["receiving_chain"]["length"] == 6
