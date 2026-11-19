"""
Demonstrate the send-failure contract of python-doubleratchet.

Each scenario runs Alice and Bob through the same session and prints a state comparison after every step.
The scenarios differ only in where the sending pipeline is interrupted:

1. KDF failure while deriving the message key.
2. AEAD failure before a ciphertext exists.
3. AEAD/transport failure after a ciphertext exists.
4. Cancellation while the KDF is running (before the message key exists).
5. Cancellation after the ciphertext exists, followed by late delivery.

Run with ``python examples/send_failure_contract.py``.
"""

import asyncio
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from doubleratchet import DoubleRatchet as DR, EncryptedMessage, Header
from doubleratchet.recommended import (
    aead_aes_hmac,
    diffie_hellman_ratchet_curve25519 as dhr25519,
    HashFunction,
    kdf_hkdf
)


ASSOCIATED_DATA = b"send-failure-contract associated data"
SHARED_SECRET = b"send-failure shared secret 32b!!"


class RootChainKDF(kdf_hkdf.KDF):
    """
    Root chain KDF of the demonstration.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_256

    @staticmethod
    def _get_info() -> bytes:
        return b"send-failure-contract root chain"


class MessageChainKDF(kdf_hkdf.KDF):
    """
    Message chain KDF of the demonstration, with scripted failure injection.
    """

    fail_next_call = False
    gate: Optional[asyncio.Event] = None
    entered: Optional[asyncio.Event] = None

    @classmethod
    def reset(cls) -> None:
        cls.fail_next_call = False
        cls.gate = None
        cls.entered = None

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512_256

    @staticmethod
    def _get_info() -> bytes:
        return b"send-failure-contract message chain"

    @classmethod
    async def derive(cls, key: bytes, data: bytes, length: int) -> bytes:
        await asyncio.sleep(0)

        if cls.gate is not None:
            assert cls.entered is not None
            cls.entered.set()
            await cls.gate.wait()

        if cls.fail_next_call:
            cls.fail_next_call = False
            raise RuntimeError("scripted KDF failure")

        return await super().derive(key, data, length)


class AEAD(aead_aes_hmac.AEAD):
    """
    AEAD of the demonstration, with scripted failure injection and call recording.
    """

    failure: Optional[str] = None
    seen_keys: List[bytes] = []
    last_ciphertext: Optional[bytes] = None
    encrypt_gate: Optional[asyncio.Event] = None
    encrypt_entered: Optional[asyncio.Event] = None

    @classmethod
    def reset(cls) -> None:
        cls.failure = None
        cls.seen_keys = []
        cls.last_ciphertext = None
        cls.encrypt_gate = None
        cls.encrypt_entered = None

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return b"send-failure-contract aead"

    @classmethod
    async def encrypt(cls, plaintext: bytes, key: bytes, associated_data: bytes) -> bytes:
        cls.seen_keys.append(key)

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


class RecordingDiffieHellmanRatchet(dhr25519.DiffieHellmanRatchet):
    """
    Diffie-Hellman ratchet that records the last header for which a message key was derived.
    """

    last_header: Optional[Header] = None

    async def next_encryption_key(self) -> Tuple[bytes, Header]:
        key, header = await super().next_encryption_key()
        type(self).last_header = header
        return key, header


class DoubleRatchet(DR):
    """
    Double Ratchet of the demonstration.
    """

    @staticmethod
    def _build_associated_data(associated_data: bytes, header: Header) -> bytes:
        return (
            associated_data
            + header.ratchet_pub
            + header.sending_chain_length.to_bytes(8, "big")
            + header.previous_sending_chain_length.to_bytes(8, "big")
        )


CONFIGURATION: Dict[str, Any] = {
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
    Reset all scripted failures and recordings.
    """

    MessageChainKDF.reset()
    AEAD.reset()
    RecordingDiffieHellmanRatchet.last_header = None


async def make_pair() -> Tuple[DoubleRatchet, DoubleRatchet]:
    """
    Create Alice' and Bob's Double Ratchets.

    Returns:
        The two Double Ratchets, with the initial message already decrypted by Bob.
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
        associated_data=ASSOCIATED_DATA,
        **CONFIGURATION
    )
    bob, plaintext = await DoubleRatchet.decrypt_initial_message(
        shared_secret=SHARED_SECRET,
        own_ratchet_priv=bob_ratchet_priv_bytes,
        message=initial_message,
        associated_data=ASSOCIATED_DATA,
        **CONFIGURATION
    )
    assert plaintext == b"initial"

    reset_plugins()

    return alice, bob


def state(dr: DoubleRatchet) -> str:
    """
    Render the externally relevant state of a Double Ratchet.

    Args:
        dr: The Double Ratchet to inspect.

    Returns:
        A compact string describing the sending/receiving chain lengths and stored skipped key indices.
    """

    model = dr.json
    key_ratchet = model["diffie_hellman_ratchet"]["symmetric_key_ratchet"]
    sending_chain = key_ratchet["sending_chain"]
    receiving_chain = key_ratchet["receiving_chain"]

    return (
        f"send={sending_chain['length'] if sending_chain else None}"
        f" recv={receiving_chain['length'] if receiving_chain else None}"
        f" skipped={[entry['index'] for entry in model['skipped_message_keys']]}"
    )


def print_step(step: str, alice: DoubleRatchet, bob: DoubleRatchet, note: str = "") -> None:
    """
    Print one row of the two-party state comparison.

    Args:
        step: Name of the step.
        alice: Alice' Double Ratchet.
        bob: Bob's Double Ratchet.
        note: Additional information to print.
    """

    print(f"| {step:<34} | {state(alice):<46} | {state(bob):<46} | {note}")


async def scenario_success() -> None:
    """
    Show the baseline: a successful send consumes one key and the receiver accepts it.
    """

    print("\n### Baseline: successful send")
    alice, bob = await make_pair()

    message = await alice.encrypt_message(b"hello", ASSOCIATED_DATA)
    print_step("after encrypt", alice, bob, f"n={message.header.sending_chain_length}")

    assert await bob.decrypt_message(message, ASSOCIATED_DATA) == b"hello"
    print_step("after decrypt", alice, bob, "delivered")


async def scenario_kdf_failure() -> None:
    """
    Show that a KDF failure leaves the sending chain untouched, so the retry keeps the index.
    """

    print("\n### KDF failure: no message key exists")
    alice, bob = await make_pair()
    before = state(alice)

    MessageChainKDF.fail_next_call = True
    try:
        await alice.encrypt_message(b"failed", ASSOCIATED_DATA)
    except RuntimeError as e:
        print_step("KDF raised", alice, bob, str(e))
    finally:
        MessageChainKDF.fail_next_call = False

    assert state(alice) == before

    message = await alice.encrypt_message(b"retried", ASSOCIATED_DATA)
    print_step("retry encrypted", alice, bob, f"n={message.header.sending_chain_length}")

    assert await bob.decrypt_message(message, ASSOCIATED_DATA) == b"retried"
    print_step("retry decrypted", alice, bob, "delivered, no skipped key")


async def scenario_aead_before_ciphertext() -> None:
    """
    Show that an AEAD failure after key derivation spends the key, so the retry increments the index.
    """

    print("\n### AEAD failure before a ciphertext exists")
    alice, bob = await make_pair()
    failed_index = alice.sending_chain_length

    AEAD.failure = "before"
    try:
        await alice.encrypt_message(b"failed", ASSOCIATED_DATA)
    except RuntimeError as e:
        print_step("AEAD raised", alice, bob, str(e))
    finally:
        AEAD.failure = None

    message = await alice.encrypt_message(b"retried", ASSOCIATED_DATA)
    print_step("retry encrypted", alice, bob, f"n={message.header.sending_chain_length}")

    assert await bob.decrypt_message(message, ASSOCIATED_DATA) == b"retried"
    print_step("retry decrypted", alice, bob, f"index {failed_index} skipped")

    assert AEAD.seen_keys[0] != AEAD.seen_keys[1]


async def scenario_aead_after_ciphertext() -> None:
    """
    Show that a ciphertext produced before the failure can be delivered later, from the skipped key.
    """

    print("\n### AEAD/transport failure after a ciphertext exists")
    alice, bob = await make_pair()
    failed_index = alice.sending_chain_length

    AEAD.failure = "transport"
    try:
        await alice.encrypt_message(b"late", ASSOCIATED_DATA)
    except RuntimeError as e:
        print_step("transport raised", alice, bob, str(e))
    finally:
        AEAD.failure = None

    failed_ciphertext = AEAD.last_ciphertext
    failed_header = RecordingDiffieHellmanRatchet.last_header
    assert failed_ciphertext is not None
    assert failed_header is not None

    retried = await alice.encrypt_message(b"retried", ASSOCIATED_DATA)
    print_step("retry encrypted", alice, bob, f"n={retried.header.sending_chain_length}")

    assert await bob.decrypt_message(retried, ASSOCIATED_DATA) == b"retried"
    print_step("retry decrypted", alice, bob, f"index {failed_index} skipped")

    late = EncryptedMessage(header=failed_header, ciphertext=failed_ciphertext)
    assert await bob.decrypt_message(late, ASSOCIATED_DATA) == b"late"
    print_step("failed ciphertext delivered", alice, bob, f"index {failed_index} consumed")

    assert AEAD.seen_keys[0] != AEAD.seen_keys[1]


async def scenario_cancel_before_key() -> None:
    """
    Show that cancelling while the KDF runs leaves the sending chain untouched.
    """

    print("\n### Cancellation during KDF: no message key exists")
    alice, bob = await make_pair()
    before = state(alice)
    next_index = alice.sending_chain_length

    gate = asyncio.Event()
    entered = asyncio.Event()
    MessageChainKDF.gate = gate
    MessageChainKDF.entered = entered

    task = asyncio.create_task(alice.encrypt_message(b"cancelled", ASSOCIATED_DATA))
    await entered.wait()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        print_step("send cancelled", alice, bob, "KDF was still running")
    finally:
        MessageChainKDF.gate = None
        MessageChainKDF.entered = None

    assert state(alice) == before

    message = await alice.encrypt_message(b"retried", ASSOCIATED_DATA)
    assert message.header.sending_chain_length == next_index
    assert await bob.decrypt_message(message, ASSOCIATED_DATA) == b"retried"
    print_step("retry decrypted", alice, bob, "delivered, index unchanged")


async def scenario_cancel_after_ciphertext() -> None:
    """
    Show that cancelling after the ciphertext exists spends the key but keeps the ciphertext usable.
    """

    print("\n### Cancellation after the ciphertext exists")
    alice, bob = await make_pair()
    failed_index = alice.sending_chain_length

    gate = asyncio.Event()
    entered = asyncio.Event()
    AEAD.encrypt_gate = gate
    AEAD.encrypt_entered = entered

    task = asyncio.create_task(alice.encrypt_message(b"cancelled", ASSOCIATED_DATA))
    await entered.wait()

    failed_ciphertext = AEAD.last_ciphertext
    failed_header = RecordingDiffieHellmanRatchet.last_header
    assert failed_ciphertext is not None
    assert failed_header is not None

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        print_step("send cancelled", alice, bob, "ciphertext already exists")
    finally:
        AEAD.encrypt_gate = None
        AEAD.encrypt_entered = None

    retried = await alice.encrypt_message(b"retried", ASSOCIATED_DATA)
    assert retried.header.sending_chain_length == failed_index + 1
    assert await bob.decrypt_message(retried, ASSOCIATED_DATA) == b"retried"
    print_step("retry decrypted", alice, bob, f"index {failed_index} skipped")

    late = EncryptedMessage(header=failed_header, ciphertext=failed_ciphertext)
    assert await bob.decrypt_message(late, ASSOCIATED_DATA) == b"cancelled"
    print_step("cancelled ciphertext delivered", alice, bob, f"index {failed_index} consumed")


async def main() -> None:
    """
    Run all scenarios and print the state comparison.
    """

    print("| step                               | alice state                                    "
          "| bob state                                      | note")
    print("|------------------------------------|------------------------------------------------|"
          "------------------------------------------------|-----")

    await scenario_success()
    await scenario_kdf_failure()
    await scenario_aead_before_ciphertext()
    await scenario_aead_after_ciphertext()
    await scenario_cancel_before_key()
    await scenario_cancel_after_ciphertext()

    print("\nLibrary-confirmable facts:")
    print("- A returned EncryptedMessage is authenticated and reproducible (header + ciphertext).")
    print("- A derived sending-chain index is spent once the key exists, no matter what happens next.")
    print("- A raised exception before key derivation leaves the sending chain unchanged.")
    print("\nExternal facts the library cannot observe:")
    print("- Whether the caller transmitted the ciphertext, and whether the recipient received it.")
    print("- Therefore delivery is only confirmed by the receiver (a reply or an application-level ack),")
    print("  never by a successful encrypt_message call.")


if __name__ == "__main__":
    asyncio.run(main())
