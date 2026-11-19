import base64
import copy
import json
import os
from typing import Set, Dict, Any, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from doubleratchet import (
    AuthenticationFailedException,
    DoubleRatchet as DR,
    DuplicateMessageException,
    EncryptedMessage,
    EvictionReason,
    Header,
    InconsistentSerializationException,
    MessagePosition,
    ReceiveDiagnostic,
    ReceiveDiagnostics,
    ReceiveStatus
)
from doubleratchet.recommended import (
    aead_aes_hmac,
    diffie_hellman_ratchet_curve25519 as dhr25519,
    diffie_hellman_ratchet_curve448 as dhr448,
    HashFunction,
    kdf_hkdf
)

from .test_recommended_kdfs import generate_unique_random_data


__all__ = [
    "test_double_ratchet",
    "test_receive_diagnostics",
    "test_migrations"
]


try:
    import pytest
except ImportError:
    pass
else:
    pytestmark = pytest.mark.asyncio


class RootChainKDF(kdf_hkdf.KDF):
    """
    The root chain KDF to use while testing.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_256

    @staticmethod
    def _get_info() -> bytes:
        return "test_double_ratchet Root Chain KDF info".encode("ASCII")


class MessageChainKDF(kdf_hkdf.KDF):
    """
    The message chain KDF to use while testing.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512_256

    @staticmethod
    def _get_info() -> bytes:
        return "test_double_ratchet Message Chain KDF info".encode("ASCII")


class AEAD(aead_aes_hmac.AEAD):
    """
    The AEAD to use while testing.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return "test_double_ratchet AEAD info".encode("ASCII")


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


def skipped_message_keys(dr: DoubleRatchet) -> Dict[Tuple[bytes, int], bytes]:
    """
    Return a copy of a Double Ratchet's skipped message keys, for white-box assertions in tests.

    Args:
        dr: The Double Ratchet instance to inspect.

    Returns:
        A copy of the internal skipped message key mapping.
    """

    # pylint: disable-next=protected-access
    return dict(dr._DoubleRatchet__skipped_message_keys)


drc: Dict[str, Any] = {
    "diffie_hellman_ratchet_class": dhr448.DiffieHellmanRatchet,
    "root_chain_kdf": RootChainKDF,
    "message_chain_kdf": MessageChainKDF,
    "message_chain_constant": "test_double_ratchet Message Chain constant".encode("ASCII"),
    "dos_protection_threshold": 10,
    "max_num_skipped_message_keys": 15,
    "aead": AEAD
}


async def test_double_ratchet() -> None:
    """
    Test the Double Ratchet implementation.
    """

    shared_secret_set: Set[bytes] = set()
    message_set: Set[bytes] = set()
    ad_set: Set[bytes] = set()

    # for _ in range(200):
    for _ in range(10):
        bob_ratchet_priv = X448PrivateKey.generate()
        bob_ratchet_pub = bob_ratchet_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        shared_secret = generate_unique_random_data(32, 32 + 1, shared_secret_set)
        message = generate_unique_random_data(0, 2 ** 16, message_set)
        ad = generate_unique_random_data(0, 2 ** 16, ad_set)

        # Test that passing a shared secret which doesn't consist of 32 bytes raises an exception:
        try:
            await DoubleRatchet.encrypt_initial_message(
                shared_secret=b"\x00" * 64,
                recipient_ratchet_pub=bob_ratchet_pub,
                message=message,
                associated_data=ad,
                **drc
            )
            assert False
        except ValueError as e:
            assert "shared secret" in str(e)
            assert "32 bytes" in str(e)

        # Test that passing a DoS protection threshold higher than the maximum number of skipped message key
        # raises an exception:
        try:
            drc_copy = copy.copy(drc)
            drc_copy["dos_protection_threshold"] = 20
            await DoubleRatchet.encrypt_initial_message(
                shared_secret=shared_secret,
                recipient_ratchet_pub=bob_ratchet_pub,
                message=message,
                associated_data=ad,
                **drc_copy
            )
            assert False
        except ValueError as e:
            assert "dos_protection_threshold" in str(e)
            assert "bigger than" in str(e)
            assert "max_num_skipped_message_keys" in str(e)

        # Encrypt an initial message from Alice to Bob
        alice_dr, encrypted_message = await DoubleRatchet.encrypt_initial_message(
            shared_secret=shared_secret,
            recipient_ratchet_pub=bob_ratchet_pub,
            message=message,
            associated_data=ad,
            **drc
        )
        bob_dr, plaintext = await DoubleRatchet.decrypt_initial_message(
            shared_secret=shared_secret,
            own_ratchet_priv=bob_ratchet_priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ),
            message=encrypted_message,
            associated_data=ad,
            **drc
        )

        assert alice_dr.sending_chain_length == 1
        assert alice_dr.receiving_chain_length is None
        assert bob_dr.sending_chain_length == 0
        assert bob_dr.receiving_chain_length == 1
        assert plaintext == message

        # Send a message back and forth
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        assert await alice_dr.decrypt_message(await bob_dr.encrypt_message(message, ad), ad) == message

        # Make sure that each ciphertext is different even though the message is always the same:
        encrypted_message_1 = await alice_dr.encrypt_message(message, ad)
        assert await bob_dr.decrypt_message(encrypted_message_1, ad) == message
        encrypted_message_2 = await alice_dr.encrypt_message(message, ad)
        assert await bob_dr.decrypt_message(encrypted_message_2, ad) == message
        assert encrypted_message_1.ciphertext != encrypted_message_2.ciphertext

        # Test the first case of skipped messages (without a Diffie-Hellman ratchet step):
        skipped_message_1 = await alice_dr.encrypt_message(message, ad)
        skipped_message_2 = await alice_dr.encrypt_message(message, ad)
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        assert await bob_dr.decrypt_message(skipped_message_2, ad) == message
        assert await bob_dr.decrypt_message(skipped_message_1, ad) == message

        # Test the second case of skipped messages (with Diffie-Hellman ratchet steps):
        skipped_message_1 = await alice_dr.encrypt_message(message, ad)
        skipped_message_2 = await alice_dr.encrypt_message(message, ad)
        assert await alice_dr.decrypt_message(await bob_dr.encrypt_message(message, ad), ad) == message
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        assert await alice_dr.decrypt_message(await bob_dr.encrypt_message(message, ad), ad) == message
        skipped_message_3 = await alice_dr.encrypt_message(message, ad)
        skipped_message_4 = await alice_dr.encrypt_message(message, ad)
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        assert await bob_dr.decrypt_message(skipped_message_4, ad) == message
        assert await bob_dr.decrypt_message(skipped_message_3, ad) == message
        assert await bob_dr.decrypt_message(skipped_message_2, ad) == message
        assert await bob_dr.decrypt_message(skipped_message_1, ad) == message

        # Test that only the last 15 skipped message keys are kept around:
        skipped_message = await alice_dr.encrypt_message(message, ad)  # Skipped messages: 1
        for _ in range(7):
            await alice_dr.encrypt_message(message, ad)  # Skipped messages: 8
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        for _ in range(7):
            await alice_dr.encrypt_message(message, ad)  # Skipped messages: 15
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        assert await bob_dr.decrypt_message(skipped_message, ad) == message

        skipped_message = await alice_dr.encrypt_message(message, ad)  # Skipped messages: 1
        for _ in range(7):
            await alice_dr.encrypt_message(message, ad)  # Skipped messages: 8
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        for _ in range(8):
            await alice_dr.encrypt_message(message, ad)  # Skipped messages: 16
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        try:
            await bob_dr.decrypt_message(skipped_message, ad)
            assert False
        except DuplicateMessageException:
            pass

        # Test decrypting a message twice, before a Diffie-Hellman ratchet step. This should throw a
        # DuplicateMessageException and leave the ratchet intact:
        encrypted_message = await alice_dr.encrypt_message(message, ad)
        assert await bob_dr.decrypt_message(encrypted_message, ad) == message
        try:
            await bob_dr.decrypt_message(encrypted_message, ad)
            assert False
        except DuplicateMessageException:
            pass

        # Test decrypting a message twice, after a Diffie-Hellman ratchet step. The Double Ratchet does not
        # detect this, thus no DuplicateMessageException should be raise, but a generic
        # AuthenticationFailedException:
        assert await alice_dr.decrypt_message(await bob_dr.encrypt_message(message, ad), ad) == message
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        assert await alice_dr.decrypt_message(await bob_dr.encrypt_message(message, ad), ad) == message
        encrypted_message = await alice_dr.encrypt_message(message, ad)
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        assert await alice_dr.decrypt_message(await bob_dr.encrypt_message(message, ad), ad) == message
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        assert await bob_dr.decrypt_message(encrypted_message, ad) == message
        try:
            await bob_dr.decrypt_message(encrypted_message, ad)
            assert False
        except AuthenticationFailedException:
            pass

        # Even after this failure, the ratchets should still work as before:
        assert await alice_dr.decrypt_message(await bob_dr.encrypt_message(message, ad), ad) == message
        assert await alice_dr.decrypt_message(await bob_dr.encrypt_message(message, ad), ad) == message
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message

        # Test that (de)serialization doesn't damage the instances:
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        alice_dr = DoubleRatchet.from_json(alice_dr.json, **drc)
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        bob_dr = DoubleRatchet.from_json(bob_dr.json, **drc)
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        skipped_message = await alice_dr.encrypt_message(message, ad)
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        bob_dr = DoubleRatchet.from_json(bob_dr.json, **drc)
        assert await bob_dr.decrypt_message(skipped_message, ad) == message

        # Test that (de)serialization can be used to decrypt the same message twice:
        encrypted_message = await alice_dr.encrypt_message(message, ad)
        bob_dr_serialized = bob_dr.json
        assert await bob_dr.decrypt_message(encrypted_message, ad) == message
        bob_dr = DoubleRatchet.from_json(bob_dr_serialized, **drc)
        assert await bob_dr.decrypt_message(encrypted_message, ad) == message


async def test_receive_diagnostics() -> None:
    """
    Test that receive diagnostics explain cache eviction, duplicate delivery and authentication failure
    across two Diffie-Hellman ratchet steps, without altering regular behavior or serialization.
    """

    diagnostics_configuration: Dict[str, Any] = {
        "diffie_hellman_ratchet_class": dhr448.DiffieHellmanRatchet,
        "root_chain_kdf": RootChainKDF,
        "message_chain_kdf": MessageChainKDF,
        "message_chain_constant": "test_double_ratchet Message Chain constant".encode("ASCII"),
        "dos_protection_threshold": 2,
        "max_num_skipped_message_keys": 2,
        "aead": AEAD
    }
    associated_data = "test_double_ratchet diagnostics associated data".encode("ASCII")
    chat_message = b"diagnostics"

    bob_ratchet_priv = X448PrivateKey.generate()
    bob_ratchet_pub = bob_ratchet_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    shared_secret = b"\x42" * 32

    bob_diagnostics = ReceiveDiagnostics(history_limit=64)
    alice_diagnostics = ReceiveDiagnostics(history_limit=64)

    alice_dr, encrypted_message = await DoubleRatchet.encrypt_initial_message(
        shared_secret=shared_secret,
        recipient_ratchet_pub=bob_ratchet_pub,
        message=chat_message,
        associated_data=associated_data,
        **diagnostics_configuration
    )
    alice_dr.set_receive_diagnostics(alice_diagnostics)
    bob_dr, plaintext = await DoubleRatchet.decrypt_initial_message(
        shared_secret=shared_secret,
        own_ratchet_priv=bob_ratchet_priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        message=encrypted_message,
        associated_data=associated_data,
        diagnostics=bob_diagnostics,
        **diagnostics_configuration
    )
    assert plaintext == chat_message
    assert bob_diagnostics.last is not None
    assert bob_diagnostics.last.status is ReceiveStatus.ACCEPTED

    async def receive(
        receiver: DoubleRatchet,
        message: EncryptedMessage
    ) -> Tuple[Optional[bytes], ReceiveDiagnostic]:
        result = await receiver.decrypt_message_with_diagnostics(message, associated_data)
        assert (result.plaintext is not None) == (result.status is ReceiveStatus.ACCEPTED)
        return (result.plaintext, result.diagnostic)

    # Chain 0: Alice sends three messages, Bob only receives the last one. The two earlier keys are
    # skipped. Chain 0 is the receiving chain of Bob until Alice's next chain arrives.
    alice_chain_0 = [
        await alice_dr.encrypt_message(chat_message, associated_data)
        for _ in range(3)
    ]
    decrypted, diagnostic = await receive(bob_dr, alice_chain_0[2])
    assert decrypted == chat_message
    assert diagnostic.status is ReceiveStatus.ACCEPTED
    assert diagnostic.evicted == ()
    assert diagnostic.cache_size == diagnostic.cache_limit == 2

    # Let Alice receive one message so that she performs a Diffie-Hellman ratchet step. Bob's sending chain
    # advances independently of his receiving cache.
    bob_chain_0 = [
        await bob_dr.encrypt_message(chat_message, associated_data)
        for _ in range(3)
    ]
    decrypted, diagnostic = await receive(alice_dr, bob_chain_0[0])
    assert decrypted == chat_message
    assert diagnostic.status is ReceiveStatus.ACCEPTED

    # Chain 1: Alice sends three messages, Bob receives only the last. Bob's cache holds at most two keys,
    # and these are the two skipped keys of chain 1.
    alice_chain_1 = [
        await alice_dr.encrypt_message(chat_message, associated_data)
        for _ in range(3)
    ]
    _, diagnostic = await receive(bob_dr, alice_chain_1[2])
    assert diagnostic.status is ReceiveStatus.ACCEPTED
    # The chain 0 keys are evicted to make space for the chain 1 keys.
    assert { position.sending_chain_length for position in diagnostic.evicted } == { 1, 2 }

    bob_chain_1 = [
        await bob_dr.encrypt_message(chat_message, associated_data)
        for _ in range(3)
    ]
    _, diagnostic = await receive(alice_dr, bob_chain_1[0])
    assert diagnostic.status is ReceiveStatus.ACCEPTED

    # Chain 2: Alice sends three messages, Bob receives only the last. This evicts the two chain 1 keys.
    alice_chain_2 = [
        await alice_dr.encrypt_message(chat_message, associated_data)
        for _ in range(3)
    ]

    # A forged first message of the new chain would, if it authenticated, evict the chain 1 keys while
    # performing the Diffie-Hellman ratchet step. A failed authentication must not advance the ratchet or
    # push any eviction, so the cache and its contents remain exactly as before.
    cache_before_forged_new_chain = skipped_message_keys(bob_dr)
    forged_new_chain = alice_chain_2[2]._replace(
        ciphertext=bytes([alice_chain_2[2].ciphertext[0] ^ 1]) + alice_chain_2[2].ciphertext[1:]
    )
    decrypted, diagnostic = await receive(bob_dr, forged_new_chain)
    assert decrypted is None
    assert diagnostic.status is ReceiveStatus.AUTHENTICATION_FAILED
    assert diagnostic.evicted == ()
    assert skipped_message_keys(bob_dr) == cache_before_forged_new_chain

    _, diagnostic = await receive(bob_dr, alice_chain_2[2])
    assert diagnostic.status is ReceiveStatus.ACCEPTED
    # Eviction covers exact positions of the previous chain, not one single maximum index.
    evicted_chain_1 = {
        position.sending_chain_length
        for position in diagnostic.evicted
        if position.ratchet_pub == alice_chain_1[2].header.ratchet_pub
    }
    assert evicted_chain_1 == { 0, 1 }
    assert all(position.ratchet_pub == alice_chain_1[0].header.ratchet_pub for position in diagnostic.evicted)

    # Late messages from chain 1 have no key anymore: they are reported as missing historical keys, with
    # the observed eviction as the reason. The higher chain index of a later message is not used as a proxy.
    for index in (0, 1):
        decrypted, diagnostic = await receive(bob_dr, alice_chain_1[index])
        assert decrypted is None
        assert diagnostic.status is ReceiveStatus.MISSING_HISTORICAL_KEY
        assert diagnostic.reason is EvictionReason.EVICTED
        assert diagnostic.position.sending_chain_length == index
        assert diagnostic.position.ratchet_pub == alice_chain_1[index].header.ratchet_pub

    # The already processed chain 1 message is explained as such, even though its chain is superseded.
    decrypted, diagnostic = await receive(bob_dr, alice_chain_1[2])
    assert decrypted is None
    assert diagnostic.status is ReceiveStatus.ALREADY_PROCESSED

    # A forged message at a position that still has a key fails authentication. It must not consume that key
    # or push any eviction, and the genuine message must still be accepted afterwards.
    forged = alice_chain_2[1]._replace(
        ciphertext=bytes([alice_chain_2[1].ciphertext[0] ^ 1]) + alice_chain_2[1].ciphertext[1:]
    )
    cache_size_before = len(skipped_message_keys(bob_dr))
    records_before = len(bob_diagnostics)
    decrypted, diagnostic = await receive(bob_dr, forged)
    assert decrypted is None
    assert diagnostic.status is ReceiveStatus.AUTHENTICATION_FAILED
    assert len(skipped_message_keys(bob_dr)) == cache_size_before
    assert len(bob_diagnostics) == records_before + 1
    assert bob_diagnostics.records[-1] is diagnostic

    # Both exact chain 2 keys are still cached and can be used.
    for index in (0, 1):
        decrypted, diagnostic = await receive(bob_dr, alice_chain_2[index])
        assert decrypted == chat_message
        assert diagnostic.status is ReceiveStatus.ACCEPTED

    # Replays of an accepted message are reported as already processed.
    decrypted, diagnostic = await receive(bob_dr, alice_chain_2[2])
    assert decrypted is None
    assert diagnostic.status is ReceiveStatus.ALREADY_PROCESSED

    # Diagnostics contain no key material, plaintext or serialized state.
    for record in bob_diagnostics.records:
        rendered = repr(record)
        assert chat_message not in rendered.encode("ASCII")
        assert "message_key" not in rendered
        assert "own_ratchet_priv" not in rendered

    # A late message from a superseded chain is accepted if its exact key is still cached. Set up a fresh
    # pair with a cache limit of two, so that one old-chain key survives one ratchet step.
    stale_diagnostics = ReceiveDiagnostics(history_limit=16)
    stale_alice, stale_encrypted = await DoubleRatchet.encrypt_initial_message(
        shared_secret=shared_secret,
        recipient_ratchet_pub=bob_ratchet_pub,
        message=chat_message,
        associated_data=associated_data,
        **diagnostics_configuration
    )
    stale_bob, _ = await DoubleRatchet.decrypt_initial_message(
        shared_secret=shared_secret,
        own_ratchet_priv=bob_ratchet_priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        message=stale_encrypted,
        associated_data=associated_data,
        diagnostics=stale_diagnostics,
        **diagnostics_configuration
    )
    stale_alice.set_receive_diagnostics(stale_diagnostics)
    stale_chain_0 = [
        await stale_alice.encrypt_message(chat_message, associated_data)
        for _ in range(2)
    ]
    stale_first_plaintext, stale_first_diagnostic = await receive(stale_bob, stale_chain_0[1])
    assert stale_first_plaintext == chat_message
    assert stale_first_diagnostic.status is ReceiveStatus.ACCEPTED
    assert not stale_first_diagnostic.evicted

    # A reply rotates Alice's chain and produces a new chain from her. Bob receives its last message, which
    # only skips one key. Both the old chain 0 key and the new chain 1 key fit into the cache.
    stale_reply = await stale_bob.encrypt_message(chat_message, associated_data)
    stale_reply_plaintext, stale_reply_diagnostic = await receive(stale_alice, stale_reply)
    assert stale_reply_plaintext == chat_message
    assert stale_reply_diagnostic.status is ReceiveStatus.ACCEPTED
    stale_chain_1 = [
        await stale_alice.encrypt_message(chat_message, associated_data)
        for _ in range(2)
    ]
    _, stale_second_diagnostic = await receive(stale_bob, stale_chain_1[1])
    assert stale_second_diagnostic.status is ReceiveStatus.ACCEPTED
    assert stale_second_diagnostic.evicted == ()

    # The old chain key is still cached: the late message is accepted, not rejected by a chain index rule.
    stale_late_plaintext, stale_late_diagnostic = await receive(stale_bob, stale_chain_0[0])
    assert stale_late_plaintext == chat_message
    assert stale_late_diagnostic.status is ReceiveStatus.ACCEPTED
    assert stale_late_diagnostic.position.ratchet_pub == stale_chain_0[0].header.ratchet_pub
    _, stale_replay_diagnostic = await receive(stale_bob, stale_chain_0[0])
    assert stale_replay_diagnostic.status is ReceiveStatus.ALREADY_PROCESSED

    # A genuinely unknown missing position is explained conservatively as not retained, never as evicted.
    unknown_diagnostics = ReceiveDiagnostics(history_limit=16)
    unknown_diagnostic = unknown_diagnostics.record_missing_historical_key(
        MessagePosition(b"unknown ratchet public key", 0)
    )
    assert unknown_diagnostic.status is ReceiveStatus.MISSING_HISTORICAL_KEY
    assert unknown_diagnostic.reason is EvictionReason.NOT_RETAINED

    # Build a pair where an entire old chain's keys were evicted before diagnostics were attached.
    evicted_alice, evicted_encrypted = await DoubleRatchet.encrypt_initial_message(
        shared_secret=shared_secret,
        recipient_ratchet_pub=bob_ratchet_pub,
        message=chat_message,
        associated_data=associated_data,
        **diagnostics_configuration
    )
    evicted_bob, _ = await DoubleRatchet.decrypt_initial_message(
        shared_secret=shared_secret,
        own_ratchet_priv=bob_ratchet_priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        message=evicted_encrypted,
        associated_data=associated_data,
        **diagnostics_configuration
    )
    evicted_chain_0 = [
        await evicted_alice.encrypt_message(chat_message, associated_data)
        for _ in range(3)
    ]
    assert await evicted_bob.decrypt_message(evicted_chain_0[2], associated_data) == chat_message
    evicted_reply = await evicted_bob.encrypt_message(chat_message, associated_data)
    assert await evicted_alice.decrypt_message(evicted_reply, associated_data) == chat_message
    evicted_chain_1 = [
        await evicted_alice.encrypt_message(chat_message, associated_data)
        for _ in range(3)
    ]
    # Receiving the last chain 1 message evicts both chain 0 keys while diagnostics are detached.
    assert await evicted_bob.decrypt_message(evicted_chain_1[2], associated_data) == chat_message
    evicted_snapshot = evicted_bob.json

    # A freshly attached diagnostics instance never saw the eviction. It must not claim eviction; since it
    # also never observed the old chain, the attempt follows the actual authentication outcome.
    fresh_diagnostics = ReceiveDiagnostics(history_limit=16)
    fresh_bob = DoubleRatchet.from_json(
        evicted_snapshot,
        diagnostics=fresh_diagnostics,
        **diagnostics_configuration
    )
    fresh_plaintext, fresh_diagnostic = await receive(fresh_bob, evicted_chain_0[0])
    assert fresh_plaintext is None
    assert fresh_diagnostic.status is ReceiveStatus.AUTHENTICATION_FAILED
    assert fresh_diagnostic.reason is None

    # If diagnostics observed the chain before but were detached during the eviction, they know the chain
    # but not the eviction. The missing key is reported with the conservative reason.
    detached_diagnostics = ReceiveDiagnostics(history_limit=16)
    detached_alice, detached_encrypted = await DoubleRatchet.encrypt_initial_message(
        shared_secret=shared_secret,
        recipient_ratchet_pub=bob_ratchet_pub,
        message=chat_message,
        associated_data=associated_data,
        **diagnostics_configuration
    )
    detached_bob, detached_initial_plaintext = await DoubleRatchet.decrypt_initial_message(
        shared_secret=shared_secret,
        own_ratchet_priv=bob_ratchet_priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        message=detached_encrypted,
        associated_data=associated_data,
        diagnostics=detached_diagnostics,
        **diagnostics_configuration
    )
    detached_alice.set_receive_diagnostics(detached_diagnostics)
    assert detached_initial_plaintext == chat_message
    detached_chain_0 = [
        await detached_alice.encrypt_message(chat_message, associated_data)
        for _ in range(3)
    ]
    assert await detached_bob.decrypt_message(detached_chain_0[2], associated_data) == chat_message
    detached_reply = await detached_bob.encrypt_message(chat_message, associated_data)
    detached_reply_plaintext, detached_reply_diagnostic = await receive(detached_alice, detached_reply)
    assert detached_reply_plaintext == chat_message
    assert detached_reply_diagnostic.status is ReceiveStatus.ACCEPTED
    detached_chain_1 = [
        await detached_alice.encrypt_message(chat_message, associated_data)
        for _ in range(3)
    ]
    detached_bob.set_receive_diagnostics(None)
    assert await detached_bob.decrypt_message(detached_chain_1[2], associated_data) == chat_message
    detached_bob.set_receive_diagnostics(detached_diagnostics)
    detached_plaintext, detached_diagnostic = await receive(detached_bob, detached_chain_0[0])
    assert detached_plaintext is None
    assert detached_diagnostic.status is ReceiveStatus.MISSING_HISTORICAL_KEY
    assert detached_diagnostic.reason is EvictionReason.NOT_RETAINED

    # API guards: diagnostics must be attached, and the history limit must be positive.
    plain_bob = DoubleRatchet.from_json(bob_dr.json, **diagnostics_configuration)
    assert plain_bob.receive_diagnostics is None
    try:
        await plain_bob.decrypt_message_with_diagnostics(
            alice_chain_0[0],
            associated_data
        )
        raise AssertionError("expected RuntimeError")
    except RuntimeError as e:
        assert "diagnostics" in str(e)
    try:
        ReceiveDiagnostics(0)
        raise AssertionError("expected ValueError")
    except ValueError as e:
        assert "positive" in str(e)

    # Mixed use of the regular and diagnostic receive APIs keeps diagnostics accurate: a message accepted
    # through decrypt_message is later reported as already processed, not as an unknown old position.
    mixed_diagnostics = ReceiveDiagnostics(history_limit=16)
    mixed_alice, mixed_encrypted = await DoubleRatchet.encrypt_initial_message(
        shared_secret=shared_secret,
        recipient_ratchet_pub=bob_ratchet_pub,
        message=chat_message,
        associated_data=associated_data,
        **diagnostics_configuration
    )
    mixed_bob, _ = await DoubleRatchet.decrypt_initial_message(
        shared_secret=shared_secret,
        own_ratchet_priv=bob_ratchet_priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        message=mixed_encrypted,
        associated_data=associated_data,
        diagnostics=mixed_diagnostics,
        **diagnostics_configuration
    )
    mixed_message = await mixed_alice.encrypt_message(chat_message, associated_data)
    assert await mixed_bob.decrypt_message(mixed_message, associated_data) == chat_message
    mixed_plaintext, mixed_diagnostic = await receive(mixed_bob, mixed_message)
    assert mixed_plaintext is None
    assert mixed_diagnostic.status is ReceiveStatus.ALREADY_PROCESSED

    # The diagnostics attached to an instance are never serialized.
    assert bob_dr.receive_diagnostics is bob_diagnostics
    assert "diagnostics" not in json.dumps(bob_dr.json)

    # With diagnostics disabled, regular decryption and state serialization must behave exactly as with
    # diagnostics attached. Restore two instances from the same snapshot and feed them the same messages.
    reference_alice, reference_encrypted = await DoubleRatchet.encrypt_initial_message(
        shared_secret=shared_secret,
        recipient_ratchet_pub=bob_ratchet_pub,
        message=chat_message,
        associated_data=associated_data,
        **diagnostics_configuration
    )
    reference_bob, reference_plaintext = await DoubleRatchet.decrypt_initial_message(
        shared_secret=shared_secret,
        own_ratchet_priv=bob_ratchet_priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        message=reference_encrypted,
        associated_data=associated_data,
        **diagnostics_configuration
    )
    assert reference_plaintext == chat_message

    snapshot = reference_bob.json
    reference_messages = [
        await reference_alice.encrypt_message(chat_message, associated_data)
        for _ in range(3)
    ]
    # Deliver the last message first, then a forged skipped message, the genuine skipped message and finally
    # a replay. This exercises accepted, authentication failed, accepted and duplicate boundaries.
    forged_reference = reference_messages[0]._replace(
        ciphertext=bytes([reference_messages[0].ciphertext[0] ^ 1])
        + reference_messages[0].ciphertext[1:]
    )
    reference_sequence = [
        reference_messages[2],
        forged_reference,
        reference_messages[0],
        reference_messages[2]
    ]

    with_diagnostics = DoubleRatchet.from_json(
        snapshot,
        diagnostics=ReceiveDiagnostics(),
        **diagnostics_configuration
    )
    without_diagnostics = DoubleRatchet.from_json(snapshot, **diagnostics_configuration)
    assert with_diagnostics.json == without_diagnostics.json == snapshot

    expected_outcomes = [True, False, True, False]
    for message, should_succeed in zip(reference_sequence, expected_outcomes):
        plaintext_with, diagnostic = await receive(with_diagnostics, message)
        if should_succeed:
            assert plaintext_with == chat_message
            assert diagnostic.status is ReceiveStatus.ACCEPTED
            assert await without_diagnostics.decrypt_message(message, associated_data) == chat_message
        else:
            assert plaintext_with is None
            assert diagnostic.status in (
                ReceiveStatus.AUTHENTICATION_FAILED,
                ReceiveStatus.ALREADY_PROCESSED
            )
            try:
                await without_diagnostics.decrypt_message(message, associated_data)
                assert False
            except (AuthenticationFailedException, DuplicateMessageException):
                pass
        assert with_diagnostics.json == without_diagnostics.json

    # After processing the sequence, the state has advanced identically for both instances.
    assert with_diagnostics.json == without_diagnostics.json
    assert with_diagnostics.json != snapshot

    # The diagnostics attached to an instance are never serialized, and a plain instance never gains them.
    assert without_diagnostics.receive_diagnostics is None
    assert with_diagnostics.receive_diagnostics is not None
    assert with_diagnostics.json == without_diagnostics.json
MIGRATION_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "migration_data")


async def test_migrations() -> None:
    """
    Test serialization format migrations.
    """

    double_ratchet_configuration: Dict[str, Any] = {
        "diffie_hellman_ratchet_class": dhr25519.DiffieHellmanRatchet,
        "root_chain_kdf": RootChainKDF,
        "message_chain_kdf": MessageChainKDF,
        "message_chain_constant": "test_double_ratchet Message Chain constant".encode("ASCII"),
        "dos_protection_threshold": 10,
        "max_num_skipped_message_keys": 15,
        "aead": AEAD
    }

    associated_data = "test_double_ratchet associated data".encode("ASCII")

    with open(os.path.join(MIGRATION_DATA_DIR, "dr-alice-pre-stable.json"), encoding="utf-8") as file:
        alice_dr_serialized = json.load(file)

    with open(os.path.join(MIGRATION_DATA_DIR, "dr-bob-pre-stable.json"), encoding="utf-8") as file:
        bob_dr_serialized = json.load(file)

    with open(os.path.join(MIGRATION_DATA_DIR, "uninitialized-dr-pre-stable.json"), encoding="utf-8") as file:
        uninitialized_dr_serialized = json.load(file)

    with open(
        os.path.join(MIGRATION_DATA_DIR, "alice-skipped-messages-pre-stable.json"),
        encoding="utf-8"
    ) as file:
        alice_skipped_messages_serialized = json.load(file)

    with open(
        os.path.join(MIGRATION_DATA_DIR, "bob-skipped-messages-pre-stable.json"),
        encoding="utf-8"
    ) as file:
        bob_skipped_messages_serialized = json.load(file)

    alice_skipped_messages: List[Tuple[EncryptedMessage, bytes]] = []
    for skipped_message, plaintext in alice_skipped_messages_serialized:
        alice_skipped_messages.append((
            EncryptedMessage(
                header=Header(
                    ratchet_pub=base64.b64decode(skipped_message["header"]["ratchet_pub"].encode("ASCII")),
                    previous_sending_chain_length=skipped_message["header"]["pn"],
                    sending_chain_length=skipped_message["header"]["n"]
                ),
                ciphertext=base64.b64decode(skipped_message["ciphertext"].encode("ASCII"))
            ),
            base64.b64decode(plaintext.encode("ASCII"))
        ))

    bob_skipped_messages: List[Tuple[EncryptedMessage, bytes]] = []
    for skipped_message, plaintext in bob_skipped_messages_serialized:
        bob_skipped_messages.append((
            EncryptedMessage(
                header=Header(
                    ratchet_pub=base64.b64decode(skipped_message["header"]["ratchet_pub"].encode("ASCII")),
                    previous_sending_chain_length=skipped_message["header"]["pn"],
                    sending_chain_length=skipped_message["header"]["n"]
                ),
                ciphertext=base64.b64decode(skipped_message["ciphertext"].encode("ASCII"))
            ),
            base64.b64decode(plaintext.encode("ASCII"))
        ))

    # Verify that the uninitialized ratchet data can't be migrated
    try:
        DoubleRatchet.from_json(uninitialized_dr_serialized, **double_ratchet_configuration)
        assert False
    except InconsistentSerializationException:
        pass

    # Migrate the two valid ratchets
    alice_dr = DoubleRatchet.from_json(alice_dr_serialized, **double_ratchet_configuration)
    bob_dr = DoubleRatchet.from_json(bob_dr_serialized, **double_ratchet_configuration)

    # Verify that skipped messages can be correctly decrypted using the restored instances
    for encrypted_message, plaintext in alice_skipped_messages:
        assert await bob_dr.decrypt_message(encrypted_message, associated_data) == plaintext

    for encrypted_message, plaintext in bob_skipped_messages:
        assert await alice_dr.decrypt_message(encrypted_message, associated_data) == plaintext
