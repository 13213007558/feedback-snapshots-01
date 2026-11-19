"""
Tests that treat :class:`~doubleratchet.double_ratchet.DoubleRatchet` state restoration
(:meth:`~doubleratchet.double_ratchet.DoubleRatchet.from_json`/
:meth:`~doubleratchet.double_ratchet.DoubleRatchet.from_model`) as the ingestion of an untrusted archive.

Beyond "pydantic can parse the fields", these tests verify the relationships between skipped message keys,
chain counters and Diffie-Hellman public keys that are required to safely continue a session:

* Every accepted archive must be able to continue the session, including out-of-order message delivery.
* Every rejected archive must raise a clean exception and must not modify the original (live) instance.
  Corruption is never masked by re-initializing the session via ``encrypt_initial_message`` or
  ``decrypt_initial_message``.
* A defect control ensures that type-correct but inconsistent archives are still rejected, i.e. that the
  library does not regress to "restore whatever pydantic can parse".

Consistency properties that can NOT be proven from the archive alone (documented here, not tested):

* Whether the root chain key and the message chain keys actually match the peer's state. This can only be
  proven by successfully exchanging (authenticating) messages afterwards.
* Whether a stored skipped message key actually decrypts the message it claims to belong to.
* Whether skipped message keys stored under old (non-current) ratchet public keys have indices consistent
  with the final lengths of those chains. The archive no longer contains those chains.
* Whether ``other_ratchet_pub`` and the public keys of the skipped message keys are authentic keys of the
  peer rather than attacker-chosen. The archive is only as trustworthy as the storage it came from.
* Whether the archive is fresh, i.e. whether the peer has already advanced beyond the archived state
  (rollback detection requires state external to the archive).
"""

import copy
import os
from typing import Any, Dict, List, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from pydantic import ValidationError
from doubleratchet import EncryptedMessage, InconsistentSerializationException
from doubleratchet.models import DoubleRatchetModel

from .test_double_ratchet import AEAD, DoubleRatchet, MessageChainKDF, RootChainKDF
from doubleratchet.recommended import diffie_hellman_ratchet_curve448 as dhr448


__all__ = [
    "test_valid_archive_roundtrip_and_out_of_order_continuation",
    "test_legitimate_initial_unreceived_state_is_accepted",
    "test_negative_counters_are_rejected",
    "test_duplicate_skipped_message_keys_are_rejected",
    "test_invalid_key_lengths_are_rejected",
    "test_missing_chains_are_rejected",
    "test_future_skipped_message_key_index_is_rejected",
    "test_unknown_or_missing_version_is_rejected",
    "test_defect_control_type_correct_but_inconsistent"
]


try:
    import pytest
except ImportError:
    pass
else:
    pytestmark = pytest.mark.asyncio


DRC: Dict[str, Any] = {
    "diffie_hellman_ratchet_class": dhr448.DiffieHellmanRatchet,
    "root_chain_kdf": RootChainKDF,
    "message_chain_kdf": MessageChainKDF,
    "message_chain_constant": "test_untrusted_state_restoration Message Chain constant".encode("ASCII"),
    "dos_protection_threshold": 10,
    "max_num_skipped_message_keys": 15,
    "aead": AEAD
}


async def _build_archived_session() -> Tuple[
    DoubleRatchet,
    DoubleRatchet,
    bytes,
    Dict[str, Any],
    List[EncryptedMessage],
    List[EncryptedMessage]
]:
    """
    Run a real two-party interaction between Alice and Bob, including out-of-order delivery, and export
    Bob's state as a JSON archive. The archive contains skipped message keys both under Alice's previous
    ratchet public key and under her current one.
    """

    bob_ratchet_priv = X448PrivateKey.generate()
    shared_secret = os.urandom(32)
    ad = b"test_untrusted_state_restoration associated data"

    alice, initial_message = await DoubleRatchet.encrypt_initial_message(
        shared_secret=shared_secret,
        recipient_ratchet_pub=bob_ratchet_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ),
        message=b"initial",
        associated_data=ad,
        **DRC
    )
    bob, plaintext = await DoubleRatchet.decrypt_initial_message(
        shared_secret=shared_secret,
        own_ratchet_priv=bob_ratchet_priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        message=initial_message,
        associated_data=ad,
        **DRC
    )
    assert plaintext == b"initial"

    # Two skipped message keys under Alice's first ratchet public key
    skipped_old_pub = [
        await alice.encrypt_message(b"skipped old 1", ad),
        await alice.encrypt_message(b"skipped old 2", ad)
    ]
    assert await bob.decrypt_message(await alice.encrypt_message(b"in order 1", ad), ad) == b"in order 1"

    # A Diffie-Hellman ratchet step on both sides
    assert await alice.decrypt_message(await bob.encrypt_message(b"reply", ad), ad) == b"reply"

    # One skipped message key under Alice's new (current) ratchet public key
    skipped_current_pub = [await alice.encrypt_message(b"skipped current", ad)]
    assert await bob.decrypt_message(await alice.encrypt_message(b"in order 2", ad), ad) == b"in order 2"

    archive = bob.json

    # Sanity check the shape of the archive: skipped message keys under two distinct public keys, an
    # initialized receiving chain and a previous sending chain length.
    skipped_pubs = { smk["ratchet_pub"] for smk in archive["skipped_message_keys"] }
    assert len(archive["skipped_message_keys"]) == 3
    assert len(skipped_pubs) == 2
    assert archive["diffie_hellman_ratchet"]["symmetric_key_ratchet"]["receiving_chain"] is not None
    assert archive["diffie_hellman_ratchet"]["symmetric_key_ratchet"]["previous_sending_chain_length"] \
        is not None

    return alice, bob, ad, archive, skipped_old_pub, skipped_current_pub


async def _assert_original_instance_unchanged(alice: DoubleRatchet, bob: DoubleRatchet, ad: bytes) -> None:
    """
    Assert that the live instance an archive was exported from is still fully functional after a (failed)
    restoration attempt, i.e. that the attempt did not touch the original instance.
    """

    message = os.urandom(32)
    assert await bob.decrypt_message(await alice.encrypt_message(message, ad), ad) == message


async def _assert_rejected(
    archive: Dict[str, Any],
    exception_type: type,
    alice: DoubleRatchet,
    bob: DoubleRatchet,
    ad: bytes
) -> None:
    """
    Assert that restoring the (mutated) archive raises the expected exception, that the failed attempt
    modifies neither the archive nor the original live instance, without re-initializing the session.
    """

    archive_snapshot = copy.deepcopy(archive)
    try:
        DoubleRatchet.from_json(archive, **DRC)
        assert False, f"Restoring the mutated archive did not raise {exception_type}."
    except exception_type:
        pass
    assert archive == archive_snapshot
    await _assert_original_instance_unchanged(alice, bob, ad)


async def test_valid_archive_roundtrip_and_out_of_order_continuation() -> None:
    """
    A genuine archive exported from a real session must restore losslessly and continue the session,
    including out-of-order delivery of messages sent both before and after the export.
    """

    alice, _, ad, archive, skipped_old_pub, skipped_current_pub = await _build_archived_session()

    # The round-trip must be lossless
    bob = DoubleRatchet.from_json(archive, **DRC)
    assert bob.json == archive

    # Messages sent by Alice after the export, delivered out of order
    message_1 = await alice.encrypt_message(b"after export 1", ad)
    message_2 = await alice.encrypt_message(b"after export 2", ad)
    message_3 = await alice.encrypt_message(b"after export 3", ad)
    assert await bob.decrypt_message(message_3, ad) == b"after export 3"
    assert await bob.decrypt_message(message_1, ad) == b"after export 1"
    assert await bob.decrypt_message(message_2, ad) == b"after export 2"

    # Messages skipped before the export, decrypted from the restored skipped message keys
    assert await bob.decrypt_message(skipped_current_pub[0], ad) == b"skipped current"
    assert await bob.decrypt_message(skipped_old_pub[1], ad) == b"skipped old 2"
    assert await bob.decrypt_message(skipped_old_pub[0], ad) == b"skipped old 1"

    # The restored instance must also be able to send
    assert await alice.decrypt_message(await bob.encrypt_message(b"restored reply", ad), ad) \
        == b"restored reply"
    assert await bob.decrypt_message(await alice.encrypt_message(b"final", ad), ad) == b"final"


async def test_legitimate_initial_unreceived_state_is_accepted() -> None:
    """
    A state serialized before the first message was received (no receiving chain, no previous sending
    chain length, no skipped message keys) is legitimate and must not be confused with a corrupt state
    that is missing its receiving chain.
    """

    bob_ratchet_priv = X448PrivateKey.generate()
    shared_secret = os.urandom(32)
    ad = b"test_untrusted_state_restoration associated data"

    alice, initial_message = await DoubleRatchet.encrypt_initial_message(
        shared_secret=shared_secret,
        recipient_ratchet_pub=bob_ratchet_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ),
        message=b"initial",
        associated_data=ad,
        **DRC
    )

    # Alice has sent but not received a single message: no receiving chain, no previous sending chain
    # length, no skipped message keys.
    alice_archive = alice.json
    alice_skr = alice_archive["diffie_hellman_ratchet"]["symmetric_key_ratchet"]
    assert alice_skr["receiving_chain"] is None
    assert alice_skr["previous_sending_chain_length"] is None
    assert alice_archive["skipped_message_keys"] == []

    bob, _ = await DoubleRatchet.decrypt_initial_message(
        shared_secret=shared_secret,
        own_ratchet_priv=bob_ratchet_priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        message=initial_message,
        associated_data=ad,
        **DRC
    )

    # Bob has received a message, but never replaced his sending chain: no previous sending chain length.
    bob_archive = bob.json
    bob_skr = bob_archive["diffie_hellman_ratchet"]["symmetric_key_ratchet"]
    assert bob_skr["receiving_chain"] is not None
    assert bob_skr["previous_sending_chain_length"] is None

    alice = DoubleRatchet.from_json(alice_archive, **DRC)
    bob = DoubleRatchet.from_json(bob_archive, **DRC)

    # Both restored instances must be able to continue the session, including out-of-order delivery.
    assert await alice.decrypt_message(await bob.encrypt_message(b"first reply", ad), ad) == b"first reply"
    skipped = await alice.encrypt_message(b"skipped", ad)
    assert await bob.decrypt_message(await alice.encrypt_message(b"later", ad), ad) == b"later"
    assert await bob.decrypt_message(skipped, ad) == b"skipped"


async def test_negative_counters_are_rejected() -> None:
    """
    Negative chain lengths, previous sending chain lengths and skipped message key indices must be
    rejected, even though they are valid JSON integers.
    """

    alice, bob, ad, archive, _, _ = await _build_archived_session()

    for mutate in (
        lambda a: a["diffie_hellman_ratchet"]["root_chain"].update(length=-1),
        lambda a: a["diffie_hellman_ratchet"]["symmetric_key_ratchet"]["sending_chain"].update(length=-1),
        lambda a: a["diffie_hellman_ratchet"]["symmetric_key_ratchet"]["receiving_chain"].update(length=-1),
        lambda a: a["diffie_hellman_ratchet"]["symmetric_key_ratchet"].update(
            previous_sending_chain_length=-1
        ),
        lambda a: a["skipped_message_keys"][0].update(index=-1)
    ):
        mutated = copy.deepcopy(archive)
        mutate(mutated)
        await _assert_rejected(mutated, ValidationError, alice, bob, ad)


async def test_duplicate_skipped_message_keys_are_rejected() -> None:
    """
    Multiple skipped message keys for the same ratchet public key/index combination must be rejected
    instead of silently overwriting each other.
    """

    alice, bob, ad, archive, _, _ = await _build_archived_session()

    mutated = copy.deepcopy(archive)
    mutated["skipped_message_keys"].append(mutated["skipped_message_keys"][0].copy())

    # The mutation is type-correct: the pydantic model parses it without complaints.
    DoubleRatchetModel.model_validate(mutated)

    await _assert_rejected(mutated, InconsistentSerializationException, alice, bob, ad)


async def test_invalid_key_lengths_are_rejected() -> None:
    """
    Chain keys, message keys and Diffie-Hellman key material of the wrong length must be rejected, even
    though they are valid JSON strings/bytes.
    """

    alice, bob, ad, archive, _, _ = await _build_archived_session()

    # Skipped message keys always consist of 32 bytes; caught by the pydantic model.
    for message_key in ("x" * 31, "x" * 33):
        mutated = copy.deepcopy(archive)
        mutated["skipped_message_keys"][0]["message_key"] = message_key
        await _assert_rejected(mutated, ValidationError, alice, bob, ad)

    # Chain keys always consist of 32 bytes in this implementation; caught by the consistency checks.
    for chain_path, key in (
        (("diffie_hellman_ratchet", "root_chain"), "x" * 31),
        (("diffie_hellman_ratchet", "symmetric_key_ratchet", "sending_chain"), "x" * 31),
        (("diffie_hellman_ratchet", "symmetric_key_ratchet", "receiving_chain"), "x" * 33)
    ):
        mutated = copy.deepcopy(archive)
        section = mutated
        for element in chain_path:
            section = section[element]
        section["key"] = key
        await _assert_rejected(mutated, InconsistentSerializationException, alice, bob, ad)

    # Diffie-Hellman key material that can't be used for a key exchange (Curve448 keys are 56 bytes).
    for field in ("own_ratchet_priv", "other_ratchet_pub"):
        mutated = copy.deepcopy(archive)
        mutated["diffie_hellman_ratchet"][field] = "x" * 31
        await _assert_rejected(mutated, InconsistentSerializationException, alice, bob, ad)


async def test_missing_chains_are_rejected() -> None:
    """
    A missing sending chain, or a missing receiving chain in a state that requires one, must be rejected.
    """

    alice, bob, ad, archive, _, _ = await _build_archived_session()

    # The sending chain must always exist.
    mutated = copy.deepcopy(archive)
    mutated["diffie_hellman_ratchet"]["symmetric_key_ratchet"]["sending_chain"] = None
    await _assert_rejected(mutated, InconsistentSerializationException, alice, bob, ad)

    # A missing receiving chain contradicts the presence of skipped message keys.
    mutated = copy.deepcopy(archive)
    mutated["diffie_hellman_ratchet"]["symmetric_key_ratchet"]["receiving_chain"] = None
    mutated["diffie_hellman_ratchet"]["symmetric_key_ratchet"]["previous_sending_chain_length"] = None
    await _assert_rejected(mutated, InconsistentSerializationException, alice, bob, ad)

    # A missing receiving chain contradicts a previous sending chain length.
    mutated = copy.deepcopy(archive)
    mutated["diffie_hellman_ratchet"]["symmetric_key_ratchet"]["receiving_chain"] = None
    mutated["skipped_message_keys"] = []
    await _assert_rejected(mutated, InconsistentSerializationException, alice, bob, ad)


async def test_future_skipped_message_key_index_is_rejected() -> None:
    """
    A skipped message key stored under the current ratchet public key of the other party with an index
    that the receiving chain has not reached yet claims to belong to a message that has not been sent.
    Such "future keys" must be rejected.
    """

    alice, bob, ad, archive, _, _ = await _build_archived_session()
    dhr = archive["diffie_hellman_ratchet"]
    receiving_chain_length = dhr["symmetric_key_ratchet"]["receiving_chain"]["length"]
    other_ratchet_pub = dhr["other_ratchet_pub"]

    mutated = copy.deepcopy(archive)
    for skipped_message_key in mutated["skipped_message_keys"]:
        if skipped_message_key["ratchet_pub"] == other_ratchet_pub:
            skipped_message_key["index"] = receiving_chain_length + 3
            break
    else:
        assert False, "The archive does not contain a skipped message key under the current public key."

    # The mutation is type-correct: the pydantic model parses it without complaints.
    DoubleRatchetModel.model_validate(mutated)

    await _assert_rejected(mutated, InconsistentSerializationException, alice, bob, ad)


async def test_unknown_or_missing_version_is_rejected() -> None:
    """
    An unsupported version must be rejected with a clean error, and a missing version must not be
    mistaken for supported data.
    """

    alice, bob, ad, archive, _, _ = await _build_archived_session()

    mutated = copy.deepcopy(archive)
    mutated["version"] = "9.9.9"
    await _assert_rejected(mutated, ValueError, alice, bob, ad)

    # A missing version is treated as pre-stable data, which this archive is not.
    mutated = copy.deepcopy(archive)
    del mutated["version"]
    await _assert_rejected(mutated, ValidationError, alice, bob, ad)


async def test_defect_control_type_correct_but_inconsistent() -> None:
    """
    Defect control: archives whose fields are all individually type-correct (the pydantic model parses
    them) but whose cross-field relationships are inconsistent must still be rejected, via both
    :meth:`~doubleratchet.double_ratchet.DoubleRatchet.from_json` and
    :meth:`~doubleratchet.double_ratchet.DoubleRatchet.from_model`. If the library ever regresses to
    "restore whatever pydantic can parse", this test fails.
    """

    alice, bob, ad, archive, _, _ = await _build_archived_session()
    dhr = archive["diffie_hellman_ratchet"]
    receiving_chain_length = dhr["symmetric_key_ratchet"]["receiving_chain"]["length"]
    other_ratchet_pub = dhr["other_ratchet_pub"]

    mutations: List[Dict[str, Any]] = []

    # Duplicate ratchet public key/index combination
    mutated = copy.deepcopy(archive)
    mutated["skipped_message_keys"].append(mutated["skipped_message_keys"][0].copy())
    mutations.append(mutated)

    # Skipped message key index beyond the receiving chain length under the current public key
    mutated = copy.deepcopy(archive)
    for skipped_message_key in mutated["skipped_message_keys"]:
        if skipped_message_key["ratchet_pub"] == other_ratchet_pub:
            skipped_message_key["index"] = receiving_chain_length
            break
    mutations.append(mutated)

    # Skipped message keys without a receiving chain
    mutated = copy.deepcopy(archive)
    mutated["diffie_hellman_ratchet"]["symmetric_key_ratchet"]["receiving_chain"] = None
    mutated["diffie_hellman_ratchet"]["symmetric_key_ratchet"]["previous_sending_chain_length"] = None
    mutations.append(mutated)

    for mutated in mutations:
        # All fields are individually type-correct: the pydantic model parses the archive.
        model = DoubleRatchetModel.model_validate(mutated)

        # ...yet restoration must be rejected as inconsistent, via both public restoration APIs.
        try:
            DoubleRatchet.from_json(mutated, **DRC)
            assert False, "from_json restored a type-correct but inconsistent archive."
        except InconsistentSerializationException:
            pass

        try:
            DoubleRatchet.from_model(model, **DRC)
            assert False, "from_model restored a type-correct but inconsistent archive."
        except InconsistentSerializationException:
            pass

        await _assert_original_instance_unchanged(alice, bob, ad)
