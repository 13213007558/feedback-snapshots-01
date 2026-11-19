import asyncio
import itertools
from typing import Any, Dict, List, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from doubleratchet import (
    AuthenticationFailedException,
    DoubleRatchet as DR,
    EncryptedMessage,
    Header
)
from doubleratchet.associated_data import (
    AssociatedDataError,
    Direction,
    SessionContext,
    build_associated_data,
    decode_associated_data,
    encode_associated_data,
    encode_session_context
)
from doubleratchet.recommended import (
    aead_aes_hmac,
    diffie_hellman_ratchet_curve448,
    HashFunction,
    kdf_hkdf,
    kdf_separate_hmacs
)


class RootChainKDF(kdf_hkdf.KDF):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_256

    @staticmethod
    def _get_info() -> bytes:
        return "test_associated_data Root Chain KDF".encode("ASCII")


class MessageChainKDF(kdf_separate_hmacs.KDF):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512_256


class AEAD(aead_aes_hmac.AEAD):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return "test_associated_data AEAD".encode("ASCII")


class CanonicalDoubleRatchet(DR):
    """
    A Double Ratchet using the canonical associated data contract from :mod:`doubleratchet.associated_data`.
    """

    @staticmethod
    def _build_associated_data(associated_data: bytes, header: Header) -> bytes:
        return build_associated_data(associated_data, header)


class PreviousChainUnboundDoubleRatchet(DR):
    """
    A deliberately incomplete subclass that authenticates the ratchet public key and chain length, but not
    the previous sending chain length. The library accepts this subclass, so the missing binding is a caller
    mistake, not a library error.
    """

    @staticmethod
    def _build_associated_data(associated_data: bytes, header: Header) -> bytes:
        return (
            associated_data
            + b"\x00"
            + header.ratchet_pub
            + header.sending_chain_length.to_bytes(8, "big")
        )


CAPTURED_HEADER = Header(bytes(range(0x11, 0x31)), 3, 7)

CONFIGURATION: Dict[str, Any] = {
    "diffie_hellman_ratchet_class": diffie_hellman_ratchet_curve448.DiffieHellmanRatchet,
    "root_chain_kdf": RootChainKDF,
    "message_chain_kdf": MessageChainKDF,
    "message_chain_constant": b"\x01\x02",
    "dos_protection_threshold": 10,
    "max_num_skipped_message_keys": 15,
    "aead": AEAD
}


def context(session_id: bytes, initiator: bytes = b"alice", responder: bytes = b"bob") -> SessionContext:
    return SessionContext(session_id=session_id, initiator=initiator, responder=responder)


async def create_pair(
    double_ratchet_class: Any = CanonicalDoubleRatchet
) -> Tuple[DR, DR]:
    bob_private = X448PrivateKey.generate()
    bob_public = bob_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    shared_secret = b"k" * 32
    alice_to_bob = encode_associated_data(
        context(b"acme/group/1"),
        Direction.INITIATOR_TO_RESPONDER,
        b"hello"
    )

    alice, initial_message = await double_ratchet_class.encrypt_initial_message(
        shared_secret=shared_secret,
        recipient_ratchet_pub=bob_public,
        message=b"hello",
        associated_data=alice_to_bob,
        **CONFIGURATION
    )
    bob, plaintext = await double_ratchet_class.decrypt_initial_message(
        shared_secret=shared_secret,
        own_ratchet_priv=bob_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        message=initial_message,
        associated_data=alice_to_bob,
        **CONFIGURATION
    )
    assert plaintext == b"hello"

    return alice, bob


async def make_alice_ratchet(alice: DR, bob: DR) -> None:
    associated_data = encode_associated_data(
        context(b"acme/group/1"),
        Direction.RESPONDER_TO_INITIATOR,
        b"reply"
    )
    message = await bob.encrypt_message(b"reply", associated_data)
    assert await alice.decrypt_message(message, associated_data) == b"reply"


def test_encoding_vector() -> None:
    alice_context = context(b"acme/room/1", b"2alice", b"bob")
    encoded = encode_associated_data(
        alice_context,
        Direction.INITIATOR_TO_RESPONDER,
        b"hi"
    )
    associated_data = build_associated_data(encoded, CAPTURED_HEADER)

    assert associated_data.hex() == (
        "0000007a44522d4141440100010000003944522d414442010000002744522d435458010000000b"
        "61636d652f726f6f6d2f310000000632616c69636500000003626f6200000000026869000000"
        "201112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30000000000000"
        "00030000000000000007"
    )

    decoded = decode_associated_data(associated_data)
    assert decoded.context == alice_context
    assert decoded.direction is Direction.INITIATOR_TO_RESPONDER
    assert decoded.application_data == b"hi"
    assert decoded.header == CAPTURED_HEADER
    assert decoded.suite == 1


def test_confusable_sessions_have_distinct_associated_data() -> None:
    # Under naive concatenation these two sessions hash the same associated data:
    #   b"acme/room/1" + b"2alice" + b"hi" == b"acme/room/12" + b"alice" + b"hi"
    first = context(b"acme/room/1", b"2alice", b"bob")
    second = context(b"acme/room/12", b"alice", b"bob")

    first_bytes = encode_associated_data(first, Direction.INITIATOR_TO_RESPONDER, b"hi")
    second_bytes = encode_associated_data(second, Direction.INITIATOR_TO_RESPONDER, b"hi")

    assert first_bytes != second_bytes
    assert len(first_bytes) == len(second_bytes)

    first_associated_data = build_associated_data(first_bytes, CAPTURED_HEADER)
    second_associated_data = build_associated_data(second_bytes, CAPTURED_HEADER)
    assert first_associated_data != second_associated_data


def test_session_context_encoding_is_injective() -> None:
    fragments = [b"a", b"ab", b"abc"]
    encodings = {
        encode_session_context(SessionContext(session_id, initiator, responder))
        for session_id, initiator, responder in itertools.product(fragments, repeat=3)
    }
    assert len(encodings) == len(fragments) ** 3

    # Empty identifiers are rejected instead of shifting bytes between fields.
    for position in range(3):
        fields = [b"a", b"b", b"c"]
        fields[position] = b""
        try:
            encode_session_context(SessionContext(*fields))
            assert False
        except AssociatedDataError:
            pass


def test_naive_concatenation_collision_reaches_the_aead() -> None:
    async def run() -> None:
        # The two business contexts are different, but the naive concatenation is identical.
        first = b"acme/room/1" + b"2alice" + b"hi"
        second = b"acme/room/12" + b"alice" + b"hi"
        assert first == second

        key = bytes(range(32))
        ciphertext = await AEAD.encrypt(b"payload", key, first)

        # The same ciphertext authenticates under both labels, because the AEAD never saw a boundary.
        assert await AEAD.decrypt(ciphertext, key, second) == b"payload"

        # The canonical encoding turns the two contexts into different authentication inputs.
        canonical_first = encode_associated_data(
            context(b"acme/room/1", b"2alice"),
            Direction.INITIATOR_TO_RESPONDER,
            b"hi"
        )
        canonical_second = encode_associated_data(
            context(b"acme/room/12", b"alice"),
            Direction.INITIATOR_TO_RESPONDER,
            b"hi"
        )
        ciphertext = await AEAD.encrypt(b"payload", key, canonical_first)
        try:
            await AEAD.decrypt(ciphertext, key, canonical_second)
            assert False
        except AuthenticationFailedException:
            pass

    asyncio.run(run())


def test_all_header_fields_are_authenticated() -> None:
    encoded = encode_associated_data(
        context(b"acme/room/1"),
        Direction.INITIATOR_TO_RESPONDER,
        b"hi"
    )
    reference = build_associated_data(encoded, CAPTURED_HEADER)

    candidates: List[Header] = [
        CAPTURED_HEADER._replace(ratchet_pub=bytes(range(0x12, 0x32))),
        CAPTURED_HEADER._replace(ratchet_pub=CAPTURED_HEADER.ratchet_pub[:-1]),
        CAPTURED_HEADER._replace(previous_sending_chain_length=4),
        CAPTURED_HEADER._replace(sending_chain_length=8)
    ]
    for candidate in candidates:
        assert build_associated_data(encoded, candidate) != reference


def test_build_rejects_non_canonical_associated_data() -> None:
    encoded = encode_associated_data(
        context(b"acme/room/1"),
        Direction.INITIATOR_TO_RESPONDER,
        b"hi"
    )
    for invalid in [b"", b"ctx", encoded + b"\x00"]:
        try:
            build_associated_data(invalid, CAPTURED_HEADER)
            assert False
        except AssociatedDataError:
            pass


def test_application_data_is_authenticated_end_to_end() -> None:
    async def run() -> None:
        alice, bob = await create_pair()
        alice_context = context(b"acme/group/1")
        correct = encode_associated_data(alice_context, Direction.INITIATOR_TO_RESPONDER, b"topic=a")
        message = await alice.encrypt_message(b"payload", correct)

        wrong_values = [
            encode_associated_data(alice_context, Direction.INITIATOR_TO_RESPONDER, b"topic=b"),
            encode_associated_data(context(b"acme/group/2"), Direction.INITIATOR_TO_RESPONDER, b"topic=a"),
            encode_associated_data(
                context(b"acme/group/1", b"bob", b"alice"),
                Direction.INITIATOR_TO_RESPONDER,
                b"topic=a"
            ),
            encode_associated_data(alice_context, Direction.RESPONDER_TO_INITIATOR, b"topic=a"),
            b"acme/group/1alicebobtopic=a"
        ]
        for wrong in wrong_values:
            try:
                await bob.decrypt_message(message, wrong)
                assert False
            except (AuthenticationFailedException, AssociatedDataError):
                pass

        # Failed attempts must not consume the message key.
        assert await bob.decrypt_message(message, correct) == b"payload"

    asyncio.run(run())


def test_direction_and_session_are_bound_end_to_end() -> None:
    async def run() -> None:
        alice, bob = await create_pair()
        alice_context = context(b"acme/group/1")
        correct = encode_associated_data(alice_context, Direction.INITIATOR_TO_RESPONDER, b"payload")
        message = await alice.encrypt_message(b"payload", correct)

        # Reflecting the message back to Alice must fail: the direction field is authenticated.
        try:
            await alice.decrypt_message(message, correct)
            assert False
        except AuthenticationFailedException:
            pass

        # The same message under a different session identifier must fail as well.
        try:
            await bob.decrypt_message(
                message,
                encode_associated_data(
                    context(b"acme/group/2"),
                    Direction.INITIATOR_TO_RESPONDER,
                    b"payload"
                )
            )
            assert False
        except AuthenticationFailedException:
            pass

        assert await bob.decrypt_message(message, correct) == b"payload"

    asyncio.run(run())


def test_previous_chain_length_must_be_explicitly_bound() -> None:
    async def run() -> None:
        for double_ratchet_class, tampering_accepted in [
            (CanonicalDoubleRatchet, False),
            (PreviousChainUnboundDoubleRatchet, True)
        ]:
            alice, bob = await create_pair(double_ratchet_class)
            alice_context = context(b"acme/group/1")
            alice_to_bob = encode_associated_data(
                alice_context,
                Direction.INITIATOR_TO_RESPONDER,
                b"chain"
            )

            # Alice's sending chain already contains the initial message, then three more messages. Bob
            # receives only the first of the three.
            old_messages = [await alice.encrypt_message(f"old-{index}".encode(), alice_to_bob)
                            for index in range(3)]
            assert await bob.decrypt_message(old_messages[0], alice_to_bob) == b"old-0"

            # Alice receives one message and ratchets, so the new header reports all four messages sent on
            # the previous chain.
            await make_alice_ratchet(alice, bob)
            new_message = await alice.encrypt_message(b"new", alice_to_bob)
            assert new_message.header.previous_sending_chain_length == 4
            assert new_message.header.sending_chain_length == 0

            tampered = EncryptedMessage(
                header=new_message.header._replace(previous_sending_chain_length=0),
                ciphertext=new_message.ciphertext
            )
            if tampering_accepted:
                # The subclass never put the previous chain length into the AEAD input, so the changed value
                # is invisible to authentication. Bob cannot recover the two messages that were skipped on
                # Alice's previous chain.
                assert await bob.decrypt_message(tampered, alice_to_bob) == b"new"
                for lost in old_messages[1:]:
                    try:
                        await bob.decrypt_message(lost, alice_to_bob)
                        assert False
                    except AuthenticationFailedException:
                        pass
            else:
                try:
                    await bob.decrypt_message(tampered, alice_to_bob)
                    assert False
                except AuthenticationFailedException:
                    pass

                # The genuine message still decrypts, and the skipped messages remain recoverable.
                assert await bob.decrypt_message(new_message, alice_to_bob) == b"new"
                assert await bob.decrypt_message(old_messages[1], alice_to_bob) == b"old-1"
                assert await bob.decrypt_message(old_messages[2], alice_to_bob) == b"old-2"

    asyncio.run(run())


def test_header_tampering_is_rejected_end_to_end() -> None:
    async def run() -> None:
        alice, bob = await create_pair()
        await make_alice_ratchet(alice, bob)

        alice_context = context(b"acme/group/1")
        correct = encode_associated_data(alice_context, Direction.INITIATOR_TO_RESPONDER, b"payload")
        first = await alice.encrypt_message(b"first", correct)
        message = await alice.encrypt_message(b"payload", correct)
        assert first.header.sending_chain_length == 0
        assert message.header.sending_chain_length == 1

        candidates: List[Header] = [
            message.header._replace(
                previous_sending_chain_length=message.header.previous_sending_chain_length + 1
            ),
            message.header._replace(
                sending_chain_length=message.header.sending_chain_length + 1
            ),
            message.header._replace(
                sending_chain_length=message.header.sending_chain_length - 1
            )
        ]
        for header in candidates:
            try:
                await bob.decrypt_message(
                    EncryptedMessage(header=header, ciphertext=message.ciphertext),
                    correct
                )
                assert False
            except AuthenticationFailedException:
                pass

        # The original messages must still decrypt, proving that no failed attempt advanced the ratchet.
        assert await bob.decrypt_message(first, correct) == b"first"
        assert await bob.decrypt_message(message, correct) == b"payload"

    asyncio.run(run())


def test_outer_length_prefix_makes_associated_data_self_delimiting() -> None:
    first = build_associated_data(
        encode_associated_data(context(b"acme/room/1"), Direction.INITIATOR_TO_RESPONDER, b"hi"),
        CAPTURED_HEADER
    )
    second = build_associated_data(
        encode_associated_data(context(b"acme/room/12"), Direction.INITIATOR_TO_RESPONDER, b"hi"),
        CAPTURED_HEADER
    )

    # Neither value can be extended to equal the other by moving a suffix into the AEAD's ciphertext input.
    assert int.from_bytes(first[:4], "big") == len(first) - 4
    assert int.from_bytes(second[:4], "big") == len(second) - 4
    assert first[:4] != second[:4]
