"""
Fork risk demonstration for python-doubleratchet 1.3.0.

Scenario: one persisted Double Ratchet session is restored by TWO service
processes from the SAME snapshot. Both can produce ciphertext. This script shows
why "both can encrypt" is not evidence that horizontal scaling is safe, and
demonstrates a minimal generation/fence guard that blocks reuse of a stale
sending state.

The script never prints raw private keys, message keys, IVs or plaintexts from
the real session. It prints only short SHA-256 fingerprints, public header
numbers and exception types. A separate random *probe* key (not session
material) is used to illustrate the AEAD's deterministic IV behaviour.

Run with the repository's virtualenv:
    .venv/bin/python demo/fork_demo.py
"""

import asyncio
import copy
import hashlib
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey

from doubleratchet import DoubleRatchet as DR, Header
from doubleratchet.diffie_hellman_ratchet import (
    DuplicateMessageException,
)
from doubleratchet.recommended import (
    aead_aes_hmac,
    diffie_hellman_ratchet_curve448 as dhr448,
    HashFunction,
    kdf_hkdf,
    kdf_separate_hmacs,
)


AD = "service + peer".encode("ASCII")
SHARED_SECRET = b"0123456789abcdef0123456789abcdef"  # 32 bytes, demo only


class DoubleRatchet(DR):
    @staticmethod
    def _build_associated_data(associated_data: bytes, header: Header) -> bytes:
        return (
            associated_data
            + header.ratchet_pub
            + header.sending_chain_length.to_bytes(8, "big")
            + header.previous_sending_chain_length.to_bytes(8, "big")
        )


class AEAD(aead_aes_hmac.AEAD):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return b"fork-demo AEAD info"


class RootChainKDF(kdf_hkdf.KDF):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return b"fork-demo root chain KDF"


class MessageChainKDF(kdf_separate_hmacs.KDF):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512_256


DR_CONFIG = {
    "diffie_hellman_ratchet_class": dhr448.DiffieHellmanRatchet,
    "root_chain_kdf": RootChainKDF,
    "message_chain_kdf": MessageChainKDF,
    "message_chain_constant": b"\x01\x02",
    "dos_protection_threshold": 100,
    "max_num_skipped_message_keys": 1000,
    "aead": AEAD,
}


def fp(data: bytes) -> str:
    """Public, non-reversible fingerprint so secrets never appear in output."""
    return hashlib.sha256(data).hexdigest()[:12]


def state_fingerprint(dr_obj: DR) -> str:
    """Fingerprint over the FULL serialized state (incl. chain/message keys)."""
    import json

    return fp(json.dumps(dr_obj.json, sort_keys=True, separators=(",", ":")).encode())


def header_summary(header: Header) -> str:
    return (
        f"ratchet_pub={fp(header.ratchet_pub)} "
        f"prev_chain_len={header.previous_sending_chain_length} "
        f"send_chain_len(=msg_no N)={header.sending_chain_length}"
    )


def banner(title: str) -> None:
    print("\n" + "=" * 74)
    print(title)
    print("=" * 74)


async def establish_session():
    """One normal service-side (Alice) session and one normal peer (Bob)."""
    bob_ratchet_priv = X448PrivateKey.generate()
    bob_ratchet_pub = bob_ratchet_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    alice, initial = await DoubleRatchet.encrypt_initial_message(
        shared_secret=SHARED_SECRET,
        recipient_ratchet_pub=bob_ratchet_pub,
        message=b"(session bootstrap)",
        associated_data=AD,
        **DR_CONFIG,
    )
    bob, _ = await DoubleRatchet.decrypt_initial_message(
        shared_secret=SHARED_SECRET,
        own_ratchet_priv=bob_ratchet_priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        message=initial,
        associated_data=AD,
        **DR_CONFIG,
    )
    return alice, bob


def restore(snapshot, n):
    """Simulate n independent service processes each loading the same snapshot."""
    return [DoubleRatchet.from_json(copy.deepcopy(snapshot), **DR_CONFIG) for _ in range(n)]


async def try_decrypt(peer, encrypted, label):
    try:
        plaintext = await peer.decrypt_message(encrypted, AD)
        print(f"  [{label}] ACCEPTED, decrypted {len(plaintext)}B (content hidden), "
              f"peer recv_chain_len={peer.receiving_chain_length}")
        return True
    except DuplicateMessageException as exc:
        print(f"  [{label}] REJECTED -> DuplicateMessageException: {type(exc).__name__}")
        return False
    except Exception as exc:  # noqa: BLE001 - demo wants the concrete class name
        print(f"  [{label}] REJECTED -> {type(exc).__name__}: {exc}")
        return False


async def scenario_fork_identical_headers(alice):
    banner("SCENARIO 1: two processes restore the SAME snapshot and each send")
    snapshot = alice.json
    print(f"shared snapshot state fingerprint: {state_fingerprint(alice)}")
    proc_a, proc_b = restore(snapshot, 2)
    print(f"process A restored state:          {state_fingerprint(proc_a)}")
    print(f"process B restored state:          {state_fingerprint(proc_b)}")

    msg_a = await proc_a.encrypt_message(b"distinct payload from process A", AD)
    msg_b = await proc_b.encrypt_message(b"distinct payload from process B", AD)

    print("\npublic header carried by A's message:")
    print("  " + header_summary(msg_a.header))
    print("public header carried by B's message:")
    print("  " + header_summary(msg_b.header))
    same_header = (
        msg_a.header.ratchet_pub == msg_b.header.ratchet_pub
        and msg_a.header.sending_chain_length == msg_b.header.sending_chain_length
        and msg_a.header.previous_sending_chain_length
        == msg_b.header.previous_sending_chain_length
    )
    print(f"\nidentical public header? {same_header}")
    print(f"ciphertext fingerprint A: {fp(msg_a.ciphertext)}")
    print(f"ciphertext fingerprint B: {fp(msg_b.ciphertext)}")
    print("ciphertexts differ ONLY because plaintexts differ; header (hence message")
    print("number and ratchet key) is identical, so both used the SAME message key.")
    print(f"\nstate after sending -> A: {state_fingerprint(proc_a)}")
    print(f"state after sending -> B: {state_fingerprint(proc_b)}")
    print("the two states are byte-identical again after the step: the fork is")
    print("invisible to the library, nothing marks one copy as the 'real' writer.")
    return msg_a, msg_b


async def scenario_receiver_conflict(bob_factory, msg_a, msg_b):
    banner("SCENARIO 2: a single normal peer consumes the forked messages")
    for order_name, first, second in (
        ("order A-then-B", msg_a, msg_b),
        ("order B-then-A", msg_b, msg_a),
    ):
        peer = bob_factory()
        print(f"\n-- {order_name} (fresh peer, identical starting state) --")
        ok1 = await try_decrypt(peer, first, "1st")
        await try_decrypt(peer, second, "2nd")
        print(f"  surviving peer recv_chain_len={peer.receiving_chain_length}; "
              f"one payload is silently unrecoverable regardless of order: {ok1}")


async def scenario_single_writer_and_skipping():
    banner("SCENARIO 3: single-writer baseline vs. cross-process collision")
    alice, bob = await establish_session()

    def bob_factory():
        return DoubleRatchet.from_json(copy.deepcopy(bob.json), **DR_CONFIG)

    # Align the peer with one normally delivered message before the experiment.
    aligned_peer = bob_factory()
    await try_decrypt(aligned_peer, await alice.encrypt_message(b"alignment msg", AD), "align")

    m0 = await alice.encrypt_message(b"single-writer msg 0", AD)
    m1 = await alice.encrypt_message(b"single-writer msg 1", AD)
    print("\nheaders from ONE process advance the message number deterministically:")
    print("  m0 " + header_summary(m0.header))
    print("  m1 " + header_summary(m1.header))

    print("\nout-of-order delivery (m1 then m0) is tolerated via skipped message keys:")
    await try_decrypt(aligned_peer, m1, "m1 1st")
    await try_decrypt(aligned_peer, m0, "m0 2nd")

    # Fork from the current sending state; both derive the next identical number.
    snapshot = alice.json
    ghost, = restore(snapshot, 1)
    m_real = await alice.encrypt_message(b"legitimate next message", AD)
    m_fork = await ghost.encrypt_message(b"forked reuse of current sending state", AD)
    print("\nlegitimate header: " + header_summary(m_real.header))
    print("forked ghost:      " + header_summary(m_fork.header))
    print("same (ratchet_pub, message number) -> only one can be accepted:")
    collision_peer = bob_factory()
    await try_decrypt(collision_peer, m_real, "legit 1st")
    await try_decrypt(collision_peer, m_fork, "ghost 2nd")


async def scenario_deterministic_iv_probe():
    banner("SCENARIO 4: deterministic (key, IV) reuse probe (random probe key)")
    probe_key = os.urandom(32)
    print(f"probe key is freshly generated and unrelated to any session: {fp(probe_key)}")
    p1 = b"common-prefix-payload-aaaaaaaa"
    p2 = b"common-prefix-payload-BBBBBBBB"
    c1 = await AEAD.encrypt(p1, probe_key, b"probe-ad")
    c2 = await AEAD.encrypt(p2, probe_key, b"probe-ad")
    block = 16
    print(f"first AES block ciphertext #1: {fp(c1[:block])}")
    print(f"first AES block ciphertext #2: {fp(c2[:block])}")
    print(
        "same first block despite different plaintexts: IV is derived from the",
    )
    print("message key, not random. Two forked messages share the message key, so")
    print("they reuse (key, IV): CBC two-time-pad / key-reuse, not a safe nonce.")


class GenerationStore:
    """
    Minimal external persistence guard. The library only serializes state; it
    cannot prove which writer owns the current sending state. That fact must be
    enforced by the storage layer using a generation/fence with compare-and-set.
    """

    def __init__(self, snapshot):
        self._record = {"generation": 1, "state": copy.deepcopy(snapshot)}

    def lease(self):
        return self._record["generation"], copy.deepcopy(self._record["state"])

    def compare_and_swap(self, expected_generation, new_state):
        current = self._record["generation"]
        if current != expected_generation:
            return False, current
        self._record = {
            "generation": current + 1,
            "state": copy.deepcopy(new_state),
        }
        return True, self._record["generation"]

    @property
    def generation(self):
        return self._record["generation"]


async def scenario_fenced_deployment():
    banner("SCENARIO 5: minimal integration - generation fence blocks stale send")
    alice, bob = await establish_session()

    def bob_factory():
        return DoubleRatchet.from_json(copy.deepcopy(bob.json), **DR_CONFIG)

    store = GenerationStore(alice.json)

    gen_a, state_a = store.lease()
    gen_b, state_b = store.lease()
    print(f"both processes initially lease generation {gen_a} from the same record")

    proc_a = DoubleRatchet.from_json(state_a, **DR_CONFIG)
    proc_b = DoubleRatchet.from_json(state_b, **DR_CONFIG)
    enc_a = await proc_a.encrypt_message(b"writer A payload", AD)

    saved, new_gen = store.compare_and_swap(gen_a, proc_a.json)
    print(f"\nwriter A CAS expected_gen={gen_a}: committed={saved}, new generation={new_gen}")

    enc_b = await proc_b.encrypt_message(b"stale writer B payload", AD)
    saved_b, cur_gen = store.compare_and_swap(gen_b, proc_b.json)
    print(f"writer B CAS expected_gen={gen_b}: committed={saved_b} "
          f"(store already at generation {cur_gen})")
    print("writer B is fenced off BEFORE its message reaches the peer; its sending")
    print("state is discarded and it must re-lease the current state before retrying.")

    peer = bob_factory()
    print("\nonly the committed writer's message is delivered:")
    await try_decrypt(peer, enc_a, "committed A")

    gen_b2, state_b2 = store.lease()
    proc_b = DoubleRatchet.from_json(state_b2, **DR_CONFIG)
    enc_b2 = await proc_b.encrypt_message(b"writer B after re-lease", AD)
    saved_b2, _ = store.compare_and_swap(gen_b2, proc_b.json)
    print(f"\nwriter B re-leases generation {gen_b2}, CAS committed={saved_b2}")
    print("re-leased header: " + header_summary(enc_b2.header))
    await try_decrypt(peer, enc_b2, "re-leased B")


async def main():
    alice, bob = await establish_session()

    def fresh_peer():
        return DoubleRatchet.from_json(copy.deepcopy(bob.json), **DR_CONFIG)

    msg_a, msg_b = await scenario_fork_identical_headers(alice)
    await scenario_receiver_conflict(fresh_peer, msg_a, msg_b)
    await scenario_single_writer_and_skipping()
    await scenario_deterministic_iv_probe()
    await scenario_fenced_deployment()

    banner("SUMMARY")
    print("1) Both forked processes emit ciphertext, but with identical headers and")
    print("   message numbers - 'can encrypt' proves nothing about safety.")
    print("2) The peer accepts exactly one message per (ratchet_pub, message number);")
    print("   the other raises DuplicateMessageException, in either delivery order.")
    print("3) In-order/out-of-order works only under a single advancing sending chain.")
    print("4) The AEAD derives the IV from the message key deterministically, so key")
    print("   reuse is (key, IV) reuse (CBC two-time-pad), not harmless duplication.")
    print("5) The library cannot prove persistence facts (single writer, atomic load/")
    print("   store, fencing). A generation compare-and-set in storage is the minimal")
    print("   control that blocks reuse of a stale sending state.")


if __name__ == "__main__":
    asyncio.run(main())
