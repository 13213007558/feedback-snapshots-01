"""
End-to-end, verifiable migration of a pre-stable Double Ratchet session.

This script is intentionally self-contained and prints no secret key material. It demonstrates the full
operational path that a service upgrading python-doubleratchet should follow:

1. Run a read-only preflight check on each pre-stable archive and refuse ambiguous/contradictory data.
2. Migrate on disk with an automatic backup; the original file is preserved on any failure.
3. Restore both peers and decrypt the retained, out-of-order messages that arrived before the upgrade.
4. Continue the conversation with fresh mutual replies after the upgrade.
5. Show that a replayed (duplicate) message is rejected after the upgrade.

Run it with the project virtualenv active::

    .venv/bin/python examples/migrate_session.py
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import shutil
import tempfile
from typing import Any, Dict, List, Tuple

from doubleratchet import (
    AuthenticationFailedException,
    DoubleRatchet as DR,
    DuplicateMessageException,
    EncryptedMessage,
    Header,
    MigrationError,
    migrate_json_file,
    preflight_check,
    redact_archive
)
from doubleratchet.recommended import (
    aead_aes_hmac,
    diffie_hellman_ratchet_curve25519 as dhr25519,
    HashFunction,
    kdf_hkdf
)


_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(_PROJECT_ROOT, "tests", "migration_data")
ASSOCIATED_DATA = "test_double_ratchet associated data".encode("ASCII")


class RootChainKDF(kdf_hkdf.KDF):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_256

    @staticmethod
    def _get_info() -> bytes:
        return "test_double_ratchet Root Chain KDF info".encode("ASCII")


class MessageChainKDF(kdf_hkdf.KDF):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512_256

    @staticmethod
    def _get_info() -> bytes:
        return "test_double_ratchet Message Chain KDF info".encode("ASCII")


class AEAD(aead_aes_hmac.AEAD):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return "test_double_ratchet AEAD info".encode("ASCII")


class DoubleRatchet(DR):
    @staticmethod
    def _build_associated_data(associated_data: bytes, header: Header) -> bytes:
        return (
            associated_data
            + header.ratchet_pub
            + header.sending_chain_length.to_bytes(8, "big")
            + header.previous_sending_chain_length.to_bytes(8, "big")
        )


DRC: Dict[str, Any] = {
    "diffie_hellman_ratchet_class": dhr25519.DiffieHellmanRatchet,
    "root_chain_kdf": RootChainKDF,
    "message_chain_kdf": MessageChainKDF,
    "message_chain_constant": "test_double_ratchet Message Chain constant".encode("ASCII"),
    "dos_protection_threshold": 10,
    "max_num_skipped_message_keys": 15,
    "aead": AEAD
}


def _load_skipped(name: str) -> List[Tuple[EncryptedMessage, bytes]]:
    with open(os.path.join(DATA_DIR, name), encoding="utf-8") as handle:
        raw = json.load(handle)
    messages: List[Tuple[EncryptedMessage, bytes]] = []
    for skipped_message, plaintext in raw:
        messages.append((
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
    return messages


def _stage(tmp: str, name: str) -> str:
    source = os.path.join(DATA_DIR, name)
    destination = os.path.join(tmp, name)
    shutil.copyfile(source, destination)
    return destination


async def main() -> None:
    workspace = tempfile.mkdtemp(prefix="dr-migration-demo-")
    print(f"Workspace: {workspace}\n")

    alice_path = _stage(workspace, "dr-alice-pre-stable.json")
    bob_path = _stage(workspace, "dr-bob-pre-stable.json")
    broken_path = _stage(workspace, "uninitialized-dr-pre-stable.json")

    # --- Step 1: read-only preflight ---------------------------------------------------------------
    print("== Step 1: read-only preflight ==")
    for label, path in (("Alice", alice_path), ("Bob", bob_path), ("Uninitialized", broken_path)):
        with open(path, encoding="utf-8") as handle:
            archive = json.load(handle)
        report = preflight_check(archive)
        print(f"{label:>13}: format={report.file_format} migratable={report.migratable}")
        print(f"               summary={json.dumps(report.summary, sort_keys=True)}")
        for error in report.errors:
            print(f"               ERROR: {error}")
    print("Redacted Alice archive (safe to log):")
    with open(alice_path, encoding="utf-8") as handle:
        print("   " + json.dumps(redact_archive(json.load(handle)))[:220] + " ...")
    print()

    # --- Step 2: migrate on disk, preserving the original on failure ------------------------------
    print("== Step 2: file migration with backup ==")
    migrated_paths: Dict[str, str] = {}
    for label, path in (("Alice", alice_path), ("Bob", bob_path)):
        result = migrate_json_file(path)
        migrated_paths[label] = result.output_path
        print(f"{label}: migrated -> {result.output_path}")
        print(f"        backup  -> {result.backup_path} (skipped keys preserved: "
              f"{result.report.summary['skipped_message_keys']})")

    original_bytes_before = open(broken_path, "rb").read()
    try:
        migrate_json_file(broken_path)
    except MigrationError as exc:
        print(f"Uninitialized: refused as expected -> {exc}")
    assert open(broken_path, "rb").read() == original_bytes_before, "original file must be untouched"
    assert not os.path.exists(broken_path + ".bak"), "no backup may be created on failure"
    print("Uninitialized: original file left byte-for-byte intact, no backup written.\n")

    # --- Step 3: restore and decrypt retained out-of-order messages -------------------------------
    print("== Step 3: decrypt retained out-of-order messages after upgrade ==")
    with open(migrated_paths["Alice"], encoding="utf-8") as handle:
        alice_dr = DoubleRatchet.from_json(json.load(handle), **DRC)
    with open(migrated_paths["Bob"], encoding="utf-8") as handle:
        bob_dr = DoubleRatchet.from_json(json.load(handle), **DRC)

    alice_backlog = _load_skipped("alice-skipped-messages-pre-stable.json")
    bob_backlog = _load_skipped("bob-skipped-messages-pre-stable.json")
    for encrypted_message, plaintext in alice_backlog:
        decrypted = await bob_dr.decrypt_message(encrypted_message, ASSOCIATED_DATA)
        assert decrypted == plaintext
    print(f"Bob decrypted {len(alice_backlog)} retained messages from Alice (out of order).")
    for encrypted_message, plaintext in bob_backlog:
        decrypted = await alice_dr.decrypt_message(encrypted_message, ASSOCIATED_DATA)
        assert decrypted == plaintext
    print(f"Alice decrypted {len(bob_backlog)} retained messages from Bob (out of order).")
    print(f"Remaining skipped keys -> Alice: {len(alice_dr.json['skipped_message_keys'])}, "
          f"Bob: {len(bob_dr.json['skipped_message_keys'])}\n")

    # --- Step 4: fresh mutual replies after the upgrade -------------------------------------------
    print("== Step 4: mutual replies after the upgrade ==")
    for round_index in range(3):
        a_to_b = f"post-upgrade Alice {round_index}".encode("ASCII")
        assert await bob_dr.decrypt_message(
            await alice_dr.encrypt_message(a_to_b, ASSOCIATED_DATA), ASSOCIATED_DATA
        ) == a_to_b
        b_to_a = f"post-upgrade Bob {round_index}".encode("ASCII")
        assert await alice_dr.decrypt_message(
            await bob_dr.encrypt_message(b_to_a, ASSOCIATED_DATA), ASSOCIATED_DATA
        ) == b_to_a
    print("Three fresh bidirectional rounds succeeded on the migrated ratchets.\n")

    # --- Step 5: duplicate messages are still rejected --------------------------------------------
    print("== Step 5: duplicate replay rejection ==")
    replayed, _ = alice_backlog[0]
    try:
        await bob_dr.decrypt_message(replayed, ASSOCIATED_DATA)
    except AuthenticationFailedException:
        print("Replaying an already consumed retained message is rejected (its skipped key was removed).")

    fresh = await alice_dr.encrypt_message(b"duplicate guard check", ASSOCIATED_DATA)
    await bob_dr.decrypt_message(fresh, ASSOCIATED_DATA)
    try:
        await bob_dr.decrypt_message(fresh, ASSOCIATED_DATA)
    except DuplicateMessageException:
        print("Replaying a fresh chain message raises DuplicateMessageException; the ratchet stays intact.")
    follow_up = b"still alive"
    assert await bob_dr.decrypt_message(
        await alice_dr.encrypt_message(follow_up, ASSOCIATED_DATA), ASSOCIATED_DATA
    ) == follow_up
    print("Conversation continues normally after the rejected replay.\n")

    print("All migration checks succeeded.")


if __name__ == "__main__":
    asyncio.run(main())
