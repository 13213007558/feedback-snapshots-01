import base64
import copy
import json
import os
from typing import Any, Dict, List, Tuple

from doubleratchet import (
    AuthenticationFailedException,
    DoubleRatchet as DR,
    DuplicateMessageException,
    EncryptedMessage,
    Header,
    InconsistentSerializationException,
    MigrationError,
    PRE_STABLE,
    STABLE,
    UNKNOWN_FORMAT,
    detect_format,
    migrate_json,
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


__all__ = [
    "test_preflight_classification",
    "test_lossless_migration_and_skipped_messages",
    "test_post_upgrade_mutual_conversation",
    "test_duplicate_rejected_after_upgrade",
    "test_contradictory_and_ambiguous_archives_rejected",
    "test_no_random_key_substitution",
    "test_file_migration_preserves_original_on_failure",
    "test_redaction_hides_all_secrets"
]


try:
    import pytest
except ImportError:
    pytest = None  # type: ignore[assignment]


MIGRATION_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "migration_data")


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

ASSOCIATED_DATA = "test_double_ratchet associated data".encode("ASCII")


def _load(name: str) -> Any:
    with open(os.path.join(MIGRATION_DATA_DIR, name), encoding="utf-8") as handle:
        return json.load(handle)


def _load_skipped(name: str) -> List[Tuple[EncryptedMessage, bytes]]:
    messages: List[Tuple[EncryptedMessage, bytes]] = []
    for skipped_message, plaintext in _load(name):
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


def _all_secret_strings(archive: Any) -> List[str]:
    """Collect every pre-stable secret value (priv/chain keys/message keys) for leakage assertions."""

    secrets: List[str] = []
    dhr = archive["super"]
    skr = archive["skr"]
    if dhr["own_key"]["priv"] is not None:
        secrets.append(dhr["own_key"]["priv"])
    for chain in (dhr["root_chain"], skr["schain"], skr["rchain"]):
        if chain is not None:
            secrets.append(chain["key"])
    secrets.extend(archive["smks"].values())
    return secrets


def test_preflight_classification() -> None:
    alice = _load("dr-alice-pre-stable.json")
    assert detect_format(alice) == PRE_STABLE

    report = preflight_check(alice)
    assert report.file_format == PRE_STABLE
    assert report.migratable is True
    assert report.needs_migration is True
    assert report.errors == []
    # The summary reports structure, never key material.
    assert report.summary["skipped_message_keys"] == 4
    assert report.summary["has_sending_chain"] is True
    assert report.summary["has_receiving_chain"] is True

    migrated, _ = migrate_json(copy.deepcopy(alice))
    assert detect_format(migrated) == STABLE
    stable_report = preflight_check(migrated)
    assert stable_report.migratable is True
    assert stable_report.needs_migration is False

    assert detect_format({"version": "9.9.9"}) == UNKNOWN_FORMAT
    assert detect_format(["not", "an", "object"]) == UNKNOWN_FORMAT
    assert detect_format({"super": 1, "skr": 2, "ad": 3, "smks": 4, "rogue": 5}) == UNKNOWN_FORMAT


@pytest.mark.asyncio
async def test_lossless_migration_and_skipped_messages() -> None:
    alice = _load("dr-alice-pre-stable.json")
    bob = _load("dr-bob-pre-stable.json")
    alice_skipped = _load_skipped("alice-skipped-messages-pre-stable.json")
    bob_skipped = _load_skipped("bob-skipped-messages-pre-stable.json")

    # Success criteria: every skipped message key, chain length and counter survives the translation.
    alice_migrated, alice_report = migrate_json(copy.deepcopy(alice))
    bob_migrated, bob_report = migrate_json(copy.deepcopy(bob))
    assert len(alice_migrated["skipped_message_keys"]) == alice_report.summary["skipped_message_keys"] == 4
    assert len(bob_migrated["skipped_message_keys"]) == bob_report.summary["skipped_message_keys"] == 4

    # Restore via the public, migrating API and confirm it equals a direct migration.
    alice_dr = DoubleRatchet.from_json(alice_migrated, **DRC)
    bob_dr = DoubleRatchet.from_json(bob_migrated, **DRC)

    # The retained, out-of-order messages decrypt to their exact original plaintexts, on both peers.
    for encrypted_message, plaintext in alice_skipped:
        assert await bob_dr.decrypt_message(encrypted_message, ASSOCIATED_DATA) == plaintext
    for encrypted_message, plaintext in bob_skipped:
        assert await alice_dr.decrypt_message(encrypted_message, ASSOCIATED_DATA) == plaintext

    # After consuming all skipped keys, none remain (state advanced cleanly, no phantom keys).
    assert alice_dr.json["skipped_message_keys"] == []
    assert bob_dr.json["skipped_message_keys"] == []


@pytest.mark.asyncio
async def test_post_upgrade_mutual_conversation() -> None:
    alice_dr = DoubleRatchet.from_json(migrate_json(_load("dr-alice-pre-stable.json"))[0], **DRC)
    bob_dr = DoubleRatchet.from_json(migrate_json(_load("dr-bob-pre-stable.json"))[0], **DRC)

    # Drain the retained out-of-order backlog first, exactly as a real upgrade would.
    for encrypted_message, plaintext in _load_skipped("alice-skipped-messages-pre-stable.json"):
        assert await bob_dr.decrypt_message(encrypted_message, ASSOCIATED_DATA) == plaintext
    for encrypted_message, plaintext in _load_skipped("bob-skipped-messages-pre-stable.json"):
        assert await alice_dr.decrypt_message(encrypted_message, ASSOCIATED_DATA) == plaintext

    # Fresh, post-upgrade messages flow both ways across several ratchet steps.
    for round_index in range(5):
        a_to_b = f"alice message {round_index}".encode("ASCII")
        assert await bob_dr.decrypt_message(
            await alice_dr.encrypt_message(a_to_b, ASSOCIATED_DATA), ASSOCIATED_DATA
        ) == a_to_b
        b_to_a = f"bob reply {round_index}".encode("ASCII")
        assert await alice_dr.decrypt_message(
            await bob_dr.encrypt_message(b_to_a, ASSOCIATED_DATA), ASSOCIATED_DATA
        ) == b_to_a

    # Serialize the upgraded ratchets once more and confirm a round-trip keeps the conversation alive.
    alice_dr = DoubleRatchet.from_json(alice_dr.json, **DRC)
    bob_dr = DoubleRatchet.from_json(bob_dr.json, **DRC)
    final_message = b"post round-trip message"
    assert await bob_dr.decrypt_message(
        await alice_dr.encrypt_message(final_message, ASSOCIATED_DATA), ASSOCIATED_DATA
    ) == final_message


@pytest.mark.asyncio
async def test_duplicate_rejected_after_upgrade() -> None:
    alice_dr = DoubleRatchet.from_json(migrate_json(_load("dr-alice-pre-stable.json"))[0], **DRC)
    bob_dr = DoubleRatchet.from_json(migrate_json(_load("dr-bob-pre-stable.json"))[0], **DRC)

    # Drain the retained out-of-order backlog first, exactly as a real upgrade would.
    for encrypted_message, plaintext in _load_skipped("alice-skipped-messages-pre-stable.json"):
        assert await bob_dr.decrypt_message(encrypted_message, ASSOCIATED_DATA) == plaintext
    for encrypted_message, plaintext in _load_skipped("bob-skipped-messages-pre-stable.json"):
        assert await alice_dr.decrypt_message(encrypted_message, ASSOCIATED_DATA) == plaintext

    # A retained message key is single-use: replaying an already consumed out-of-order message cannot decrypt
    # again after the upgrade (its skipped key was removed on first use).
    consumed_message, _ = _load_skipped("alice-skipped-messages-pre-stable.json")[0]
    with pytest.raises(AuthenticationFailedException):
        await bob_dr.decrypt_message(consumed_message, ASSOCIATED_DATA)

    # On a live chain, the in-spec duplicate guard rejects a replayed message with DuplicateMessageException
    # and leaves the ratchet intact.
    fresh_message = await alice_dr.encrypt_message(b"fresh after upgrade", ASSOCIATED_DATA)
    assert await bob_dr.decrypt_message(fresh_message, ASSOCIATED_DATA) == b"fresh after upgrade"
    with pytest.raises(DuplicateMessageException):
        await bob_dr.decrypt_message(fresh_message, ASSOCIATED_DATA)

    # The ratchet is undamaged by the rejected replay and still exchanges fresh messages.
    follow_up = b"after replay"
    assert await bob_dr.decrypt_message(
        await alice_dr.encrypt_message(follow_up, ASSOCIATED_DATA), ASSOCIATED_DATA
    ) == follow_up


def test_contradictory_and_ambiguous_archives_rejected() -> None:
    alice = _load("dr-alice-pre-stable.json")

    # 1) Missing own private key: cannot be reconstructed, must fail rather than be filled randomly.
    missing_priv = copy.deepcopy(alice)
    missing_priv["super"]["own_key"]["priv"] = None
    assert preflight_check(missing_priv).migratable is False
    with pytest.raises(MigrationError):
        migrate_json(missing_priv)
    with pytest.raises(InconsistentSerializationException):
        DoubleRatchet.from_json(missing_priv, **DRC)

    # 2) Contradictory key pair: stored public key does not match the private key.
    contradictory = copy.deepcopy(alice)
    bob = _load("dr-bob-pre-stable.json")
    contradictory["super"]["own_key"]["pub"] = bob["super"]["own_key"]["pub"]
    report = preflight_check(contradictory)
    assert report.migratable is False
    assert any("does not match" in error for error in report.errors)

    # 3) Unknown/ambiguous version string.
    unknown_version = migrate_json(copy.deepcopy(alice))[0]
    unknown_version["version"] = "7.0.0"
    assert preflight_check(unknown_version).migratable is False

    # 4) Unknown top-level field: an unrecognized serializer, not safe to assume.
    rogue = copy.deepcopy(alice)
    rogue["unexpected_field"] = "value"
    assert detect_format(rogue) == UNKNOWN_FORMAT
    assert preflight_check(rogue).migratable is False

    # 5) Malformed base64 in a chain key.
    bad_b64 = copy.deepcopy(alice)
    bad_b64["skr"]["schain"]["key"] = "not valid base64!!"
    assert preflight_check(bad_b64).migratable is False

    # 6) A skipped message key with a negative index is an inconsistent, non-recoverable position.
    negative_index = copy.deepcopy(alice)
    first_raw_key = next(iter(negative_index["smks"]))
    key_obj = json.loads(first_raw_key)
    key_obj["index"] = -1
    negative_index["smks"][json.dumps(key_obj)] = negative_index["smks"].pop(first_raw_key)
    negative_report = preflight_check(negative_index)
    assert negative_report.migratable is False
    assert any("negative index" in error for error in negative_report.errors)

    # 7) The known, genuinely uninitialized archive is refused.
    assert preflight_check(_load("uninitialized-dr-pre-stable.json")).migratable is False


def test_no_random_key_substitution() -> None:
    alice = _load("dr-alice-pre-stable.json")
    migrated, report = migrate_json(copy.deepcopy(alice))

    # Every migrated secret must be the base64-decoded, faithfully relocated original - nothing new generated.
    own_priv = base64.b64decode(alice["super"]["own_key"]["priv"])
    assert migrated["diffie_hellman_ratchet"]["own_ratchet_priv"] == \
        "".join(map(chr, own_priv))
    other_pub = base64.b64decode(alice["super"]["other_pub"]["pub"])
    assert migrated["diffie_hellman_ratchet"]["other_ratchet_pub"] == \
        "".join(map(chr, other_pub))

    # Skipped message keys are preserved one-to-one and map to the same (ratchet_pub, index) positions.
    migrated_positions = {
        (smk["ratchet_pub"], smk["index"]): smk["message_key"]
        for smk in migrated["skipped_message_keys"]
    }
    assert len(migrated_positions) == len(alice["smks"])
    for raw_key, raw_message_key in alice["smks"].items():
        key_obj = json.loads(raw_key)
        position = ("".join(map(chr, base64.b64decode(key_obj["pub"]))), key_obj["index"])
        assert position in migrated_positions
        assert migrated_positions[position] == "".join(map(chr, base64.b64decode(raw_message_key)))

    # A report must never embed secret bytes; its summary only carries sizes and counts.
    report_blob = json.dumps(report.summary)
    for secret in _all_secret_strings(alice):
        assert secret not in report_blob


def test_file_migration_preserves_original_on_failure(tmp_path) -> None:
    good_source = os.path.join(MIGRATION_DATA_DIR, "dr-alice-pre-stable.json")
    good_input = tmp_path / "good.json"
    good_input.write_text(open(good_source, encoding="utf-8").read(), encoding="utf-8")

    result = migrate_json_file(str(good_input))
    assert os.path.exists(result.backup_path)
    # The backup is byte-identical to the untouched original.
    assert open(result.backup_path, encoding="utf-8").read() == \
        open(good_source, encoding="utf-8").read()
    # The output now parses as stable and round-trips through the DR API.
    written = json.loads(good_input.read_text(encoding="utf-8"))
    assert detect_format(written) == STABLE
    DoubleRatchet.from_json(written, **DRC)

    # A failing migration must not create, overwrite or delete any file, and must keep the original intact.
    bad_input = tmp_path / "bad.json"
    original_bad = json.dumps(_load("uninitialized-dr-pre-stable.json"))
    bad_input.write_text(original_bad, encoding="utf-8")
    before = set(os.listdir(tmp_path))
    with pytest.raises(MigrationError):
        migrate_json_file(str(bad_input))
    assert set(os.listdir(tmp_path)) == before
    assert bad_input.read_text(encoding="utf-8") == original_bad
    assert not os.path.exists(str(bad_input) + ".bak")

    # Refusing to silently overwrite an existing separate output also leaves everything in place.
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    fresh_good = tmp_path / "fresh.json"
    fresh_good.write_text(open(good_source, encoding="utf-8").read(), encoding="utf-8")
    with pytest.raises(MigrationError):
        migrate_json_file(str(fresh_good), str(target))
    assert target.read_text(encoding="utf-8") == "{}"


def test_redaction_hides_all_secrets() -> None:
    alice = _load("dr-alice-pre-stable.json")
    redacted = redact_archive(copy.deepcopy(alice))
    blob = json.dumps(redacted)
    for secret in _all_secret_strings(alice):
        assert secret not in blob
    # Public, non-secret structure remains visible for auditing.
    assert redacted["super"]["own_key"]["pub"] == alice["super"]["own_key"]["pub"]
    assert redacted["super"]["own_key"]["priv"].startswith("<redacted:")
