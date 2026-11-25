"""Key-material isolation tests for a document gateway using client-side encryption.

The gateway shares one data connection between two write identities and
encrypts a few fields with PyMongo (driver auto-encryption plus explicit
encryption).  The key vault is permissioned independently of the data
connection.  These tests use local stand-ins that record every key-vault
query and every synthesized command so the two can be compared:

* each identity must encrypt with its own approved key material, on both
  the auto-encryption and the explicit-encryption paths;
* retired key material must stay unusable (boundary holds for old data);
* permission denials (server-side authz) must be distinguishable from
  transport failures (network), and only the latter are retryable.

No MongoDB server or pymongocrypt is required: the cipher is a structural
stand-in that embeds the key id so issued commands can be audited.
"""

from __future__ import annotations

import hashlib
import unittest
from uuid import UUID, uuid4

from bson import Binary
from pymongo.errors import AutoReconnect, ConnectionFailure, OperationFailure

ENCRYPTED_SUBTYPE = 6
PERMISSION_DENIED = 13  # MongoDB "Unauthorized" error code.
KEY_ID_LEN = 16
TAG_LEN = 8


class KeyRecord:
    """A data key stored in the key vault."""

    def __init__(self, alt_name: str):
        self.key_id = uuid4()
        self.alt_name = alt_name
        # Deterministic 96-byte stand-in for real key material.
        self.material = hashlib.sha256(b"material:" + alt_name.encode()).digest() * 3
        self.retired = False


class RecordingKeyVault:
    """Stand-in for the key vault collection, with its own ACL.

    Records every key query so tests can compare vault traffic against the
    commands issued on the data connection.
    """

    def __init__(self):
        self._keys_by_alt: dict[str, KeyRecord] = {}
        self._grants: dict[str, set[str]] = {}
        self.queries: list[dict] = []
        self._transport_errors = 0

    def add_key(self, alt_name: str, grants=()) -> KeyRecord:
        record = KeyRecord(alt_name)
        self._keys_by_alt[alt_name] = record
        self._grants[alt_name] = set(grants)
        return record

    def retire(self, alt_name: str) -> None:
        """Simulate an authorization change: old material exits use."""
        self._keys_by_alt[alt_name].retired = True

    def inject_transport_failure(self, count: int = 1) -> None:
        """Make the next ``count`` vault queries fail at the transport layer."""
        self._transport_errors += count

    def _find(self, identity: str, query_filter: dict, record: KeyRecord | None) -> KeyRecord:
        self.queries.append({"identity": identity, "op": "find", "filter": query_filter})
        if self._transport_errors:
            self._transport_errors -= 1
            raise AutoReconnect("key vault transport failure")
        if (
            record is None
            or record.retired
            or identity not in self._grants.get(record.alt_name, ())
        ):
            raise OperationFailure("not authorized to use key", code=PERMISSION_DENIED)
        return record

    def find_by_alt_name(self, identity: str, alt_name: str) -> KeyRecord:
        return self._find(
            identity, {"keyAltNames": alt_name}, self._keys_by_alt.get(alt_name)
        )

    def find_by_key_id(self, identity: str, key_id: UUID) -> KeyRecord:
        record = next(
            (r for r in self._keys_by_alt.values() if r.key_id == key_id), None
        )
        return self._find(identity, {"_id": key_id}, record)


class RecordingCommandListener:
    """Stand-in for the data connection's command monitor."""

    def __init__(self):
        self.commands: list[dict] = []

    def publish(self, command: dict) -> None:
        self.commands.append(command)

    def count(self, command_name: str) -> int:
        return sum(1 for c in self.commands if command_name in c)


def _encrypt(record: KeyRecord, value: str) -> Binary:
    """Stand-in cipher: key id || tag || value, BSON subtype 6."""
    tag = hashlib.sha256(record.material + value.encode()).digest()[:TAG_LEN]
    return Binary(record.key_id.bytes + tag + value.encode(), ENCRYPTED_SUBTYPE)


def _decrypt(record: KeyRecord, ciphertext: Binary) -> str:
    tag = hashlib.sha256(record.material + ciphertext[KEY_ID_LEN + TAG_LEN :]).digest()[:TAG_LEN]
    if ciphertext[KEY_ID_LEN : KEY_ID_LEN + TAG_LEN] != tag:
        raise OperationFailure("ciphertext integrity check failed", code=2)
    return ciphertext[KEY_ID_LEN + TAG_LEN :].decode()


class DocumentGateway:
    """Encrypts schema fields and issues commands over one shared connection.

    ``key_alt_name`` maps ``(identity, field)`` to the key each identity is
    approved to use, mirroring how the gateway binds writer roles to data
    keys.  The auto-encryption path caches keys per identity (like the
    driver's key cache); the explicit path resolves the key on every call.
    """

    def __init__(self, vault, listener, encrypted_fields):
        self._vault = vault
        self._listener = listener
        self._encrypted_fields = set(encrypted_fields)
        self._auto_cache: dict[tuple[str, str], KeyRecord] = {}

    @staticmethod
    def _alt_name(identity: str, field: str) -> str:
        return f"{identity}.{field}"

    def refresh_authorization(self) -> None:
        """Drop cached keys so an authorization change takes effect."""
        self._auto_cache.clear()

    def auto_encrypt_field(self, identity: str, field: str, value: str) -> Binary:
        cache_key = (identity, field)
        if cache_key not in self._auto_cache:
            record = self._vault.find_by_alt_name(identity, self._alt_name(identity, field))
            self._auto_cache[cache_key] = record
        return _encrypt(self._auto_cache[cache_key], value)

    def explicit_encrypt(self, identity: str, field: str, value: str) -> Binary:
        record = self._vault.find_by_alt_name(identity, self._alt_name(identity, field))
        return _encrypt(record, value)

    def decrypt(self, identity: str, ciphertext: Binary) -> str:
        key_id = UUID(bytes=bytes(ciphertext[:KEY_ID_LEN]))
        record = self._vault.find_by_key_id(identity, key_id)
        return _decrypt(record, ciphertext)

    def insert(self, identity: str, db: str, coll: str, document: dict) -> None:
        doc = dict(document)
        for field in self._encrypted_fields & doc.keys():
            doc[field] = self.auto_encrypt_field(identity, field, doc[field])
        # Only reached when every field encrypted successfully.
        self._listener.publish({"insert": coll, "documents": [doc], "$db": db})


class TestGatewayKeyIsolation(unittest.TestCase):
    def setUp(self):
        self.vault = RecordingKeyVault()
        self.listener = RecordingCommandListener()
        self.key_a = self.vault.add_key("writer-a.ssn", grants={"writer-a"})
        self.key_b = self.vault.add_key("writer-b.ssn", grants={"writer-b"})
        self.gateway = DocumentGateway(self.vault, self.listener, encrypted_fields={"ssn"})

    def assert_encrypted_with(self, ciphertext, record, plaintext):
        self.assertIsInstance(ciphertext, Binary)
        self.assertEqual(ciphertext.subtype, ENCRYPTED_SUBTYPE)
        self.assertEqual(ciphertext[:KEY_ID_LEN], record.key_id.bytes)
        self.assertEqual(ciphertext[KEY_ID_LEN + TAG_LEN :], plaintext.encode())

    def test_identities_use_own_material_on_both_paths(self):
        # Identity A warms up the auto-encryption cache.
        self.gateway.insert("writer-a", "gateway", "records", {"_id": 1, "ssn": "aaa-01"})
        self.gateway.insert("writer-a", "gateway", "records", {"_id": 2, "ssn": "aaa-02"})
        # Second insert hit the cache: one vault query, two commands.
        self.assertEqual(len(self.vault.queries), 1)
        self.assertEqual(self.vault.queries[0]["identity"], "writer-a")
        self.assertEqual(
            self.vault.queries[0]["filter"], {"keyAltNames": "writer-a.ssn"}
        )
        self.assertEqual(self.listener.count("insert"), 2)

        # Identity B requests the same field: separate cache entry, own query.
        self.gateway.insert("writer-b", "gateway", "records", {"_id": 3, "ssn": "bbb-01"})
        self.assertEqual(len(self.vault.queries), 2)
        self.assertEqual(self.vault.queries[1]["identity"], "writer-b")
        self.assertEqual(self.listener.count("insert"), 3)

        # Explicit encryption on the same connection also uses B's material.
        explicit = self.gateway.explicit_encrypt("writer-b", "ssn", "bbb-02")
        self.assertEqual(len(self.vault.queries), 3)
        self.assertEqual(self.listener.count("insert"), 3)  # no command issued

        # Final synthesized command content: B's approved key, not A's.
        cmd_a = self.listener.commands[0]
        cmd_b = self.listener.commands[-1]
        self.assertEqual(cmd_a["insert"], "records")
        self.assertEqual(cmd_a["$db"], "gateway")
        self.assert_encrypted_with(cmd_a["documents"][0]["ssn"], self.key_a, "aaa-01")
        self.assert_encrypted_with(cmd_b["documents"][0]["ssn"], self.key_b, "bbb-01")
        self.assert_encrypted_with(explicit, self.key_b, "bbb-02")
        self.assertNotEqual(self.key_a.key_id, self.key_b.key_id)

        # Cross-identity boundary: B cannot decrypt A's ciphertext.
        with self.assertRaises(OperationFailure) as ctx:
            self.gateway.decrypt("writer-b", cmd_a["documents"][0]["ssn"])
        self.assertEqual(ctx.exception.code, PERMISSION_DENIED)

    def test_retired_material_stays_unusable(self):
        self.gateway.insert("writer-a", "gateway", "records", {"_id": 1, "ssn": "aaa-01"})
        old = self.gateway.explicit_encrypt("writer-a", "ssn", "aaa-old")
        self.assertEqual(len(self.vault.queries), 2)
        self.assertEqual(self.listener.count("insert"), 1)

        # Authorization change: A's key material exits use.
        self.vault.retire("writer-a.ssn")
        self.gateway.refresh_authorization()

        # New writes as A are denied before any command is synthesized.
        with self.assertRaises(OperationFailure) as ctx:
            self.gateway.insert("writer-a", "gateway", "records", {"_id": 2, "ssn": "x"})
        self.assertEqual(ctx.exception.code, PERMISSION_DENIED)
        self.assertEqual(self.listener.count("insert"), 1)
        self.assertEqual(len(self.vault.queries), 3)

        # Old material is guarded too: historical ciphertext cannot be read.
        with self.assertRaises(OperationFailure) as ctx:
            self.gateway.decrypt("writer-a", old)
        self.assertEqual(ctx.exception.code, PERMISSION_DENIED)
        self.assertEqual(len(self.vault.queries), 4)

        # Explicit path is denied as well; still no new commands.
        with self.assertRaises(OperationFailure):
            self.gateway.explicit_encrypt("writer-a", "ssn", "aaa-new")
        self.assertEqual(self.listener.count("insert"), 1)
        self.assertEqual(len(self.vault.queries), 5)

        # The boundary is per-identity: B is unaffected by A's retirement.
        self.gateway.insert("writer-b", "gateway", "records", {"_id": 3, "ssn": "bbb-01"})
        self.assertEqual(self.listener.count("insert"), 2)
        final_cmd = self.listener.commands[-1]
        self.assert_encrypted_with(final_cmd["documents"][0]["ssn"], self.key_b, "bbb-01")
        # No command issued after retirement carries the retired key id.
        for command in self.listener.commands[1:]:
            payload = command["documents"][0]["ssn"]
            self.assertNotEqual(payload[:KEY_ID_LEN], self.key_a.key_id.bytes)

    def test_permission_denied_is_distinct_from_transport_failure(self):
        # Baseline: one successful explicit encryption as B.
        self.gateway.explicit_encrypt("writer-b", "ssn", "bbb-01")
        self.assertEqual(len(self.vault.queries), 1)

        # Transport failure: network-layer error, retryable, nothing cached.
        self.vault.inject_transport_failure(1)
        with self.assertRaises(AutoReconnect) as ctx:
            self.gateway.insert("writer-b", "gateway", "records", {"_id": 1, "ssn": "x"})
        self.assertIsInstance(ctx.exception, ConnectionFailure)
        self.assertNotIsInstance(ctx.exception, OperationFailure)
        self.assertEqual(self.listener.count("insert"), 0)
        self.assertEqual(len(self.vault.queries), 2)

        # Retry after the transport recovers succeeds on the same connection.
        self.gateway.insert("writer-b", "gateway", "records", {"_id": 1, "ssn": "bbb-02"})
        self.assertEqual(self.listener.count("insert"), 1)
        self.assertEqual(len(self.vault.queries), 3)

        # Permission denial: server-side authz error, not a connection error.
        with self.assertRaises(OperationFailure) as ctx:
            self.gateway.explicit_encrypt("writer-c", "ssn", "ccc-01")
        self.assertEqual(ctx.exception.code, PERMISSION_DENIED)
        self.assertNotIsInstance(ctx.exception, ConnectionFailure)
        self.assertEqual(self.listener.count("insert"), 1)
        self.assertEqual(len(self.vault.queries), 4)

        # Final synthesized content still carries only B's approved key.
        final_cmd = self.listener.commands[-1]
        self.assert_encrypted_with(final_cmd["documents"][0]["ssn"], self.key_b, "bbb-02")


if __name__ == "__main__":
    unittest.main()
