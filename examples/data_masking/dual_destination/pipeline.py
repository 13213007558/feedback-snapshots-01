"""
Dual-destination fan-out for one event: recoverable audit copy and irreversible metrics copy.

The audit branch encrypts the whole two-layer event with an audit-only provider. The public
branch erases direct identifiers with DataMasking.erase and then projects an allowlisted
metrics record. The public branch never receives the audit ciphertext or a decrypt-capable
provider.

The fake provider is a test double. It makes the DataMasking contract observable; it is not
cryptography and must never be used outside tests.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any

from aws_lambda_powertools.utilities.data_masking import DataMasking
from aws_lambda_powertools.utilities.data_masking.exceptions import (
    DataMaskingContextMismatchError,
    DataMaskingDecryptKeyError,
    DataMaskingDecryptValueError,
    DataMaskingUnsupportedTypeError,
)
from aws_lambda_powertools.utilities.data_masking.provider import BaseProvider

FAKE_ENVELOPE_PREFIX = b"FAKE-ENVELOPE:"
FAKE_TAG_LENGTH = 16

# Paths that point at direct identifiers or personal data. The list crosses both layers:
# the EventBridge envelope (``id``) and the domain event (``detail``).
PUBLIC_ERASE_FIELDS: tuple[str, ...] = (
    "id",
    "detail.event_id",
    "detail.payload.order.order_id",
    "detail.payload.customer.customer_id",
    "detail.payload.customer.full_name",
    "detail.payload.customer.email",
    "detail.payload.customer.document",
    "detail.payload.customer.address.street",
    "detail.payload.customer.address.postcode",
    "detail.payload.payment.card_number",
    "detail.payload.payment.card_holder",
)

# The public destination is an allowlist, not a denylist. Every field here is either an
# aggregate or a non-personal routing dimension.
METRICS_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "event_type",
        "source",
        "tenant_id",
        "plan",
        "currency",
        "amount",
        "item_count",
        "payment_method",
        "checkout_duration_ms",
        "payment_attempts",
        "event_date",
    },
)

# Test canaries. Production should enforce the allowlist above; this scan is only a
# backstop that makes a regression fail loudly in the test suite.
PII_CANARIES: tuple[str, ...] = (
    "Ada Lovelace",
    "ada@example.com",
    "123.456.789-00",
    "12 Analytical Engine Way",
    "01000-000",
    "4111 1111 1111 1111",
    "ADA LOVELACE",
    "cus-7788",
    "ord-9001",
    "evt-0001",
)


class EventIdConflictError(RuntimeError):
    """The same event_id arrived with different content."""


class PersonalDataLeakError(RuntimeError):
    """The public metrics record failed the personal-data gate."""


class DeliveryStatus(Enum):
    DELIVERED = "delivered"
    DUPLICATE = "duplicate"


class FakeAuditKmsProvider(BaseProvider):
    """Observable test double with explicit key and encryption-context checks.

    ``ciphertext`` is a base64-encoded JSON envelope. Never use this provider in production.
    """

    def __init__(self, key_id: str, permitted_key_ids: set[str] | None = None) -> None:
        super().__init__()
        self.key_id = key_id
        self.permitted_key_ids = set(permitted_key_ids or {key_id})
        self.encrypt_calls = 0
        self.decrypt_calls = 0

    @staticmethod
    def _validate_context(context: dict[str, str]) -> None:
        for key, value in context.items():
            if not isinstance(value, str):
                raise DataMaskingUnsupportedTypeError(
                    f"Encryption context values must be string. Received: {key}={value}",
                )

    def _key(self, key_id: str) -> bytes:
        return hashlib.sha256(f"fake-audit-key:{key_id}".encode()).digest()

    @staticmethod
    def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
        blocks: list[bytes] = []
        counter = 0
        while sum(len(block) for block in blocks) < length:
            blocks.append(hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest())
            counter += 1
        return b"".join(blocks)[:length]

    @staticmethod
    def _xor(data: bytes, stream: bytes) -> bytes:
        return bytes(left ^ right for left, right in zip(data, stream, strict=True))

    def encrypt(self, data: Any, provider_options: dict | None = None, **encryption_context: str) -> str:
        self._validate_context(encryption_context)
        self.encrypt_calls += 1

        key = self._key(self.key_id)
        nonce = os.urandom(16)
        plaintext = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ciphertext = self._xor(plaintext, self._keystream(key, nonce, len(plaintext)))
        tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()[:FAKE_TAG_LENGTH]
        envelope = {
            "v": 1,
            "key_id": self.key_id,
            "encryption_context": dict(encryption_context),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "tag": base64.b64encode(tag).decode("ascii"),
        }
        payload = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return base64.b64encode(FAKE_ENVELOPE_PREFIX + payload.encode("utf-8")).decode("ascii")

    def decrypt(self, data: str, provider_options: dict | None = None, **encryption_context: str) -> Any:
        self._validate_context(encryption_context)
        self.decrypt_calls += 1

        try:
            raw = base64.b64decode(data, validate=True)
        except (binascii.Error, TypeError, ValueError) as exc:
            raise DataMaskingDecryptValueError(
                "Data decryption failed. Please ensure that you are attempting to decrypt data "
                "that was previously encrypted.",
            ) from exc

        if not raw.startswith(FAKE_ENVELOPE_PREFIX):
            raise DataMaskingDecryptValueError("Data decryption failed. The envelope header is missing.")

        try:
            envelope = json.loads(raw[len(FAKE_ENVELOPE_PREFIX) :])
            key_id = envelope["key_id"]
            stored_context = envelope["encryption_context"]
            nonce = base64.b64decode(envelope["nonce"], validate=True)
            ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
            tag = base64.b64decode(envelope["tag"], validate=True)
        except (binascii.Error, json.JSONDecodeError, KeyError, TypeError, UnicodeDecodeError) as exc:
            raise DataMaskingDecryptValueError("Data decryption failed. The envelope is malformed.") from exc

        if key_id not in self.permitted_key_ids:
            raise DataMaskingDecryptKeyError(
                "Failed to decrypt data - this provider is not permitted to use the envelope key.",
            )

        key = self._key(key_id)
        expected_tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()[:FAKE_TAG_LENGTH]
        if not hmac.compare_digest(tag, expected_tag):
            raise DataMaskingDecryptValueError("Data decryption failed. The envelope integrity check failed.")

        if stored_context != encryption_context or key_id != self.key_id:
            raise DataMaskingContextMismatchError(
                "Encryption context does not match. You must use the exact same context used during encryption",
            )

        plaintext = self._xor(ciphertext, self._keystream(key, nonce, len(ciphertext)))
        try:
            return json.loads(plaintext)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise DataMaskingDecryptValueError("Data decryption failed. The plaintext is malformed.") from exc


class CountingEraseProvider(BaseProvider):
    """Public-side provider: erase only, no encrypt/decrypt capability, plus a call counter."""

    def __init__(self) -> None:
        super().__init__()
        # DataMasking calls provider.erase once per matched field expression.
        self.erase_calls = 0

    def erase(
        self,
        data: Any,
        dynamic_mask: bool | None = None,
        custom_mask: str | None = None,
        regex_pattern: str | None = None,
        mask_format: str | None = None,
        masking_rules: dict | None = None,
        **kwargs: Any,
    ) -> Any:
        self.erase_calls += 1
        return super().erase(
            data,
            dynamic_mask=dynamic_mask,
            custom_mask=custom_mask,
            regex_pattern=regex_pattern,
            mask_format=mask_format,
            masking_rules=masking_rules,
            **kwargs,
        )


class InMemoryDestinationSink:
    """One destination's storage. Production maps this to the destination's own store.

    ``put_if_absent`` is keyed by ``event_id``. Replaying the same event returns ``False``
    instead of appending; reusing the key with different content raises. Keeping the content
    hash with the stored record is what makes a partial fan-out retry safe.
    """

    def __init__(self) -> None:
        self._records: dict[str, dict[str, Any]] = {}
        self._hashes: dict[str, str] = {}

    def content_hash(self, event_id: str) -> str | None:
        return self._hashes.get(event_id)

    def put_if_absent(self, event_id: str, record: dict[str, Any], content_hash: str) -> bool:
        existing_hash = self._hashes.get(event_id)
        if existing_hash is None:
            self._records[event_id] = record
            self._hashes[event_id] = content_hash
            return True
        if not hmac.compare_digest(existing_hash, content_hash):
            raise EventIdConflictError(f"event {event_id} was already written to this sink with different content")
        return False

    def records(self) -> list[dict[str, Any]]:
        return list(self._records.values())


class CompletionLedger:
    """Marks an event complete only after both destinations have accepted it."""

    def __init__(self) -> None:
        self._completed: dict[str, str] = {}

    def get(self, event_id: str) -> str | None:
        return self._completed.get(event_id)

    def complete(self, event_id: str, content_hash: str) -> None:
        self._completed[event_id] = content_hash


@dataclass(frozen=True)
class DeliveryResult:
    status: DeliveryStatus
    event_id: str
    audit_written: bool
    metrics_written: bool


def build_audit_record(
    event: dict[str, Any],
    audit_masker: DataMasking,
    key_ref: str,
) -> dict[str, Any]:
    """Encrypt the whole two-layer event and keep only recoverable audit material."""
    detail = event["detail"]
    encryption_context = {
        "purpose": "audit",
        "event_id": event["id"],
        "tenant_id": detail["tenant"]["tenant_id"],
        "schema_version": detail["schema_version"],
    }
    ciphertext = audit_masker.encrypt(event, **encryption_context)
    return {
        "event_id": event["id"],
        "schema_version": detail["schema_version"],
        "tenant_id": detail["tenant"]["tenant_id"],
        "key_ref": key_ref,
        "encryption_context": encryption_context,
        "ciphertext": ciphertext,
    }


def build_metrics_record(erased_event: dict[str, Any]) -> dict[str, Any]:
    """Project the public allowlist from an already-erased event."""
    detail = erased_event["detail"]
    return {
        "event_type": erased_event["detail-type"],
        "source": erased_event["source"],
        "tenant_id": detail["tenant"]["tenant_id"],
        "plan": detail["tenant"]["plan"],
        "currency": detail["payload"]["order"]["currency"],
        "amount": detail["payload"]["order"]["amount"],
        "item_count": detail["payload"]["order"]["item_count"],
        "payment_method": detail["payload"]["payment"]["method"],
        "checkout_duration_ms": detail["metrics"]["checkout_duration_ms"],
        "payment_attempts": detail["metrics"]["payment_attempts"],
        "event_date": erased_event["time"][:10],
    }


def assert_no_personal_data(metrics_record: dict[str, Any]) -> None:
    """Fail closed if the public record has an unknown field or a known direct identifier."""
    unknown_fields = set(metrics_record) - METRICS_FIELD_NAMES
    if unknown_fields:
        raise PersonalDataLeakError(f"metrics record contains fields outside the public allowlist: {unknown_fields}")

    serialized = json.dumps(metrics_record, sort_keys=True, ensure_ascii=False)
    if any(canary in serialized for canary in PII_CANARIES):
        raise PersonalDataLeakError("metrics record contains a value outside the public allowlist")


class DualDestinationPipeline:
    """Fan out one event without ever handing plaintext or ciphertext to the other side."""

    def __init__(
        self,
        audit_masker: DataMasking,
        public_masker: DataMasking,
        audit_sink: InMemoryDestinationSink,
        metrics_sink: InMemoryDestinationSink,
        ledger: CompletionLedger,
        audit_key_ref: str,
    ) -> None:
        self.audit_masker = audit_masker
        self.public_masker = public_masker
        self.audit_sink = audit_sink
        self.metrics_sink = metrics_sink
        self.ledger = ledger
        self.audit_key_ref = audit_key_ref

    def content_hash(self, event: dict[str, Any], dedupe_key: bytes) -> str:
        canonical = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return hmac.new(dedupe_key, canonical, hashlib.sha256).hexdigest()

    def process(self, event: dict[str, Any], dedupe_key: bytes) -> DeliveryResult:
        event_id = event["id"]
        content_hash = self.content_hash(event, dedupe_key)

        completed_hash = self.ledger.get(event_id)
        if completed_hash is not None:
            return self._already_completed(completed_hash, content_hash, event_id)

        # A retry after a partial fan-out must not overwrite a destination that already
        # accepted this event, nor pay for encryption that is no longer needed.
        audit_pending = self._require_same_content(self.audit_sink, event_id, content_hash)
        metrics_pending = self._require_same_content(self.metrics_sink, event_id, content_hash)

        # Public projection first: a missing PII path fails before any KMS encryption call.
        metrics_record = None
        if metrics_pending:
            erased_event = self.public_masker.erase(event, fields=list(PUBLIC_ERASE_FIELDS))
            metrics_record = build_metrics_record(erased_event)
            assert_no_personal_data(metrics_record)

        audit_record = build_audit_record(event, self.audit_masker, self.audit_key_ref) if audit_pending else None

        # Each sink is idempotent on its own. The event is complete only when both accepted it.
        audit_written = (
            self.audit_sink.put_if_absent(event_id, audit_record, content_hash) if audit_record is not None else False
        )
        metrics_written = (
            self.metrics_sink.put_if_absent(event_id, metrics_record, content_hash)
            if metrics_record is not None
            else False
        )
        self.ledger.complete(event_id, content_hash)

        return DeliveryResult(
            status=DeliveryStatus.DELIVERED,
            event_id=event_id,
            audit_written=audit_written,
            metrics_written=metrics_written,
        )

    @staticmethod
    def _require_same_content(sink: InMemoryDestinationSink, event_id: str, content_hash: str) -> bool:
        existing_hash = sink.content_hash(event_id)
        if existing_hash is None:
            return True
        if not hmac.compare_digest(existing_hash, content_hash):
            raise EventIdConflictError(f"event {event_id} was already written to a destination with different content")
        return False

    @staticmethod
    def _already_completed(completed_hash: str, content_hash: str, event_id: str) -> DeliveryResult:
        if not hmac.compare_digest(completed_hash, content_hash):
            raise EventIdConflictError(f"event {event_id} was already processed with different content")
        return DeliveryResult(
            status=DeliveryStatus.DUPLICATE,
            event_id=event_id,
            audit_written=False,
            metrics_written=False,
        )
