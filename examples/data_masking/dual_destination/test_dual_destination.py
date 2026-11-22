from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from aws_lambda_powertools.utilities.data_masking import DataMasking
from aws_lambda_powertools.utilities.data_masking.exceptions import (
    DataMaskingContextMismatchError,
    DataMaskingDecryptKeyError,
    DataMaskingDecryptValueError,
    DataMaskingFieldNotFoundError,
)
from aws_lambda_powertools.utilities.data_masking.provider import BaseProvider

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from examples.data_masking.dual_destination.pipeline import (  # noqa: E402
    FAKE_ENVELOPE_PREFIX,
    PII_CANARIES,
    PUBLIC_ERASE_FIELDS,
    CompletionLedger,
    CountingEraseProvider,
    DeliveryStatus,
    DualDestinationPipeline,
    EventIdConflictError,
    FakeAuditKmsProvider,
    InMemoryDestinationSink,
    PersonalDataLeakError,
    assert_no_personal_data,
    build_audit_record,
)

AUDIT_KEY = "arn:aws:kms:sa-east-1:111122223333:key/audit"
OTHER_KEY = "arn:aws:kms:sa-east-1:111122223333:key/other"
DEDUPE_KEY = b"test-only-dedupe-key-32-bytes-long!!"
EVENTS = Path(__file__).parent / "events"


def load_event(name: str) -> dict[str, Any]:
    return json.loads((EVENTS / name).read_text(encoding="utf-8"))


@pytest.fixture
def first_event() -> dict[str, Any]:
    return load_event("checkout_event.json")


@pytest.fixture
def second_event() -> dict[str, Any]:
    return load_event("checkout_event_second.json")


@pytest.fixture
def audit_provider() -> FakeAuditKmsProvider:
    return FakeAuditKmsProvider(AUDIT_KEY, {AUDIT_KEY})


@pytest.fixture
def public_provider() -> CountingEraseProvider:
    return CountingEraseProvider()


@pytest.fixture
def pipeline(audit_provider, public_provider):
    audit_sink = InMemoryDestinationSink()
    metrics_sink = InMemoryDestinationSink()
    ledger = CompletionLedger()
    pipeline = DualDestinationPipeline(
        audit_masker=DataMasking(provider=audit_provider),
        public_masker=DataMasking(provider=public_provider),
        audit_sink=audit_sink,
        metrics_sink=metrics_sink,
        ledger=ledger,
        audit_key_ref=AUDIT_KEY,
    )
    return pipeline, audit_sink, metrics_sink, audit_provider, public_provider


def decrypt_audit_record(provider: FakeAuditKmsProvider, record: dict[str, Any]) -> dict[str, Any]:
    return DataMasking(provider=provider).decrypt(record["ciphertext"], **record["encryption_context"])


def test_audit_destination_recovers_the_whole_two_layer_event(pipeline, first_event):
    pipeline, audit_sink, metrics_sink, *_ = pipeline

    result = pipeline.process(first_event, DEDUPE_KEY)

    assert result.status is DeliveryStatus.DELIVERED
    assert len(audit_sink.records()) == 1
    assert len(metrics_sink.records()) == 1

    audit_record = audit_sink.records()[0]
    assert set(audit_record) == {
        "event_id",
        "schema_version",
        "tenant_id",
        "key_ref",
        "encryption_context",
        "ciphertext",
    }
    assert audit_record["event_id"] == first_event["id"]
    assert audit_record["schema_version"] == "1.0"
    assert audit_record["tenant_id"] == "tenant-42"
    assert audit_record["key_ref"] == AUDIT_KEY
    assert audit_record["encryption_context"] == {
        "purpose": "audit",
        "event_id": "evt-0001",
        "tenant_id": "tenant-42",
        "schema_version": "1.0",
    }

    # The audit payload is opaque: neither layer's identifiers appear in the ciphertext bytes.
    raw_envelope = base64.b64decode(audit_record["ciphertext"])
    assert raw_envelope.startswith(FAKE_ENVELOPE_PREFIX)
    ciphertext_payload = json.loads(raw_envelope[len(FAKE_ENVELOPE_PREFIX) :])["ciphertext"]
    ciphertext_bytes = base64.b64decode(ciphertext_payload)
    for canary in PII_CANARIES + ("tenant-42", "129.9"):
        assert canary.encode() not in ciphertext_bytes

    assert audit_record["ciphertext"] != json.dumps(first_event)

    # An auditor with the audit key recovers both layers exactly, including all personal data.
    recovered = decrypt_audit_record(pipeline.audit_masker.provider, audit_record)
    assert recovered == first_event
    assert recovered["detail"]["payload"]["customer"]["email"] == "ada@example.com"
    assert recovered["detail"]["payload"]["payment"]["card_number"] == "4111 1111 1111 1111"
    assert recovered["detail"]["payload"]["order"]["order_id"] == "ord-9001"


def test_metrics_destination_gets_only_the_public_allowlist(pipeline, first_event):
    pipeline, _, metrics_sink, _, public_provider = pipeline

    pipeline.process(first_event, DEDUPE_KEY)

    metrics_record = metrics_sink.records()[0]
    assert metrics_record == {
        "event_type": "checkout.completed",
        "source": "checkout.service",
        "tenant_id": "tenant-42",
        "plan": "business",
        "currency": "BRL",
        "amount": 129.9,
        "item_count": 2,
        "payment_method": "credit_card",
        "checkout_duration_ms": 1840,
        "payment_attempts": 1,
        "event_date": "2026-11-19",
    }

    serialized = json.dumps(metrics_record, ensure_ascii=False)
    for canary in PII_CANARIES:
        assert canary not in serialized

    assert set(metrics_record).isdisjoint(
        {
            "event_id",
            "order_id",
            "customer_id",
            "full_name",
            "email",
            "document",
            "street",
            "postcode",
            "card_number",
            "card_holder",
        },
    )
    # The public branch only used erase. It has no encrypt/decrypt call counters because
    # the provider never implements those methods at all.
    assert public_provider.erase_calls >= 1
    assert not hasattr(public_provider, "encrypt_calls")
    assert not hasattr(public_provider, "decrypt_calls")


def test_metrics_side_has_no_ciphertext_or_key_reference(pipeline, first_event):
    pipeline, audit_sink, metrics_sink, *_ = pipeline

    pipeline.process(first_event, DEDUPE_KEY)

    audit_record = audit_sink.records()[0]
    metrics_serialized = json.dumps(metrics_sink.records()[0], sort_keys=True)
    assert audit_record["ciphertext"] not in metrics_serialized
    assert AUDIT_KEY not in metrics_serialized
    assert "ciphertext" not in metrics_serialized


def test_erase_covers_every_declared_pii_path(pipeline, first_event):
    pipeline, *_ = pipeline
    erased = pipeline.public_masker.erase(first_event, fields=list(PUBLIC_ERASE_FIELDS))

    assert erased["id"] == "*****"
    assert erased["detail"]["event_id"] == "*****"
    assert erased["detail"]["payload"]["order"]["order_id"] == "*****"
    assert erased["detail"]["payload"]["customer"] == {
        "customer_id": "*****",
        "full_name": "*****",
        "email": "*****",
        "document": "*****",
        "address": {"street": "*****", "postcode": "*****", "country": "BR"},
    }
    assert erased["detail"]["payload"]["payment"] == {
        "method": "credit_card",
        "card_number": "*****",
        "card_holder": "*****",
    }
    assert erased["detail"]["payload"]["order"]["currency"] == "BRL"
    assert erased["detail"]["tenant"] == {"tenant_id": "tenant-42", "plan": "business"}


@pytest.mark.parametrize(
    "leaky_projection",
    [
        pytest.param(
            {
                "event_type": "checkout.completed",
                "tenant_id": "tenant-42",
                "full_name": "Ada Lovelace",
            },
            id="unknown_field",
        ),
        pytest.param(
            {
                "event_type": "checkout.completed",
                "tenant_id": "tenant-42",
                "amount": "4111 1111 1111 1111",
            },
            id="known_field_with_pii_value",
        ),
    ],
)
def test_metrics_gate_fails_closed(pipeline, leaky_projection):
    pipeline, *_ = pipeline

    with pytest.raises(PersonalDataLeakError):
        assert_no_personal_data(leaky_projection)


@pytest.mark.parametrize(
    ("case", "expected_exception", "message"),
    [
        ("wrong_key", DataMaskingDecryptKeyError, "not permitted"),
        ("tampered", DataMaskingDecryptValueError, "integrity"),
        ("not_base64", DataMaskingDecryptValueError, "previously encrypted"),
        ("missing_header", DataMaskingDecryptValueError, "header"),
        ("malformed", DataMaskingDecryptValueError, "malformed"),
    ],
)
def test_decrypt_failures_are_typed(pipeline, first_event, case, expected_exception, message):
    pipeline, audit_sink, metrics_sink, *_ = pipeline
    pipeline.process(first_event, DEDUPE_KEY)
    audit_record = audit_sink.records()[0]
    audit_snapshot = json.loads(json.dumps(audit_record))
    metrics_snapshot = metrics_sink.records()

    provider = FakeAuditKmsProvider(AUDIT_KEY, {AUDIT_KEY})
    masker = DataMasking(provider=provider)
    ciphertext = audit_record["ciphertext"]
    context = audit_record["encryption_context"]

    if case == "wrong_key":
        provider = FakeAuditKmsProvider(OTHER_KEY, {OTHER_KEY})
        masker = DataMasking(provider=provider)
    elif case == "tampered":
        raw = base64.b64decode(ciphertext)
        envelope = json.loads(raw[len(FAKE_ENVELOPE_PREFIX) :])
        payload = bytearray(base64.b64decode(envelope["ciphertext"]))
        payload[0] ^= 0xFF
        envelope["ciphertext"] = base64.b64encode(bytes(payload)).decode("ascii")
        body = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        ciphertext = base64.b64encode(FAKE_ENVELOPE_PREFIX + body.encode("utf-8")).decode("ascii")
    elif case == "not_base64":
        ciphertext = "not base64 at all!!"
    elif case == "missing_header":
        ciphertext = base64.b64encode(b"NOT-OUR-ENVELOPE").decode("ascii")
    elif case == "malformed":
        ciphertext = base64.b64encode(FAKE_ENVELOPE_PREFIX + b"{not json").decode("ascii")

    with pytest.raises(expected_exception, match=message):
        masker.decrypt(ciphertext, **context)

    # A failed read is not a write and must not become a public fallback.
    assert audit_sink.records()[0] == audit_snapshot
    assert metrics_sink.records() == metrics_snapshot


def test_decrypt_rejects_a_different_encryption_context(pipeline, first_event):
    pipeline, audit_sink, *_ = pipeline
    pipeline.process(first_event, DEDUPE_KEY)
    audit_record = audit_sink.records()[0]
    wrong_context = {**audit_record["encryption_context"], "tenant_id": "tenant-99"}

    with pytest.raises(DataMaskingContextMismatchError, match="exact same context"):
        pipeline.audit_masker.decrypt(audit_record["ciphertext"], **wrong_context)


def test_missing_field_fails_the_whole_event_before_either_destination_writes(pipeline):
    pipeline, audit_sink, metrics_sink, audit_provider, public_provider = pipeline
    event = load_event("checkout_event.json")
    # Empty the address object, so payload.customer.address.street no longer matches.
    event["detail"]["payload"]["customer"]["address"] = {"country": "BR"}

    with pytest.raises(DataMaskingFieldNotFoundError, match="payload.customer.address.street not found"):
        pipeline.process(event, DEDUPE_KEY)

    assert audit_sink.records() == []
    assert metrics_sink.records() == []
    assert pipeline.ledger.get(event["id"]) is None
    assert audit_provider.encrypt_calls == 0
    assert public_provider.erase_calls >= 1


def test_lenient_missing_field_is_not_an_acceptable_public_configuration(first_event):
    """A lenient masker warns and leaves the value intact; that must fail the public gate."""
    public_provider = CountingEraseProvider()
    lenient = DataMasking(provider=public_provider, raise_on_missing_field=False)
    event = load_event("checkout_event.json")
    event["detail"]["payload"]["customer"]["address"] = {"country": "BR"}

    erased = lenient.erase(event, fields=["detail.payload.customer.address.street"])

    assert "street" not in erased["detail"]["payload"]["customer"]["address"]
    assert erased["detail"]["payload"]["customer"]["full_name"] == "Ada Lovelace"


def test_replaying_the_same_event_does_not_duplicate_or_reencrypt(pipeline, first_event):
    pipeline, audit_sink, metrics_sink, audit_provider, public_provider = pipeline

    first = pipeline.process(first_event, DEDUPE_KEY)
    audit_after_first = audit_sink.records()
    metrics_after_first = metrics_sink.records()
    erase_calls_after_first = public_provider.erase_calls

    second = pipeline.process(json.loads(json.dumps(first_event)), DEDUPE_KEY)

    assert first.status is DeliveryStatus.DELIVERED
    assert second.status is DeliveryStatus.DUPLICATE
    assert second.audit_written is False
    assert second.metrics_written is False
    assert audit_sink.records() == audit_after_first
    assert metrics_sink.records() == metrics_after_first
    assert audit_provider.encrypt_calls == 1
    assert public_provider.erase_calls == erase_calls_after_first


def test_same_event_id_with_different_content_is_rejected(pipeline, first_event, second_event):
    pipeline, audit_sink, metrics_sink, *_ = pipeline
    pipeline.process(first_event, DEDUPE_KEY)

    conflicting = json.loads(json.dumps(first_event))
    conflicting["detail"]["payload"]["order"]["amount"] = 1.0

    with pytest.raises(EventIdConflictError, match="different content"):
        pipeline.process(conflicting, DEDUPE_KEY)

    assert audit_sink.records() == [audit_sink.records()[0]]
    assert metrics_sink.records() == [metrics_sink.records()[0]]
    # A different event_id with different content is a new, valid event.
    assert pipeline.process(second_event, DEDUPE_KEY).status is DeliveryStatus.DELIVERED
    assert len(audit_sink.records()) == 2
    assert len(metrics_sink.records()) == 2


def test_partial_fanout_retry_fills_only_the_missing_destination(pipeline, first_event):
    pipeline, audit_sink, metrics_sink, audit_provider, _ = pipeline
    event = load_event("checkout_event.json")

    # Simulate: the audit destination committed, the metrics destination did not, and the
    # process died before the completion ledger was updated.
    content_hash = pipeline.content_hash(event, DEDUPE_KEY)
    audit_sink.put_if_absent(
        event["id"],
        build_audit_record(event, pipeline.audit_masker, AUDIT_KEY),
        content_hash,
    )
    assert metrics_sink.records() == []
    assert pipeline.ledger.get(event["id"]) is None

    result = pipeline.process(event, DEDUPE_KEY)

    assert result.status is DeliveryStatus.DELIVERED
    assert result.audit_written is False
    assert result.metrics_written is True
    assert len(audit_sink.records()) == 1
    assert len(metrics_sink.records()) == 1
    # The retry reused the audit destination's already-committed ciphertext: one encryption total.
    assert audit_provider.encrypt_calls == 1


def test_two_events_keep_two_independent_projections(pipeline, first_event, second_event):
    pipeline, audit_sink, metrics_sink, *_ = pipeline

    pipeline.process(first_event, DEDUPE_KEY)
    pipeline.process(second_event, DEDUPE_KEY)

    audit_ids = [record["event_id"] for record in audit_sink.records()]
    metrics_ids = [record["tenant_id"] for record in metrics_sink.records()]
    assert audit_ids == ["evt-0001", "evt-0002"]
    assert metrics_ids == ["tenant-42", "tenant-42"]
    assert [record["amount"] for record in metrics_sink.records()] == [129.9, 89.5]

    recovered = decrypt_audit_record(pipeline.audit_masker.provider, audit_sink.records()[1])
    assert recovered == second_event


def test_public_provider_cannot_decrypt_even_if_handed_a_ciphertext(pipeline, first_event):
    pipeline, audit_sink, metrics_sink, *_ = pipeline
    pipeline.process(first_event, DEDUPE_KEY)
    audit_record = audit_sink.records()[0]

    # BaseProvider.decrypt is abstract-by-contract: it raises NotImplementedError.
    with pytest.raises(NotImplementedError):
        pipeline.public_masker.decrypt(audit_record["ciphertext"])


class _EraseOnlyProvider(BaseProvider):
    pass


def test_erase_only_provider_never_exposes_encryption():
    provider = _EraseOnlyProvider()
    with pytest.raises(NotImplementedError):
        provider.encrypt({"a": 1})
    with pytest.raises(NotImplementedError):
        provider.decrypt("abc")
    assert provider.erase({"a": 1}) == "*****"
