"""Tests for the constraint inventory and the fail-close strict gateway.

Run from this directory:
    ../../.venv/bin/python -m pytest test_secure_message.py -v
"""

import json
from pathlib import Path

import asn1tools
import pytest

from build_inventory import build
from strict_gateway import StrictGateway, AdmissionError, PolicyError
from validators import BER_VALIDATORS, PER_VALIDATORS

HERE = Path(__file__).resolve().parent
SCHEMA_TEXT = (HERE / "protocol.asn1").read_text()

VALID = {
    "msgId": 5,
    "severity": 2,
    "token": "ABC2",
    "recipients": [1, 255],
    "envelope": {"traceId": 500, "remark": "ok", "innerToken": "9Z8A"},
}


@pytest.fixture
def inventory():
    return build(HERE / "protocol.asn1")


@pytest.fixture
def ber_gateway():
    return StrictGateway("ber", validators=BER_VALIDATORS)


@pytest.fixture
def uper_gateway():
    return StrictGateway("uper", validators=PER_VALIDATORS)


def test_inventory_covers_every_declared_constraint(inventory):
    kinds = {(c["path"], c["constraint"]["kind"]) for c in inventory["constraints"]}
    expected = {
        ("SecureMessage.msgId", "integer-range"),
        ("SecureMessage.severity", "integer-range"),
        ("SecureMessage.token", "size"),
        ("SecureMessage.token", "alphabet"),
        ("SecureMessage.recipients", "size"),
        ("SecureMessage.recipients[]", "integer-range"),
        ("SecureMessage.envelope.traceId", "integer-range"),
        ("SecureMessage.envelope.remark", "size"),
        ("SecureMessage.envelope.innerToken", "size"),
        ("SecureMessage.envelope.innerToken", "alphabet"),
    }
    assert kinds == expected


def test_extension_marker_never_marked_guaranteed(inventory):
    msg_id = next(c for c in inventory["constraints"]
                  if c["path"] == "SecureMessage.msgId")
    for codec, planes in msg_id["admission_guarantee"].items():
        assert planes["default_entry"]["guaranteed"] is False
        assert planes["strict_gateway"]["guaranteed"] is False


def test_ber_default_entry_has_no_guarantee_for_plain_ranges(inventory):
    severity = next(c for c in inventory["constraints"]
                    if c["path"] == "SecureMessage.severity")
    assert severity["admission_guarantee"]["ber"]["default_entry"]["guaranteed"] is False
    assert severity["admission_guarantee"]["ber"]["strict_gateway"]["guaranteed"] is True


def test_capability_probes_classify_unsupported_statements(inventory):
    by_probe = {p["probe"]: p for p in inventory["compiler_capability_probes"]}
    # WITH COMPONENTS compiles everywhere but is never enforced.
    assert all(c["compiles"] for c in by_probe["with-components"]["codecs"].values())
    # Time-period constraints cannot even be parsed.
    assert all(not c["compiles"]
               for c in by_probe["time-period-constraint"]["codecs"].values())


def test_gateway_refuses_without_msgid_validator():
    with pytest.raises(PolicyError) as exc:
        StrictGateway("ber", validators={})
    assert "SecureMessage.msgId" in str(exc.value)


def test_valid_message_roundtrip_ber(ber_gateway):
    wire = ber_gateway.send(VALID)
    assert ber_gateway.receive(wire) == VALID


def test_valid_message_roundtrip_uper(uper_gateway):
    wire = uper_gateway.send(VALID)
    assert uper_gateway.receive(wire) == VALID


@pytest.mark.parametrize("codec,validators,mutation", [
    ("ber", BER_VALIDATORS, dict(VALID, severity=99)),
    ("ber", BER_VALIDATORS, dict(VALID, token="abc2")),
    ("ber", BER_VALIDATORS, dict(VALID, recipients=[1, 2, 3, 4])),
    ("ber", BER_VALIDATORS,
     dict(VALID, envelope={"traceId": 50, "remark": "x"})),
    ("ber", BER_VALIDATORS, dict(VALID, token="AB")),
])
def test_ber_default_admits_but_gateway_rejects(codec, validators, mutation):
    compiled = asn1tools.compile_string(SCHEMA_TEXT, codec)
    gateway = StrictGateway(codec, validators=validators)
    wire = compiled.encode("SecureMessage", mutation)
    # Default entry: admitted.
    assert compiled.decode("SecureMessage", wire) is not None
    # Strict gateway: rejected.
    with pytest.raises(AdmissionError):
        gateway.receive(wire)


def test_extension_marker_integer_needs_application_validator(ber_gateway, uper_gateway):
    compiled_ber = asn1tools.compile_string(SCHEMA_TEXT, "ber")
    wire = compiled_ber.encode("SecureMessage", dict(VALID, msgId=77))
    # Default decode admits the extension value.
    assert compiled_ber.decode("SecureMessage", wire)["msgId"] == 77
    # Gateway rejects through the registered validator on both codecs.
    with pytest.raises(AdmissionError):
        ber_gateway.receive(wire)
    uper_wire = asn1tools.compile_string(SCHEMA_TEXT, "uper").encode(
        "SecureMessage", dict(VALID, msgId=77))
    with pytest.raises(AdmissionError):
        uper_gateway.receive(uper_wire)


def test_unknown_extension_addition_rejected_by_gateway(ber_gateway):
    extended_schema = """
SecureMessageModule DEFINITIONS ::= BEGIN
MsgId ::= INTEGER (1..10, ...)
Severity ::= INTEGER (0..3)
Token ::= PrintableString (SIZE(4..8))
    (FROM("ABCDEFGHJKLMNPQRSTUVWXYZ23456789"))
InnerEnvelope ::= SEQUENCE {
    traceId INTEGER (100..999),
    remark  PrintableString (SIZE(0..16)) OPTIONAL,
    innerToken Token OPTIONAL
}
SecureMessage ::= SEQUENCE {
    msgId MsgId, severity Severity, token Token,
    recipients SEQUENCE (SIZE(1..3)) OF INTEGER (1..255),
    envelope InnerEnvelope OPTIONAL,
    ...,
    futureScore INTEGER (0..100)
}
END
"""
    extended = asn1tools.compile_string(extended_schema, "ber")
    hostile = extended.encode("SecureMessage", dict(VALID, futureScore=999))
    root = asn1tools.compile_string(SCHEMA_TEXT, "ber")
    # Default decoder silently hides the addition.
    assert "futureScore" not in root.decode("SecureMessage", hostile)
    # Gateway detects the extra outer TLV element.
    with pytest.raises(AdmissionError, match="extension addition"):
        ber_gateway.receive(hostile)


def test_uper_wire_mutation_only_caught_by_l3(uper_gateway):
    compiled = asn1tools.compile_string(SCHEMA_TEXT, "uper")
    valid_wire = bytearray(compiled.encode("SecureMessage", VALID))
    # recipients element becomes 256 (> 255) while staying structurally decodable.
    valid_wire[6] ^= 1 << 6
    assert compiled.decode("SecureMessage", bytes(valid_wire))["recipients"] == [1, 256]
    with pytest.raises(AdmissionError):
        uper_gateway.receive(bytes(valid_wire))


def test_outbound_send_rejects_nonconforming_messages(ber_gateway):
    with pytest.raises(AdmissionError):
        ber_gateway.send(dict(VALID, severity=99))


def test_generated_inventory_matches_committed_file():
    committed = json.loads((HERE / "constraint_inventory.json").read_text())
    fresh = build(HERE / "protocol.asn1")
    assert fresh == committed
