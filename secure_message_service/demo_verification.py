"""Empirical comparison of the default asn1tools entry points vs StrictGateway.

Each probe encodes one out-of-bounds value and runs it through:

  1. the default entry point (decode without check_constraints);
  2. the strict gateway (L3 check_constraints + registered validators).

The output states, for every probe, exactly which layer rejects the value
(or that it is silently admitted), so the inventory claims are backed by
observed behavior rather than assumptions.
"""

import json
from pathlib import Path

import asn1tools

from strict_gateway import StrictGateway, AdmissionError, PolicyError
from validators import BER_VALIDATORS, PER_VALIDATORS

# A newer peer schema that adds a member in the extension area; its wire is
# fed to a service that only knows the root schema.
EXTENDED_SCHEMA = """
SecureMessageModule DEFINITIONS ::= BEGIN
MsgId ::= INTEGER (1..10, ...)
Severity ::= INTEGER (0..3)
Token ::= PrintableString (SIZE(4..8)) (FROM("ABCDEFGHJKLMNPQRSTUVWXYZ23456789"))
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

HERE = Path(__file__).resolve().parent
SCHEMA = (HERE / "protocol.asn1").read_text()

VALID = {
    "msgId": 5,
    "severity": 2,
    "token": "ABC2",
    "recipients": [1, 255],
    "envelope": {"traceId": 500, "remark": "ok", "innerToken": "9Z8A"},
}

# (case id, human description, mutation, expected rejecting layer per codec)
PROBES = [
    ("C1", "severity out of INTEGER(0..3)",
     lambda v: dict(v, severity=99),
     {"ber": "L3 check_constraints", "uper": "L1 layout / L3"}),
    ("C2", "token char outside FROM alphabet",
     lambda v: dict(v, token="abc2"),
     {"ber": "L3 check_constraints", "uper": "L1 layout (alphabet index)"}),
    ("C3", "recipients outside SIZE(1..3)",
     lambda v: dict(v, recipients=[1, 2, 3, 4]),
     {"ber": "L3 check_constraints", "uper": "L3 (length count) / L1"}),
    ("C4", "nested optional envelope.traceId out of (100..999)",
     lambda v: dict(v, envelope={"traceId": 50, "remark": "x"}),
     {"ber": "L3 recursive check", "uper": "L1 layout / L3"}),
    ("C5", "msgId outside (1..10) via extension marker",
     lambda v: dict(v, msgId=77),
     {"ber": "application validator (L3 skips it)",
      "uper": "application validator (extension branch admitted)"}),
    ("C6", "token shorter than SIZE(4..8)",
     lambda v: dict(v, token="AB"),
     {"ber": "L3 check_constraints", "uper": "L1 layout / L3"}),
]

# Wire-level mutations: (case, description, (byte_index, bit_mask), layer note).
# These simulate a hostile or corrupted peer; default UPER decode admits them
# because the bits stay structurally decodable, and only L3 rejects them.
UPER_WIRE_PROBES = [
    ("W1", "bit flip drives nested envelope.traceId below 100",
     (6, 1 << 3), {"uper": "L3 recursive check (L1 admits)"}),
    ("W2", "bit flip drives recipients element to 256 (>255)",
     (6, 1 << 6), {"uper": "L3 element range check (L1 admits)"}),
]


def default_decode(codec, compiled, wire):
    """The asn1tools default entry: no check_constraints flag."""
    return compiled.decode("SecureMessage", wire)


def run():
    report = {"codecs": {}}
    # BER/DER TLV can carry any value, so it is the canonical source of
    # hostile wire data for codecs whose own encoder refuses the mutation.
    ber_compiled = asn1tools.compile_string(SCHEMA, "ber")

    for codec, validator_set in (("ber", BER_VALIDATORS), ("uper", PER_VALIDATORS)):
        compiled = asn1tools.compile_string(SCHEMA, codec)
        gateway = StrictGateway(codec, validators=validator_set)
        rows = []

        for case_id, description, mutate, expected in PROBES:
            mutated = mutate(VALID)
            row = {"case": case_id, "description": description,
                   "expected_layer": expected[codec]}
            wire = None

            # --- default entry point ---
            try:
                wire = compiled.encode("SecureMessage", mutated)
            except Exception as exc:  # noqa: BLE001 - encoder itself is an L1 gate
                row["default_entry"] = {
                    "verdict": "encode-rejected",
                    "layer": "L1-encoding-layout",
                    "error": f"{type(exc).__name__}: {str(exc).splitlines()[0][:90]}",
                }

            # When the codec's own encoder blocks the mutation, a hostile
            # peer cannot build that value through this codec either: the
            # encode-side L1 gate is itself the observed result. We still try
            # a BER transcode for the SIZE-style cases the layout tolerates.
            transcoded = False
            if wire is None:
                try:
                    ber_wire = ber_compiled.encode("SecureMessage", mutated)
                    hostile = ber_compiled.decode("SecureMessage", ber_wire)
                    wire = compiled.encode("SecureMessage", hostile)
                    transcoded = True
                except Exception as exc:  # noqa: BLE001
                    row["default_entry"]["error"] += (
                        f" | transcode also blocked: {type(exc).__name__}")

            if wire is not None:
                try:
                    decoded = default_decode(codec, compiled, wire)
                    row["default_entry"] = {
                        "verdict": "ADMITTED",
                        "wire_source": "ber-transcoded hostile input" if transcoded
                                       else "native encoder",
                        "decoded_preview": _preview(decoded),
                    }
                except Exception as exc:  # noqa: BLE001
                    row["default_entry"] = {
                        "verdict": "rejected",
                        "layer": "L1-encoding-layout",
                        "wire_source": "ber-transcoded hostile input" if transcoded
                                       else "native encoder",
                        "error": f"{type(exc).__name__}: {str(exc).splitlines()[0][:90]}",
                    }

            # --- strict gateway ---
            if wire is not None:
                try:
                    decoded = gateway.receive(wire)
                    row["strict_gateway"] = {"verdict": "ADMITTED",
                                             "decoded_preview": _preview(decoded)}
                except AdmissionError as exc:
                    row["strict_gateway"] = {"verdict": "rejected",
                                             "error": str(exc)[:140]}
            else:
                row["strict_gateway"] = {"verdict": "not-testable",
                                         "reason": "no wire could be produced"}

            rows.append(row)
        report["codecs"][codec] = rows

        # Wire-level bit-flip probes for PER: prove L1 decode can admit a
        # structurally decodable but semantically illegal message.
        if codec == "uper":
            valid_wire = bytearray(compiled.encode("SecureMessage", VALID))
            for case_id, description, (byte_i, bit_mask), expected in UPER_WIRE_PROBES:
                hostile = bytearray(valid_wire)
                hostile[byte_i] ^= bit_mask
                row = {"case": case_id, "description": description,
                       "expected_layer": expected[codec]}
                try:
                    decoded = default_decode(codec, compiled, bytes(hostile))
                    row["default_entry"] = {
                        "verdict": "ADMITTED",
                        "wire_source": f"bit-flip byte{byte_i}",
                        "decoded_preview": _preview(decoded),
                    }
                except Exception as exc:  # noqa: BLE001
                    row["default_entry"] = {
                        "verdict": "rejected", "layer": "L1-encoding-layout",
                        "error": f"{type(exc).__name__}: {str(exc)[:90]}"}
                try:
                    gateway.receive(bytes(hostile))
                    row["strict_gateway"] = {"verdict": "ADMITTED"}
                except AdmissionError as exc:
                    row["strict_gateway"] = {"verdict": "rejected",
                                             "error": str(exc)[:140]}
                rows.append(row)

    # --- extension-addition attack: newer peer vs root-only service ---
    report["extension_attack"] = {}
    extended = asn1tools.compile_string(EXTENDED_SCHEMA, "ber")
    extended_message = dict(VALID)
    extended_message["futureScore"] = 999
    hostile_ber = extended.encode("SecureMessage", extended_message)
    root_gateway = StrictGateway("ber", validators=BER_VALIDATORS)
    root_compiled = asn1tools.compile_string(SCHEMA, "ber")
    report["extension_attack"]["ber_default_decode"] = {
        "verdict": "ADMITTED",
        "decoded": root_compiled.decode("SecureMessage", hostile_ber),
        "note": "Unknown extension addition silently stripped from the value.",
    }
    try:
        root_gateway.receive(hostile_ber)
        report["extension_attack"]["ber_strict_gateway"] = {"verdict": "ADMITTED"}
    except AdmissionError as exc:
        report["extension_attack"]["ber_strict_gateway"] = {
            "verdict": "rejected", "error": str(exc)}

    # --- fail-close: a gateway missing the msgId policy must refuse to start ---
    try:
        StrictGateway("ber", validators={
            # extension validator is auto-installed; msgId deliberately missing
        })
        report["fail_close_check"] = "ERROR: gateway started without the msgId validator"
    except PolicyError as exc:
        report["fail_close_check"] = "OK: refused to start\n" + str(exc)

    return report


def _preview(decoded):
    text = json.dumps(decoded, default=str, ensure_ascii=False)
    return text[:110] + ("..." if len(text) > 110 else "")


def print_human(report):
    for codec, rows in report["codecs"].items():
        print(f"\n==================== codec: {codec.upper()} ====================")
        print(f"{'case':4} {'default entry':38} {'strict gateway':30} layer")
        for row in rows:
            default = row["default_entry"]
            strict = row["strict_gateway"]
            default_text = (default["verdict"] if default["verdict"] == "ADMITTED"
                            else f"{default['verdict']} @ {default.get('layer','?')}")
            strict_text = strict["verdict"]
            print(f"{row['case']:4} {default_text:38} {strict_text:30} {row['expected_layer']}")
    ext = report["extension_attack"]["ber_default_decode"]
    strict_ext = report["extension_attack"]["ber_strict_gateway"]
    print("\n==================== extension addition attack (BER) ====================")
    print(f"default decode: {ext['verdict']} -> {ext['decoded']}")
    print(f"strict gateway: {strict_ext['verdict']}"
          + (f" -> {strict_ext.get('error','')[:100]}" if strict_ext['verdict'] == 'rejected' else ''))
    print("\n==================== fail-close ====================")
    print(report["fail_close_check"])


if __name__ == "__main__":
    report = run()
    out = HERE / "verification_report.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print_human(report)
    print(f"\nmachine-readable report written to {out}")
