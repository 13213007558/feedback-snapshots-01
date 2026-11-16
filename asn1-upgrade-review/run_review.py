#!/usr/bin/env python3
"""ASN.1 schema upgrade compatibility review, built on asn1tools.

For every change case and every rule codec (BER / PER / UPER) it answers three
distinct questions for the wire bytes produced by each side:

  1. DECODE  - does the other schema decode the bytes without raising?
  2. MEANING - for fields present in BOTH schemas, is the decoded value
               semantically identical? Schemas are supplied explicitly; field
               identity is established by explicit shared-field lists here,
               never by type-name inference.
  3. SIGN    - re-encoding the decoded value with the receiving schema yields
               the exact same wire bytes (proxy for "original signature over
               the payload stays valid").
"""
import json
import os
import traceback

import asn1tools

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_DIR = os.path.join(HERE, "schemas")
ARTIFACT_DIR = os.path.join(HERE, "artifacts")
TYPE = "AuthToken"
CODECS = ("ber", "per", "uper")


def compile_case(filename, codec):
    return asn1tools.compile_files(os.path.join(SCHEMA_DIR, filename), codec)


def err(exc):
    return "{}: {}".format(type(exc).__name__, str(exc).split("\n")[0][:110])


def shared_meaning_ok(shared_fields, decoded, expected):
    """Compare only fields explicitly declared shared by the two schemas."""
    diffs = []
    for field in shared_fields:
        if field not in decoded:
            diffs.append("{} absent after decode".format(field))
        elif decoded[field] != expected[field]:
            diffs.append("{}: {!r} -> {!r}".format(field, expected[field],
                                                   decoded[field]))
    return (not diffs), diffs


def roundtrip(sender, receiver, value, shared_fields):
    """Encode with sender, decode + re-encode with receiver. Returns verdict."""
    result = {
        "encoded_value": value,
        "wire_hex": None,
        "decoded": None,
        "decode": None,
        "decode_error": None,
        "meaning": None,
        "meaning_diffs": None,
        "reencoded_hex": None,
        "sign_bytes_identical": None,
        "reencode_error": None,
    }
    try:
        wire = sender.encode(TYPE, value)
    except Exception as exc:
        result["decode"] = "ENCODE_FAIL"
        result["decode_error"] = err(exc)
        return result
    result["wire_hex"] = wire.hex()

    try:
        decoded = receiver.decode(TYPE, wire)
    except Exception as exc:
        result["decode"] = "FAIL"
        result["decode_error"] = err(exc)
        result["meaning"] = "N/A"
        result["sign_bytes_identical"] = "N/A"
        return result

    result["decode"] = "OK"
    result["decoded"] = decoded
    ok, diffs = shared_meaning_ok(shared_fields, decoded, value)
    result["meaning"] = "SAME" if ok else "DIFFERENT"
    result["meaning_diffs"] = diffs

    try:
        re_encoded = receiver.encode(TYPE, decoded)
        result["reencoded_hex"] = re_encoded.hex()
        result["sign_bytes_identical"] = bool(re_encoded == wire)
    except Exception as exc:
        result["reencode_error"] = err(exc)
        result["sign_bytes_identical"] = False
    return result


# Each case wires together EXPLICIT old/new schema files, the concrete values
# used, and the explicit list of fields that carry the same business meaning
# across the two revisions.
CASES = [
    {
        "id": "C1a-root-insert-mandatory",
        "title": "Root member insertion (new MANDATORY scope)",
        "old": "case1_old_root.asn",
        "new": "case1_new_root_mandatory.asn",
        "shared_fields": ["deviceId", "level"],
        "old_value": {"deviceId": 7, "level": "admin"},
        "new_value": {"deviceId": 7, "scope": b"\xde\xad", "level": "admin"},
    },
    {
        "id": "C1b-root-insert-optional",
        "title": "Root member insertion (new OPTIONAL scope) - the dev claim",
        "old": "case1_old_root.asn",
        "new": "case1_new_root_optional.asn",
        "shared_fields": ["deviceId", "level"],
        "old_value": {"deviceId": 7, "level": "admin"},
        "new_value": {"deviceId": 7, "scope": b"\xde\xad", "level": "admin"},
    },
    {
        "id": "C2-extension-append",
        "title": "Extension addition after extension marker (...)",
        "old": "case2_old_extension.asn",
        "new": "case2_new_extension.asn",
        "shared_fields": ["deviceId", "level", "label"],
        "old_value": {"deviceId": 7, "level": "admin", "label": "x"},
        "new_value": {"deviceId": 7, "level": "admin", "label": "x",
                      "token": b"\xaa\xbb"},
    },
    {
        "id": "C3a-constraint-widen",
        "title": "Constraint widening INTEGER(0..255) -> (0..65535)",
        "old": "case3_old_constraint.asn",
        "new": "case3_new_constraint_widen.asn",
        "shared_fields": ["maxPower"],
        "old_value": {"maxPower": 200},
        "new_value": {"maxPower": 300},
    },
    {
        "id": "C3b-constraint-narrow",
        "title": "Constraint narrowing INTEGER(0..255) -> (0..254)",
        "old": "case3_old_constraint.asn",
        "new": "case3_new_constraint_narrow.asn",
        "shared_fields": ["maxPower"],
        "old_value": {"maxPower": 255},
        "new_value": {"maxPower": 100},
    },
    {
        "id": "C4a-enum-middle-insert",
        "title": "ENUMERATED middle insertion (renumbers user/admin)",
        "old": "case4_old_enum.asn",
        "new": "case4_new_enum_middle.asn",
        "shared_fields": ["level"],
        "old_value": {"level": "admin"},
        "new_value": {"level": "admin"},
    },
    {
        "id": "C4b-enum-extension",
        "title": "ENUMERATED extension enumerant after (...)",
        "old": "case4_old_enum_extensible.asn",
        "new": "case4_new_enum_extensible.asn",
        "shared_fields": ["level"],
        "old_value": {"level": "admin"},
        "new_value": {"level": "guest"},
    },
]


def run():
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    full = []
    for case in CASES:
        case_out = {"id": case["id"], "title": case["title"], "codecs": {}}
        for codec in CODECS:
            old = compile_case(case["old"], codec)
            new = compile_case(case["new"], codec)
            case_out["codecs"][codec] = {
                "old_sender_to_new": roundtrip(
                    old, new, case["old_value"], case["shared_fields"]),
                "new_sender_to_old": roundtrip(
                    new, old, case["new_value"], case["shared_fields"]),
            }
        full.append(case_out)

    with open(os.path.join(ARTIFACT_DIR, "results.json"), "w") as fh:
        json.dump(full, fh, indent=2, ensure_ascii=False, default=str)
    render_text(full)
    return full


def cell(value):
    return {"OK": "OK", "FAIL": "FAIL", "SAME": "SAME",
            "DIFFERENT": "DIFFERENT"}.get(value, str(value))


def render_text(full):
    lines = []
    lines.append("ASN.1 UPGRADE COMPATIBILITY REVIEW (asn1tools {})"
                 .format(asn1tools.__version__))
    lines.append("=" * 100)
    for case in full:
        lines.append("")
        lines.append(case["id"] + "  " + case["title"])
        lines.append("-" * 100)
        for codec in CODECS:
            block = case["codecs"][codec]
            for direction, label in (("old_sender_to_new", "old -> new"),
                                     ("new_sender_to_old", "new -> old")):
                r = block[direction]
                lines.append("  [{:4}] {:11} decode={:11} meaning={:11} "
                             "sign_same_bytes={}".format(
                                 codec.upper(), label,
                                 cell(r["decode"]), cell(r["meaning"]),
                                 cell(r["sign_bytes_identical"])))
                if r["wire_hex"]:
                    lines.append("           wire={} ({} bytes)".format(
                        r["wire_hex"], len(bytes.fromhex(r["wire_hex"]))))
                if r["decode_error"]:
                    lines.append("           decode_error: " + r["decode_error"])
                if r["meaning_diffs"]:
                    lines.append("           MEANING DRIFT: " +
                                 "; ".join(r["meaning_diffs"]))
                if r["reencoded_hex"]:
                    lines.append("           reenc={}".format(r["reencoded_hex"]))
    text = "\n".join(lines)
    with open(os.path.join(ARTIFACT_DIR, "review_table.txt"), "w") as fh:
        fh.write(text + "\n")
    print(text)


if __name__ == "__main__":
    try:
        run()
    except Exception:
        traceback.print_exc()
        raise
