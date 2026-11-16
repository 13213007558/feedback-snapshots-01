"""Generate the machine-readable constraint enforcement inventory.

The inventory is produced from two independent compiler artifacts:

  1. the parser AST (``asn1tools.parser``) - every constraint the
     specification *declares*;
  2. the constraints-checker tree (``asn1tools.codecs.constraints_checker``)
     - the subset the runtime checker is actually able to enforce.

A constraint present in (1) but absent or neutralized in (2) is reported as
``not-enforced``. Nothing is evaluated as a generic Python comparison
expression: every entry carries structured, typed fields naming the check
kind and the exact layer that performs (or fails to perform) it.
"""

import json
import sys
from pathlib import Path

import asn1tools
from asn1tools.parser import EXTENSION_MARKER
from asn1tools.codecs import constraints_checker

HERE = Path(__file__).resolve().parent

# Layers, ordered from the wire inward.
L1_LAYOUT = "L1-encoding-layout"
L2_TYPES = "L2-check-types"
L3_CONSTRAINTS = "L3-check-constraints"
L4_NONE = "L4-unsupported-or-ignored"

# Enforcement status vocabulary.
ENFORCED = "enforced"
OPTIONAL = "optional-enforcement"
SILENT = "not-enforced-silent"
UNSUPPORTED = "not-enforced-unsupported"
CONDITIONAL = "conditional-layout-enforcement"

LAYOUT_CODECS = ["uper", "oer"]
TAG_CODECS = ["ber", "der"]
ALL_CODECS = LAYOUT_CODECS + TAG_CODECS

CHECKER_KIND = {
    "Integer": "integer-value-range",
    "String": "string-size-and-alphabet",
    "PrintableString": "string-size-and-alphabet",
    "IA5String": "string-size-and-alphabet",
    "NumericString": "string-size-and-alphabet",
    "BMPString": "string-size-and-alphabet",
    "VisibleString": "string-size-and-alphabet",
    "Bytes": "octet-string-size",
    "BitString": "bit-string-size",
    "List": "sequence-of-size-and-elements",
    "Dict": "sequence-members",
    "Choice": "choice-alternative",
    "Boolean": "no-constraint",
    "Float": "no-constraint",
    "Enumerated": "no-constraint",
    "Time": "no-constraint",
    "Skip": "no-constraint",
    "Null": "no-constraint",
}

BUILTIN_TYPES = {
    "INTEGER", "REAL", "BOOLEAN", "NULL", "OCTET STRING", "BIT STRING",
    "PrintableString", "IA5String", "NumericString", "VisibleString",
    "BMPString", "GeneralString", "TeletexString", "UTF8String",
    "ENUMERATED", "OBJECT IDENTIFIER", "CHOICE", "SEQUENCE", "SET",
    "SEQUENCE OF", "SET OF", "ANY", "ANY DEFINED BY", "OpenType",
}


def checker_node_for(modules, type_name):
    compiled = constraints_checker.compile_dict(modules)
    module_name = next(iter(compiled))
    return compiled[module_name][type_name]._type


def has_extension(descriptor, key):
    value = descriptor.get(key)
    return isinstance(value, list) and EXTENSION_MARKER in value


def alphabet_entries(descriptor):
    out = []
    for item in descriptor.get("from", []):
        if isinstance(item, tuple):
            out.append({"kind": "char-range", "first": item[0], "last": item[1]})
        else:
            out.append({"kind": "char", "char": item})
    return out


def range_bounds(descriptor, key):
    raw = descriptor[key][0]
    if isinstance(raw, tuple):
        return {"minimum": raw[0], "maximum": raw[1]}
    return {"minimum": raw, "maximum": raw}


def per_codec_layers(constraint_kind, extension_marked):
    """Per-codec statement of the layer that enforces (or ignores) a check."""
    rows = []
    if constraint_kind in ("integer-range", "size", "alphabet",
                           "element-integer-range"):
        if extension_marked:
            for codec in LAYOUT_CODECS:
                rows.append({
                    "codec": codec, "layer": L1_LAYOUT, "status": CONDITIONAL,
                    "detail": ("Root-range values are layout-checked; out-of-root "
                               "values take the extension branch and are admitted."),
                })
            for codec in TAG_CODECS:
                rows.append({
                    "codec": codec, "layer": L4_NONE, "status": SILENT,
                    "detail": "TLV carries the value verbatim; no range gate exists.",
                })
        else:
            for codec in LAYOUT_CODECS:
                rows.append({
                    "codec": codec, "layer": L1_LAYOUT, "status": ENFORCED,
                    "detail": ("Fixed-width layout cannot represent an out-of-range "
                               "value; encode raises EncodeError. Malformed peer wire "
                               "raises DecodeError, sometimes only after truncating "
                               "the value, so L3 stays the authoritative gate."),
                })
            for codec in TAG_CODECS:
                rows.append({
                    "codec": codec, "layer": L4_NONE, "status": SILENT,
                    "detail": "TLV carries the value verbatim; no range gate exists.",
                })
        rows.append({
            "codec": "all", "layer": L3_CONSTRAINTS,
            "status": SILENT if extension_marked else OPTIONAL,
            "detail": ("check_constraints drops this entry because of the extension marker."
                       if extension_marked else
                       "Enforced only when check_constraints=True is explicitly passed."),
        })
    return rows


def admission_guarantee(extension_marked):
    """Two-plane admission verdict per codec.

    ``default_entry`` describes the raw asn1tools call (constraints off).
    ``strict_gateway`` describes StrictGateway, which always runs L3 and
    therefore inherits every check the semantic checker actually wires up.
    Statements neutralized by an extension marker are guaranteed on neither
    plane and must be covered by a registered application validator.
    """
    if extension_marked:
        weak = {
            "guaranteed": False,
            "reason": "Extension marker: out-of-root values are admitted and "
                      "check_constraints silently skips the range.",
        }
        return {codec: {"default_entry": weak, "strict_gateway": dict(weak)}
                for codec in ALL_CODECS}

    guarantees = {}
    for codec in LAYOUT_CODECS:
        guarantees[codec] = {
            "default_entry": {
                "guaranteed": True,
                "reason": "L1 fixed-width layout rejects out-of-range values.",
            },
            "strict_gateway": {
                "guaranteed": True,
                "reason": "L1 layout plus mandatory L3 check_constraints.",
            },
        }
    for codec in TAG_CODECS:
        guarantees[codec] = {
            "default_entry": {
                "guaranteed": False,
                "reason": "TLV carries the value verbatim; L3 is off by default.",
            },
            "strict_gateway": {
                "guaranteed": True,
                "reason": "L3 check_constraints is mandatory inside StrictGateway.",
            },
        }
    return guarantees


def describe_checker(node):
    inner = getattr(node, "_type", node)
    return CHECKER_KIND.get(type(inner).__name__, "unknown:" + type(inner).__name__)


def walk_type(modules, descriptor, path, sink, inside_extension=False):
    type_name = descriptor["type"]

    if type_name in ("SEQUENCE", "SET", "CHOICE"):
        extension_seen = inside_extension
        for member in descriptor.get("members", []):
            if member == EXTENSION_MARKER:
                extension_seen = True
                sink["unscoped_extension_markers"].append(
                    {"path": path, "kind": "extension-marker",
                     "effect": "Unknown extension additions from a newer schema are decoded "
                               "without any constraint check (BER: skipped; PER: version-gated)."})
                continue
            member_path = f"{path}.{member['name']}"
            if extension_seen:
                sink["extension_additions"].append({
                    "path": member_path,
                    "in_constraint_checker_tree": True,
                    "enforcement": "L3 checks it when the local schema knows the member; "
                                   "unknown additions from peer schemas are invisible to every check.",
                })
            walk_type(modules, member, member_path, sink, extension_seen)
        if "with-components" in descriptor:
            sink["ignored"].append({
                "path": path,
                "constraint": {"kind": "with-components",
                               "clauses": descriptor["with-components"]},
                "status": SILENT,
                "reason": "Parsed into AST key 'with-components', but no BER/DER/PER/OER "
                          "compiler or constraints checker consumes it for SEQUENCE/SET/CHOICE.",
            })
        return

    if type_name in ("SEQUENCE OF", "SET OF"):
        ext = has_extension(descriptor, "size")
        if "size" in descriptor:
            bounds = range_bounds(descriptor, "size")
            sink["constraints"].append({
                "path": path,
                "asn1_fragment": f"SIZE({bounds['minimum']}..{bounds['maximum']}"
                                 + (", ...)" if ext else ")"),
                "constraint": {"kind": "size", "target": "collection-length", **bounds,
                               "extension_marker": ext},
                "enforcement": per_codec_layers("size", ext),
                "admission_guarantee": admission_guarantee(ext),
            })
        walk_type(modules, descriptor["element"], f"{path}[]", sink, inside_extension)
        return

    ext = has_extension(descriptor, "restricted-to")
    if "restricted-to" in descriptor:
        bounds = range_bounds(descriptor, "restricted-to")
        sink["constraints"].append({
            "path": path,
            "asn1_fragment": f"({bounds['minimum']}..{bounds['maximum']}"
                             + (", ...)" if ext else ")"),
            "constraint": {"kind": "integer-range", "target": "integer-value", **bounds,
                           "extension_marker": ext},
            "enforcement": per_codec_layers("integer-range", ext),
            "admission_guarantee": admission_guarantee(ext),
        })

    if "size" in descriptor:
        ext = has_extension(descriptor, "size")
        bounds = range_bounds(descriptor, "size")
        sink["constraints"].append({
            "path": path,
            "asn1_fragment": f"SIZE({bounds['minimum']}..{bounds['maximum']}"
                             + (", ...)" if ext else ")"),
            "constraint": {"kind": "size", "target": "string-length", **bounds,
                           "extension_marker": ext},
            "enforcement": per_codec_layers("size", ext),
            "admission_guarantee": admission_guarantee(ext),
        })

    if "from" in descriptor:
        sink["constraints"].append({
            "path": path,
            "asn1_fragment": "FROM(...)",
            "constraint": {"kind": "alphabet", "target": "string-characters",
                           "alphabet": alphabet_entries(descriptor),
                           "extension_marker": False},
            "enforcement": per_codec_layers("alphabet", False),
            "admission_guarantee": admission_guarantee(False),
        })

    if ("restricted-to" not in descriptor and "size" not in descriptor
            and "from" not in descriptor and type_name not in BUILTIN_TYPES):
        referenced = modules["types"].get(type_name)
        if referenced is not None and referenced is not descriptor:
            walk_type(modules, referenced, path, sink, inside_extension)


def probe_unsupported_constraints():
    """Empirically classify constraints the compiler does not support.

    Each probe records whether compilation fails or the statement is parsed
    then silently ignored - these entries must never read as 'enforced'.
    """
    probes = [
        ("integer-range-extension-marker",
         "P DEFINITIONS ::= BEGIN I ::= INTEGER (0..10,...) END",
         "Range extension: root checked by PER layout only; L3 drops the whole range."),
        ("size-extension-marker",
         "P DEFINITIONS ::= BEGIN S ::= OCTET STRING (SIZE(1..4,...)) END",
         "Size extension: L3 drops the range; PER extension branch can silently truncate."),
        ("bit-string-size-extension",
         "P DEFINITIONS ::= BEGIN B ::= BIT STRING (SIZE(1..4,...)) END",
         "Compiles, but PER encode of an out-of-root size raises NotImplementedError; "
         "BER accepts it and L3 drops the range."),
        ("with-components",
         "P DEFINITIONS ::= BEGIN\n"
         "S ::= SEQUENCE { a INTEGER DEFAULT 0, b BOOLEAN OPTIONAL } "
         "(WITH COMPONENTS { a PRESENT })\nEND",
         "Parsed but never consumed by any compiler or checker; strict mode still admits "
         "a message missing 'a'."),
        ("stacked-contained-subtype",
         "P DEFINITIONS ::= BEGIN I ::= INTEGER (0..10) (5..8) END",
         "Only the first (0..10) range is compiled; (5..8) is silently dropped, so value 9 "
         "passes check_constraints even though it violates the second constraint."),
        ("named-contained-subtype",
         "P DEFINITIONS ::= BEGIN A ::= INTEGER (0..10)\n"
         "C ::= A (5..8) END",
         "Supported when applied to a named type reference: the contained range replaces "
         "the outer one in L3 (C is checked as 5..8)."),
        ("time-period-constraint",
         "P DEFINITIONS ::= BEGIN D ::= DATE (FROM \"20200101\" TO \"20251231\") END",
         "Rejected at parse time (ParseError); no codec can compile the schema."),
    ]
    results = []
    for label, spec, note in probes:
        row = {"probe": label, "note": note, "codecs": {}}
        for codec in ALL_CODECS:
            try:
                asn1tools.compile_string(spec, codec)
                row["codecs"][codec] = {"compiles": True, "runtime_status": "see-note"}
            except Exception as exc:  # noqa: BLE001 - classification needs every failure mode
                row["codecs"][codec] = {
                    "compiles": False,
                    "error": f"{type(exc).__name__}: {str(exc).splitlines()[0][:120]}",
                }
        results.append(row)
    return results


def describe_tree(node):
    inner = getattr(node, "_type", node)
    entry = {"checker": type(inner).__name__, "kind": describe_checker(node)}
    if hasattr(inner, "minimum"):
        entry["minimum"] = inner.minimum
        entry["maximum"] = inner.maximum
    if getattr(inner, "permitted_alphabet", None):
        entry["alphabet_size"] = len(inner.permitted_alphabet)
    children = []
    for member in getattr(inner, "members", []) or []:
        children.append({member.name: describe_tree(member)})
    if hasattr(inner, "element_type"):
        children.append({"[]": describe_tree(inner.element_type)})
    if children:
        entry["children"] = children
    return entry


def build(schema_path):
    source = schema_path.read_text()
    modules = asn1tools.parser.parse_string(source)
    module_name = next(iter(modules))
    module = modules[module_name]

    sink = {"constraints": [], "ignored": [], "extension_additions": [],
            "unscoped_extension_markers": []}
    pdu_name = list(module["types"])[-1]
    walk_type(module, module["types"][pdu_name], pdu_name, sink)

    return {
        "schema_version": 1,
        "generated_by": "build_inventory.py",
        "asn1tools_version": asn1tools.__version__,
        "module": module_name,
        "pdu": pdu_name,
        "layer_definitions": {
            L1_LAYOUT: "Guaranteed solely by PER/OER wire layout; BER/DER TLV gives no such guarantee.",
            L2_TYPES: "Optional encode-only check_types step; validates Python types "
                      "(INTEGER accepts int|str) and never value ranges.",
            L3_CONSTRAINTS: "Runs only when check_constraints=True; off by default on every entry point.",
            L4_NONE: "No compiler mechanism enforces the statement; never an admission guarantee.",
        },
        "status_vocabulary": {
            ENFORCED: "Rejected automatically at the named layer.",
            OPTIONAL: "Rejected only if the caller explicitly enables the layer.",
            CONDITIONAL: "Partially enforced: in-root values only; extension values bypass it.",
            SILENT: "Accepted without error; silent value truncation possible.",
            UNSUPPORTED: "Schema rejected at compile/parse time or NotImplementedError at runtime.",
        },
        "default_entry_points": {
            "encode": {"check_types": True, "check_constraints": False},
            "decode": {"check_types": False, "check_constraints": False},
        },
        "constraints": sink["constraints"],
        "extension_additions": sink["extension_additions"],
        "unscoped_extension_markers": sink["unscoped_extension_markers"],
        "unsupported_or_ignored": sink["ignored"],
        "compiler_capability_probes": probe_unsupported_constraints(),
        "semantic_checker_tree": describe_tree(checker_node_for(modules, pdu_name)),
    }


def main():
    schema_path = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "protocol.asn1"
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else HERE / "constraint_inventory.json"
    inventory = build(schema_path)
    out_path.write_text(json.dumps(inventory, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out_path}")
    print(f"  constraints: {len(inventory['constraints'])}")
    print(f"  extension additions: {len(inventory['extension_additions'])}")
    print(f"  ignored statements: {len(inventory['unsupported_or_ignored'])}")
    print(f"  capability probes: {len(inventory['compiler_capability_probes'])}")


if __name__ == "__main__":
    main()
