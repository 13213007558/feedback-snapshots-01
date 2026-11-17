import sys
import json
from pathlib import Path

import metadata_identity_fixture

import dnfile.identity


def write_variant(tmp_path, name, model):
    path = tmp_path / name
    path.write_bytes(metadata_identity_fixture.build_variant(model))
    return path


def test_self_comparison_is_clean(tmp_path):
    model = metadata_identity_fixture.ModuleModel()
    path = write_variant(tmp_path, "base.exe", model)

    result = dnfile.identity.compare(str(path), str(path))

    assert result.is_clean
    assert len(result.type_mappings) == 4
    assert len(result.method_mappings) == 5
    assert not result.ambiguities
    assert result.left.digest == result.right.digest


def test_row_reorder_keeps_identity(tmp_path):
    model = metadata_identity_fixture.ModuleModel()
    reordered = model.variant(type_order=[0, 2, 1, 3], typeref_order=[1, 0])
    left = write_variant(tmp_path, "base.exe", model)
    right = write_variant(tmp_path, "reordered.exe", reordered)

    result = dnfile.identity.compare(str(left), str(right))

    assert result.is_clean
    assert not result.removed_types
    assert not result.added_types
    assert not result.removed_methods
    assert not result.added_methods


def test_reorder_changes_tokens_but_not_identity(tmp_path):
    model = metadata_identity_fixture.ModuleModel()
    reordered = model.variant(type_order=[0, 2, 1, 3], typeref_order=[1, 0])
    left = write_variant(tmp_path, "base.exe", model)
    right = write_variant(tmp_path, "reordered.exe", reordered)

    before = dnfile.identity.SideBuilder(str(left)).side()
    after = dnfile.identity.SideBuilder(str(right)).side()

    # The raw signature bytes did change: the class token for Inner moved.
    inner_before = next(r for r in before.methods.values() if r.name == "TakeInner")
    inner_after = next(r for r in after.methods.values() if r.name == "TakeInner")
    assert inner_before.raw_signature != inner_after.raw_signature

    # And at least one method moved to a different physical token.
    moved = [
        rid for rid in before.methods
        if rid in after.methods and before.methods[rid].name != after.methods[rid].name
    ]
    assert moved

    result = dnfile.identity.compare(str(left), str(right))
    assert result.is_clean
    assert result.naive_token_summary["same_token_different_identity"] > 0


def test_signature_change_is_reported_once(tmp_path):
    model = metadata_identity_fixture.ModuleModel()
    resigned = model.variant(signature_edits={"Work#str": {"returns": 0x0E}})
    left = write_variant(tmp_path, "base.exe", model)
    right = write_variant(tmp_path, "resigned.exe", resigned)

    result = dnfile.identity.compare(str(left), str(right))

    assert not result.is_clean
    assert not result.type_changes
    assert len(result.method_mappings) == 4
    assert len(result.method_changes) == 1
    change = result.method_changes[0]
    assert change.left.name == "Work"
    assert change.right.name == "Work"
    assert "signature" in change.changes
    assert change.left.rid != change.right.rid or change.left.raw_signature != change.right.raw_signature
    assert "string" in change.left.signature
    assert change.right.signature.endswith("->string")


def test_overloads_are_never_merged(tmp_path):
    model = metadata_identity_fixture.ModuleModel()
    ambiguous = model.variant(
        extra_methods=[
            {"key": "Work#bool", "owner": "Inner",
             "method": {"name": "Work", "params": [0x02], "returns": 0x01, "generic": 0}},
            {"key": "Work#obj", "owner": "Inner",
             "method": {"name": "Work", "params": [0x1C], "returns": 0x01, "generic": 0}},
        ]
    )
    # Remove Work(string) so one removed overload faces two added overloads.
    for typedef in ambiguous.typedefs:
        if typedef["name"] == "Inner":
            typedef["methods"] = [k for k in typedef["methods"] if k != "Work#str"]
    left = write_variant(tmp_path, "base.exe", model)
    right = write_variant(tmp_path, "ambiguous.exe", ambiguous)

    result = dnfile.identity.compare(str(left), str(right))

    assert not result.is_clean
    assert len(result.ambiguities) == 1
    ambiguity = result.ambiguities[0]
    assert len(ambiguity.left) == 1
    assert len(ambiguity.right) == 2
    # Existing overload matched by identity; nothing was forced onto the
    # missing Work(string) row.
    assert all(m.left.name != "Work" or m.left.signature == m.right.signature for m in result.method_mappings)


def test_type_namespace_and_nesting_are_part_of_identity(tmp_path):
    model = metadata_identity_fixture.ModuleModel()
    changed = model.variant(namespace_edits={"Inner": "Ns"})
    left = write_variant(tmp_path, "base.exe", model)
    right = write_variant(tmp_path, "nschanged.exe", changed)

    result = dnfile.identity.compare(str(left), str(right))

    assert not result.is_clean
    assert len(result.type_changes) == 1
    change = result.type_changes[0]
    assert change.left.name == "Inner"
    assert "namespace" in change.changes
    assert not result.removed_types
    assert not result.added_types
    # Methods follow the changed owner instead of being reported as new.  The
    # one method whose signature references Inner is reported as a signature
    # change caused by that referenced type's identity move.
    assert len(result.method_mappings) == 4
    assert len(result.method_changes) == 1
    assert result.method_changes[0].left.name == "TakeInner"
    assert "signature-via-referenced-type" in result.method_changes[0].changes


def test_generic_parameter_is_part_of_type_identity(tmp_path):
    model = metadata_identity_fixture.ModuleModel()
    changed = model.variant()
    changed.generic_params = [{"owner": "Outer`1", "number": 0, "name": "U"}]
    left = write_variant(tmp_path, "base.exe", model)
    right = write_variant(tmp_path, "genericrenamed.exe", changed)

    result = dnfile.identity.compare(str(left), str(right))

    # Renaming a generic parameter changes the type identity.
    assert len(result.type_changes) == 1
    assert result.type_changes[0].left.name == "Outer`1"
    assert "generic_params" in result.type_changes[0].changes
    assert not result.removed_methods
    assert not result.added_methods


def test_text_and_json_keep_both_tokens_and_digests(tmp_path):
    model = metadata_identity_fixture.ModuleModel()
    resigned = model.variant(signature_edits={"Work#str": {"returns": 0x0E}})
    left = write_variant(tmp_path, "base.exe", model)
    right = write_variant(tmp_path, "resigned.exe", resigned)

    result = dnfile.identity.compare(str(left), str(right))
    text = result.render()
    payload = result.to_dict()

    assert "left : TypeDef:" in text or "left : MethodDef:" in text
    assert "sha256:" in text
    assert payload["left"]["sha256"] == result.left.digest
    assert payload["right"]["sha256"] == result.right.digest
    change = payload["methods"]["changed"][0]
    assert change["left"]["token"].startswith("0x")
    assert change["right"]["token"].startswith("0x")
    assert change["left"]["file_offset"] is not None
    assert change["right"]["file_offset"] is not None
    assert payload["left"]["sha256"] != payload["right"]["sha256"]

    # The JSON must be serializable as-is.
    json.dumps(payload)


def test_same_name_at_same_string_offset_is_not_one_identity(tmp_path):
    """Two types can share a name string yet remain different identities.

    Both TypeDefs point at the same #Strings offset because identical strings
    are deduplicated.  Namespace still separates them, so the comparison must
    report two confirmed mappings rather than one ambiguous duplicate.
    """
    model = metadata_identity_fixture.ModuleModel()
    model.typedefs = [dict(td) for td in model.typedefs] + [
        {
            "name": "Demo",
            "namespace": "OtherNs",
            "flags": 0x100001,
            "extends": ("class", "Object"),
            "methods": [],
        }
    ]
    path = write_variant(tmp_path, "duplicate-name.exe", model)

    result = dnfile.identity.compare(str(path), str(path))

    assert result.is_clean
    demo_types = [
        record for record in result.left.types.values()
        if record.name == "Demo"
    ]
    assert len(demo_types) == 2
    assert {record.identity.namespace for record in demo_types} == {"Ns", "OtherNs"}
    assert len(result.type_mappings) == 5
    assert not any(a.kind == "duplicate-type-identity" for a in result.ambiguities)


def test_signature_type_reference_follows_reordered_type(tmp_path):
    """A signature's coded TypeDef token may move; parsed identity must not."""
    model = metadata_identity_fixture.ModuleModel()
    reordered = model.variant(type_order=[0, 2, 1, 3])
    left = write_variant(tmp_path, "base.exe", model)
    right = write_variant(tmp_path, "reordered.exe", reordered)

    builder_left = dnfile.identity.SideBuilder(str(left))
    builder_right = dnfile.identity.SideBuilder(str(right))
    left_take = next(r for r in builder_left.side().methods.values() if r.name == "TakeInner")
    right_take = next(r for r in builder_right.side().methods.values() if r.name == "TakeInner")

    assert left_take.raw_signature != right_take.raw_signature
    assert left_take.signature == right_take.signature

    result = dnfile.identity.compare(str(left), str(right))
    assert result.is_clean


def test_token_and_offset_are_provenance_not_identity(tmp_path):
    model = metadata_identity_fixture.ModuleModel()
    reordered = model.variant(type_order=[0, 2, 1, 3])
    left = write_variant(tmp_path, "base.exe", model)
    right = write_variant(tmp_path, "reordered.exe", reordered)

    result = dnfile.identity.compare(str(left), str(right))
    payload = result.to_dict()
    mapping = next(
        m for m in payload["types"]["confirmed"] if m["identity"].endswith("Outer`1<T>")
    )

    assert mapping["left"]["token"] != mapping["right"]["token"]
    assert mapping["left"]["file_offset"] != mapping["right"]["file_offset"]
    assert mapping["left"]["sha256"] != mapping["right"]["sha256"]


def test_cli_json_and_exit_status(tmp_path):
    import subprocess

    model = metadata_identity_fixture.ModuleModel()
    resigned = model.variant(signature_edits={"Work#str": {"returns": 0x0E}})
    left = write_variant(tmp_path, "base.exe", model)
    right = write_variant(tmp_path, "resigned.exe", resigned)
    script = Path(__file__).parent.parent / "examples" / "dnidentity.py"

    clean = subprocess.run(
        [sys.executable, str(script), str(left), str(left), "--json"],
        capture_output=True,
        text=True,
    )
    assert clean.returncode == 0
    assert json.loads(clean.stdout)["clean"] is True

    changed = subprocess.run(
        [sys.executable, str(script), str(left), str(right), "--json"],
        capture_output=True,
        text=True,
    )
    assert changed.returncode == 1
    assert json.loads(changed.stdout)["clean"] is False


def test_nested_type_chain_changes_are_reported(tmp_path):
    """Moving a type out of its nesting chain is an identity change, not add/remove."""
    model = metadata_identity_fixture.ModuleModel()
    changed = model.variant()
    changed.nested = []
    left = write_variant(tmp_path, "base.exe", model)
    right = write_variant(tmp_path, "unnested.exe", changed)

    result = dnfile.identity.compare(str(left), str(right))

    assert len(result.type_changes) == 1
    change = result.type_changes[0]
    assert change.left.name == "Inner"
    assert "nesting" in change.changes
    assert change.left.label() == "Outer`1.Inner"
    assert change.right.label() == "Inner"
    assert not result.removed_types
    assert not result.added_types


def test_conflicting_overload_signature_change_is_ambiguous(tmp_path):
    """Two overloads change signature at once: no confident pairing."""
    model = metadata_identity_fixture.ModuleModel()
    changed = model.variant(signature_edits={
        "Work#str": {"params": [0x02]},
        "Work#ii": {"params": [0x02, 0x02]},
    })
    left = write_variant(tmp_path, "base.exe", model)
    right = write_variant(tmp_path, "contested.exe", changed)

    result = dnfile.identity.compare(str(left), str(right))

    assert not result.is_clean
    assert not result.method_changes
    assert len(result.ambiguities) == 1
    assert len(result.ambiguities[0].left) == 2
    assert len(result.ambiguities[0].right) == 2
