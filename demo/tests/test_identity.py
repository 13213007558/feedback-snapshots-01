import hashlib

import pytest

import pebuilder
import identity


def _ref_row(**overrides):
    class Row:
        pass

    row = Row()
    row.Name = overrides.get("name", "Contoso.Utils")
    row.MajorVersion = 1
    row.MinorVersion = 0
    row.BuildNumber = 0
    row.RevisionNumber = 0
    row.Culture = overrides.get("culture", "")
    blob = overrides.get("blob", b"\x01" * 8)
    row.PublicKey = type("Blob", (), {"value": blob})()
    row.struct = type("Struct", (), {"Flags": overrides.get("flags", 0)})()
    return row


def test_token_blob_is_not_promoted_to_full_key():
    ref = identity.assembly_ref_identity(_ref_row(flags=0))
    assert ref.key_kind_effective == "token"
    assert ref.token == b"\x01" * 8


def test_full_key_derives_token():
    key = pebuilder.synthetic_public_key(b"unit")
    ref = identity.assembly_ref_identity(_ref_row(blob=key, flags=identity.AF_PUBLIC_KEY))
    assert ref.key_kind_effective == "full_key"
    assert ref.token == pebuilder.public_key_token(key)
    assert ref.token != key[-8:]


def test_non_token_blob_without_flag_is_ambiguous():
    ref = identity.assembly_ref_identity(_ref_row(blob=b"\x02" * 32, flags=0))
    assert ref.key_kind_effective == "ambiguous"
    assert ref.token is None


def test_missing_blob_is_none_not_empty_token():
    ref = identity.assembly_ref_identity(_ref_row(blob=b"", flags=identity.AF_PUBLIC_KEY))
    assert ref.key_kind_effective == "none"
    assert ref.token is None


@pytest.mark.parametrize("flag", [0x0, identity.AF_PUBLIC_KEY | identity.AF_RETARGETABLE])
def test_retargetable_flag_is_read_from_raw_flags(flag):
    ref = identity.assembly_ref_identity(_ref_row(blob=b"\x03" * 8, flags=flag))
    assert ref.retargetable is (bool(flag & identity.AF_RETARGETABLE))


def test_culture_neutral_equivalence():
    a = identity.assembly_ref_identity(_ref_row(culture=""))
    b = identity.assembly_ref_identity(_ref_row(culture="Neutral"))
    comparison = identity.compare_identities(a, b)
    assert comparison["culture"]["match"] is True


def test_exact_requires_all_four_fields():
    a = identity.assembly_ref_identity(_ref_row())
    b = identity.assembly_ref_identity(_ref_row(culture="de"))
    assert identity.identity_exact(identity.compare_identities(a, b)) is False


def test_public_key_token_known_value():
    # CAPI blob for a fixed seed must always yield the same token.
    key = pebuilder.synthetic_public_key(b"contoso-a")
    assert hashlib.sha1(key).digest()[-8:][::-1] == pebuilder.public_key_token(key)
