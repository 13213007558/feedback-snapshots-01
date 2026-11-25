"""Tests for creator-aware private tag retention."""

from __future__ import annotations

import pytest

from pydicom import Dataset, PrivateTagPolicy, PrivateTagRule, dcmread
from pydicom.dataelem import RawDataElement
from pydicom.datadict import (
    add_private_dict_entries,
    private_dictionary_description,
)
from pydicom.dataset import FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

CREATOR_A = "FB7558 Creator Alpha"
CREATOR_B = "FB7558 Creator Beta"


def _synthetic_dataset() -> Dataset:
    meta = FileMetaDataset()
    meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.7"
    meta.MediaStorageSOPInstanceUID = generate_uid()
    meta.TransferSyntaxUID = ExplicitVRLittleEndian

    ds = Dataset()
    ds.file_meta = meta
    ds.SOPClassUID = meta.MediaStorageSOPClassUID
    ds.SOPInstanceUID = meta.MediaStorageSOPInstanceUID
    ds.PatientName = "SYNTHETIC"

    items = []
    for creator, first, second in (
        (CREATOR_A, "alpha-allowed", "alpha-secret"),
        (CREATOR_B, "beta-secret", "beta-allowed"),
    ):
        item = Dataset()
        block = item.private_block(0x0045, creator, create=True)
        block.add_new(0x01, "LO", first)
        block.add_new(0x02, "LO", second)
        block.add_new(0x03, "SH", "HIDDEN")
        items.append(item)

    ds.OtherPatientIDsSequence = items
    return ds


def _write_synthetic(path) -> None:
    _synthetic_dataset().save_as(path, enforce_file_format=True)


@pytest.mark.parametrize("opened", [False, True])
def test_remove_private_tags_uses_item_local_creator(tmp_path, opened):
    source = tmp_path / "source.dcm"
    exported = tmp_path / "exported.dcm"
    _write_synthetic(source)

    ds = dcmread(source)
    items = ds.OtherPatientIDsSequence
    if opened:
        for item in items:
            for tag in (0x00451001, 0x00451002, 0x00451003):
                if tag in item:
                    item[tag].value

    ds.remove_private_tags(
        {
            CREATOR_A: [0x00451001],
            CREATOR_B: [0x00451002],
        }
    )
    ds.save_as(exported, enforce_file_format=True)

    reread = dcmread(exported)
    alpha, beta = reread.OtherPatientIDsSequence

    assert list(alpha.keys()) == [0x00450010, 0x00451001]
    assert list(beta.keys()) == [0x00450010, 0x00451002]
    assert alpha[0x00450010].value == CREATOR_A
    assert beta[0x00450010].value == CREATOR_B
    assert alpha.private_block(0x0045, CREATOR_A)[0x01].value == "alpha-allowed"
    assert beta.private_block(0x0045, CREATOR_B)[0x02].value == "beta-allowed"

    assert 0x00451002 not in alpha
    assert 0x00451003 not in alpha
    assert 0x00451001 not in beta
    assert 0x00451003 not in beta

    raw = exported.read_bytes()
    assert b"alpha-allowed" in raw
    assert b"beta-allowed" in raw
    assert b"alpha-secret" not in raw
    assert b"beta-secret" not in raw
    assert b"HIDDEN" not in raw


def test_private_dictionary_explains_retained_tags_after_reread(tmp_path):
    add_private_dict_entries(
        CREATOR_A,
        {0x00451001: ("LO", "1", "FB7558 Alpha Diagnostic", "")},
    )
    add_private_dict_entries(
        CREATOR_B,
        {0x00451002: ("LO", "1", "FB7558 Beta Diagnostic", "")},
    )

    path = tmp_path / "explain.dcm"
    _write_synthetic(path)
    ds = dcmread(path)
    policy = PrivateTagPolicy(
        [
            PrivateTagRule(creator=CREATOR_A, tags=["00451001"]),
            PrivateTagRule(creator=CREATOR_B, tags=[0x02]),
        ]
    )
    ds.remove_private_tags(policy)
    out = tmp_path / "explain-out.dcm"
    ds.save_as(out, enforce_file_format=True)

    reread = dcmread(out)
    alpha, beta = reread.OtherPatientIDsSequence
    assert alpha[0x00451001].name == "[FB7558 Alpha Diagnostic]"
    assert beta[0x00451002].name == "[FB7558 Beta Diagnostic]"
    assert (
        private_dictionary_description(0x00451001, CREATOR_A)
        == "FB7558 Alpha Diagnostic"
    )
    assert (
        private_dictionary_description(0x00451002, CREATOR_B)
        == "FB7558 Beta Diagnostic"
    )


def test_deferred_raw_private_element_is_classified_by_creator(tmp_path):
    path = tmp_path / "deferred.dcm"
    ds = _synthetic_dataset()
    block = ds.private_block(0x0047, "FB7558 Deferred", create=True)
    block.add_new(0x01, "UT", "D" * 200)
    ds.save_as(path, enforce_file_format=True)

    deferred = dcmread(path, defer_size=0)
    raw = deferred.get_item(0x00471001, keep_deferred=True)
    assert isinstance(raw, RawDataElement)
    assert raw.value is None

    deferred.remove_private_tags(allowed_private_tags={"FB7558 Deferred": [0x00471001]})
    assert 0x00471001 in deferred
    assert deferred[0x00471001].value == "D" * 200


def test_rule_does_not_allow_same_tag_for_untrusted_item(tmp_path):
    path = tmp_path / "same-number.dcm"
    _write_synthetic(path)
    ds = dcmread(path)
    ds.remove_private_tags(
        trusted_creators=CREATOR_A,
        allowed_private_tags={CREATOR_A: [0x00451001]},
    )

    alpha, beta = ds.OtherPatientIDsSequence
    assert 0x00451001 in alpha
    assert 0x00450010 in alpha
    assert len(beta) == 0
