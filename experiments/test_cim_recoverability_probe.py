"""Regression tests for the offline CIM recoverability probe.

These tests pin the *evidence* the review relies on. They intentionally assert
both what can be recovered and what must not be reported as a value.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from cim_recoverability_probe import Status, load_cim, parse_instance, run, state_for  # noqa: E402

DATA = Path(__file__).parent.parent / "tests" / "_data"


@pytest.fixture(scope="module")
def cim():
    return load_cim(DATA)


@pytest.fixture(scope="module")
def findings(cim):
    return {f.subject: f for f in run(DATA)}


def test_corrected_dynprops_boundary_recovers_mykey(cim, findings):
    c = cim.namespace("root\\DEFAULT").class_("SystemRestoreConfig")
    ci = next(iter(c.instances)).class_instance
    props = sorted(c.properties.values(), key=lambda p: p.index)
    rec = parse_instance(ci.header.remaining_data, props)

    assert rec.dyn_state == 0x2
    assert rec.dyn_count == 4
    assert rec.dyn_declared_size == 561
    assert rec.trailing == 0
    assert rec.data_region[0] == 0
    assert ci.class_name != "SystemRestoreConfig"  # current parser is misaligned
    assert findings["SystemRestoreConfig / MyKey (corrected boundary)"].value == "SR"


def test_current_parser_does_not_silently_report_empty_string(findings):
    row = findings["SystemRestoreConfig / MyKey (current dissect.cim)"]
    assert row.status == Status.CONFLICT.value
    assert row.value == {"library_class_name": "\x08", "library_value": ""}


def test_uninitialized_is_not_false_or_empty(findings):
    row = findings["SystemRestoreConfig / RPGlobalInterval"]
    assert row.status == Status.UNINITIALIZED.value
    assert row.value is None


def test_string_array_qualifier_is_offsets_but_bytes_decode(cim, findings):
    c = cim.namespace("root\\CIMV2").class_("Win32_BaseService")
    prop = c.class_definition.properties["State"]
    qual = prop.qualifiers["ValueMap"]

    assert all(isinstance(v, int) for v in qual.value)
    assert findings["Win32_BaseService.State.ValueMap (byte decode)"].value[:2] == ["Stopped", "Start Pending"]


def test_inherited_key_is_missed_by_current_code(cim, findings):
    row = findings["root\\CIMV2 / __Win32Provider"]
    assert row.status == Status.CONFLICT.value
    assert row.value["distinct_records"] > row.value["instances_yielded"]


def test_object_value_is_reported_unsupported(findings):
    row = findings["MSFT_CliAlias / Connection (OBJECT)"]
    assert row.status == Status.UNSUPPORTED.value


def test_unresolved_state_is_not_boolean_false(findings):
    row = findings["root\\CIMV2 / __Win32Provider.DefaultMachineName"]
    assert row.status == Status.UNAVAILABLE.value
    assert row.value["state"] == {"use_default": True, "initialized": False}
    assert row.value["has_schema_default"] is False
    assert row.value["is_default_value"] is False


def test_schema_default_is_labelled_default(findings):
    row = findings["root\\subscription / __FilterToConsumerBinding.DeliverSynchronously"]
    assert row.status == Status.DEFAULT.value
    assert row.value is False
