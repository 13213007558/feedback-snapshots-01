"""Tests for trusted-only compatibility transforms and `Schema.load_trusted`."""

import pytest

from marshmallow import (
    RAISE,
    Schema,
    TrustedImport,
    ValidationError,
    fields,
    pre_load,
    validate,
    validates_schema,
)


class ConfigSchema(Schema):
    class Meta:
        unknown = RAISE

    name = fields.String(required=True)
    timeout_seconds = fields.Integer(
        required=True, validate=validate.Range(min=1, max=3600)
    )
    enabled = fields.Boolean(load_default=True)

    @pre_load
    def normalize_name(self, data, **kwargs):
        if isinstance(data.get("name"), str):
            data = {**data, "name": data["name"].strip()}
        return data

    @pre_load(trusted_only=True)
    def convert_legacy_label(self, data, **kwargs):
        data = dict(data)
        if "label" in data:
            data["name"] = data.pop("label")
        return data

    @pre_load(trusted_only=True)
    def convert_legacy_timeout(self, data, **kwargs):
        data = dict(data)
        legacy_timeout = data.pop("timeout", None)
        if legacy_timeout is not None:
            data["timeout_seconds"] = int(str(legacy_timeout).removesuffix("s"))
        return data

    @validates_schema
    def check_reserved_name(self, data, **kwargs):
        if data.get("name") == "forbidden":
            raise ValidationError("name is reserved", "name")


LEGACY_PAYLOAD = {"label": "  cache  ", "timeout": "30s"}
MODERN_PAYLOAD = {"name": "cache", "timeout_seconds": 30}


def test_load_rejects_legacy_payload():
    """The regular entry point must not apply trusted-only transforms."""
    with pytest.raises(ValidationError) as excinfo:
        ConfigSchema().load(LEGACY_PAYLOAD)
    messages = excinfo.value.messages
    assert messages["label"] == ["Unknown field."]
    assert messages["timeout"] == ["Unknown field."]
    assert messages["name"] == ["Missing data for required field."]
    assert messages["timeout_seconds"] == ["Missing data for required field."]


def test_validate_rejects_legacy_payload():
    errors = ConfigSchema().validate(LEGACY_PAYLOAD)
    assert "label" in errors
    assert "timeout" in errors


def test_load_trusted_applies_transforms_and_reports_them():
    result = ConfigSchema().load_trusted(LEGACY_PAYLOAD)
    assert isinstance(result, TrustedImport)
    assert result.data == {"name": "cache", "timeout_seconds": 30, "enabled": True}
    assert set(result.applied_transforms) == {
        "convert_legacy_label",
        "convert_legacy_timeout",
    }


def test_load_trusted_result_supports_unpacking():
    data, applied_transforms = ConfigSchema().load_trusted(LEGACY_PAYLOAD)
    assert data["timeout_seconds"] == 30
    assert "convert_legacy_timeout" in applied_transforms


def test_load_trusted_rejects_transform_output_failing_field_validation():
    """A transform producing an illegal value is rejected by business checks."""
    # "0s" converts to 0, which violates the Range validator
    with pytest.raises(ValidationError) as excinfo:
        ConfigSchema().load_trusted({"label": "cache", "timeout": "0s"})
    assert excinfo.value.messages == {
        "timeout_seconds": ["Must be greater than or equal to 1 and less than or equal to 3600."]
    }


def test_load_trusted_rejects_transform_output_failing_schema_validation():
    with pytest.raises(ValidationError) as excinfo:
        ConfigSchema().load_trusted({"label": "forbidden", "timeout": "30s"})
    assert excinfo.value.messages == {"name": ["name is reserved"]}


def test_load_trusted_accepts_modern_payload():
    result = ConfigSchema().load_trusted(MODERN_PAYLOAD)
    assert result.data == {"name": "cache", "timeout_seconds": 30, "enabled": True}


def test_load_accepts_modern_payload_without_running_transforms():
    assert ConfigSchema().load(MODERN_PAYLOAD) == {
        "name": "cache",
        "timeout_seconds": 30,
        "enabled": True,
    }


def test_load_trusted_many_reports_each_transform_once():
    payload = [
        {"label": "a", "timeout": "1s"},
        {"label": "b", "timeout": "2s"},
    ]
    result = ConfigSchema().load_trusted(payload, many=True)
    assert result.data == [
        {"name": "a", "timeout_seconds": 1, "enabled": True},
        {"name": "b", "timeout_seconds": 2, "enabled": True},
    ]
    assert sorted(result.applied_transforms) == [
        "convert_legacy_label",
        "convert_legacy_timeout",
    ]


def test_regular_pre_load_hooks_still_run_in_both_entry_points():
    schema = ConfigSchema()
    assert schema.load({"name": "  cache  ", "timeout_seconds": 30})["name"] == "cache"
    assert (
        schema.load_trusted({"name": "  cache  ", "timeout_seconds": 30}).data["name"]
        == "cache"
    )
