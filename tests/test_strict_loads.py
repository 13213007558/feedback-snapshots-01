"""Tests for strict decoding in `Schema.loads` (duplicate object members)."""

import json

import pytest

from marshmallow import Schema, fields, pre_load
from marshmallow.exceptions import ValidationError


class ChildSchema(Schema):
    age = fields.Integer(required=True)


class ItemSchema(Schema):
    name = fields.String(required=True)


class PayloadSchema(Schema):
    name = fields.String(required=True)
    child = fields.Nested(ChildSchema)
    items = fields.List(fields.Nested(ItemSchema))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pre_load_calls = []

    @pre_load
    def record_pre_load(self, data, **kwargs):
        self.pre_load_calls.append(data)
        return data


class PairsAwareModule:
    """Render module that records calls and honors object_pairs_hook."""

    dumps = staticmethod(json.dumps)

    def __init__(self):
        self.loads_calls = []

    def loads(self, s, object_pairs_hook=None, **kwargs):
        self.loads_calls.append(
            {"s": s, "object_pairs_hook": object_pairs_hook, "kwargs": kwargs}
        )
        return json.loads(s, object_pairs_hook=object_pairs_hook, **kwargs)


class PairsUnawareModule:
    """Render module with no object_pairs_hook capability."""

    dumps = staticmethod(json.dumps)

    def __init__(self):
        self.loads_calls = []

    def loads(self, s):
        self.loads_calls.append({"s": s})
        return json.loads(s)


class HookIgnoringModule:
    """Render module that accepts **kwargs but silently drops the hook."""

    dumps = staticmethod(json.dumps)

    def __init__(self):
        self.loads_calls = []

    def loads(self, s, **kwargs):
        self.loads_calls.append({"s": s, "kwargs": kwargs})
        return json.loads(s)


def make_schema(module):
    class ModuleSchema(PayloadSchema):
        class Meta:
            render_module = module

    return ModuleSchema()


def test_strict_loads_reports_normal_nested_errors():
    schema = PayloadSchema()
    text = '{"name": "placeholder", "child": {"age": "placeholder"}}'
    with pytest.raises(ValidationError) as excinfo:
        schema.loads(text, strict=True)
    assert excinfo.value.messages == {"child": {"age": ["Not a valid integer."]}}
    assert len(schema.pre_load_calls) == 1


def test_strict_loads_valid_input_passes_pre_load_once():
    schema = PayloadSchema()
    text = '{"name": "placeholder", "child": {"age": 0}, "items": [{"name": "placeholder"}]}'
    result = schema.loads(text, strict=True)
    assert result == {
        "name": "placeholder",
        "child": {"age": 0},
        "items": [{"name": "placeholder"}],
    }
    assert len(schema.pre_load_calls) == 1


def test_strict_loads_top_level_duplicate_member():
    schema = PayloadSchema()
    text = '{"name": "placeholder", "name": "placeholder"}'
    with pytest.raises(ValidationError) as excinfo:
        schema.loads(text, strict=True)
    assert excinfo.value.messages == ["Duplicate object member at path name"]
    # Invalid objects must not reach pre-processing hooks
    assert schema.pre_load_calls == []


def test_strict_loads_duplicate_member_in_nested_object():
    schema = PayloadSchema()
    text = '{"name": "placeholder", "child": {"age": 0, "age": 0}}'
    with pytest.raises(ValidationError) as excinfo:
        schema.loads(text, strict=True)
    assert excinfo.value.messages == ["Duplicate object member at path child.age"]
    assert schema.pre_load_calls == []


def test_strict_loads_duplicate_member_in_array_item():
    schema = PayloadSchema()
    text = '{"name": "placeholder", "items": [{"name": "placeholder", "name": "placeholder"}]}'
    with pytest.raises(ValidationError) as excinfo:
        schema.loads(text, strict=True)
    assert excinfo.value.messages == ["Duplicate object member at path items[0].name"]
    assert schema.pre_load_calls == []


def test_strict_loads_duplicate_member_with_many():
    schema = PayloadSchema()
    text = '[{"name": "placeholder"}, {"name": "placeholder", "name": "placeholder"}]'
    with pytest.raises(ValidationError) as excinfo:
        schema.loads(text, many=True, strict=True)
    assert excinfo.value.messages == ["Duplicate object member at path [1].name"]
    assert schema.pre_load_calls == []


def test_strict_loads_many_and_partial_still_work():
    schema = PayloadSchema()
    text = '[{"name": "placeholder"}, {"child": {"age": 0}}]'
    result = schema.loads(text, many=True, partial=True, strict=True)
    assert result == [{"name": "placeholder"}, {"child": {"age": 0}}]
    # pre_load runs once per collection item, per the usual many convention
    assert len(schema.pre_load_calls) == 2


def test_load_of_plain_dict_is_unaffected():
    schema = PayloadSchema()
    result = schema.load({"name": "placeholder", "child": {"age": 0}})
    assert result == {"name": "placeholder", "child": {"age": 0}}
    assert len(schema.pre_load_calls) == 1


def test_strict_loads_with_pairs_aware_render_module():
    module = PairsAwareModule()
    schema = make_schema(module)
    text = '{"name": "placeholder", "name": "placeholder"}'
    with pytest.raises(ValidationError) as excinfo:
        schema.loads(text, strict=True)
    assert excinfo.value.messages == ["Duplicate object member at path name"]
    assert len(module.loads_calls) == 1
    assert module.loads_calls[0]["object_pairs_hook"] is not None
    assert schema.pre_load_calls == []


def test_non_strict_loads_does_not_pass_object_pairs_hook():
    module = PairsAwareModule()
    schema = make_schema(module)
    result = schema.loads('{"name": "placeholder"}')
    assert result == {"name": "placeholder"}
    assert len(module.loads_calls) == 1
    # Old-style calls keep working: no hook is forced on the module
    assert module.loads_calls[0]["object_pairs_hook"] is None
    assert len(schema.pre_load_calls) == 1


def test_strict_loads_with_incapable_render_module_fails_without_calling():
    module = PairsUnawareModule()
    schema = make_schema(module)
    with pytest.raises(ValueError, match="object_pairs_hook"):
        schema.loads('{"name": "placeholder"}', strict=True)
    # The decoder is never invoked, so no duplicates can be silently dropped
    assert module.loads_calls == []
    assert schema.pre_load_calls == []


def test_strict_loads_with_hook_ignoring_render_module_fails():
    module = HookIgnoringModule()
    schema = make_schema(module)
    with pytest.raises(ValueError, match="object_pairs_hook"):
        schema.loads('{"name": "placeholder", "name": "placeholder"}', strict=True)
    assert len(module.loads_calls) == 1
    assert schema.pre_load_calls == []


def test_strict_loads_rejects_user_supplied_object_pairs_hook():
    schema = PayloadSchema()
    with pytest.raises(ValueError, match="object_pairs_hook"):
        schema.loads('{"name": "placeholder"}', strict=True, object_pairs_hook=dict)
