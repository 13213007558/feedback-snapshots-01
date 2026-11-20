"""Tests for the shared per-request traversal budget (``max_traversal``)."""

import pytest
from marshmallow import Schema, fields, pre_load, validate, validates, validates_schema
from marshmallow.budget import TraversalBudget, TraversalBudgetExceeded
from marshmallow.exceptions import ValidationError


def make_entries(count, value=1):
    return [{"key": f"k{i}", "value": value} for i in range(count)]


class EntrySchema(Schema):
    key = fields.Str(required=True)
    value = fields.Int()


class ConfigSchema(Schema):
    name = fields.Str()
    entries = fields.List(fields.Nested(EntrySchema))


class TestBudgetUnit:
    def test_consume_raises_when_exhausted(self):
        budget = TraversalBudget(1)
        budget.consume()
        assert not budget.exceeded
        with pytest.raises(TraversalBudgetExceeded, match="budget of 1"):
            budget.consume()
        assert budget.exceeded

    def test_negative_limit_rejected(self):
        with pytest.raises(ValueError, match=">= 0"):
            TraversalBudget(-1)


class TestTopLevelBatch:
    def test_within_budget_loads(self):
        schema = EntrySchema(many=True)
        data = make_entries(5)
        # 2 fields per entry -> exactly 10 units
        assert schema.load(data, max_traversal=10) == data

    def test_budget_exceeded_reports_index_and_field(self):
        schema = EntrySchema(many=True)
        with pytest.raises(ValidationError) as excinfo:
            schema.load(make_entries(5), max_traversal=7)
        messages = excinfo.value.messages
        # 7 units cover 3 full entries + "key" of entry 3, failing on "value"
        assert messages == {3: {"value": ["Traversal budget of 7 exceeded."]}}

    def test_business_validators_not_called_after_exhaustion(self):
        calls = []

        def spy(value):
            calls.append(value)

        class BatchSchema(Schema):
            key = fields.Str(validate=spy)
            value = fields.Int()

        schema = BatchSchema(many=True)
        with pytest.raises(ValidationError):
            schema.load(make_entries(10), max_traversal=5)
        # 5 units cover key/value of entries 0-1 and key of entry 2;
        # the remaining 7 "key" validators never run
        assert calls == ["k0", "k1", "k2"]

    def test_schema_level_validators_skipped_after_exhaustion(self):
        calls = []

        class BatchSchema(Schema):
            key = fields.Str()

            @validates("key")
            def check_key(self, value, **kwargs):
                calls.append(("field", value))

            @validates_schema
            def check_schema(self, data, **kwargs):
                calls.append(("schema", data))

        schema = BatchSchema(many=True)
        with pytest.raises(ValidationError):
            schema.load(make_entries(10), max_traversal=3)
        assert calls == []


class TestNestedAndCollections:
    def test_nested_shares_budget(self):
        schema = ConfigSchema()
        data = {"name": "cfg", "entries": make_entries(3)}
        # name(1) + entries list(1) + 3 * (nested(1) + key(1) + value(1)) = 11
        assert schema.load(data, max_traversal=11) == data

    def test_nested_budget_error_has_location(self):
        schema = ConfigSchema()
        data = {"name": "cfg", "entries": make_entries(5)}
        # 2 (name + list) + 3*3 (entries 0-2) + nested node of entry 3 = 12;
        # entry 3 fails on "key"
        with pytest.raises(ValidationError) as excinfo:
            schema.load(data, max_traversal=12)
        assert excinfo.value.messages == {
            "entries": {3: {"key": ["Traversal budget of 12 exceeded."]}}
        }

    def test_deep_but_small_data_allowed(self):
        schemas: list[type[Schema]] = []
        for depth in range(10):
            name = f"Level{depth}Schema"
            if schemas:
                inner = schemas[-1]
                schema = type(name, (Schema,), {"child": fields.Nested(inner)})
            else:
                schema = type(name, (Schema,), {"leaf": fields.Str()})
            schemas.append(schema)
        data: dict = {"leaf": "x"}
        for _ in range(9):
            data = {"child": data}
        # 9 nested fields + 1 leaf field = 10 nodes
        result = schemas[-1]().load(data, max_traversal=10)
        assert (
            result["child"]["child"]["child"]["child"]["child"]["child"]["child"][
                "child"
            ]["child"]["leaf"]
            == "x"
        )

    def test_list_of_scalars_consumes_budget(self):
        class S(Schema):
            tags = fields.List(fields.Str())

        with pytest.raises(ValidationError) as excinfo:
            S().load({"tags": ["a", "b", "c", "d"]}, max_traversal=3)
        # tags field(1) + 2 elements, 3rd element exceeds
        assert excinfo.value.messages == {
            "tags": {2: ["Traversal budget of 3 exceeded."]}
        }

    def test_dict_field_consumes_budget(self):
        class S(Schema):
            mapping = fields.Dict(keys=fields.Str(), values=fields.Int())

        with pytest.raises(ValidationError) as excinfo:
            S().load({"mapping": {"a": 1, "b": 2, "c": 3}}, max_traversal=4)
        # mapping field(1) + 3 keys(3); first value exceeds the budget
        assert excinfo.value.messages == {
            "mapping": {"a": {"value": ["Traversal budget of 4 exceeded."]}}
        }


class TestPreLoadExpansion:
    def test_budget_applies_to_expanded_input(self):
        class ExpandingSchema(Schema):
            entries = fields.List(fields.Nested(EntrySchema))

            @pre_load
            def expand(self, data, **kwargs):
                if "bulk" in data:
                    data = dict(data)
                    data["entries"] = [
                        {"key": key, "value": 0} for key in data.pop("bulk")
                    ]
                return data

        schema = ExpandingSchema()
        payload = {"bulk": [f"k{i}" for i in range(10)]}
        # entries(1) + 10 * 3 = 31 units for the expanded input
        assert len(schema.load(payload, max_traversal=31)["entries"]) == 10
        with pytest.raises(ValidationError) as excinfo:
            schema.load(payload, max_traversal=30)
        assert excinfo.value.messages == {
            "entries": {9: {"value": ["Traversal budget of 30 exceeded."]}}
        }


class TestEntryPoints:
    def test_meta_option_sets_default_budget(self):
        class MetaEntrySchema(EntrySchema):
            class Meta:
                max_traversal = 3

        with pytest.raises(ValidationError):
            MetaEntrySchema(many=True).load(make_entries(5))

    def test_load_argument_overrides_meta(self):
        class MetaEntrySchema(EntrySchema):
            class Meta:
                max_traversal = 3

        data = make_entries(5)
        assert MetaEntrySchema(many=True).load(data, max_traversal=10) == data

    def test_loads_supports_budget(self):
        schema = EntrySchema(many=True)
        with pytest.raises(ValidationError):
            schema.loads('[{"key": "a"}, {"key": "b"}]', max_traversal=1)

    def test_validate_supports_budget(self):
        schema = EntrySchema(many=True)
        errors = schema.validate(make_entries(5), max_traversal=7)
        assert errors == {3: {"value": ["Traversal budget of 7 exceeded."]}}

    def test_budget_not_leaked_between_requests(self):
        schema = EntrySchema(many=True)
        with pytest.raises(ValidationError):
            schema.load(make_entries(5), max_traversal=1)
        # subsequent unbudgeted loads are unaffected
        assert schema.load(make_entries(50)) == make_entries(50)


class TestDisabledBehavior:
    def test_no_budget_by_default(self):
        schema = EntrySchema(many=True)
        data = make_entries(1000)
        assert schema.load(data) == data

    def test_none_budget_keeps_validation(self):
        class S(Schema):
            value = fields.Int(validate=validate.Range(min=0))

        with pytest.raises(ValidationError) as excinfo:
            S().load({"value": -1}, max_traversal=None)
        assert list(excinfo.value.messages) == ["value"]
