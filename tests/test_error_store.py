from typing import NamedTuple

from marshmallow import missing
from marshmallow.error_store import ErrorStore, merge_errors
from marshmallow.exceptions import _CodedMessage


def test_missing_is_falsy():
    assert bool(missing) is False


class CustomError(NamedTuple):
    code: int
    message: str


class TestMergeErrors:
    def test_merging_none_and_string(self):
        assert merge_errors(None, "error1") == "error1"

    def test_merging_none_and_custom_error(self):
        assert CustomError(123, "error1") == merge_errors(
            None, CustomError(123, "error1")
        )

    def test_merging_none_and_list(self):
        assert merge_errors(None, ["error1", "error2"]) == ["error1", "error2"]

    def test_merging_none_and_dict(self):
        assert merge_errors(None, {"field1": "error1"}) == {"field1": "error1"}

    def test_merging_string_and_none(self):
        assert merge_errors("error1", None) == "error1"

    def test_merging_custom_error_and_none(self):
        assert CustomError(123, "error1") == merge_errors(
            CustomError(123, "error1"), None
        )

    def test_merging_list_and_none(self):
        assert merge_errors(["error1", "error2"], None) == ["error1", "error2"]

    def test_merging_dict_and_none(self):
        assert merge_errors({"field1": "error1"}, None) == {"field1": "error1"}

    def test_merging_string_and_string(self):
        assert merge_errors("error1", "error2") == ["error1", "error2"]

    def test_merging_custom_error_and_string(self):
        assert [CustomError(123, "error1"), "error2"] == merge_errors(
            CustomError(123, "error1"), "error2"
        )

    def test_merging_string_and_custom_error(self):
        assert ["error1", CustomError(123, "error2")] == merge_errors(
            "error1", CustomError(123, "error2")
        )

    def test_merging_custom_error_and_custom_error(self):
        assert [CustomError(123, "error1"), CustomError(456, "error2")] == merge_errors(
            CustomError(123, "error1"), CustomError(456, "error2")
        )

    def test_merging_string_and_list(self):
        assert merge_errors("error1", ["error2"]) == ["error1", "error2"]

    def test_merging_string_and_dict(self):
        assert merge_errors("error1", {"field1": "error2"}) == {
            "_schema": "error1",
            "field1": "error2",
        }

    def test_merging_string_and_dict_with_schema_error(self):
        assert merge_errors("error1", {"_schema": "error2", "field1": "error3"}) == {
            "_schema": ["error1", "error2"],
            "field1": "error3",
        }

    def test_merging_custom_error_and_list(self):
        assert [CustomError(123, "error1"), "error2"] == merge_errors(
            CustomError(123, "error1"), ["error2"]
        )

    def test_merging_custom_error_and_dict(self):
        assert {
            "_schema": CustomError(123, "error1"),
            "field1": "error2",
        } == merge_errors(CustomError(123, "error1"), {"field1": "error2"})

    def test_merging_custom_error_and_dict_with_schema_error(self):
        assert {
            "_schema": [CustomError(123, "error1"), "error2"],
            "field1": "error3",
        } == merge_errors(
            CustomError(123, "error1"), {"_schema": "error2", "field1": "error3"}
        )

    def test_merging_list_and_string(self):
        assert merge_errors(["error1"], "error2") == ["error1", "error2"]

    def test_merging_list_and_custom_error(self):
        assert ["error1", CustomError(123, "error2")] == merge_errors(
            ["error1"], CustomError(123, "error2")
        )

    def test_merging_list_and_list(self):
        assert merge_errors(["error1"], ["error2"]) == ["error1", "error2"]

    def test_merging_list_and_dict(self):
        assert merge_errors(["error1"], {"field1": "error2"}) == {
            "_schema": ["error1"],
            "field1": "error2",
        }

    def test_merging_list_and_dict_with_schema_error(self):
        assert merge_errors(["error1"], {"_schema": "error2", "field1": "error3"}) == {
            "_schema": ["error1", "error2"],
            "field1": "error3",
        }

    def test_merging_dict_and_string(self):
        assert merge_errors({"field1": "error1"}, "error2") == {
            "_schema": "error2",
            "field1": "error1",
        }

    def test_merging_dict_and_custom_error(self):
        assert {
            "_schema": CustomError(123, "error2"),
            "field1": "error1",
        } == merge_errors({"field1": "error1"}, CustomError(123, "error2"))

    def test_merging_dict_and_list(self):
        assert merge_errors({"field1": "error1"}, ["error2"]) == {
            "_schema": ["error2"],
            "field1": "error1",
        }

    def test_merging_dict_and_dict(self):
        assert merge_errors(
            {"field1": "error1", "field2": "error2"},
            {"field2": "error3", "field3": "error4"},
        ) == {
            "field1": "error1",
            "field2": ["error2", "error3"],
            "field3": "error4",
        }

    def test_deep_merging_dicts(self):
        assert merge_errors(
            {"field1": {"field2": "error1"}}, {"field1": {"field2": "error2"}}
        ) == {"field1": {"field2": ["error1", "error2"]}}

    def test_list_not_changed(self):
        store = ErrorStore()
        message = ["foo"]
        store.store_error(message)
        store.store_error(message)
        assert message == ["foo"]
        assert store.errors == {"_schema": ["foo", "foo"]}

    def test_dict_not_changed(self):
        store = ErrorStore()
        message = {"foo": ["bar"]}
        store.store_error(message)
        store.store_error(message)
        assert message == {"foo": ["bar"]}
        assert store.errors == {"foo": ["bar", "bar"]}


class TestStoreErrorCode:
    def test_code_is_attached_to_leaf_messages(self):
        store = ErrorStore()
        store.store_error(["bad"], "email", code="invalid")
        store.store_error(["missing"], "name", code="required")
        assert store.errors == {"email": ["bad"], "name": ["missing"]}
        assert store.errors["email"][0].code == "invalid"
        assert store.errors["name"][0].code == "required"

    def test_code_is_preserved_when_set_on_message(self):
        store = ErrorStore()
        store.store_error([_CodedMessage("bad", "custom")], "email", code="invalid")
        assert store.errors["email"][0].code == "custom"

    def test_existing_codes_survive_merging(self):
        store = ErrorStore()
        store.store_error(["first"], "email", code="invalid")
        store.store_error(["second"], "email", code="required")
        assert store.errors["email"] == ["first", "second"]
        assert [message.code for message in store.errors["email"]] == [
            "invalid",
            "required",
        ]

    def test_structured_message_dict_is_left_alone(self):
        store = ErrorStore()
        store.store_error({"message": "City required", "code": 400}, "city")
        assert store.errors == {"city": {"code": 400, "message": "City required"}}
