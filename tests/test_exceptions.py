import pytest

from marshmallow import Schema, fields, validates_schema
from marshmallow.exceptions import ValidationError


class TestValidationError:
    def test_stores_message_in_list(self):
        err = ValidationError("foo")
        assert err.messages == ["foo"]

    def test_can_pass_list_of_messages(self):
        err = ValidationError(["foo", "bar"])
        assert err.messages == ["foo", "bar"]

    def test_stores_dictionaries(self):
        messages = {"user": {"email": ["email is invalid"]}}
        err = ValidationError(messages)
        assert err.messages == messages

    def test_can_store_field_name(self):
        err = ValidationError("invalid email", field_name="email")
        assert err.field_name == "email"

    def test_str(self):
        err = ValidationError("invalid email")
        assert str(err) == "invalid email"

        err2 = ValidationError("invalid email", "email")
        assert str(err2) == "invalid email"

    def test_stores_dictionaries_in_messages_dict(self):
        messages = {"user": {"email": ["email is invalid"]}}
        err = ValidationError(messages)
        assert err.messages_dict == messages

    def test_messages_dict_type_error_on_badval(self):
        err = ValidationError("foo")
        with pytest.raises(TypeError) as excinfo:
            err.messages_dict  # noqa: B018
        assert "cannot access 'messages_dict' when 'messages' is of type list" in str(
            excinfo.value
        )


class TestPublicErrorPayload:
    def test_aliased_field_uses_input_location_and_field_code(self):
        class RegisterSchema(Schema):
            email = fields.Email(data_key="contactEmail", required=True)
            password = fields.Str(data_key="password", required=True)

        schema = RegisterSchema()
        with pytest.raises(ValidationError) as excinfo:
            schema.load({"contactEmail": "not-an-email"})

        payload = excinfo.value.to_public_dict()
        assert payload == {
            "errors": [
                {"location": ["contactEmail"], "code": "invalid"},
                {"location": ["password"], "code": "required"},
            ]
        }

    def test_batch_item_location_includes_index(self):
        class MemberSchema(Schema):
            email = fields.Email(data_key="contactEmail", required=True)
            nickname = fields.Str(required=True)

        data = [
            {"contactEmail": "ok@example.invalid", "nickname": "ok"},
            {"contactEmail": "not-an-email", "nickname": "second"},
            {"contactEmail": "ok2@example.invalid"},
        ]
        with pytest.raises(ValidationError) as excinfo:
            MemberSchema(many=True).load(data)

        assert excinfo.value.to_public_dict() == {
            "errors": [
                {"location": [1, "contactEmail"], "code": "invalid"},
                {"location": [2, "nickname"], "code": "required"},
            ]
        }

    def test_cross_field_error_has_field_location(self):
        class PasswordSchema(Schema):
            email = fields.Email(data_key="contactEmail")
            password = fields.Str(data_key="password")

            @validates_schema
            def check(self, data, **kwargs):
                if data["password"] in data["email"]:
                    raise ValidationError(
                        "password must not contain the email address",
                        field_name="password",
                    )

        with pytest.raises(ValidationError) as excinfo:
            PasswordSchema().load(
                {
                    "contactEmail": "synthetic-secret@example.invalid",
                    "password": "synthetic-secret@example.invalid",
                }
            )

        assert excinfo.value.to_public_dict() == {
            "errors": [{"location": ["password"], "code": "schema"}]
        }

    def test_cross_field_error_without_field_name_is_schema_level(self):
        class RangeSchema(Schema):
            start = fields.Int()
            end = fields.Int()

            @validates_schema
            def check(self, data, **kwargs):
                if data["end"] < data["start"]:
                    raise ValidationError("end must not be less than start")

        with pytest.raises(ValidationError) as excinfo:
            RangeSchema().load({"start": 5, "end": 1})

        assert excinfo.value.to_public_dict() == {
            "errors": [{"location": [], "code": "schema"}]
        }

    def test_payload_does_not_include_input_or_parsed_data(self):
        class SensitiveSchema(Schema):
            token = fields.Str(data_key="apiToken", required=True)
            accepted = fields.Integer()

        raw = {"apiToken": "SYNTHETIC-TOKEN-123", "accepted": "not-an-int"}
        with pytest.raises(ValidationError) as excinfo:
            SensitiveSchema().load(raw)

        err = excinfo.value
        assert err.data == raw
        assert err.valid_data == {"token": "SYNTHETIC-TOKEN-123"}
        payload = err.to_public_dict(include_messages=True)
        assert set(payload) == {"errors"}
        assert "SYNTHETIC-TOKEN-123" not in str(payload)
        assert set(payload["errors"][0]) == {"location", "code", "message"}

    def test_messages_excluded_by_default(self):
        def validate_secret(value):
            raise ValidationError(f"{value} is not allowed")

        class SensitiveSchema(Schema):
            secret = fields.Str(validate=validate_secret)

        with pytest.raises(ValidationError) as excinfo:
            SensitiveSchema().load({"secret": "SYNTHETIC-VALUE"})

        payload = excinfo.value.to_public_dict()
        assert payload == {"errors": [{"location": ["secret"], "code": "invalid"}]}
        assert "SYNTHETIC-VALUE" not in str(payload)

    def test_explicit_code_takes_precedence(self):
        def validate_password(value):
            raise ValidationError("too weak", code="weak_password")

        class RegisterSchema(Schema):
            password = fields.Str(validate=validate_password)

        with pytest.raises(ValidationError) as excinfo:
            RegisterSchema().load({"password": "short"})

        assert excinfo.value.to_public_dict() == {
            "errors": [{"location": ["password"], "code": "weak_password"}]
        }


def test_code_is_keyword_only():
    with pytest.raises(TypeError):
        ValidationError("foo", "field", None, None, "code")  # type: ignore[misc]
