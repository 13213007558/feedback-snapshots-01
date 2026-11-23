from __future__ import annotations

import json
from unittest import TestCase

from jsonschema import classification

SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://example.com/order",
    "type": "object",
    "required": ["orderType", "shipments"],
    "properties": {
        "orderType": {
            "type": "string",
            "enum": ["retail", "wholesale"],
            "x-classification": "public",
        },
    },
    "allOf": [
        {
            "if": {
                "properties": {"orderType": {"const": "retail"}},
                "required": ["orderType"],
            },
            "then": {
                "properties": {
                    "shipments": {
                        "type": "array",
                        "items": {"$ref": "#/$defs/retailShipment"},
                    },
                },
            },
            "else": {
                "properties": {
                    "shipments": {
                        "type": "array",
                        "items": {"$ref": "#/$defs/freightShipment"},
                    },
                },
            },
        },
    ],
    "$defs": {
        "retailShipment": {
            "type": "object",
            "properties": {
                "parcels": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/retailParcel"},
                },
            },
        },
        "retailParcel": {
            "type": "object",
            "properties": {
                "contents": {
                    "type": "string",
                    "x-classification": "internal",
                },
            },
        },
        "freightShipment": {
            "type": "object",
            "properties": {
                "parcels": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/freightParcel"},
                },
            },
        },
        "freightParcel": {
            "type": "object",
            "properties": {
                "contents": {
                    "type": "string",
                    "x-classification": "confidential",
                },
            },
        },
    },
}


def levels(result):
    return {entry.instance_path: entry.level for entry in result.approved}


class TestClassification(TestCase):
    def test_retail_branch(self):
        instance = {
            "orderType": "retail",
            "shipments": [{"parcels": [{"contents": "books"}]}],
        }
        result = classification.classify(instance, SCHEMA)
        self.assertTrue(result.valid)
        self.assertEqual(result.status, "approved")
        self.assertEqual(
            levels(result),
            {
                "/orderType": "public",
                "/shipments/0/parcels/0/contents": "internal",
            },
        )

    def test_freight_branch(self):
        instance = {
            "orderType": "wholesale",
            "shipments": [{"parcels": [{"contents": "pallets"}]}],
        }
        result = classification.classify(instance, SCHEMA)
        self.assertEqual(result.status, "approved")
        self.assertEqual(
            levels(result),
            {
                "/orderType": "public",
                "/shipments/0/parcels/0/contents": "confidential",
            },
        )

    def test_rejected_branch_is_only_diagnostic(self):
        instance = {
            "orderType": "retail",
            "shipments": [{"parcels": [{"contents": "books"}]}],
        }
        document = classification.classify(instance, SCHEMA).to_dict()
        approved = {
            field["instance_path"]
            for field in document["classification"]["fields"]
        }
        self.assertIn("/shipments/0/parcels/0/contents", approved)
        rejected = {
            source["instance_path"]: source["level"]
            for source in document["diagnostics"]["rejected_branches"]
        }
        self.assertEqual(
            rejected["/shipments/0/parcels/0/contents"],
            "confidential",
        )
        self.assertEqual(
            document["classification"]["summary"]["highest_level"],
            "internal",
        )

    def test_equivalent_definitions_do_not_conflict(self):
        schema = {
            "type": "object",
            "properties": {
                "email": {"type": "string", "x-classification": "internal"},
            },
            "allOf": [
                {
                    "properties": {
                        "email": {
                            "type": "string",
                            "x-classification": "internal",
                        },
                    },
                },
            ],
        }
        result = classification.classify({"email": "a@b"}, schema)
        self.assertEqual(result.conflicts, ())
        self.assertEqual(
            levels(result),
            {"/email": "internal"},
        )

    def test_conflict_uses_strictest(self):
        schema = {
            "type": "object",
            "properties": {
                "email": {"type": "string", "x-classification": "internal"},
            },
            "allOf": [
                {
                    "properties": {
                        "email": {
                            "type": "string",
                            "x-classification": "restricted",
                        },
                    },
                },
            ],
        }
        result = classification.classify({"email": "a@b"}, schema)
        self.assertEqual(
            levels(result),
            {"/email": "restricted"},
        )
        [conflict] = result.conflicts
        self.assertEqual(conflict.instance_path, "/email")
        self.assertEqual(conflict.levels, ("internal", "restricted"))
        self.assertEqual(conflict.selected, "restricted")

    def test_unconfigured_field_is_unknown(self):
        schema = {
            "type": "object",
            "properties": {"email": {"type": "string"}},
        }
        result = classification.classify({"email": "a@b"}, schema)
        [entry] = result.approved
        self.assertEqual(entry.level, classification.UNKNOWN)
        self.assertFalse(entry.known)

    def test_partially_unconfigured_object(self):
        schema = {
            "type": "object",
            "properties": {
                "email": {"type": "string", "x-classification": "internal"},
                "loyaltyId": {"type": "string"},
            },
        }
        result = classification.classify(
            {"email": "a@b", "loyaltyId": "L-1"},
            schema,
        )
        self.assertEqual(
            levels(result),
            {"/email": "internal", "/loyaltyId": "unknown"},
        )

    def test_unknown_level_is_rejected(self):
        schema = {
            "type": "object",
            "properties": {
                "email": {"x-classification": "top-secret"},
            },
        }
        with self.assertRaises(classification.UnknownLevelError):
            classification.classify({"email": "a@b"}, schema)

    def test_invalid_instance_withholds_classification(self):
        instance = {"orderType": "retail", "shipments": [{"parcels": [{}]}]}
        schema = json.loads(json.dumps(SCHEMA))
        schema["$defs"]["retailParcel"]["required"] = ["contents"]
        result = classification.classify(instance, schema)
        self.assertFalse(result.valid)
        self.assertEqual(result.status, "withheld")
        self.assertEqual(result.approved, ())
        document = result.to_dict()
        self.assertEqual(document["classification"]["fields"], [])
        self.assertEqual(document["classification"]["conflicts"], [])
        self.assertEqual(document["validation"]["valid"], False)
        self.assertIn(
            "unapproved_observations",
            document["diagnostics"],
        )

    def test_invalid_instance_does_not_leak_levels(self):
        schema = {
            "type": "object",
            "required": ["email"],
            "properties": {
                "email": {
                    "type": "string",
                    "x-classification": "restricted",
                },
            },
        }
        document = classification.classify({"email": 5}, schema).to_dict()
        self.assertEqual(document["classification"]["status"], "withheld")
        self.assertEqual(document["classification"]["fields"], [])
        self.assertNotIn(
            "restricted",
            json.dumps(document["classification"]["fields"]),
        )
        self.assertNotIn(
            '"restricted"',
            json.dumps(document["classification"]["conflicts"]),
        )

    def test_local_reference_scopes_do_not_collide(self):
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://example.com/root",
            "type": "object",
            "properties": {
                "one": {"$ref": "#/$defs/one"},
                "two": {"$ref": "#/$defs/two"},
            },
            "$defs": {
                "one": {
                    "type": "object",
                    "properties": {
                        "value": {
                            "type": "string",
                            "x-classification": "public",
                        },
                    },
                },
                "two": {
                    "type": "object",
                    "properties": {
                        "value": {
                            "type": "string",
                            "x-classification": "confidential",
                        },
                    },
                },
            },
        }
        result = classification.classify(
            {"one": {"value": "a"}, "two": {"value": "b"}},
            schema,
        )
        self.assertEqual(
            levels(result),
            {
                "/one/value": "public",
                "/two/value": "confidential",
            },
        )

    def test_policy_can_rename_levels(self):
        policy = classification.ClassificationPolicy(
            levels=("low", "high"),
            keywords=("x-level",),
        )
        schema = {
            "type": "object",
            "properties": {"field": {"x-level": "high"}},
        }
        result = classification.classify(
            {"field": 1},
            schema,
            policy=policy,
        )
        self.assertEqual(levels(result), {"/field": "high"})

    def test_non_string_level_is_configuration_error(self):
        schema = {
            "type": "object",
            "properties": {"a": {"x-classification": 4}},
        }
        with self.assertRaises(
            classification.ClassificationConfigurationError
        ):
            classification.classify({"a": 1}, schema)

    def test_schema_uri_is_reported(self):
        result = classification.classify(
            {
                "orderType": "retail",
                "shipments": [{"parcels": [{"contents": "books"}]}],
            },
            SCHEMA,
        )
        document = result.to_dict()
        self.assertEqual(document["schema_id"], "https://example.com/order")
        vendor = {
            source["schema_uri"]
            for field in document["classification"]["fields"]
            for source in field["sources"]
            if "schema_uri" in source
        }
        self.assertIn(
            "https://example.com/order#/$defs/retailParcel"
            "/properties/contents/x-classification",
            vendor,
        )


class TestExternalReferences(TestCase):
    def test_registry_is_used_for_external_refs(self):
        import referencing
        import referencing.jsonschema

        common = {
            "$id": "https://example.com/common",
            "$defs": {
                "email": {
                    "$anchor": "EMAIL",
                    "type": "string",
                    "x-classification": "restricted",
                },
            },
        }
        root = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://example.com/root",
            "type": "object",
            "properties": {
                "email": {"$ref": "https://example.com/common#EMAIL"},
            },
        }
        registry = referencing.Registry().with_resource(
            "https://example.com/common",
            referencing.jsonschema.DRAFT202012.create_resource(common),
        )
        result = classification.classify(
            {"email": "a@b"},
            root,
            registry=registry,
        )
        self.assertEqual(levels(result), {"/email": "restricted"})
        [source] = result.approved[0].sources
        self.assertEqual(source.resolved_uri, "https://example.com/common")
