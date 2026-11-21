"""Shared fixtures for the gateway cache tests."""

from __future__ import annotations

from typing import Any

from graphql import GraphQLResolveInfo, build_schema
from graphql.gateway import AllowListPermissionPolicy

__all__ = [
    "DOCUMENT",
    "POLICY_V1",
    "POLICY_V2",
    "SCHEMA_V1",
    "SCHEMA_V2",
    "build_calls",
    "make_schema_v1",
    "make_schema_v2",
    "root_value",
]

DOCUMENT = """
query Viewer {
  viewer {
    id
    name
    email
  }
}
"""

SCHEMA_V1 = """
directive @requiresScope(scope: String!) on FIELD_DEFINITION

type User {
  id: ID!
  name: String
  email: String
}

type Query {
  viewer: User
}
"""

SCHEMA_V2 = """
directive @requiresScope(scope: String!) on FIELD_DEFINITION

type User {
  id: ID!
  name: String
  email: String @requiresScope(scope: "user:email")
}

type Query {
  viewer: User
}
"""

POLICY_V1 = AllowListPermissionPolicy(
    {
        ("Query", "viewer"),
        ("User", "id"),
        ("User", "name"),
        ("User", "email"),
    },
    fingerprint="viewer-policy-2026-11-01",
)

POLICY_V2 = AllowListPermissionPolicy(
    {
        ("Query", "viewer"),
        ("User", "id"),
        ("User", "name"),
    },
    fingerprint="viewer-policy-2026-11-21",
)


def build_calls() -> list[str]:
    """Create a list of resolver calls and instrument a schema with it."""
    return []


def _instrument(schema: Any, calls: list[str]) -> Any:
    """Attach resolvers that record calls instead of touching a database."""

    def tracked(name: str) -> Any:
        def resolver(source: Any, _info: GraphQLResolveInfo, **_args: Any) -> Any:
            calls.append(name)
            return source[name]

        return resolver

    for type_name in ("Query", "User"):
        object_type = schema.get_type(type_name)
        for field_name, field in object_type.fields.items():
            field.resolve = tracked(field_name)
    return schema


def make_schema_v1(calls: list[str]) -> Any:
    """Build the schema before the permission-sensitive directive was added."""
    return _instrument(build_schema(SCHEMA_V1), calls)


def make_schema_v2(calls: list[str]) -> Any:
    """Build the schema after the tightened field directive was added."""
    return _instrument(build_schema(SCHEMA_V2), calls)


def root_value() -> dict[str, Any]:
    """Return an in-memory viewer without touching any external service."""
    return {
        "viewer": {
            "id": "user-1",
            "name": "Ada",
            "email": "ada@example.com",
        }
    }
