"""Demonstrate schema- and policy-aware caching of validated GraphQL documents.

Run from the repository root:

    python examples/gateway_document_cache.py

The example is completely offline. It uses two in-memory schemas and two versions
of an external permission policy with one and the same GraphQL document:

1. Before the upgrade, the policy allows the viewer's email address, and the
   document is executed. The email is returned by its resolver.
2. After the upgrade, the policy no longer grants the email field. The parsed
   document is reused, but the changed policy fingerprint invalidates the cached
   validation result. Even a repeated request that hits both caches still runs the
   per-field authorization gate, which blocks the email field before its resolver
   is called.

The last section also shows a schema version that attaches a scope directive to the
email field. That directive changes the schema's authorization metadata, so the
validation result is not reused even though GraphQL validation would accept the
document.

The cache counters at the end show that neither the parsed AST nor the validation
result is ever treated as an execution permit.
"""

from __future__ import annotations

from typing import Any

from graphql import GraphQLResolveInfo, build_schema, graphql_sync
from graphql.gateway import (
    AllowListPermissionPolicy,
    GatewayDocumentCache,
    authorization_middleware,
)

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

ROOT_VALUE = {
    "viewer": {
        "id": "user-1",
        "name": "Ada",
        "email": "ada@example.com",
    }
}


def build_schema_with_calls(sdl: str, calls: list[str]) -> Any:
    """Build an offline schema whose resolvers only record their field names."""
    schema = build_schema(sdl)

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


def show(label: str, result: Any, calls: list[str]) -> None:
    """Print one request result in a compact, reproducible form."""
    print(f"{label}:")
    print(f"  data: {result.data}")
    print(f"  errors: {[error.message for error in result.errors or []]}")
    print(f"  resolvers called: {calls}")
    gateway = (result.extensions or {}).get("gateway")
    if gateway is not None:
        print(
            "  cache: "
            f"parse_hit={gateway['parse_cache_hit']}, "
            f"validation_hit={gateway['validation_cache_hit']}, "
            f"schema={gateway['schema_fingerprint'][:8]}, "
            f"policy={gateway['policy_fingerprint']}"
        )


def main() -> None:
    cache = GatewayDocumentCache()

    print("== Before the upgrade ==")
    calls_v1: list[str] = []
    schema_v1 = build_schema_with_calls(SCHEMA_V1, calls_v1)
    result_v1 = cache.execute_sync(
        schema_v1,
        DOCUMENT,
        policy=POLICY_V1,
        root_value=ROOT_VALUE,
    )
    show("v1 schema + v1 policy", result_v1, calls_v1)

    print()
    print("== After the policy upgrade, same document and schema ==")
    calls_v1.clear()
    result_tightened = cache.execute_sync(
        schema_v1,
        DOCUMENT,
        policy=POLICY_V2,
        root_value=ROOT_VALUE,
    )
    show("v1 schema + v2 policy", result_tightened, calls_v1)

    print()
    print("== Repeated request under the tightened policy ==")
    calls_v1.clear()
    result_repeat = cache.execute_sync(
        schema_v1,
        DOCUMENT,
        policy=POLICY_V2,
        root_value=ROOT_VALUE,
    )
    show("v1 schema + v2 policy (cached)", result_repeat, calls_v1)

    print()
    print("== New schema version with a field-level scope directive ==")
    calls_v2: list[str] = []
    schema_v2 = build_schema_with_calls(SCHEMA_V2, calls_v2)
    result_v2 = cache.execute_sync(
        schema_v2,
        DOCUMENT,
        policy=POLICY_V2,
        root_value=ROOT_VALUE,
    )
    show("v2 schema + v2 policy", result_v2, calls_v2)

    print()
    print("== Direct middleware check without the cache ==")
    calls_direct: list[str] = []
    schema_direct = build_schema_with_calls(SCHEMA_V1, calls_direct)
    result_direct = graphql_sync(
        schema_direct,
        DOCUMENT,
        root_value=ROOT_VALUE,
        middleware=[authorization_middleware(POLICY_V2)],
    )
    show("v1 schema + v2 policy middleware", result_direct, calls_direct)

    print()
    print(f"cache stats: {cache.stats}")


if __name__ == "__main__":
    main()
