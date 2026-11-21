Caching Validated Documents in a Gateway
----------------------------------------

.. currentmodule:: graphql.gateway

A gateway often parses and validates a document once and reuses the result for
many requests. Parsing is independent of the schema and of the caller's
permissions, so a parsed document can be shared freely. Validation is different:
a result that was accepted for one schema or one external permission policy must
not silently become an execution permit for another. The :mod:`graphql.gateway`
package keeps that distinction explicit.

The :class:`GatewayDocumentCache` records the schema fingerprint and the policy
fingerprint with every validation result. A cached validation result is reused only
when the document, the schema, the policy, the validation rules, and the validation
options all match. A policy change always causes a fresh validation. A purely safe,
additive schema change may reuse an existing accepted result, because the document
remains valid under the new schema. Execution never relies on the cache for
authorization: :func:`authorization_middleware` consults the current policy for every
field before its resolver runs.

A permission policy is any object with a ``fingerprint`` and an
``authorize_field(info)`` method. The :class:`AllowListPermissionPolicy` is a small
built-in implementation:

.. code-block:: python

    from graphql import build_schema
    from graphql.gateway import AllowListPermissionPolicy, GatewayDocumentCache

    schema = build_schema("""
        directive @requiresScope(scope: String!) on FIELD_DEFINITION

        type User {
          id: ID!
          name: String
          email: String @requiresScope(scope: "user:email")
        }

        type Query {
          viewer: User
        }
    """)

    policy = AllowListPermissionPolicy(
        {
            ("Query", "viewer"),
            ("User", "id"),
            ("User", "name"),
        },
        fingerprint="viewer-policy-2026-11-21",
    )

    cache = GatewayDocumentCache()
    result = cache.execute_sync(
        schema,
        "{ viewer { id name email } }",
        policy=policy,
        root_value={
            "viewer": {
                "id": "user-1",
                "name": "Ada",
                "email": "ada@example.com",
            },
        },
    )
    assert result.data == {
        "viewer": {"id": "user-1", "name": "Ada", "email": None},
    }
    assert result.errors[0].extensions == {
        "code": "FORBIDDEN",
        "field": "User.email",
    }

The denied field produced a field error, and its resolver never ran. The
``extensions["gateway"]`` metadata of the result records the schema and policy
fingerprints as well as the parse and validation cache hits. That metadata is meant
for logs and responses, not as proof of authorization.

When a schema changes, :func:`get_schema_fingerprint` changes as well. That
fingerprint also includes the policy metadata (applied directives and extension
fields) reported by :func:`get_authorization_fingerprint`, so attaching a scope
directive changes the schema identity even though GraphQL validation does not
interpret it. A validation result is recomputed unless every reported change is
purely additive and the attached policy metadata is unchanged.
Changes such as a narrowed field type, a changed default, or an applied
authorization directive are never treated as reusable, because they can affect the
meaning of an already-accepted document. When only the policy changes, the validation
cache is invalidated explicitly and the per-field authorization gate is re-applied. A
cache hit therefore never lets a restricted field reach its resolver.

To add a different policy backend, implement the two members of the
:class:`PermissionPolicy` protocol. ``authorize_field`` may return an awaitable when
the decision requires an asynchronous lookup; the middleware awaits it before the
resolver runs.
