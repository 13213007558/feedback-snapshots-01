"""GraphQL gateway helpers.

The :mod:`graphql.gateway` package provides opt-in helpers for gateways that cache
parsed and validated GraphQL documents. It keeps cache applicability explicit:
parsed documents are reusable across schemas and policies, while validated results
are bound to a schema fingerprint and an external permission policy fingerprint.
Execution always re-applies the current permission policy before resolvers run.
"""

from .document_cache import (
    AllowListPermissionPolicy,
    CacheStats,
    GatewayDocumentCache,
    ParseResult,
    PermissionPolicy,
    PreparedOperation,
    ValidationResult,
    authorization_middleware,
    get_authorization_fingerprint,
    get_document_fingerprint,
    get_schema_fingerprint,
)

__all__ = [
    "AllowListPermissionPolicy",
    "CacheStats",
    "GatewayDocumentCache",
    "ParseResult",
    "PermissionPolicy",
    "PreparedOperation",
    "ValidationResult",
    "authorization_middleware",
    "get_authorization_fingerprint",
    "get_document_fingerprint",
    "get_schema_fingerprint",
]
