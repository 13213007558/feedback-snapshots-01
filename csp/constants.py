from typing import Any

HEADER = "Content-Security-Policy"
HEADER_REPORT_ONLY = "Content-Security-Policy-Report-Only"

# Top-level keys supported inside the ``CONTENT_SECURITY_POLICY`` and
# ``CONTENT_SECURITY_POLICY_REPORT_ONLY`` settings dictionaries.
DIRECTIVES = "DIRECTIVES"
EXCLUDE_URL_PREFIXES = "EXCLUDE_URL_PREFIXES"
MEDIA_TYPE_POLICIES = "MEDIA_TYPE_POLICIES"
UNKNOWN_MEDIA_TYPE = "UNKNOWN_MEDIA_TYPE"

# Values for the ``UNKNOWN_MEDIA_TYPE`` setting.
# Fall back to the default (top-level ``DIRECTIVES``) policy, the historical behaviour.
UNKNOWN_MEDIA_TYPE_DEFAULT = "default"
# Do not add a header when the response carries no usable media type.
UNKNOWN_MEDIA_TYPE_SKIP = "skip"

NONE = "'none'"
REPORT_SAMPLE = "'report-sample'"
SELF = "'self'"
STRICT_DYNAMIC = "'strict-dynamic'"
UNSAFE_ALLOW_REDIRECTS = "'unsafe-allow-redirects'"
UNSAFE_EVAL = "'unsafe-eval'"
UNSAFE_HASHES = "'unsafe-hashes'"
UNSAFE_INLINE = "'unsafe-inline'"
WASM_UNSAFE_EVAL = "'wasm-unsafe-eval'"


class Nonce:
    _instance = None

    def __new__(cls: type["Nonce"], *args: Any, **kwargs: Any) -> "Nonce":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "csp.constants.NONCE"


NONCE = Nonce()
