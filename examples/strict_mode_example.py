"""
Runnable example of django-csp strict directive validation.

Shows how the strict validator (enabled via ``CSP_STRICT = True``) distinguishes:

* legal explicit removal (``None``),
* flag directives with an ambiguous empty value,
* conflicting 'none' source combinations,
* unknown directives that would be silently dropped,
* deployer-registered extension directives,

and finishes by printing which directives are kept and which are removed.

Run from the repository root:

    python examples/strict_mode_example.py
"""

from csp.constants import NONE, SELF
from csp.strict import summarize_directives, validate_directives
from csp.utils import build_policy

ORIGIN = 'CONTENT_SECURITY_POLICY["DIRECTIVES"]'

# A directives dict containing one entry per ambiguity the strict validator
# catches, alongside legitimate entries.
PROBLEMATIC_DIRECTIVES = {
    # Kept: an ordinary, unambiguous source list.
    "default-src": [SELF],
    # Legal explicit removal: None drops the directive from the header.
    "frame-ancestors": None,
    # Ambiguous: a flag directive with an empty value is silently rendered as
    # a bare flag, enabling it.
    "upgrade-insecure-requests": [],
    # Conflicting: 'none' combined with other sources is ignored by browsers.
    "script-src": [NONE, "cdn.example.com"],
    # Unknown: silently dropped unless registered as an extension directive.
    "x-acme-tracking": ["https://tracker.example"],
}

# Deployer-registered extension directives (CSP_EXTRA_DIRECTIVES).
EXTRA_DIRECTIVES = ["x-acme-tracking"]

# The same policy expressed unambiguously: passes strict validation.
CORRECTED_DIRECTIVES = {
    "default-src": [SELF],
    "frame-ancestors": None,  # explicit removal
    "upgrade-insecure-requests": True,  # explicit flag
    "script-src": ["cdn.example.com"],  # conflict resolved
    "x-acme-tracking": ["https://tracker.example"],  # registered extension
}


def main() -> None:
    print("== 1. Strict validation of the problematic config ==")
    issues = validate_directives(PROBLEMATIC_DIRECTIVES, origin=ORIGIN)
    for issue in issues:
        print(f"  [{issue.code}] {issue}")

    print("\n== 2. After registering the extension directive ==")
    issues = validate_directives(PROBLEMATIC_DIRECTIVES, origin=ORIGIN, extra_directives=EXTRA_DIRECTIVES)
    for issue in issues:
        print(f"  [{issue.code}] {issue}")

    print("\n== 3. Strict validation of the corrected config ==")
    issues = validate_directives(CORRECTED_DIRECTIVES, origin=ORIGIN, extra_directives=EXTRA_DIRECTIVES)
    if issues:
        for issue in issues:
            print(f"  [{issue.code}] {issue}")
    else:
        print("  No issues: every directive is semantically unambiguous.")

    print("\n== 4. Final output: kept vs removed ==")
    summary = summarize_directives(CORRECTED_DIRECTIVES)
    policy = build_policy(config=CORRECTED_DIRECTIVES)
    print(f"  Content-Security-Policy: {policy}")
    print(f"  Kept directives:    {', '.join(summary.kept)}")
    print(f"  Removed directives: {', '.join(summary.removed)}")


if __name__ == "__main__":
    main()
