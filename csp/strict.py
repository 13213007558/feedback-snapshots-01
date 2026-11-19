from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from django.conf import settings

from csp.constants import NONE
from csp.exceptions import CSPStrictError
from csp.utils import DEFAULT_DIRECTIVES, DIRECTIVES_T

# Directives that take no value; their mere presence in the header is the flag.
FLAG_DIRECTIVES = frozenset(key for key, value in DEFAULT_DIRECTIVES.items() if isinstance(value, bool))


@dataclass(frozen=True)
class DirectiveIssue:
    """A single strict-validation finding for one directive."""

    code: str
    directive: str
    location: str
    message: str

    def __str__(self) -> str:
        return f"{self.location}: {self.message}"


@dataclass(frozen=True)
class DirectiveSummary:
    """Which directives a config keeps and which it explicitly removes."""

    kept: dict[str, Any]
    removed: tuple[str, ...]


def strict_mode_enabled() -> bool:
    return bool(getattr(settings, "CSP_STRICT", False))


def registered_extra_directives() -> tuple[str, ...]:
    return tuple(getattr(settings, "CSP_EXTRA_DIRECTIVES", ()))


def _is_empty_value(value: Any) -> bool:
    return isinstance(value, (str, list, tuple, set, frozenset)) and len(value) == 0


def _source_values(value: Any) -> list[Any]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    return [value]


def validate_directives(
    directives: DIRECTIVES_T,
    *,
    origin: str,
    extra_directives: Iterable[str] = (),
) -> list[DirectiveIssue]:
    """
    Validate a directives dict, returning an issue for every entry whose meaning
    is ambiguous or that would be silently ignored when the policy is built.

    ``origin`` should identify the config item being validated (e.g.
    ``'CONTENT_SECURITY_POLICY["DIRECTIVES"]'``) so each issue can be traced
    back to its source. ``extra_directives`` registers deployer-specific
    extension directives that would otherwise be reported as unknown.
    """
    issues: list[DirectiveIssue] = []
    known = set(DEFAULT_DIRECTIVES) | set(extra_directives)

    for directive, value in directives.items():
        location = f"{origin}[{directive!r}]"

        if not isinstance(directive, str) or directive not in known:
            issues.append(
                DirectiveIssue(
                    code="unknown-directive",
                    directive=str(directive),
                    location=location,
                    message=(
                        f"Unknown directive {directive!r}; it will be silently dropped from the policy. "
                        "Register custom directives via the CSP_EXTRA_DIRECTIVES setting."
                    ),
                )
            )
            continue

        if value is None:
            # Explicit removal of the directive; unambiguous and allowed.
            continue

        if directive in FLAG_DIRECTIVES:
            if isinstance(value, bool):
                continue
            if _is_empty_value(value):
                code = "empty-flag-value"
                message = (
                    f"Flag directive {directive!r} has empty value {value!r}, which is rendered as a bare "
                    "flag and silently enables it. Use True to enable, or None/False to omit."
                )
            else:
                code = "invalid-flag-value"
                message = f"Flag directive {directive!r} takes no value, but got {value!r}. " "Use True to enable, or None/False to omit."
            issues.append(DirectiveIssue(code=code, directive=directive, location=location, message=message))
            continue

        if _is_empty_value(value):
            issues.append(
                DirectiveIssue(
                    code="empty-source-list",
                    directive=directive,
                    location=location,
                    message=(
                        f"Directive {directive!r} has empty value {value!r}, which renders as a bare directive "
                        "name that browsers ignore. Use None to remove the directive, or provide at least one source."
                    ),
                )
            )
            continue

        sources = _source_values(value)
        if NONE in sources and len(sources) > 1:
            issues.append(
                DirectiveIssue(
                    code="conflicting-none",
                    directive=directive,
                    location=location,
                    message=(
                        f"Directive {directive!r} combines 'none' with other sources; browsers ignore 'none' "
                        "when other sources are present. Use [NONE] alone, or drop it."
                    ),
                )
            )

    return issues


def validate_directives_or_raise(
    directives: DIRECTIVES_T,
    *,
    origin: str,
    extra_directives: Iterable[str] = (),
) -> None:
    """Validate a directives dict, raising CSPStrictError on the first sign of ambiguity."""
    issues = validate_directives(directives, origin=origin, extra_directives=extra_directives)
    if issues:
        raise CSPStrictError("Strict CSP validation failed:\n" + "\n".join(f"  {issue}" for issue in issues))


def summarize_directives(directives: DIRECTIVES_T) -> DirectiveSummary:
    """Split a directives dict into the directives it keeps and those it explicitly removes."""
    kept = {key: value for key, value in directives.items() if value is not None}
    removed = tuple(key for key, value in directives.items() if value is None)
    return DirectiveSummary(kept=kept, removed=removed)
