"""Isolated reference namespaces for concatenated Markdown sources.

A Markdown document normally has a single namespace for link reference
definitions::

    [contact]: https://intranet.example/contact

That is the right behaviour for one document, but it is a poor fit when an
application concatenates Markdown from independent sources (for example an
internal announcement template and an external submission).  A definition in
one source would then silently complete a reference in the other source, which
attributes a link to the wrong origin.

With this module, an application can give each source a *reference scope*.  A
reference written in one scope can only use definitions from that scope, plus
definitions that the application explicitly approved as shared::

    md.render_sources(
        {
            "internal": internal_markdown,
            "external": external_markdown,
        },
        shared_references={"home": {"href": "https://example.com/"}},
    )

A single already-concatenated string can be given explicit line ranges with
``env["reference_scope_ranges"]``; :func:`merged_sources` builds one from
separate sources.  :meth:`MarkdownIt.render_scoped` instead parses each source
separately and shares the definitions through ``env``.

The public API lives on :class:`markdown_it.MarkdownIt`; this module contains
the environment conventions and lookup helpers used by the parser rules.

Environment keys
----------------

``env["reference_scope"]``
    The scope currently being parsed.  Set by :meth:`MarkdownIt.parse_scoped`
    and by the core ``inline`` rule for each inline container.
``env["reference_scopes"]``
    ``{scope: {normalized_label: definition}}``, populated while parsing.
``env["reference_scope_ranges"]``
    ``[(start_line, end_line, scope), ...]`` for parsing a single already
    concatenated string.  Ranges are half-open and line numbers are zero
    based.  A range boundary must fall on a block boundary; a paragraph must
    not span two scopes.
``env["shared_references"]``
    ``{normalized_label: definition}`` approved for use by every scope.
``env["shadowed_refs"]``
    Definitions that were ignored for lookup because a shared definition with
    the same label exists.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, MutableMapping
from typing import Any

from .common.utils import normalizeReference
from .utils import EnvType

REFERENCE_SCOPE_KEY = "reference_scope"
REFERENCE_SCOPES_KEY = "reference_scopes"
REFERENCE_SCOPE_RANGES_KEY = "reference_scope_ranges"
SHARED_REFERENCES_KEY = "shared_references"


def get_active_scope(env: EnvType) -> str | None:
    """Return the reference scope active for the current parse, if any."""
    scope = env.get(REFERENCE_SCOPE_KEY)
    if scope is not None and not isinstance(scope, str):
        raise TypeError(
            f"env[{REFERENCE_SCOPE_KEY!r}] should be a str or None, not {type(scope)}"
        )
    return scope


def scope_for_line(env: EnvType, line: int) -> str | None:
    """Return the reference scope that owns a zero-based source line.

    If ``env["reference_scope_ranges"]`` is set, it takes precedence over the
    active scope.  Lines outside all ranges fall back to the active scope.
    """
    ranges = env.get(REFERENCE_SCOPE_RANGES_KEY)
    if ranges:
        for item in ranges:
            if isinstance(item, Mapping):
                try:
                    start = int(item["start"])
                    end = int(item["end"])
                    scope = item["scope"]
                except (KeyError, TypeError, ValueError) as error:
                    raise ValueError(
                        "reference scope ranges must contain start, end and scope"
                    ) from error
            else:
                try:
                    start, end, scope = item
                except (TypeError, ValueError) as error:
                    raise ValueError(
                        "reference scope ranges must be (start, end, scope) tuples"
                    ) from error
            if not isinstance(scope, str):
                raise TypeError(
                    f"reference scope names should be str, not {type(scope)}"
                )
            if start <= line < end:
                return scope
    return get_active_scope(env)


def resolve_reference(env: EnvType, label: str) -> tuple[dict[str, Any], str] | None:
    """Resolve a normalized label, returning ``(definition, source)``.

    Shared definitions take precedence over per-scope definitions with the
    same label.  This keeps an explicitly approved shared definition from
    being shadowed by an unapproved definition in one of the concatenated
    sources.
    """
    scope = get_active_scope(env)

    if scope is None:
        references = env.get("references")
        if isinstance(references, Mapping):
            ref = references.get(label)
            if ref is not None:
                return ref, _definition_source(ref, "document")
        return None

    shared = env.get(SHARED_REFERENCES_KEY)
    if isinstance(shared, Mapping):
        ref = shared.get(label)
        if ref is not None:
            return ref, _definition_source(ref, "shared")

    scoped = env.get(REFERENCE_SCOPES_KEY)
    if isinstance(scoped, Mapping):
        references = scoped.get(scope)
        if isinstance(references, Mapping):
            ref = references.get(label)
            if ref is not None:
                return ref, _definition_source(ref, scope)

    return None


def store_scoped_reference(
    env: EnvType,
    label: str,
    reference: Mapping[str, Any],
    scope: str,
) -> None:
    """Store a definition in one scope.

    As in CommonMark, the first definition of a label in a scope wins.  The
    same label may be defined independently in other scopes.  A definition
    that duplicates a shared label is recorded in ``env["shadowed_refs"]``;
    it is kept in its scope for introspection, but lookup always uses the
    shared definition.
    """
    scoped = env.setdefault(REFERENCE_SCOPES_KEY, {})
    if not isinstance(scoped, MutableMapping):
        raise TypeError(
            f"env[{REFERENCE_SCOPES_KEY!r}] should be a mutable mapping, "
            f"not {type(scoped)}"
        )
    references = scoped.setdefault(scope, {})
    if not isinstance(references, MutableMapping):
        raise TypeError(
            f"env[{REFERENCE_SCOPES_KEY!r}][{scope!r}] should be a mutable "
            f"mapping, not {type(references)}"
        )

    entry = dict(reference)
    entry["source"] = scope

    if label in references:
        env.setdefault("duplicate_refs", []).append(
            {
                "title": entry.get("title", ""),
                "href": entry.get("href", ""),
                "label": label,
                "map": entry.get("map"),
                "source": scope,
            }
        )
        return

    references[label] = entry

    shared = env.get(SHARED_REFERENCES_KEY)
    if isinstance(shared, Mapping) and label in shared:
        env.setdefault("shadowed_refs", []).append(
            {
                "title": entry.get("title", ""),
                "href": entry.get("href", ""),
                "label": label,
                "map": entry.get("map"),
                "source": scope,
                "reason": "shared",
            }
        )


def merge_shared_references(
    env: EnvType, references: Mapping[str, Mapping[str, Any]] | None
) -> None:
    """Add application-approved definitions to ``env["shared_references"]``.

    Labels are normalized exactly like labels written in Markdown, so callers
    may use ``"Contact"`` or ``"contact"`` interchangeably.
    """
    if references is None:
        return
    if not isinstance(references, Mapping):
        raise TypeError(
            "shared_references should be a mapping of label to definition, "
            f"not {type(references)}"
        )

    target = env.setdefault(SHARED_REFERENCES_KEY, {})
    if not isinstance(target, MutableMapping):
        raise TypeError(
            f"env[{SHARED_REFERENCES_KEY!r}] should be a mutable mapping, "
            f"not {type(target)}"
        )

    for raw_label, raw_reference in references.items():
        if not isinstance(raw_label, str):
            raise TypeError(f"reference labels should be str, not {type(raw_label)}")
        label = normalizeReference(raw_label)
        if not label:
            raise ValueError("reference labels may not be empty")
        if not isinstance(raw_reference, Mapping):
            raise TypeError(
                f"reference {raw_label!r} should be a mapping, "
                f"not {type(raw_reference)}"
            )
        entry = dict(raw_reference)
        entry.setdefault("title", "")
        entry.setdefault("href", "")
        entry.setdefault("map", None)
        entry.setdefault("source", "shared")
        target[label] = entry


def record_token_reference(token: Any, env: EnvType, label: str, source: str) -> None:
    """Record where a resolved reference came from on its token.

    Only scoped parses add this metadata, so existing token streams and
    snapshots are unchanged.
    """
    scope = get_active_scope(env)
    if scope is None:
        return
    token.meta["reference_scope"] = scope
    token.meta["reference_source"] = source
    token.meta["reference_label"] = label


def has_reference_namespace(env: EnvType) -> bool:
    """Whether any reference definitions could be available for lookup."""
    return bool(
        env.get(SHARED_REFERENCES_KEY)
        or env.get(REFERENCE_SCOPES_KEY)
        or env.get("references")
    )


def merged_sources(
    sources: Mapping[str, str] | Iterable[tuple[str, str]] | Iterable[str],
    shared_references: Mapping[str, Mapping[str, Any]] | None = None,
    separator: str = "\n\n",
) -> tuple[str, dict[str, Any]]:
    """Join sources into one string and prepare an ``env`` for it.

    The returned string parses exactly like the sources concatenated with
    ``separator``; the returned environment records which line ranges belong
    to which scope, so every reference resolves only against its own source
    (and any explicitly shared definitions).  The caller may add more keys to
    the environment before passing it to :meth:`MarkdownIt.parse`.

    A scope boundary must fall on a block boundary: a paragraph that runs
    into the next source is still one paragraph, and is resolved as part of
    the scope where it starts.
    """
    source_items = normalize_sources(sources)
    text, ranges = make_scope_ranges(source_items, separator=separator)
    env: dict[str, Any] = {REFERENCE_SCOPE_RANGES_KEY: ranges}
    merge_shared_references(env, shared_references)
    return text, env


def _definition_source(reference: Mapping[str, Any], fallback: str) -> str:
    source = reference.get("source")
    return source if isinstance(source, str) else fallback


def normalize_sources(
    sources: Mapping[str, str] | Iterable[tuple[str, str]] | Iterable[str],
) -> list[tuple[str, str]]:
    """Return an ordered ``[(scope, source)]`` list from the input forms.

    Accepted forms are a mapping of ``scope -> Markdown``, an iterable of
    ``(scope, Markdown)`` pairs, or a plain iterable of Markdown strings (in
    which case the scopes are ``"source-0"``, ``"source-1"``, ...).
    """
    if isinstance(sources, str):
        raise TypeError(
            "sources should be a mapping or an iterable of (scope, source) "
            "pairs, not a single string"
        )

    if isinstance(sources, Mapping):
        items = list(sources.items())
    else:
        try:
            raw_items = list(sources)
        except TypeError as error:
            raise TypeError(
                "sources should be a mapping or an iterable of (scope, source) pairs"
            ) from error
        if all(isinstance(item, str) for item in raw_items):
            items = [(f"source-{index}", item) for index, item in enumerate(raw_items)]
        else:
            items = []
            for item in raw_items:
                try:
                    scope, source = item
                except (TypeError, ValueError) as error:
                    raise TypeError(
                        "each source should be a (scope, source) pair of strings"
                    ) from error
                items.append((scope, source))

    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for scope, source in items:
        if not isinstance(scope, str):
            raise TypeError(f"source scopes should be str, not {type(scope)}")
        if not scope:
            raise ValueError("source scopes may not be empty")
        if not isinstance(source, str):
            raise TypeError(
                f"source for scope {scope!r} should be a str, not {type(source)}"
            )
        if scope in seen:
            raise ValueError(f"duplicate source scope: {scope!r}")
        seen.add(scope)
        result.append((scope, source))
    return result


def make_scope_ranges(
    sources: Iterable[tuple[str, str]], separator: str = "\n\n"
) -> tuple[str, list[tuple[int, int, str]]]:
    """Join sources with ``separator`` and return line ranges per scope."""
    parts: list[str] = []
    ranges: list[tuple[int, int, str]] = []
    line = 0
    for index, (scope, source) in enumerate(sources):
        if index:
            parts.append(separator)
            # ``separator`` is a blank line between two blocks; it contributes
            # one line more than the newline that terminates the previous
            # source's last line.
            line += separator.count("\n") - 1
        start = line
        end = start + source.count("\n") + 1
        ranges.append((start, end, scope))
        parts.append(source)
        line = end
    return "".join(parts), ranges
