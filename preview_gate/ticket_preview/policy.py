"""Versioned Bleach policy for the ticket external-preview gate.

The external preview used to allow a few "internal" labels (for example
``<span class="internal-tag">``).  :data:`POLICY_VERSION` is bumped to mark
the tightened permission scope.  Cache records carry the rule version that
produced their cleaned artifact so the read path can decide whether to
``reuse``, ``reclean`` or declare the artifact ``unverifiable``.
"""

from __future__ import annotations

import hashlib
import json

import bleach
from bleach import html5lib_shim

POLICY_VERSION = 2
POLICY_VERSION_LABEL = "v2-tightened-internal-scope"
LEGACY_POLICY_VERSION = 1

# Ordinary rich-text typography that may survive on the public page.
# Deliberately excludes ``span``/``div`` class hooks and any internal marker.
PUBLIC_TAGS = frozenset(
    {
        "p",
        "br",
        "hr",
        "strong",
        "b",
        "em",
        "i",
        "u",
        "s",
        "del",
        "ins",
        "mark",
        "small",
        "sub",
        "sup",
        "ul",
        "ol",
        "li",
        "blockquote",
        "pre",
        "code",
        "h3",
        "h4",
        "a",
    }
)

PUBLIC_ATTRIBUTES = {
    "a": ["href", "title"],
}

PUBLIC_PROTOCOLS = frozenset({"http", "https", "mailto"})

# Class tokens that identify internal-only labels under the old policy.
INTERNAL_CLASS_TOKENS = frozenset(
    {
        "internal-tag",
        "internal-only",
        "internal-flag",
        "staff-only",
        "tag-internal",
    }
)

# Elements whose entire subtree (including text) must never reach the public
# preview.  Bleach strips disallowed tags but keeps their text content, so the
# internal markers / active-content nodes have to be pruned before cleaning.
SUBTREE_DROP_TAGS = frozenset(
    {
        "script",
        "style",
        "iframe",
        "object",
        "embed",
        "svg",
        "math",
        "noscript",
        "template",
    }
)

# ---------------------------------------------------------------------------
# Legacy (v1) policy -- only used by the seeding code to manufacture realistic
# historical "already Bleach-cleaned" cache artifacts.  It was XSS-safe but
# kept a handful of internal class labels.
# ---------------------------------------------------------------------------

LEGACY_TAGS = PUBLIC_TAGS | frozenset({"span", "div", "img"})


def legacy_attributes(tag, name, value):
    # Old policy trusted any class hook, including internal-* labels.
    if name == "class":
        return True
    if tag == "a" and name in {"href", "title", "target", "rel"}:
        return True
    if tag == "img" and name in {"src", "alt", "width", "height"}:
        return True
    return False


def bleach_version() -> str:
    return getattr(bleach, "__version__", "unknown")


def _parse_fragment(raw_html: str):
    parser = html5lib_shim.BleachHTMLParser(
        tags=None,
        strip=False,
        consume_entities=False,
        namespaceHTMLElements=False,
    )
    return parser.parseFragment(raw_html or "")


def _serialize_fragment(dom) -> str:
    walker = html5lib_shim.getTreeWalker("etree")
    serializer = html5lib_shim.BleachHTMLSerializer(
        quote_attr_values="always",
        omit_optional_tags=False,
        escape_lt_in_attrs=True,
        resolve_entities=False,
        sanitize=False,
        alphabetical_attributes=False,
    )
    return serializer.render(walker(dom))


def _is_restricted(element) -> bool:
    tag = getattr(element, "tag", None)
    if not isinstance(tag, str):
        return False
    if tag in SUBTREE_DROP_TAGS:
        return True
    if tag.startswith("internal-"):
        return True
    attrib = getattr(element, "attrib", {}) or {}
    if "data-internal" in attrib:
        return True
    class_tokens = set((attrib.get("class") or "").split())
    if class_tokens & INTERNAL_CLASS_TOKENS:
        return True
    return False


def _prune_in_place(node) -> None:
    """Remove restricted elements together with all of their content.

    Tail text that physically follows a removed node belongs to the parent and
    is preserved; only the node's own subtree is dropped.
    """
    kept = []
    for child in list(node):
        if _is_restricted(child):
            tail = child.tail
            if tail:
                if kept:
                    kept[-1].tail = (kept[-1].tail or "") + tail
                else:
                    node.text = (node.text or "") + tail
            continue
        _prune_in_place(child)
        kept.append(child)
    for child in list(node):
        node.remove(child)
    for child in kept:
        node.append(child)


def prune_restricted_nodes(raw_html: str) -> str:
    """Drop internal/active-content subtrees before Bleach tag cleaning."""
    if not raw_html:
        return ""
    dom = _parse_fragment(raw_html)
    _prune_in_place(dom)
    return _serialize_fragment(dom)


def clean_public(raw_html) -> str:
    """Clean one raw field with the current (v2) external policy."""
    if raw_html is None:
        return ""
    pruned = prune_restricted_nodes(str(raw_html))
    return bleach.clean(
        pruned,
        tags=PUBLIC_TAGS,
        attributes=PUBLIC_ATTRIBUTES,
        protocols=PUBLIC_PROTOCOLS,
        strip=True,
        strip_comments=True,
    )


def legacy_clean(raw_html) -> str:
    """Produce a realistic v1 Bleach artifact (seed/fixtures only)."""
    if raw_html is None:
        return ""
    return bleach.clean(
        str(raw_html),
        tags=LEGACY_TAGS,
        attributes=legacy_attributes,
        protocols=PUBLIC_PROTOCOLS,
        strip=True,
        strip_comments=True,
    )


def digest_parts(parts: dict) -> str:
    """Stable SHA-256 over an attested ``{field: raw_html}`` mapping."""
    blob = json.dumps(
        parts or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


def verify_original(original: dict) -> bool:
    if not isinstance(original, dict):
        return False
    parts = original.get("parts")
    expected = original.get("digest")
    if not isinstance(parts, dict) or not expected:
        return False
    return digest_parts(parts) == expected
