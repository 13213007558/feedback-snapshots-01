"""Derive two Bleach cleaners (internal page / public email) from one policy.

A team comment is rendered twice: the intranet page keeps the approved
internal formatting markup, while the public email only allows the public
styles and a subset of attributes. Both cleaners are derived from a single
shared policy via deep copies, so each can be generated independently and
neither derivation nor cleaning mutates the shared policy, the original
input, or the other layer's results.

Run from the repository root:

    .venv/bin/python scripts/derive_policies.py
"""

import copy
import html
from html.parser import HTMLParser

from bleach.css_sanitizer import CSSSanitizer
from bleach.sanitizer import Cleaner

# The single shared policy every layer derives from. Public approval is
# fine-grained: per-tag attributes, individual CSS styles, and link
# protocols (sources).
BASE_POLICY = {
    "tags": frozenset({"a", "b", "em", "i", "li", "ol", "strong", "ul"}),
    "attributes": {"a": ["href", "title"]},
    "styles": frozenset({"color", "font-weight"}),
    "protocols": frozenset({"http", "https", "mailto"}),
}

# Internal-only additions: extra formatting markup, its attributes, and the
# intranet-only style values.
INTERNAL_EXTRA = {
    "tags": frozenset({"mark", "span", "u"}),
    "attributes": {"span": ["style", "title"], "mark": ["title"]},
    "styles": frozenset({"background-color", "text-decoration"}),
    "protocols": frozenset(),
}

# Public email additions: span is allowed so the few approved public styles
# can be carried, but link sources are narrowed to https/mailto only.
EMAIL_EXTRA = {
    "tags": frozenset({"span"}),
    "attributes": {"span": ["style"]},
    "styles": frozenset(),
    "protocols": frozenset({"https", "mailto"}),  # replaces, not extends
}


def _merge(base, extra):
    """Deep-copy the shared policy and apply one layer's delta."""
    policy = copy.deepcopy(base)
    policy["tags"] = policy["tags"] | extra["tags"]
    for tag, attrs in extra["attributes"].items():
        policy["attributes"].setdefault(tag, [])
        policy["attributes"][tag] = sorted(
            set(policy["attributes"][tag]) | set(attrs)
        )
    policy["styles"] = policy["styles"] | extra["styles"]
    if extra["protocols"]:
        policy["protocols"] = frozenset(extra["protocols"])
    return policy


def _build_cleaner(policy):
    return Cleaner(
        tags=policy["tags"],
        attributes=policy["attributes"],
        protocols=policy["protocols"],
        css_sanitizer=CSSSanitizer(
            allowed_css_properties=policy["styles"],
            allowed_svg_properties=frozenset(),
        ),
    )


def build_internal_cleaner():
    """Intranet page cleaner, generated independently from the policy."""
    return _build_cleaner(_merge(BASE_POLICY, INTERNAL_EXTRA))


def build_email_cleaner():
    """Public email cleaner, generated independently from the policy."""
    return _build_cleaner(_merge(BASE_POLICY, EMAIL_EXTRA))


def build_internal_only_cleaner():
    """Cleaner built straight from the internal config, no shared policy."""
    return _build_cleaner(_merge(copy.deepcopy(BASE_POLICY), INTERNAL_EXTRA))


# A normal team comment containing synthetic markup. The same names appear
# in both layers and are treated per each layer's meaning: <mark> is an
# approved internal highlight tag but plain text in the email layer;
# "background-color" is an approved style internally but dropped publicly.
COMMENT = (
    "大家看这里：<b>加粗重点</b>，"
    '<span style="color: #c00000; background-color: #ffff99; '
    'text-decoration: underline; font-weight: bold" title="内部批注">'
    "排期结论</span>保留格式，"
    '<mark title="v3 评审">mark</mark> 是内部高亮，<u>下划线</u>仅内网可见。'
    '详情见 <a href="https://example.com/spec" title="公开文档">公开文档</a> 与 '
    '<a href="http://intranet.local/wiki">内网 wiki</a>，'
    '另有伪链接 <a href="javascript:alert(1)">点我</a>。'
    "<script>alert('xss')</script>"
)


class _Outline(HTMLParser):
    """Collect (tag, attrs) pairs and style contents from a cleaned body."""

    def __init__(self):
        super().__init__()
        self.elements = []
        self.styles = []

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))
        for name, value in attrs:
            if name == "style":
                self.styles.append(value)


def _outline(body):
    parser = _Outline()
    parser.feed(body)
    return parser


def _show(label, body):
    print(f"--- {label} ---")
    print("cleaned :", body)
    print("decoded :", html.unescape(body))
    outline = _outline(html.unescape(body))
    for tag, attrs in outline.elements:
        print(f"element : <{tag}> attrs={attrs}")
    for style in outline.styles:
        print(f"style   : {style}")
    print()


def main():
    policy_snapshot = copy.deepcopy(BASE_POLICY)
    original = COMMENT

    internal = build_internal_cleaner()
    email = build_email_cleaner()

    # Interleave page and email generation.
    page_first = internal.clean(COMMENT)
    mail = email.clean(COMMENT)
    page_second = internal.clean(COMMENT)

    _show("internal page", page_first)
    _show("public email", mail)

    # The email pass must not modify the original input, the shared policy,
    # or a later internal-page result.
    assert COMMENT == original, "email cleaning modified the original input"
    assert BASE_POLICY == policy_snapshot, "derivation mutated the shared policy"
    assert page_first == page_second, "email pass affected the internal page"

    # Compare against a cleaner built only from the internal config.
    internal_only = build_internal_only_cleaner().clean(COMMENT)
    assert page_first == internal_only, "independent internal config differs"

    # Same-named text handled per layer meaning.
    assert "<mark title=" in page_first, "internal page lost approved markup"
    assert "<mark" not in mail and "&lt;mark" in mail, "email kept internal tag"
    assert "background-color" in page_first, "internal page lost approved style"
    assert "background-color" not in mail, "email kept internal-only style"
    assert "text-decoration" not in mail, "email kept internal-only style"
    assert "color: #c00000" in mail, "email lost approved public style"
    assert 'href="http://intranet.local/wiki"' in page_first
    assert "intranet.local" not in mail, "email kept non-public link source"
    assert 'href="https://example.com/spec"' in mail, "email lost approved link"
    assert "javascript:" not in page_first and "javascript:" not in mail
    assert "<script" not in page_first and "<script" not in mail

    print("all checks passed")


if __name__ == "__main__":
    main()
