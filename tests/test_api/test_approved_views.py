# ruff: noqa: RUF001
from __future__ import annotations

from collections.abc import Iterator
from copy import deepcopy
from html.parser import HTMLParser
from typing import Any, cast

from markdown_it import (
    ApprovalScope,
    MarkdownIt,
    approved_view,
    label_access,
)
from markdown_it.access import approved_components
from markdown_it.common.utils import escapeHtml
from markdown_it.renderer import RendererHTML
from markdown_it.token import Token

DOC = """# 发布公告**内部标题密语**

![架构图：**公开粗体**；_内部图中密语_](arch.png "内部图题")

正文公开 _排版_；代号**Orion-77**；结尾公开。
"""

SECRETS = (
    "内部标题密语",
    "内部图中密语",
    "内部图题",
    "Orion-77",
    "INTERNAL-AUDIT-7788",
)


class AuditingRenderer(RendererHTML):
    """Existing-style custom renderer with two ordinary render rules."""

    def heading_open(
        self,
        tokens: Any,
        idx: int,
        options: Any,
        env: Any,
    ) -> str:
        token = tokens[idx]
        opening = self.renderToken(tokens, idx, options, env)
        note = token.meta.get("audit_note")
        if note:
            return opening + (
                '<span class="audit audit-internal">'
                + escapeHtml(str(note))
                + "</span>"
            )
        return opening + '<span class="audit audit-public">PUBLIC-AUDIT-OK</span>'

    def image(
        self,
        tokens: Any,
        idx: int,
        options: Any,
        env: Any,
    ) -> str:
        rendered = super().image(tokens, idx, options, env)
        token = tokens[idx]
        source = self.renderInlineAsText(token.children, options, env)
        parts = ",".join(sorted(approved_components(token).keys()))
        return rendered + (
            '<span class="plugin-image-help" data-parts="'
            + escapeHtml(parts)
            + '">PLUGIN_HELP:'
            + escapeHtml(source)
            + "</span>"
        )


def walk_tokens(tokens: list[Token]) -> Iterator[Token]:
    for token in tokens:
        yield token
        if token.children:
            yield from walk_tokens(token.children)


def mark_enclosing_emphasis(tokens: list[Token], text: str, level: str) -> None:
    for index, token in enumerate(tokens):
        if token.type == "text" and token.content == text:
            for candidate in reversed(tokens[:index]):
                if candidate.nesting == 1:
                    label_access(candidate, level)
                    break
        if token.children:
            mark_enclosing_emphasis(token.children, text, level)


def build_document() -> tuple[MarkdownIt, list[Token]]:
    md = MarkdownIt("commonmark", renderer_cls=AuditingRenderer)
    tokens = md.parse(DOC)

    mark_enclosing_emphasis(tokens, "内部标题密语", "internal")
    mark_enclosing_emphasis(tokens, "内部图中密语", "internal")
    mark_enclosing_emphasis(tokens, "Orion-77", "internal")

    for token in walk_tokens(tokens):
        if token.type == "image":
            label_access(token, attrs={"title": "internal"})
        if token.type == "heading_open":
            label_access(token, meta={"audit_note": "internal"})
            token.meta["audit_note"] = "INTERNAL-AUDIT-7788"

    return md, tokens


class HTMLInspector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.text: list[str] = []
        self.images: list[dict[str, str | None]] = []
        self.spans: list[tuple[tuple[str, str | None], str]] = []
        self._span_attrs: dict[str, str | None] | None = None
        self._span_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "img":
            self.images.append(attributes)
        if tag == "span":
            self._span_attrs = attributes
            self._span_text = []

    def handle_data(self, data: str) -> None:
        self.text.append(data)
        if self._span_attrs is not None:
            self._span_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "span" and self._span_attrs is not None:
            cls = self._span_attrs.get("class") or ""
            self.spans.append(
                ((cls, self._span_attrs.get("data-parts")), "".join(self._span_text))
            )
            self._span_attrs = None
            self._span_text = []


def inspect(html: str) -> HTMLInspector:
    parser = HTMLInspector()
    parser.feed(html)
    return parser


def test_public_internal_public_sequence_is_stable_and_non_mutating() -> None:
    md, tokens = build_document()
    original = deepcopy([token.as_dict() for token in tokens])

    public_1 = md.render_scoped(tokens, ApprovalScope.public(), {})
    internal = md.render_scoped(tokens, ApprovalScope.internal(), {})
    public_2 = md.render_scoped(tokens, "public", {})

    assert public_1 == public_2
    assert [token.as_dict() for token in tokens] == original

    public_inspection = inspect(public_1)
    internal_inspection = inspect(internal)

    public_text = "".join(public_inspection.text)
    internal_text = "".join(internal_inspection.text)

    for secret in SECRETS:
        assert secret not in public_1
        assert secret in internal

    for secret in (
        "内部标题密语",
        "内部图中密语",
        "Orion-77",
        "INTERNAL-AUDIT-7788",
    ):
        assert secret not in public_text
        assert secret in internal_text

    assert "发布公告" in public_text
    assert "架构图：公开粗体；" in public_text
    assert "正文公开" in public_text
    assert "排版" in public_text
    assert "结尾公开" in public_text
    assert "PUBLIC-AUDIT-OK" in public_text

    assert public_inspection.images == [
        {
            "src": "arch.png",
            "alt": "架构图：公开粗体；",
        }
    ]
    assert internal_inspection.images == [
        {
            "src": "arch.png",
            "alt": "架构图：公开粗体；内部图中密语",
            "title": "内部图题",
        }
    ]

    public_help = [
        text
        for (cls, parts), text in public_inspection.spans
        if "plugin-image-help" in cls
    ]
    internal_help = [
        text
        for (cls, parts), text in internal_inspection.spans
        if "plugin-image-help" in cls
    ]
    assert public_help == ["PLUGIN_HELP:架构图：公开粗体；"]
    assert internal_help == ["PLUGIN_HELP:架构图：公开粗体；内部图中密语"]
    public_parts = next(
        data_parts
        for (cls, data_parts), _ in public_inspection.spans
        if "plugin-image-help" in cls
    )
    assert public_parts is not None
    assert {"type", "tag", "attrs", "content", "children", "meta"} <= set(
        public_parts.split(",")
    )

    assert '<span class="audit audit-public">PUBLIC-AUDIT-OK</span>发布公告' in public_1
    assert (
        '<span class="audit audit-internal">INTERNAL-AUDIT-7788</span>发布公告'
        in internal
    )

    image_token = next(token for token in walk_tokens(tokens) if token.type == "image")
    assert image_token.attrGet("alt") == ""
    assert image_token.children is not None
    assert any(
        token.content == "内部图中密语" for token in walk_tokens(image_token.children)
    )


def test_public_view_can_be_rendered_twice_and_remains_stable() -> None:
    md, tokens = build_document()
    view = approved_view(tokens, "public")

    first = md.renderer.render(view, md.options, {})
    second = md.renderer.render(view, md.options, {})

    assert first == second
    assert "Orion-77" not in first
    assert view.scope.name == "public"


def test_public_view_is_safe_after_direct_original_internal_render() -> None:
    md, tokens = build_document()
    public_before = md.render_scoped(tokens, "public")

    # Backwards-compatible direct use of the original stream may derive and
    # write image alt exactly as RendererHTML has always done.
    md.renderer.render(tokens, md.options, {})
    image_token = next(token for token in walk_tokens(tokens) if token.type == "image")
    assert "内部图中密语" in str(image_token.attrGet("alt"))

    public_after = md.render_scoped(tokens, "public")
    assert public_after == public_before
    assert "内部图中密语" not in public_after


def test_existing_function_render_rule_receives_only_projected_components() -> None:
    md = MarkdownIt("commonmark")

    def paragraph_open(
        renderer: RendererHTML,
        tokens: list[Token],
        idx: int,
        options: Any,
        env: Any,
    ) -> str:
        token = tokens[idx]
        token.attrSet("data-plugin", "approved")
        return renderer.renderToken(tokens, idx, options, env)

    md.add_render_rule("paragraph_open", paragraph_open)
    tokens = md.parse("公开 **密语** 结尾\n")
    strong_open = next(
        token for token in walk_tokens(tokens) if token.type == "strong_open"
    )
    label_access(strong_open, "internal")

    html = md.render_scoped(tokens, "public")
    assert 'data-plugin="approved"' in html
    assert "密语" not in html
    assert "<strong>" not in html


def test_predicate_policy_can_implement_external_approval_rules() -> None:
    md = MarkdownIt("commonmark")
    tokens = md.parse("public note\n\nsecret note\n")

    def policy(request: Any) -> bool | None:
        if request.component == "token" and request.source.content == "secret note":
            return False
        return None

    public = md.render_scoped(tokens, ApprovalScope.public(), policy=policy)
    internal = md.render_scoped(tokens, "internal")

    assert "public note" in public
    assert "secret note" not in public
    assert "secret note" in internal


def test_simple_metadata_label_and_redaction_placeholder() -> None:
    md = MarkdownIt("commonmark")
    tokens = md.parse("公开 **SECRET** 结尾\n")
    strong_open = next(
        token for token in walk_tokens(tokens) if token.type == "strong_open"
    )
    strong_open.meta["security_level"] = "internal"

    html = md.render_scoped(
        tokens,
        ApprovalScope.public(redaction="[隐藏]"),
    )

    assert "SECRET" not in html
    assert "[隐藏]" in html
    assert "公开" in html
    assert "结尾" in html


def test_renderer_can_project_raw_tokens_from_env_scope() -> None:
    md, tokens = build_document()
    env: dict[str, Any] = {}
    approved_view(tokens, "public", env=env)

    html = md.renderer.render(tokens, md.options, env)

    assert "Orion-77" not in html
    assert "PUBLIC-AUDIT-OK" in html
    assert "排版" in html


def test_render_inline_as_text_sink_filters_raw_children() -> None:
    md, tokens = build_document()
    image_token = next(token for token in walk_tokens(tokens) if token.type == "image")
    env: dict[str, Any] = {}
    approved_view(tokens, "public", env=env)

    renderer = cast(RendererHTML, md.renderer)
    text = renderer.renderInlineAsText(image_token.children, md.options, env)

    assert text == "架构图：公开粗体；"
    assert "内部图中密语" not in text
