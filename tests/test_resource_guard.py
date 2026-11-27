"""Offline resource-protection regression tests for the Markdown service.

These tests exercise the resource limits a service wrapping
:class:`markdown_it.MarkdownIt` has to enforce before it can be approved for
untrusted input. They deliberately use only ordinary short prose and
*counting*-style rules (characters, blocks, nesting depth) with deliberately
low ceilings, so the suite stays fully offline, deterministic and fast.

Three distinct outcomes must be tellable apart:

* a single oversized block is *discarded* while the rest of the document is
  still rendered (recorded in ``RenderReport.discarded_blocks``);
* a document that is already too large as a whole is rejected *before* parsing
  via :class:`OverallLimitExceededError`, so no renderer work happens;
* a document within every limit is written out completely.

The suite also records the fact that the stock ``MarkdownIt`` entry point has
no overall size/count ceiling of its own (only ``maxNesting``). See
:func:`test_stock_entrypoint_has_no_overall_ceiling`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

import pytest

from markdown_it import MarkdownIt
from markdown_it.renderer import RendererHTML
from markdown_it.token import Token
from markdown_it.utils import EnvType, OptionsDict

# --------------------------------------------------------------------------- #
# Small, deliberately-low ceilings. Everything below uses short prose only.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Limits:
    """Counting-style resource ceilings, kept intentionally small."""

    max_chars: int = 60
    """Whole-document character ceiling enforced before any parsing."""

    max_block_chars: int = 8
    """Characters a single block may span before it is discarded on its own."""

    max_blocks: int = 6
    """Maximum number of block-level rule invocations per document."""

    max_nesting: int = 3
    """Mirror of the parser's built-in ``maxNesting`` recursion guard."""


class ResourceLimitError(Exception):
    """Base class for resource-protection failures."""


# Leading characters that identify a structural (non-paragraph) block.
_BLOCK_MARKERS = frozenset("#>=-+*`<")


class OverallLimitExceededError(ResourceLimitError):
    """Raised when the document as a whole is over a ceiling.

    This aborts the request up front (early termination): no block rule runs
    and the renderer is never invoked, so nothing is partially written.
    """


class BlockCountExceededError(ResourceLimitError):
    """Raised mid-parse once more blocks are produced than ``max_blocks``."""


@dataclass
class RenderReport:
    """What actually happened while producing a response."""

    html: str
    complete: bool
    discarded_blocks: list[str] = field(default_factory=list)
    blocks_seen: int = 0
    render_calls: int = 0
    rendered_fragments: int = 0
    rendered_block_tokens: int = 0


# --------------------------------------------------------------------------- #
# Renderer that records the accumulation cost instead of just returning HTML.
# --------------------------------------------------------------------------- #


class CountingRenderer(RendererHTML):
    """HTML renderer that counts how much work each render accumulates."""

    def __init__(self, parser: object = None) -> None:
        super().__init__(parser)
        self.render_calls = 0
        self.rendered_fragments = 0
        self.rendered_block_tokens = 0

    def reset(self) -> None:
        self.render_calls = 0
        self.rendered_fragments = 0
        self.rendered_block_tokens = 0

    def render(
        self, tokens: Sequence[Token], options: OptionsDict, env: EnvType
    ) -> str:
        self.render_calls += 1
        self.rendered_block_tokens += len(tokens)

        out: list[str] = []
        for i, token in enumerate(tokens):
            if token.type == "inline":
                if token.children:
                    out.append(self.renderInline(token.children, options, env))
            elif token.type in self.rules:
                out.append(self.rules[token.type](tokens, i, options, env))
            else:
                out.append(self.renderToken(tokens, i, options, env))
            # One fragment is appended per top-level token: this is the
            # accumulation the default renderer performs before a single join.
            self.rendered_fragments += 1

        return "".join(out)


# --------------------------------------------------------------------------- #
# Guarded service: a thin wrapper that adds the missing overall ceiling and a
# per-block discard rule on top of the public markdown-it-py API.
# --------------------------------------------------------------------------- #


class GuardedMarkdownService:
    """A service-layer wrapper enforcing :class:`Limits`.

    The parser instance is reused across documents. Per-document counters live
    in ``self._active`` and are reset on every call, which is what makes
    resource release observable in the tests.
    """

    GUARD_RULE = "resource_guard"

    def __init__(self, limits: Limits | None = None) -> None:
        self.limits = limits or Limits()
        self.md = MarkdownIt(
            "commonmark",
            {"maxNesting": self.limits.max_nesting},
            renderer_cls=CountingRenderer,
        )
        self.md.block.ruler.before("paragraph", self.GUARD_RULE, self._guard_block)
        # Per-document state; re-initialised at the start of every render.
        self._active: dict[str, object] = {}

    # -- internal, per-document state helpers -------------------------------- #

    def _new_state(self) -> dict[str, object]:
        self._active = {
            "blocks_seen": 0,
            "discarded": [],
        }
        return self._active

    @property
    def blocks_seen(self) -> int:
        return int(self._active.get("blocks_seen", 0))

    @property
    def discarded_blocks(self) -> list[str]:
        return list(self._active["discarded"])  # type: ignore[arg-type]

    # -- the counting + discard block rule ----------------------------------- #

    def _guard_block(
        self, state: object, start_line: int, _end_line: int, silent: bool
    ) -> bool:
        active = self._active
        active["blocks_seen"] = int(active["blocks_seen"]) + 1
        if int(active["blocks_seen"]) > self.limits.max_blocks:
            raise BlockCountExceededError(
                f"block count {active['blocks_seen']} exceeds "
                f"{self.limits.max_blocks}"
            )

        begin = state.bMarks[start_line]  # type: ignore[attr-defined]
        end = state.eMarks[start_line]  # type: ignore[attr-defined]
        block_text = state.src[begin:end]  # type: ignore[attr-defined]

        # Only plain prose paragraphs are eligible for per-block discard:
        # structural blocks (headings, blockquotes, lists, fences, ...) carry a
        # leading marker and are handed back to their dedicated rules. The block
        # counter above still counts every block regardless of type.
        is_plain_paragraph = block_text[:1] not in _BLOCK_MARKERS

        # Discard only this block when it alone is too wide; the document
        # continues. Consume exactly its line so the parser advances.
        if is_plain_paragraph and len(block_text) > self.limits.max_block_chars:
            if not silent:
                active["discarded"].append(block_text)  # type: ignore[union-attr]
                state.line = start_line + 1  # type: ignore[attr-defined]
            return True

        # Otherwise leave the block to the normal rules untouched.
        return False

    # -- public entry point -------------------------------------------------- #

    def render(self, src: str) -> RenderReport:
        renderer: CountingRenderer = self.md.renderer  # type: ignore[assignment]
        renderer.reset()
        active = self._new_state()

        # Whole-document ceiling: reject before constructing any parse state.
        if len(src) > self.limits.max_chars:
            raise OverallLimitExceededError(
                f"document is {len(src)} chars, limit is {self.limits.max_chars}"
            )

        tokens = self.md.parse(src, {})
        html = renderer.render(tokens, self.md.options, {})

        return RenderReport(
            html=html,
            complete=not active["discarded"],
            discarded_blocks=list(active["discarded"]),  # type: ignore[arg-type]
            blocks_seen=int(active["blocks_seen"]),
            render_calls=renderer.render_calls,
            rendered_fragments=renderer.rendered_fragments,
            rendered_block_tokens=renderer.rendered_block_tokens,
        )


# --------------------------------------------------------------------------- #
# Fixtures and ordinary short prose.
# --------------------------------------------------------------------------- #


@pytest.fixture()
def service() -> GuardedMarkdownService:
    return GuardedMarkdownService()


NORMAL_DOC = "# Title\n\nShort.\n\nAlso.\n"


def test_normal_document_is_written_out_completely(
    service: GuardedMarkdownService,
) -> None:
    """Control case: an in-limit document renders fully with no discards."""
    report = service.render(NORMAL_DOC)

    assert report.complete is True
    assert report.discarded_blocks == []
    assert "<h1>Title</h1>" in report.html
    assert "<p>Short.</p>" in report.html
    assert "<p>Also.</p>" in report.html
    # A complete response still incurs bounded, countable render work.
    assert report.render_calls == 1
    assert report.rendered_fragments >= 1
    assert report.blocks_seen >= 1


def test_single_oversized_block_is_discarded_but_document_continues(
    service: GuardedMarkdownService,
) -> None:
    """One too-wide paragraph is dropped; the neighbouring paragraphs survive."""
    oversized = "x" * (service.limits.max_block_chars + 5)
    doc = f"keep one\n\n{oversized}\n\nkeep two\n"

    report = service.render(doc)

    assert report.complete is False
    assert report.discarded_blocks == [oversized]
    assert "<p>keep one</p>" in report.html
    assert "<p>keep two</p>" in report.html
    assert oversized not in report.html
    # Discarding is a graceful, in-band outcome: the renderer still ran once.
    assert report.render_calls == 1


def test_whole_document_over_ceiling_is_rejected_before_parsing(
    service: GuardedMarkdownService,
) -> None:
    """An over-ceiling document terminates early with zero renderer activity."""
    doc = "a " * (service.limits.max_chars + 10)
    assert len(doc) > service.limits.max_chars

    renderer: CountingRenderer = service.md.renderer  # type: ignore[assignment]
    before_calls = renderer.render_calls
    before_blocks = service.blocks_seen

    with pytest.raises(OverallLimitExceededError):
        service.render(doc)

    # Early termination: no block rule fired and no fragment was rendered.
    assert renderer.render_calls == before_calls
    assert service.blocks_seen == before_blocks
    assert renderer.rendered_fragments == 0
    # The failed request leaves no discarded-block residue behind either.
    assert service.discarded_blocks == []


def test_deep_nesting_is_truncated_to_a_partial_result(
    service: GuardedMarkdownService,
) -> None:
    """The parser's maxNesting guard drops the over-depth tail, not the doc."""
    depth = service.limits.max_nesting + 2
    deep = " ".join([">"] * depth) + " leaf\n"

    report = service.render(deep)

    # The document is accepted (under char/block ceilings) but not complete:
    # the leaf beyond the nesting ceiling is absent while wrappers remain.
    assert report.complete is True  # nothing hit the block discard rule
    assert "leaf" not in report.html
    assert report.html.count("<blockquote>") == service.limits.max_nesting
    assert report.html.count("</blockquote>") == service.limits.max_nesting


def _equal_char_documents() -> tuple[str, str]:
    """One deeply nested paragraph vs many shallow paragraphs, same char count."""
    depth = 6
    deep = " ".join([">"] * depth) + " x"
    target = len(deep)

    words = ["a", "b", "c", "d", "e"]
    base = "\n\n".join(words)
    # Pad the final word so the shallow document matches the deep one exactly.
    pad = target - len(base)
    words[-1] = words[-1] + ("z" * pad)
    shallow = "\n\n".join(words)

    assert len(deep) == len(shallow)
    return deep, shallow


def test_equal_chars_nested_vs_shallow_have_different_cost(
    service: GuardedMarkdownService,
) -> None:
    """Same character count: depth drives nesting, breadth drives block count."""
    deep, shallow = _equal_char_documents()

    deep_report = service.render(deep)
    shallow_report = service.render(shallow)

    assert len(deep) == len(shallow)
    # The nested document concentrates cost in wrapper tokens (blockquotes)...
    assert deep_report.html.count("<blockquote>") >= 1
    # ...while the shallow document fans out into many independent paragraphs.
    assert shallow_report.html.count("<p>") >= 4
    assert shallow_report.blocks_seen > deep_report.blocks_seen
    # Both are cheap, bounded renders under the low ceilings.
    assert deep_report.render_calls == shallow_report.render_calls == 1


def test_failed_document_is_followed_immediately_by_a_clean_one(
    service: GuardedMarkdownService,
) -> None:
    """After an overall-limit failure the next document renders with fresh state."""
    too_big = "a " * (service.limits.max_chars + 10)
    with pytest.raises(OverallLimitExceededError):
        service.render(too_big)

    # Resource release: per-document counters must not carry over.
    report = service.render(NORMAL_DOC)

    assert report.complete is True
    assert report.discarded_blocks == []
    assert report.blocks_seen >= 1
    assert "<h1>Title</h1>" in report.html
    assert report.render_calls == 1
    assert report.rendered_fragments >= 1


def test_partial_discard_then_failure_releases_state(
    service: GuardedMarkdownService,
) -> None:
    """Discard counters reset even when a later request fails wholesale."""
    oversized = "y" * (service.limits.max_block_chars + 4)
    first = service.render(f"ok\n\n{oversized}\n")
    assert first.discarded_blocks == [oversized]

    with pytest.raises(OverallLimitExceededError):
        service.render("z " * (service.limits.max_chars + 5))

    # The earlier discard list must be cleared by the failed second request.
    assert service.discarded_blocks == []

    follow_up = service.render("back\n")
    assert follow_up.complete is True
    assert follow_up.discarded_blocks == []
    assert "<p>back</p>" in follow_up.html


def test_block_count_ceiling_aborts_with_partial_tokens(
    service: GuardedMarkdownService,
) -> None:
    """More blocks than allowed raise mid-parse rather than silently growing."""
    # Each short paragraph is one block; exceed max_blocks while staying small.
    paragraphs = "\n\n".join(f"p{i}" for i in range(service.limits.max_blocks + 3))
    assert len(paragraphs) <= service.limits.max_chars

    with pytest.raises(BlockCountExceededError):
        service.render(paragraphs)

    # The renderer never ran because parsing terminated first.
    renderer: CountingRenderer = service.md.renderer  # type: ignore[assignment]
    assert renderer.render_calls == 0
    assert renderer.rendered_fragments == 0
    # And the abort is fully released for the next document.
    assert service.blocks_seen > 0
    clean = service.render("ok again\n")
    assert clean.complete is True
    assert service.blocks_seen < service.limits.max_blocks


def test_renderer_accumulation_scales_with_token_count(
    service: GuardedMarkdownService,
) -> None:
    """Render accumulation is observable and bounded via the counting renderer."""
    small = service.render("one\n")
    larger = service.render("one\n\ntwo\n\nthree\n")

    assert larger.rendered_block_tokens > small.rendered_block_tokens
    assert larger.rendered_fragments > small.rendered_fragments
    # Every fragment is joined exactly once: fragments never exceed token count.
    assert small.rendered_fragments <= small.rendered_block_tokens
    assert larger.rendered_fragments <= larger.rendered_block_tokens


# --------------------------------------------------------------------------- #
# Gap in the stock entry point: documented rather than silently assumed.
# --------------------------------------------------------------------------- #


def test_stock_entrypoint_has_no_overall_ceiling() -> None:
    """The raw MarkdownIt entry point lacks a whole-document size/count cap.

    markdown-it-py only ships the ``maxNesting`` recursion guard. There is no
    option bounding total characters or the number of blocks/tokens, so a
    service must add that ceiling itself (as GuardedMarkdownService does).
    This test pins that gap so it is visible during release review.
    """
    stock = MarkdownIt("commonmark")

    option_names = set(stock.options.keys())
    assert "maxNesting" in option_names
    # No character/block/token budget exists among the supported options.
    assert (
        not {
            "maxChars",
            "maxLength",
            "maxBlocks",
            "maxTokens",
        }
        & option_names
    )

    # Consequently the stock parser happily processes an oversized document
    # that the guarded service would reject outright.
    big = "word " * 500
    with pytest.raises(OverallLimitExceededError):
        GuardedMarkdownService().render(big)

    # Same input, no exception on the raw entry point: the cap is not built in.
    html = stock.render(big)
    assert "<p>" in html
    assert len(html) > len(big)
