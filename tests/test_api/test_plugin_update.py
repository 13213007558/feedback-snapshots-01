"""Test that plugin configuration updates are atomic and versioned per document.

- ``MarkdownIt.use()`` approves parse rules, render rules and options together:
  if a plugin fails partway through initialisation, the previous approved
  configuration keeps serving unchanged.
- A document processed by ``render()`` uses the plugin set approved when it
  started, from parsing through to the final rendered output, even if a new
  configuration is approved in the meantime on the shared instance.
"""

import threading

import pytest

from markdown_it import MarkdownIt


def _make_block_rule(calls, tag, syntax):
    """A block rule matching a line starting with ``syntax``."""

    def _block(state, startLine, endLine, silent):
        start = state.bMarks[startLine] + state.tShift[startLine]
        maximum = state.eMarks[startLine]
        if not state.src.startswith(syntax, start):
            return False
        if silent:
            return True
        calls.append((tag, "block"))
        token = state.push(f"{tag}_block", "div", 0)
        token.content = state.src[start + len(syntax) : maximum]
        token.map = [startLine, startLine + 1]
        state.line = startLine + 1
        return True

    return _block


def _make_inline_rule(calls, tag, syntax):
    """An inline rule matching ``syntax``."""

    def _inline(state, silent):
        if not state.src.startswith(syntax, state.pos):
            return False
        state.pos += len(syntax)
        if not silent:
            calls.append((tag, "inline"))
            token = state.push(f"{tag}_inline", "em", 0)
            token.content = tag
        return True

    return _inline


def _make_render_rules(calls, tag):
    def _render_block(self, tokens, idx, options, env):
        calls.append((tag, "render_block"))
        return f'<div class="{tag}">{tokens[idx].content}</div>\n'

    def _render_inline(self, tokens, idx, options, env):
        calls.append((tag, "render_inline"))
        return f'<em class="{tag}">{tag}</em>'

    return _render_block, _render_inline


class _PauseControl:
    """Lets a document park itself between parsing and rendering."""

    def __init__(self):
        self.armed = False
        self.paused = threading.Event()
        self.release = threading.Event()
        self.token_types = None


def _pausable_v1_plugin(md, calls, control):
    """A normal plugin installing block, inline and render rules at once.

    Additionally installs a core rule that can pause a document after token
    production has finished but before rendering starts.
    """

    def _pause(state):
        if control.armed:
            control.armed = False
            control.token_types = [
                (t.type, [c.type for c in t.children or []]) for t in state.tokens
            ]
            control.paused.set()
            control.release.wait(10)

    render_block, render_inline = _make_render_rules(calls, "v1")
    md.block.ruler.before(
        "paragraph", "v1_block", _make_block_rule(calls, "v1", "v1::")
    )
    md.inline.ruler.push("v1_inline", _make_inline_rule(calls, "v1", "{v1}"))
    md.core.ruler.push("v1_pause", _pause)
    md.add_render_rule("v1_block", render_block)
    md.add_render_rule("v1_inline", render_inline)


def _broken_plugin(md, calls):
    """A plugin that registers only part of itself, then fails."""

    def _poisoned_text(self, tokens, idx, options, env):
        calls.append(("broken", "render_text"))
        return "BROKEN"

    md.block.ruler.before(
        "paragraph", "broken_block", _make_block_rule(calls, "broken", "broken::")
    )
    md.add_render_rule("text", _poisoned_text)
    md.options["xhtmlOut"] = not md.options["xhtmlOut"]
    raise RuntimeError("inline rule initialisation failed")


def _v2_plugin(md, calls):
    """A plugin switching the approved rules and output types to version 2."""
    md.disable(["v1_block", "v1_inline"])
    render_block, render_inline = _make_render_rules(calls, "v2")
    md.block.ruler.before(
        "paragraph", "v2_block", _make_block_rule(calls, "v2", "v2::")
    )
    md.inline.ruler.push("v2_inline", _make_inline_rule(calls, "v2", "{v2}"))
    md.add_render_rule("v2_block", render_block)
    md.add_render_rule("v2_inline", render_inline)


def test_failed_plugin_update_rolls_back():
    """A plugin that fails partway leaves the approved configuration untouched."""
    calls = []
    md = MarkdownIt()
    baseline_html = md.render("plain text")
    baseline_rules = md.get_active_rules()
    baseline_xhtml_out = md.options["xhtmlOut"]

    with pytest.raises(RuntimeError, match="inline rule initialisation failed"):
        md.use(_broken_plugin, calls)

    # nothing of the failed configuration remains registered
    assert "broken_block" not in md.block.ruler.get_all_rules()
    assert md.get_active_rules() == baseline_rules
    assert md.options["xhtmlOut"] == baseline_xhtml_out
    # the old configuration keeps serving, including the shared "text" output
    assert md.render("plain text") == baseline_html
    assert md.render("broken::x") == "<p>broken::x</p>\n"
    # the failed configuration never participated in any public output
    assert calls == []


def test_document_uses_configuration_approved_at_start():
    """A paused document finishes with its approved plugin set, while new
    documents use the configuration approved after a successful update."""
    calls = []
    control = _PauseControl()
    md = MarkdownIt().use(_pausable_v1_plugin, calls, control)

    doc1_src = "v1::first\n\n{v1}"
    doc1_html = []

    # start the first document; it parks itself between parsing and rendering
    control.armed = True
    worker = threading.Thread(target=lambda: doc1_html.append(md.render(doc1_src)))
    worker.start()
    assert control.paused.wait(10)

    # submit an update that registers only a part of itself, then fails
    with pytest.raises(RuntimeError, match="inline rule initialisation failed"):
        md.use(_broken_plugin, calls)

    # the old approved configuration keeps serving new documents
    assert md.render("v1::mid\n\nbroken::no\n\nplain") == (
        '<div class="v1">mid</div>\n<p>broken::no</p>\n<p>plain</p>\n'
    )
    assert "broken_block" not in md.block.ruler.get_all_rules()

    # now a successful update switches rules and output types together
    md.use(_v2_plugin, calls)

    # let the first document finish; it must keep its own approved config
    calls_before_release = len(calls)
    control.release.set()
    worker.join(10)
    assert not worker.is_alive()

    # the first document was parsed with the v1 rules only
    assert control.token_types == [
        ("v1_block", []),
        ("paragraph_open", []),
        ("inline", ["v1_inline"]),
        ("paragraph_close", []),
    ]
    # ... and rendered with the v1 render rules, not the newly approved v2 ones
    assert doc1_html == ['<div class="v1">first</div>\n<p><em class="v1">v1</em></p>\n']
    assert set(calls[calls_before_release:]) == {
        ("v1", "render_block"),
        ("v1", "render_inline"),
    }

    # new documents on the shared instance use the switched configuration
    assert md.render("v2::second\n\n{v2}") == (
        '<div class="v2">second</div>\n<p><em class="v2">v2</em></p>\n'
    )
    new_token_types = [
        (t.type, [c.type for c in t.children or []]) for t in md.parse("v2::x\n\n{v2}")
    ]
    assert new_token_types == [
        ("v2_block", []),
        ("paragraph_open", []),
        ("inline", ["v2_inline"]),
        ("paragraph_close", []),
    ]
    # the old syntax is no longer recognised by the new approved configuration
    assert md.render("v1::gone\n\n{v1}") == "<p>v1::gone</p>\n<p>{v1}</p>\n"

    # the failed configuration never participated in any public output
    assert not [call for call in calls if call[0] == "broken"]
