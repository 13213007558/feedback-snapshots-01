"""Reference definitions must not cross between concatenated sources."""

from __future__ import annotations

import pytest

from markdown_it import MarkdownIt

INTERNAL = "[contact][who]\n\n[who]: https://intranet.example/contact"
EXTERNAL = "[contact][who]\n\n[who]: https://example.net/contact"


def _links(tokens):
    found = []
    for token in tokens:
        for child in token.children or []:
            if child.type in ("link_open", "image"):
                found.append(child)
    return found


def test_sources_render_independently():
    md = MarkdownIt()
    assert md.render(INTERNAL) == (
        '<p><a href="https://intranet.example/contact">contact</a></p>\n'
    )
    assert md.render(EXTERNAL) == (
        '<p><a href="https://example.net/contact">contact</a></p>\n'
    )


def test_plain_concatenation_keeps_single_namespace():
    """Control: without scopes, the first definition wins for both sources."""
    md = MarkdownIt()
    html = md.render(INTERNAL + "\n\n" + EXTERNAL)
    assert html.count('href="https://intranet.example/contact"') == 2
    assert "example.net" not in html


def test_merged_sources_use_their_own_definitions():
    md = MarkdownIt()
    html = md.render_sources({"internal": INTERNAL, "external": EXTERNAL})
    assert html == (
        '<p><a href="https://intranet.example/contact">contact</a></p>\n'
        '<p><a href="https://example.net/contact">contact</a></p>\n'
    )


def test_merged_sources_are_order_independent():
    md = MarkdownIt()
    expected = (
        '<p><a href="https://example.net/contact">contact</a></p>\n'
        '<p><a href="https://intranet.example/contact">contact</a></p>\n'
    )
    assert md.render_sources({"external": EXTERNAL, "internal": INTERNAL}) == expected


def test_reference_from_another_source_does_not_resolve():
    md = MarkdownIt()
    html = md.render_sources(
        {
            "internal": "[who]: https://intranet.example/contact",
            "external": "[contact][who]",
        }
    )
    assert html == "<p>[contact][who]</p>\n"

    html = md.render_sources(
        {"internal": "[contact][who]", "external": "[who]: https://example.net/contact"}
    )
    assert html == "<p>[contact][who]</p>\n"


def test_explicit_shared_definition_wins_in_every_source():
    md = MarkdownIt()
    html = md.render_sources(
        {"internal": INTERNAL, "external": EXTERNAL},
        shared_references={"who": {"href": "https://example.com/contact"}},
    )
    assert html.count('href="https://example.com/contact"') == 2
    assert "intranet" not in html
    assert "example.net" not in html


def test_shared_definitions_only_cover_approved_labels():
    md = MarkdownIt()
    html = md.render_sources(
        {"internal": INTERNAL, "external": EXTERNAL},
        shared_references={"elsewhere": {"href": "https://example.com/"}},
    )
    assert 'href="https://intranet.example/contact"' in html
    assert 'href="https://example.net/contact"' in html


def test_image_references_are_scoped():
    md = MarkdownIt()
    sources = {
        "a": "![logo][pic]\n\n[pic]: /a.png",
        "b": "![logo][pic]\n\n[pic]: /b.png",
    }
    html = md.render_sources(sources)
    assert '<img src="/a.png" alt="logo" />' in html
    assert '<img src="/b.png" alt="logo" />' in html


def test_provenance_is_recorded_on_tokens_and_env():
    md = MarkdownIt()
    tokens, env = md.parse_sources({"internal": INTERNAL, "external": EXTERNAL})

    links = _links(tokens)
    assert [
        (t.attrs["href"], t.meta["reference_scope"], t.meta["reference_source"])
        for t in links
    ] == [
        (
            "https://intranet.example/contact",
            "internal",
            "internal",
        ),
        (
            "https://example.net/contact",
            "external",
            "external",
        ),
    ]
    assert all(t.meta["reference_label"] == "WHO" for t in links)

    scopes = env["reference_scopes"]
    assert scopes["internal"]["WHO"]["href"] == "https://intranet.example/contact"
    assert scopes["internal"]["WHO"]["source"] == "internal"
    assert scopes["external"]["WHO"]["href"] == "https://example.net/contact"
    assert scopes["external"]["WHO"]["source"] == "external"


def test_shared_source_is_reported_on_tokens():
    md = MarkdownIt()
    tokens, _ = md.parse_sources(
        {"internal": INTERNAL, "external": EXTERNAL},
        shared_references={"who": {"href": "https://example.com/contact"}},
    )
    links = _links(tokens)
    assert [t.meta["reference_source"] for t in links] == ["shared", "shared"]
    assert [t.meta["reference_scope"] for t in links] == ["internal", "external"]


def test_labels_are_normalized_in_shared_references():
    md = MarkdownIt()
    html = md.render_sources(
        {"only": "[contact][WHO]"},
        shared_references={"  Who\t": {"href": "https://example.com/contact"}},
    )
    assert html == '<p><a href="https://example.com/contact">contact</a></p>\n'


def test_source_list_forms():
    md = MarkdownIt()
    expected = (
        '<p><a href="https://intranet.example/contact">contact</a></p>\n'
        '<p><a href="https://example.net/contact">contact</a></p>\n'
    )
    assert (
        md.render_sources([("internal", INTERNAL), ("external", EXTERNAL)]) == expected
    )
    assert md.render_sources([INTERNAL, EXTERNAL]) == expected


def test_nested_blocks_keep_their_scope():
    md = MarkdownIt()
    sources = {
        "internal": "> quoted [link][ref]\n>\n> [ref]: /internal",
        "external": "- item [link][ref]\n\n  [ref]: /external",
    }
    html = md.render_sources(sources)
    assert '<a href="/internal">link</a>' in html
    assert '<a href="/external">link</a>' in html


def test_duplicate_definitions_within_a_scope_first_wins():
    md = MarkdownIt()
    tokens, env = md.parse_sources({"a": "[x]: /first\n\n[x]: /second\n\n[x]"})
    assert _links(tokens)[0].attrs["href"] == "/first"
    assert env["duplicate_refs"][0]["href"] == "/second"
    assert env["duplicate_refs"][0]["source"] == "a"


def test_render_scoped_reuses_a_scope_across_calls():
    md = MarkdownIt()
    env = {}
    assert md.render_scoped("[a][ref]", "internal", env=env) == "<p>[a][ref]</p>\n"
    html = md.render_scoped("[ref]: /internal\n\n[b][ref]", "internal", env=env)
    assert html == '<p><a href="/internal">b</a></p>\n'

    # a different scope cannot see the internal definition
    assert md.render_scoped("[b][ref]", "external", env=env) == "<p>[b][ref]</p>\n"


def test_render_scoped_can_share_definitions():
    md = MarkdownIt()
    env = {}
    shared = {"home": {"href": "https://example.com/"}}
    assert '<a href="https://example.com/">home</a>' in md.render_scoped(
        "[home]", "a", env=env, shared_references=shared
    )
    assert '<a href="https://example.com/">home</a>' in md.render_scoped(
        "[home]", "b", env=env, shared_references=shared
    )


def test_unscoped_parsing_is_unchanged():
    md = MarkdownIt()
    env = {}
    html = md.render(INTERNAL, env)
    assert html == '<p><a href="https://intranet.example/contact">contact</a></p>\n'
    assert set(env) == {"references"}
    assert env["references"]["WHO"]["href"] == "https://intranet.example/contact"
    token = _links(md.parse(INTERNAL))[0]
    assert token.meta == {}


@pytest.mark.parametrize(
    "sources",
    [
        [("", "[x]: /x")],
        [("a", "[x]: /a"), ("a", "[x]: /b")],
        [("a", 1)],
        [("a", "[x]: /a", "extra")],
    ],
)
def test_invalid_sources_raise(sources):
    with pytest.raises((TypeError, ValueError)):
        MarkdownIt().render_sources(sources)


def test_invalid_scope_for_single_source_raises():
    md = MarkdownIt()
    with pytest.raises(ValueError):
        md.render_scoped("[x]", "")
    with pytest.raises(TypeError):
        md.render_scoped("[x]", 1)  # type: ignore[arg-type]


def test_scope_ranges_can_be_supplied_for_an_already_concatenated_string():
    """Applications that already joined their sources can pass line ranges."""
    from markdown_it.reference_scopes import merged_sources

    md = MarkdownIt()
    text, env = merged_sources({"internal": INTERNAL, "external": EXTERNAL})
    assert text == INTERNAL + "\n\n" + EXTERNAL
    assert env["reference_scope_ranges"] == [(0, 3, "internal"), (4, 7, "external")]

    html = md.render(text, env)
    assert html == (
        '<p><a href="https://intranet.example/contact">contact</a></p>\n'
        '<p><a href="https://example.net/contact">contact</a></p>\n'
    )


def test_local_definition_does_not_shadow_shared_definition():
    md = MarkdownIt()
    tokens, env = md.parse_sources(
        {"external": "[home]\n\n[home]: https://attacker.example/"},
        shared_references={"home": {"href": "https://example.com/"}},
    )
    assert _links(tokens)[0].attrs["href"] == "https://example.com/"
    assert env["shadowed_refs"] == [
        {
            "title": "",
            "href": "https://attacker.example/",
            "label": "HOME",
            "map": [2, 3],
            "source": "external",
            "reason": "shared",
        }
    ]


def test_inline_definitions_are_attributed_to_their_scope():
    md = MarkdownIt("commonmark", {"inline_definitions": True})
    tokens, _ = md.parse_sources({"internal": "[a]: /internal"})
    definition = tokens[0]
    assert definition.type == "definition"
    assert definition.meta["source"] == "internal"
