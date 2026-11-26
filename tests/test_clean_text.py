"""Tests for bleach.clean_text and Cleaner.clean_text

These cover the plain-text rendering used for preview summaries and other
non-HTML contexts (for example an HTML attribute value), as opposed to
bleach.clean which keeps sanitized markup for the message body.
"""

import json
from html import escape as html_escape

import pytest

import bleach
from bleach import clean, clean_text
from bleach.sanitizer import ALLOWED_TAGS, Cleaner


# A short fragment exercising legal inline/block formatting, plain (ASCII)
# quotation marks, a character entity and non-ASCII text.
SAMPLE = (
    '<p>Hello <b>"naïve"</b> <em>world</em> &amp; '
    '<a href="http://example.com">链接</a> — '
    "<strong>2026</strong></p>"
)


def test_clean_keeps_allowed_markup_for_body():
    # The existing body interface keeps the allowed formatting tags.
    body = clean(SAMPLE)
    assert "<b>" in body
    assert "<em>" in body
    assert "<strong>" in body
    assert "<a " in body
    # Disallowed block tag is escaped, not kept.
    assert "&lt;p&gt;" in body


def test_clean_text_returns_plain_text_without_markup():
    preview = clean_text(SAMPLE)

    assert "<" not in preview
    assert ">" not in preview
    # No markup and no entity references survive.
    assert "&amp;" not in preview
    assert "链接" in preview and "naïve" in preview


def test_clean_text_decodes_entities_keeps_quotes_and_unicode():
    preview = clean_text(SAMPLE)

    # Character entity is decoded to the character it represents.
    assert "&" in preview
    assert "&amp;" not in preview
    # Plain (ASCII) quotation marks are kept verbatim, not entity encoded.
    assert '"naïve"' in preview
    # Non-ASCII text is preserved as-is.
    assert "链接" in preview
    assert "—" in preview


def test_clean_text_strips_every_tag_including_allowed_ones():
    text = 'before <b>bold</b> after <a href="http://x">link</a> end'
    assert clean_text(text) == "before bold after link end"


def test_clean_text_strips_comments_always():
    assert clean_text("visible<!-- secret -->text") == "visibletext"
    # strip_comments on a cleaner must not let comments leak into the text.
    cleaner = Cleaner(strip=False, strip_comments=False)
    assert cleaner.clean_text("visible<!-- secret -->text") == "visibletext"
    assert "secret" not in cleaner.clean_text("visible<!-- secret -->text")


def test_clean_text_guarantees_no_markup_when_cleaner_escapes_tags():
    # A default Cleaner escapes disallowed tags in clean(); clean_text must
    # still strip them so the plain text never contains literal markup.
    cleaner = Cleaner(strip=False)
    body = cleaner.clean("<span>hi</span>")
    preview = cleaner.clean_text("<span>hi</span>")

    assert body == "&lt;span&gt;hi&lt;/span&gt;"
    assert preview == "hi"
    assert "<" not in preview and ">" not in preview


def test_clean_text_drops_executable_markup():
    text = '<script>alert("xss")</script><img src=x onerror=alert(1)>ok'
    preview = clean_text(text)

    # No tags or event handlers survive, so nothing can execute or be parsed
    # back as markup; the inner words remain inert text.
    assert "<" not in preview and ">" not in preview
    assert "onerror" not in preview
    assert "script" not in preview
    assert preview.endswith("ok")


def test_clean_text_is_inert_when_reparsed():
    text = '<script>alert("xss")</script><img src=x onerror=alert(1)>ok'
    preview = clean_text(text)

    # Feeding the result back through clean_text must not introduce any markup.
    reparsed = clean_text(preview)
    assert reparsed == preview
    assert "<" not in reparsed and ">" not in reparsed


def test_clean_text_empty_string():
    assert clean_text("") == ""


@pytest.mark.parametrize("bad", [None, 123, 4.5, ["a"], {"a": 1}])
def test_clean_text_requires_text_type(bad):
    with pytest.raises(TypeError) as exc_info:
        clean_text(bad)
    assert "must be of text type" in str(exc_info.value)

    with pytest.raises(TypeError):
        Cleaner().clean_text(bad)


def test_cleaner_clean_text_matches_module_function():
    cleaner = Cleaner()
    assert cleaner.clean_text(SAMPLE) == clean_text(SAMPLE)


def test_clean_text_respects_allowed_tags_configuration():
    # Both paths apply the same tag rules; "strong" is allowed by default.
    assert "bold" in clean_text("<strong>bold</strong>")
    custom = Cleaner(tags=set())
    assert custom.clean_text("<strong>bold</strong>") == "bold"


def test_clean_and_clean_text_share_text_content():
    # The readable words are the same; only the markup treatment differs.
    preview = clean_text(SAMPLE)
    body = clean(SAMPLE)
    for word in ["Hello", "naïve", "world", "链接", "2026"]:
        assert word in preview
        assert word in body


def test_body_and_attribute_rendering_round_trip():
    # Body result goes into HTML content; attribute result goes into an
    # attribute and is encoded again by the template layer. Decoding the
    # attribute back must recover the exact clean_text output.
    from html import unescape

    body_html = clean(SAMPLE)
    preview = clean_text(SAMPLE)

    # A template engine escapes the raw text while filling the attribute.
    rendered_attribute = f'<a title="{html_escape(preview, quote=True)}">x</a>'
    attr_value = rendered_attribute.split('title="', 1)[1].rsplit('"', 1)[0]

    # The browser/template decodes the attribute to the same text, keeping
    # plain quotes and non-ASCII characters readable.
    assert unescape(attr_value) == preview
    assert '"naïve"' in preview
    assert "链接" in preview

    # The body product still carries its formatting structure.
    assert "<b>" in body_html


def test_saved_products_can_be_read_back_with_their_context():
    # Persist both products, then reload and confirm each still fits its
    # intended consumption point.
    stored = json.dumps({"body": clean(SAMPLE), "preview": clean_text(SAMPLE)})

    reloaded = json.loads(stored)

    # Body still parses as safe HTML and keeps its formatting structure.
    assert reloaded["body"] == clean(reloaded["body"])
    assert "<b>" in reloaded["body"]

    # Preview is still plain text suitable for an attribute: no markup,
    # quotes and non-ASCII characters intact.
    assert reloaded["preview"] == clean_text(SAMPLE)
    assert "<" not in reloaded["preview"]
    assert '"naïve"' in reloaded["preview"]
    assert "链接" in reloaded["preview"]


def test_clean_text_is_exported():
    assert "clean_text" in bleach.__all__
    assert bleach.clean_text is clean_text
    assert ALLOWED_TAGS  # sanity: defaults importable alongside the new API
