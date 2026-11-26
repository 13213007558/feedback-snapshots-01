from bleach.linkifier import (
    DEFAULT_CALLBACKS,
    Linker,
)
from bleach.sanitizer import (
    ALLOWED_ATTRIBUTES,
    ALLOWED_PROTOCOLS,
    ALLOWED_TAGS,
    Cleaner,
)


# yyyymmdd
__releasedate__ = "20260605"
# x.y.z or x.y.z.dev0 -- semver
__version__ = "6.4.0"


__all__ = ["clean", "clean_text", "linkify"]


def clean(
    text,
    tags=ALLOWED_TAGS,
    attributes=ALLOWED_ATTRIBUTES,
    protocols=ALLOWED_PROTOCOLS,
    strip=False,
    strip_comments=True,
    css_sanitizer=None,
):
    """Clean an HTML fragment of malicious content and return it

    This function is a security-focused function whose sole purpose is to
    remove malicious content from a string such that it can be displayed as
    content in a web page.

    This function is not designed to use to transform content to be used in
    non-web-page contexts.

    Example::

        import bleach

        better_text = bleach.clean(yucky_text)


    .. Note::

       If you're cleaning a lot of text and passing the same argument values or
       you want more configurability, consider using a
       :py:class:`bleach.sanitizer.Cleaner` instance.

    :arg str text: the text to clean

    :arg set tags: set of allowed tags; defaults to
        ``bleach.sanitizer.ALLOWED_TAGS``

    :arg dict attributes: allowed attributes; can be a callable, list or dict;
        defaults to ``bleach.sanitizer.ALLOWED_ATTRIBUTES``

    :arg set protocols: set of allowed protocols for links; defaults
        to ``bleach.sanitizer.ALLOWED_PROTOCOLS``

    :arg bool strip: whether or not to strip disallowed elements

    :arg bool strip_comments: whether or not to strip HTML comments

    :arg CSSSanitizer css_sanitizer: instance with a "sanitize_css" method for
        sanitizing style attribute values and style text; defaults to None

    :returns: cleaned text as unicode

    """
    cleaner = Cleaner(
        tags=tags,
        attributes=attributes,
        protocols=protocols,
        strip=strip,
        strip_comments=strip_comments,
        css_sanitizer=css_sanitizer,
    )
    return cleaner.clean(text)


def clean_text(
    text,
    tags=ALLOWED_TAGS,
    attributes=ALLOWED_ATTRIBUTES,
    protocols=ALLOWED_PROTOCOLS,
    css_sanitizer=None,
):
    """Clean an HTML fragment and return its plain text content

    This applies the same tag, attribute and protocol rules as
    :py:func:`clean`, but instead of returning HTML, it returns the visible
    text with every tag, attribute and comment removed. Character entities are
    decoded to the characters they represent, so the result contains no markup
    and no HTML entity references.

    Use :py:func:`clean` when the result is rendered as HTML content (the
    message body) and :py:func:`clean_text` when the result is consumed as
    plain text, for example a preview summary placed in an HTML attribute
    value::

        import bleach

        body_html = bleach.clean(user_text)
        preview = bleach.clean_text(user_text)

        # The template engine escapes ``preview`` while it fills the
        # attribute; clean_text must not pre-escape it.
        '<a title="{{ preview }}">{{ body_html|safe }}</a>'

    Tags and comments are always stripped, so the result never contains
    literal markup regardless of the arguments given. The returned value is
    left unescaped on purpose. Inserting it into an HTML attribute without the
    template engine's escaping (for example via string concatenation) is
    unsafe, just as it would be for any other raw text.

    :arg str text: the text to clean

    :arg set tags: set of allowed tags; defaults to
        ``bleach.sanitizer.ALLOWED_TAGS``

    :arg dict attributes: allowed attributes; can be a callable, list or dict;
        defaults to ``bleach.sanitizer.ALLOWED_ATTRIBUTES``

    :arg set protocols: set of allowed protocols for links; defaults
        to ``bleach.sanitizer.ALLOWED_PROTOCOLS``

    :arg CSSSanitizer css_sanitizer: instance with a "sanitize_css" method for
        sanitizing style attribute values and style text; defaults to None

    :returns: sanitized plain text as unicode

    """
    cleaner = Cleaner(
        tags=tags,
        attributes=attributes,
        protocols=protocols,
        strip=True,
        strip_comments=True,
        css_sanitizer=css_sanitizer,
    )
    return cleaner.clean_text(text)


def linkify(text, callbacks=DEFAULT_CALLBACKS, skip_tags=None, parse_email=False):
    """Convert URL-like strings in an HTML fragment to links

    This function converts strings that look like URLs, domain names and email
    addresses in text that may be an HTML fragment to links, while preserving:

    1. links already in the string
    2. urls found in attributes
    3. email addresses

    linkify does a best-effort approach and tries to recover from bad
    situations due to crazy text.

    .. Note::

       If you're linking a lot of text and passing the same argument values or
       you want more configurability, consider using a
       :py:class:`bleach.linkifier.Linker` instance.

    .. Note::

       If you have text that you want to clean and then linkify, consider using
       the :py:class:`bleach.linkifier.LinkifyFilter` as a filter in the clean
       pass. That way you're not parsing the HTML twice.

    :arg str text: the text to linkify

    :arg list callbacks: list of callbacks to run when adjusting tag attributes;
        defaults to ``bleach.linkifier.DEFAULT_CALLBACKS``

    :arg list skip_tags: list of tags that you don't want to linkify the
        contents of; for example, you could set this to ``['pre']`` to skip
        linkifying contents of ``pre`` tags

    :arg bool parse_email: whether or not to linkify email addresses

    :returns: linkified text as unicode

    """
    linker = Linker(callbacks=callbacks, skip_tags=skip_tags, parse_email=parse_email)
    return linker.linkify(text)
