.. _text_evidence:

How to trace extracted text to its source and visibility
********************************************************

``extract_text`` returns the text pdfminer.six can decode. That is useful for
search and indexing, but it does not say whether the text was painted on the
page. Text can be invisible (text rendering mode 3), clipped, covered by a
later object, or drawn inside a Form XObject. Treating the returned string as
"what the page shows" is unsafe for forensic review.

Use :func:`pdfminer.high_level.extract_text_evidence` when the provenance of
the text matters. Each text-showing operator becomes a separate
``TextEvidence`` record; records are never merged, even when two operators draw
at the same coordinates.

.. code-block:: python

    from pdfminer.high_level import extract_text_evidence

    pages = extract_text_evidence("example.pdf")
    for page in pages:
        for run in page.runs:
            print(
                run.text,
                run.visibility,
                run.render_mode,
                run.source.page_index,
                run.source.content_stream_objid,
                run.source.operator_offset,
                run.source.form_path,
                run.bbox,
            )

The same information is available as JSON from the command line:

.. code-block:: console

    $ pdf2txt.py -t evidence -o evidence.json example.pdf

Visibility values
=================

``visible``
    The rendering mode paints glyphs (fill, stroke, or both), and no active
    clip, transparency or detected later overpaint affects the run.

``invisible``
    The active text rendering mode is 3 (neither fill nor stroke) or 7 (clip
    only). This is a content-stream fact and can be used to identify hidden
    text.

``unknown``
    pdfminer.six cannot fully decide. This is reported when a clipping path is
    active, when transparency or a non-Normal blend mode is active, when the
    glyph leaves the page or Form BBox, or when a later painted object overlaps
    the glyph bounds. Do not treat ``unknown`` as visible. In particular,
    ``bbox`` is a location hint; being inside the page rectangle is not proof
    of visibility.

``TextSource`` records the page index, page object id, content stream object
and generation, the index in the page ``/Contents`` array, the byte offset of
the text-showing operator in the decoded stream, and the Form XObject nesting
path. ``GlyphEvidence`` records the glyph id, decoded character, font, advance,
text-line position, page-space matrix and page-space bounds.
