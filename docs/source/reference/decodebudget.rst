.. _api_decode_budget:

Decoding budget API
*******************

PDF streams carry filters (such as ``FlateDecode`` or ``LZWDecode``) and
predictors that can expand a small encoded payload into a very large
decoded output. A :class:`~pdfminer.decodebudget.DecodeBudget` bounds the
number of bytes produced while a whole document is processed, protecting
parsers from "decompression bomb" inputs.

Two independent limits are enforced:

- ``step_limit`` caps the output of a single decoding step (one filter
  application or one predictor restoration).
- ``total_limit`` caps the cumulative output of every step across all
  streams of the document.

The budget is charged incrementally, before output is materialized, so
unsupported or unbounded decoding paths raise instead of allocating
first and comparing lengths afterwards. Re-reading an already decoded
stream returns the cached result and is never charged a second time;
re-reading a stream that exhausted the budget keeps raising, so the
limit cannot be bypassed.

The budget is passed per document and propagates to every stream,
including inline images::

    from io import BytesIO
    from pdfminer.decodebudget import DecodeBudget
    from pdfminer.high_level import extract_text

    budget = DecodeBudget(total_limit=64 * 1024 * 1024, step_limit=16 * 1024 * 1024)
    extract_text(BytesIO(pdf_bytes), decode_budget=budget)

When a limit is reached, a
:class:`~pdfminer.decodebudget.PDFDecodeBudgetExceeded` is raised whose
message names the filter or predictor layer that exhausted the budget.

DecodeBudget
============

.. currentmodule:: pdfminer.decodebudget
.. autoclass:: DecodeBudget
    :members:

PDFDecodeBudgetExceeded
=======================

.. currentmodule:: pdfminer.decodebudget
.. autoclass:: PDFDecodeBudgetExceeded
    :members:
