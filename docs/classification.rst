=================================
Data Classification of Instances
=================================

.. currentmodule:: jsonschema.classification

Validation answers whether an instance conforms to a schema.
Many audit and compliance processes additionally need to know *how
sensitive* each field of the instance is, and why.
`jsonschema` does not interpret classifications by itself; this module
adds an opt-in collection layer which derives them from annotations in
the schema, using the same branch resolution that validation performed.

The API is deliberately small: embed a classification keyword anywhere a
subschema is allowed, call `classify`, and serialize the result with
`ClassificationResult.to_dict`.

Annotating Schemas
------------------

Any of the keywords in `DEFAULT_KEYWORDS` may be used:

.. code-block:: python

    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "email": {
                "type": "string",
                "x-classification": "confidential",
            },
        },
    }

The value is a level name from the configured policy, ordered from least
to most sensitive.
`DEFAULT_LEVELS` is
``("public", "internal", "confidential", "restricted")``; a
`ClassificationPolicy` may rename or reorder them, and may restrict the
recognized keywords.
A mapping such as ``{"level": "confidential", "reason": "..."}`` is also
accepted, in which case only its ``level`` is consumed.

A level which is not part of the policy raises `UnknownLevelError`
rather than being silently treated as a string.
A field whose schema carries no effective classification at all is
reported explicitly with the ``"unknown"`` level and ``"known": false``;
it is never omitted from the approved fields.

Which Branches Count
--------------------

Only definitions which actually apply to the instance contribute levels.
In particular:

``if`` / ``then`` / ``else``
    The condition is evaluated first; only the taken branch is effective.
``allOf``
    Every subschema applies, so their definitions combine (and may
    conflict).
``anyOf`` / ``oneOf``
    Only alternatives which validate the instance are effective.
``$ref`` / ``$dynamicRef``
    The resolved subschema is effective, and source records identify the
    reference which introduced it.
``properties``, ``patternProperties``, ``additionalProperties``,
``dependentSchemas``, ``prefixItems``, ``items``, ``contains``
    Traversed exactly as validation traverses them, descending into
    nested arrays and objects.

Definitions in rejected branches are still recorded, but only in the
``diagnostics.rejected_branches`` section of the document, with
``"effective": false`` and a reason such as ``"else_branch_not_taken"``.
They never appear among the approved fields.

Conflicts
---------

When several effective definitions give one instance location different
levels, the strictest level wins and the location is also listed under
``classification.conflicts`` with all contributing levels and sources.
Definitions which agree produce no conflict.

Invalid Instances
-----------------

Classification is only meaningful for an instance which validated.
When validation fails, `classify` still returns the ordinary validation
errors, but the classification status becomes ``"withheld"``:

* ``classification.fields`` is empty;
* ``classification.conflicts`` is empty;
* potential levels found while inspecting the failing branches are
  placed under ``diagnostics.unapproved_observations``, with
  ``"effective": false``.

No approved view can therefore be mistaken for a valid classification of
invalid input.

The Compliance Document
-----------------------

`ClassificationResult.to_dict` returns a JSON-serializable document:

``format``
    The document format identifier, ``"jsonschema-classification/v1"``.
``schema_id``
    The schema's :kw:`$id`, when present.
``validation``
    ``{"valid": ..., "errors": [...]}``, mirroring regular validation.
``classification``
    The consumer-facing view: ``status``, the ``policy`` used, the
    approved ``fields`` (each with a JSON Pointer ``instance_path``, a
    JSONPath ``json_path``, its ``level``, ``known``, and ``sources``),
    any ``conflicts``, and a ``summary``.
``diagnostics``
    Rejected branch observations, separated from the approved view.

Each source records the schema keyword, its ``schema_path`` and
``schema_uri``, and -- for referenced definitions -- the ``ref`` and
``resolved_uri``, so a reviewer can trace exactly which definition
produced a level.

.. autofunction:: classify

.. autoclass:: ClassificationPolicy
    :members:

.. autoclass:: ClassificationResult
    :members:

.. autoclass:: ClassificationEntry
    :members:

.. autoclass:: ClassificationConflict
    :members:

.. autoclass:: ClassificationSource
    :members:

.. autoexception:: ClassificationConfigurationError

.. autoexception:: UnknownLevelError

Worked Example
--------------

The ``examples/classification`` directory contains a schema whose
``if``/``then``/``else`` selects between two order shapes, each with its
own nested shipment arrays.
``python examples/classification/report.py`` writes the compliance
documents for a retail order, a wholesale order, an intentional level
conflict, and an invalid order into ``examples/classification/reports``.
