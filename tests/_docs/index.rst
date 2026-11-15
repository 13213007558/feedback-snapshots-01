API Reference
=============

.. toctree::
    :maxdepth: 1
    :glob:

    /api/*/*/index

EWF acquisition metadata
------------------------

``EWF.metadata`` exposes the declarations from every ``header`` and ``header2`` section. Each
value keeps its provenance: segment, section kind, section offset and the byte range inside the
decompressed payload. ``EWFMetadata.brief()`` returns only the selected verbatim values, while
``EWFMetadata.summary()`` and ``EWFMetadata.details()`` add the selection status and every
conflicting candidate.

.. code-block:: python

    from dissect.evidence.ewf import EWF

    with EWF("image.E01") as ewf:
        metadata = ewf.metadata

        print(metadata.brief())
        print(metadata["case_number"].value)
        print(metadata["case_number"].candidates)
        print(metadata["acquisition_time"].parsed.timezone_known)
