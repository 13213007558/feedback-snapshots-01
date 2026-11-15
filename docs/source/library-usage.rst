Library usage
#############

Use the :py:class:`~pcapng.scanner.FileScanner` class to iterate over blocks
in a pcap-ng archive file, like this:

.. code-block:: python

    from pcapng import FileScanner

    with open('/tmp/mycapture.pcap') as fp:
        scanner = FileScanner(fp)
        for block in scanner:
            pass  # do something with the block...

Block types can be checked against blocks in :py:mod:`pcapng.blocks`.

Strictness
==========

Strictness controls whether questionable data raises, warns or is repaired.
The default is process-wide, but independent tasks should carry their own
policy:

.. code-block:: python

    from pcapng import FileScanner, FileWriter
    from pcapng.strictness import Strictness, strictness_scope

    # Explicit per-reader/per-writer policy
    blocks = list(FileScanner(fp, strictness=Strictness.FORBID))
    writer = FileWriter(out, shb, strictness=Strictness.FIX)

    # Or scope an entire operation; restored on exit and safe to nest
    with strictness_scope(Strictness.FIX):
        blocks = list(FileScanner(fp))

Blocks and options capture the policy of the task that created them.  This
keeps deferred diagnostics (such as a repeated non-repeatable option decoded
later) and writer auto-repairs attributed to the same task.  An explicitly
configured reader or writer keeps its policy even if unrelated work runs
inside another scope.  :py:func:`pcapng.strictness.set_strictness` remains
as the compatibility global fallback.
