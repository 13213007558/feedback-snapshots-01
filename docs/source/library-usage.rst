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

Raw view vs edit view
=====================

Several block properties are derived from metadata that lives elsewhere:
an Enhanced Packet's ``timestamp`` depends on the interface's ``if_tsresol``
option, a Simple Packet's ``captured_len`` depends on the interface's
``snaplen``, and both depend on the section's ``endianness``.  Because that
metadata is mutable, every block exposes two explicit views:

* ``block.raw_view`` -- the values decoded from the capture, together with
  the interface and section metadata that was effective while reading.
  It is a snapshot: later edits to an ``InterfaceDescription`` or
  ``SectionHeader`` never change it, and it cannot be mutated through the
  objects it returns.
* ``block.edit_view`` -- values computed from the block's current fields and
  the *current* interface/section metadata.

Plain attribute access (``block.packet_len``, ``block.timestamp``) keeps
following edits, for backwards compatibility.

.. code-block:: python

    blocks = list(FileScanner(fp))
    shb, idb, epb = blocks

    assert epb.raw_view.packet_len == epb.packet_len
    idb.options["if_tsresol"] = b"\x03"   # milliseconds

    # Evidence does not move; the edited interpretation does.
    assert epb.raw_view.timestamp != epb.edit_view.timestamp
    assert epb.raw_view.diff()["timestamp"] == (
        epb.raw_view.timestamp,
        epb.edit_view.timestamp,
    )

Edits are recorded on the block that owns the changed field or option through
``block.edit_log`` (a tuple of ``EditRecord`` objects with ``source``, ``name``,
``before`` and ``after``).  ``block.edited`` tells whether the block itself was
modified; an interface edit is reported on the interface, not on the packets
that interpret its metadata.

Copying
=======

``copy.copy()`` and ``copy.deepcopy()`` both copy the decoded fields, the
options and the edit log, so a copy can be edited without changing the
original.  A shallow copy keeps pointing at the same section (a block cannot
exist without one); a deep copy of a block also copies its section graph, and
a deep copy of a ``SectionHeader`` copies its members with the correct
``section`` back-reference.  The raw view is carried over unchanged.
Metadata only discovered later while streaming (for example an Interface
Statistics block that follows its interface) is added to the raw snapshot when
it is read; this is capture discovery, not an edit, and is not logged.
