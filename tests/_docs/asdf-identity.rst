ASDF evidence identity
======================

ASDF stream indexes are addresses *inside one container*.  They are not disk
identity, and the on-disk block table only stores an already-translated
absolute stream offset.  The same offset on stream 0 and stream 2 is therefore
two different evidence locations, even when the bytes are identical.

Identity model
--------------

An evidence identifier has three parts, all required:

.. code-block:: text

    asdf:<container GUID>/stream/<idx>@0x<offset>+0x<length>

``<container GUID>`` comes from the ASDF header.  It is generated per writer,
so it distinguishes two acquisitions rather than two devices.  ``<idx>`` is the
stream index from the block table.  ``<offset>`` and ``<length>`` are in that
stream's coordinate system.

The optional ``asdf/identity.json`` member in the metadata tar adds:

- a declared role (``disk``, ``volume`` or ``memory``);
- an optional source claim (serial with provenance, or acquisition identifier);
- for a volume stream, a ``base`` translating offset zero of the stream to the
  parent disk, plus ``parent_idx``;
- a display label with no identity meaning.

A source claim is only used for identity when its provenance is
``acquisition``, ``os`` or ``device``.  A label, a model, a size, equal content
or equal offsets never coalesce streams.  Even a trusted serial only records a
declaration shared by streams; extents are never merged across streams.

Fallbacks without a manifest
----------------------------

Readers can always report: container GUID, stream idx, role ``stream`` (or
``memory`` for reserved idx 254, ``metadata`` for 255), captured runs, stream
size, and exact byte ranges.  They cannot report which disk a stream came from,
whether two streams are the same device, or the parent offset of a volume.
The index exposes this as ``IdentityStrength.CONTAINER_STREAM``.

Adding a manifest is backward compatible: it is an ordinary metadata tar
member, so the header, block and table-entry layouts do not change.  Old
readers ignore it.  Changing the block format, by contrast, requires a version
bump, new structs, writer/reader dual paths, repair/verify support and
re-acquisition or migration of existing evidence.  The manifest approach also
keeps unknown streams readable; a format change does not.

Worked in-memory example
------------------------

.. code-block:: python

    from io import BytesIO

    from dissect.evidence.asdf import (
        AsdfSnapshot,
        AsdfWriter,
        SourceClaim,
        StreamDeclaration,
        StreamRole,
        write_identity_manifest,
    )

    out = BytesIO()
    out.close = lambda: None  # keep the buffer readable after writer.close()
    writer = AsdfWriter(out)

    # Disk A: stream 0.
    writer.add_bytes(b"A" * 0x1000, idx=0, base=0x0000)
    writer.add_bytes(b"a" * 0x1000, idx=0, base=0x4000)

    # Volume A1: stream 1, relative to disk A at 0x4000.
    # Only part of the volume was captured in this example.
    writer.add_bytes(b"V" * 0x0200, idx=1, base=0x0000)
    writer.add_bytes(b"W" * 0x0200, idx=1, base=0x0600)

    # Disk B: stream 2, reusing disk A's offsets on purpose.
    writer.add_bytes(b"B" * 0x1000, idx=2, base=0x0000)
    writer.add_bytes(b"b" * 0x1000, idx=2, base=0x4000)

    # Memory: reserved stream 254.
    writer.add_bytes(b"M" * 0x0200, idx=254)

    write_identity_manifest(
        writer,
        [
            StreamDeclaration(
                0,
                StreamRole.DISK,
                SourceClaim(serial="DISK-A", serial_source="acquisition"),
                label="Disk A",
            ),
            StreamDeclaration(1, StreamRole.VOLUME, base=0x4000, parent_idx=0, label="Volume A1"),
            StreamDeclaration(
                2,
                StreamRole.DISK,
                SourceClaim(serial="DISK-B", serial_source="acquisition"),
                label="Disk B",
            ),
            StreamDeclaration(254, StreamRole.MEMORY, label="Memory"),
        ],
    )
    writer.close()
    out.seek(0)

    evidence = AsdfSnapshot(out).evidence

    disk_a = evidence.locate(0, 0x4000, 0x1000)  # asdf:<guid>/stream/0@0x4000+0x1000
    volume = evidence.locate(1, 0x0100, 0x0200)  # asdf:<guid>/stream/1@0x100+0x200
    disk_b = evidence.locate(2, 0x4000, 0x1000)  # asdf:<guid>/stream/2@0x4000+0x1000
    memory = evidence.locate(254, 0x0020, 0x0040)  # asdf:<guid>/stream/254@0x20+0x40

``disk_a`` and ``disk_b`` have the same offset and length, but different
identifiers and ``same_stream()`` is false.  ``volume.to_parent()`` returns
``(0, 0x4100, 0x200)``.  ``memory.to_parent()`` returns ``None``.
``evidence.resolve(disk_b.identifier)`` returns the same extent.
