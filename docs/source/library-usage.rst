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

Deriving a filtered capture
###########################

:py:func:`pcapng.derive_capture` writes a copy containing only the packets
selected by a caller predicate, and returns a manifest mapping every output
block back to its source block::

    import pcapng

    def keep(block):
        return block.packet_data.startswith(b"\x00\x01")

    manifest = pcapng.derive_capture("original.pcapng", "evidence.pcapng", keep)
    print(manifest.source_digest)          # SHA-256 of the input bytes
    for entry in manifest.entries_for_packets():
        print(entry.source_offset, entry.source_length, entry.output_offset)

Important properties:

- **Duplicates stay distinct.** Packets are selected one source block at a
  time and are never deduplicated by content, even when their bytes and
  timestamps are identical.  Every selected occurrence gets its own source
  offset in the manifest.
- **Identity is the input digest.** The manifest is bound to the SHA-256 of
  the input file bytes, not to a file name or temporary path, so it remains
  valid if either file is moved or renamed.
- **Interfaces follow the selection.** Only IDBs used by selected packets
  are written, renumbered from zero in order of first use; each manifest
  entry records the source and output interface identifiers.
- **Global blocks describe the source.** Name Resolution and Interface
  Statistics blocks are omitted by default.  When retained verbatim, they
  still describe the whole original capture, not the filtered subset; the
  manifest records this with ``represent_filtered_output = False``.
- **Faithfulness is enforced.** Selections that cannot be represented
  without changing their meaning raise
  :py:class:`pcapng.exceptions.DeriveError` before any output is written.
  Obsolete Packet Blocks are written as Enhanced Packet Blocks and flagged
  as converted in the manifest.

:py:func:`pcapng.verify_derived_capture` re-reads both files and checks the
manifest against them, including per-entry byte ranges, block indexes,
packet payloads and interface mapping.
