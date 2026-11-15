Opaque preservation of unknown blocks
#####################################

pcap-ng is extensible: a file may contain block types this library does not
implement. The scanner must not reject such a file, and an archive editor must
be able to save those blocks back without interpreting them. This document
describes how :class:`pcapng.blocks.UnknownBlock` makes that preservation
safe, and which transformations are deliberately refused.

Why the previous design could not write unknown blocks
======================================================

The previous implementation stored only ``block_type`` and ``data`` on an
``UnknownBlock`` that inherited directly from :class:`pcapng.blocks.Block`
without ever calling the base constructor:

* It had no ``section`` link and no ``_decoded`` mapping, so even reading the
  ``section`` attribute used by the writer raised infinite recursion through
  ``Block.__getattr__``.
* It inherited ``Block._write`` / ``_encode``, which iterate an empty schema
  and then dereference ``self.section`` and ``self.magic_number``, neither of
  which existed. Writing an unknown block therefore always crashed.
* The scanner created it with no record of the section or byte order the bytes
  came from, so even a patched writer would have had no basis on which to
  decide whether re-encoding the block was safe.

The fix is not a broad ``try/except`` around the write path: the block now
carries its *provenance* as first-class state, and the writer makes decisions
from that state.

Provenance: ownership flows from the scanner to the writer
==========================================================

``UnknownBlock`` is now a :class:`pcapng.blocks.SectionMemberBlock`. When the
scanner meets an unrecognized (and non-reserved) block type it constructs::

    UnknownBlock(self.current_section, block_type, data,
                 endianness=self.endianness)

Three facts are then immutable for the life of the object:

* ``section`` — the "home" :class:`pcapng.blocks.SectionHeader` the block was
  read from.
* ``source_endianness`` — that section's byte order (``'<'`` or ``'>'``).
* ``data`` — the raw block body, already padded to a 32-bit boundary, kept
  verbatim with no schema decoding.

Because the block is a normal section member, the existing guard in
:class:`pcapng.writer.FileWriter` (``blk.section is self.current_section``)
applies unchanged: a block can only be written through a writer opened on its
current section. Moving a block between sections is an explicit
``UnknownBlock.move_to_section()`` call that re-validates every rule below and
only then reassigns ``section``. There is no path by which the writer silently
guesses where a block belongs.

At write time ``UnknownBlock._write`` copies ``data`` byte for byte and only
re-emits the framing fields — block type and the two block total length
fields — in the *target* section's byte order. Before doing so it checks
``self.section.endianness == self.source_endianness``. The endianness
invariant is therefore enforced exactly once, at the boundary where bytes
leave the library, rather than being approximated by catching failures.

What can and cannot be done
===========================

+------------------------------------------------+--------------------+----------------------------------------------+
| Operation                                      | Result             | Reason                                       |
+================================================+====================+==============================================+
| Write back into the home section               | Supported          | Same byte order; framing and body are emitted|
|                                                |                    | unchanged and the output is byte-identical.  |
+------------------------------------------------+--------------------+----------------------------------------------+
| Move to another section of the same byte order | Supported for      | No numeric re-encoding is needed. The caller |
| (standardized type, MSB clear)                 | standardized types | remains responsible for any Interface ID the |
|                                                |                    | opaque payload may reference.                |
+------------------------------------------------+--------------------+----------------------------------------------+
| Move / write under a different byte order      | Refused            | The payload has no schema, so the library    |
|                                                |                    | cannot locate its numeric fields and must    |
|                                                |                    | not claim to have byte-swapped them.         |
+------------------------------------------------+--------------------+----------------------------------------------+
| Move a local-use block (MSB set) between       | Refused            | MSB-set types are private implementation     |
| sections, even with matching byte order        |                    | extensions; generic retention must not copy  |
|                                                |                    | them outside their home section.             |
+------------------------------------------------+--------------------+----------------------------------------------+
| Construct / emit a reserved type (0x00000000   | Refused            | Reserved types signal corruption or an       |
| or a corruption-detection pattern)             |                    | invalid file and cannot be laundered through |
|                                                |                    | the opaque-block path.                        |
+------------------------------------------------+--------------------+----------------------------------------------+

Refusals raise :class:`pcapng.exceptions.OpaqueBlockError`, a subclass of
:class:`pcapng.exceptions.PcapngDumpError`. They are hard errors, not
strictness warnings: no "keep unknown blocks" toggle overrides them, because
each one would produce a file that is structurally writable but semantically
wrong, with no way for the library to detect the damage afterwards.

Why byte order cannot be changed
================================

Every multi-byte numeric field in a section is represented in that section's
byte order. For a known block the library has a schema and can re-encode each
field; for an unknown block the body is an undifferentiated byte string. Two
tempting implementations are both wrong:

* Re-emit only the framing fields in the new order and copy the body
  unchanged: any 16/32/64-bit value inside the body is now misread by every
  conforming reader.
* Blindly reverse every 2/4/8-byte run: there is no way to know which runs are
  integers, which are octet strings, options, or padding, so this corrupts
  non-numeric data.

A correct conversion would require the block type's schema, which is precisely
what "unknown" means. The only honest behavior is to preserve the bytes in a
section of the matching order, or refuse.

Why local-use extensions are not portable by default
=====================================================

The pcap-ng block type space reserves values whose most significant bit is set
for local, implementation-private use. Such a type has no cross-vendor meaning
and may carry data meaningful only inside the producing implementation (and,
implicitly, its home section). Copying it into a different section on the
strength of a generic unknown-block retention option would attach private data
to a context that cannot interpret it. The library therefore allows a local-use
block to be rewritten in place — byte-exact preservation is still safe — but
refuses every relocation, even when both sections share a byte order.

Format basis
============

The rules follow the pcap-ng block structure (common block header with block
type and duplicated block total length, 32-bit aligned bodies), the section
byte order determined by the Section Header Block's Byte-Order Magic, the
reserved block type ``0x00000000`` and the corruption-detection type patterns,
and the MSB-set local-use block type range. See the bundled specification
draft in ``pcapng-docs/`` and the maintained pcapng specification (currently
``draft-tuexen-opsawg-pcapng`` / RFC 9549).
