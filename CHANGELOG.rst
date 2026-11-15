History
#######

Unreleased
==========

- ``UnknownBlock`` is now a section member that records its home section and
  the section byte order, and can be written back opaquely with the payload
  bytes preserved.
- Add ``UnknownBlock.move_to_section()`` for explicit, validated relocation:
  same-byte-order moves of standardized block types are supported; cross
  byte-order moves and copying local-use (MSB-set) extensions are refused with
  the new ``OpaqueBlockError``.
- Correctly detect corruption-detection block types using the (value, mask)
  patterns; the previous membership check never matched an integer block type.
- **Breaking:** constructing ``UnknownBlock`` now requires a ``section``
  argument (and accepts an optional ``endianness``); reserved block types are
  rejected at construction time.

2.1.1
=====

- Fix deserialization of custom options

2.1.0
=====

- Use the explicit endianness everywhere when writing.

2.0.0
=====

- Write support

v0.1
====

- Support for "scanning" streams of pcap-ng data
- Support for decoding the "standard" pcap-ng blocks:

  - Section headers
  - Interface description
  - Enhanced packet
  - Simple packet (deprecated)
  - Packet (deprecated)
  - Name resolution
  - Interface statistics
