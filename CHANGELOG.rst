History
#######

Unreleased
==========

- Blocks decoded from a capture now snapshot the interface metadata used
  to interpret them (timestamp resolution, simple-packet captured length)
  at decode time, so editing section/interface metadata after parsing no
  longer changes the decoded view of already-read blocks, regardless of
  the order in which attributes are accessed. Blocks created
  programmatically are still interpreted live against current metadata.
- Fix ``copy``/``deepcopy`` of block objects, which previously recursed
  infinitely in ``Block.__getattr__``.

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
