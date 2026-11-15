History
#######

Unreleased
==========

- Add ``pcapng.name_evidence``: a name-evidence view over Name
  Resolution Blocks. It preserves the raw record, section and position
  of every address->name mapping, keeps multiple names per address and
  per section separate, distinguishes unexplained (unknown type) from
  corrupted (e.g. truncated name) records, and never performs online
  resolution.

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
