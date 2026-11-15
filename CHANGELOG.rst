History
#######

Unreleased
==========

- Add ``pcapng.merge.merge_capture_files``: merge multiple capture
  segments into one file using an explicit, caller-provided interface
  mapping.  Interfaces are merged only when the mapping and compatible
  capture metadata (link type, snaplen, timestamp resolution, filter,
  unknown options) agree; packets keep input order (no timestamp
  reordering) and interface statistics are copied per source, never
  summed.  Merge decisions and conflict reasons are returned in a
  reviewable report, and interface provenance is recorded in the
  output.
- Fix writing options with unknown (schema-less) option codes

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
