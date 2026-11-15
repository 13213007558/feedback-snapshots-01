History
#######

Unreleased
==========

- Add ``pcapng.merge.merge_streams()``: merge several pcap-ng streams into
  a single capture using an explicit, caller-provided interface mapping.
  Interfaces are merged only when the caller declares them identical *and*
  their metadata (link type, snaplen, timestamp resolution, filter, unknown
  options) is compatible; conflicts keep interfaces separate or raise
  ``InterfaceMergeConflict``.  Packets are written in input order (no
  timestamp reordering), statistics blocks are remapped without combining
  counters, and provenance is recorded both in the returned report and in
  ``opt_comment`` options in the output.
- Fix writing blocks carrying unknown (schema-less) options, and reading
  them back via ``Options.get_raw()`` / ``Options.get_all_raw()``.

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
