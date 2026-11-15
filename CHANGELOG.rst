History
#######

Unreleased
==========

- Add :py:func:`pcapng.derive_capture` to write a predicate-filtered capture
  together with a source/output block manifest (source digest, byte ranges,
  block indexes, interface mapping).
- Add :py:func:`pcapng.verify_derived_capture` to check a manifest against
  the source and derived files.
- :py:class:`pcapng.FileScanner` now exposes the byte offset, length, type
  and raw payload of the block it last returned.

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
