History
#######

Unreleased
==========

- Add ``pcapng.sanitizer`` with ``SanitizationPolicy``, ``sanitize_capture``
  and ``sanitize_bytes`` for producing privacy-scrubbed captures with an
  auditable deletion report.
- Allow writing options whose codes are not in the schema (vendor options read
  from a capture can now be round-tripped).

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
