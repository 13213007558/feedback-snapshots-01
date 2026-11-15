History
#######

Unreleased
==========

- Harden parsing at the Name Resolution Block / options boundary:

  - Reject an ``nrb_record_end`` terminator declaring a non-zero length
    (previously the following bytes were silently re-interpreted as options)
  - Reject IPv4/IPv6 name resolution records too short to hold an address
  - Raise ``TruncatedFile`` when a record or option header/payload is cut
    off by the end of the enclosing block, instead of silently dropping it

- Add structural-mutation tests covering the boundary between the name
  resolution record list and block options (fixed-seed generator plus
  minimal failing samples)

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
