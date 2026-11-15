History
#######

Unreleased
==========

- Add the packet hash verification and editing contract
  (``pcapng.pkthash``) for the ``epb_hash`` / ``pack_hash`` options:
  supported algorithms (CRC32, MD5, SHA-1) are verified as
  match/mismatch/malformed, other algorithms are preserved as unverified;
  verification results are invalidated when the packet bytes change;
  hashes can be explicitly recomputed, and stale declarations are
  rejected (or dropped, in "fix" mode) when writing.

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
