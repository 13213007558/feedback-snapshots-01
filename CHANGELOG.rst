History
#######

Unreleased
==========

- Validate packet block length fields while reading. A captured length
  greater than the on-wire packet length now raises
  ``pcapng.exceptions.BadPacketLength``, distinct from
  ``TruncatedFile`` which still indicates the underlying stream ended
  early.
- Simple Packet Blocks now report the packet bytes actually held by the
  block and keep the snap length of zero ("unlimited") semantics. Blocks
  whose payload contradicts the original packet length / snap length
  raise ``BadPacketLength`` instead of being silently misread.
- Add packet metadata: ``packet_truncated``, ``fcs_length``,
  ``fcs_present`` and ``fcs``. The per-packet ``epb_flags`` FCS length
  takes precedence over the interface ``if_fcslen`` option (converted
  from bits to bytes); a complete FCS is only reported when the whole
  on-wire frame is held, never inferred from a plausible length.
- Fix Simple Packet Block writing so packet data is padded to a 32-bit
  boundary without zero-filling up to the on-wire packet length.

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
