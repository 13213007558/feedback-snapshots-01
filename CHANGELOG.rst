History
#######

Unreleased
==========

- Retain every Interface Statistics Block instead of overwriting earlier
  observations for the same interface. New accessors
  ``SectionHeader.interface_statistics``,
  ``SectionHeader.interface_stats_history``,
  ``SectionHeader.iter_interface_stats()`` and
  ``InterfaceDescription.statistics_history`` expose the full series. The
  legacy ``SectionHeader.interface_stats`` mapping and
  ``InterfaceDescription.statistics`` property keep returning only the
  latest block for backwards compatibility.
- Add :py:mod:`pcapng.stats` for counter semantics and reset-safe interval
  deltas. Missing counters are unknown rather than zero, and a decreasing
  counter is reported as inconclusive instead of producing a negative
  value. See ``examples/diagnose_interface_stats.py``.

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
