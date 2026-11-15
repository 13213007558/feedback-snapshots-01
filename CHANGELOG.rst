History
#######

Unreleased
==========

- Add ``StrictnessPolicy`` and ``strictness_scope`` so independent tasks
  (threads, async tasks, nested scopes) can each own a strictness policy
  without sharing the process-wide setting.  Read-time diagnostics, delayed
  option decoding and writer-side automatic fixes now follow the policy of
  the object/task doing the work.  ``set_strictness`` remains available as
  the legacy global entry point.

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
