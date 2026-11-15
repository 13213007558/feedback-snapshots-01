History
#######

Unreleased
==========

- Separate the raw reading view from the edit view.  Derived values that
  depend on mutable section/interface metadata (timestamps, Simple Packet
  captured length, interface/section endianness) no longer change after the
  metadata is edited.  ``Block.raw_view`` is a snapshot taken when the block
  is decoded; ``Block.edit_view`` follows the current metadata; direct
  attribute access keeps its previous behaviour.  ``Block.edit_log`` records
  field and option edits on the block that owns them, and ``copy`` /
  ``deepcopy`` now copy blocks (and sections) without recursion.

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
