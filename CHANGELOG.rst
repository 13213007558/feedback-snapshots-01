History
#######

Unreleased
==========

- Rework block options to keep an ordered list of entries instead of a
  code-keyed dict. Re-saving a block now preserves the original on-disk
  order, repeated options sharing a code (including interleaved ones such
  as multiple ``opt_comment`` entries), and options with unknown codes,
  whose raw payload bytes are written back verbatim.
- New ordered access API on ``Options``: ``entries()``, ``get_entry()``
  and ``set_value_at()``. Documented the effect of replacing a value
  (``options[name] = value``), appending another same-code value
  (``add()``) and deleting every value of a code (``del options[name]``),
  together with the exact return rules of the ``Mapping`` interface.
- Known numeric options are always re-encoded using the section
  endianness, including across sections with different endianness;
  blocks are fully re-encoded rather than copied back raw.

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
