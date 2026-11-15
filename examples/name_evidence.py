#!/usr/bin/env python
"""
Demo of the name-evidence view (pcapng.name_evidence).

Builds an in-memory capture where:

* section 0 (little endian) claims 10.0.0.1 as 'alpha.example' and
  'alpha-alias.example' (two names in one record) plus, in a second
  record, 'alpha2.example';
* section 0 also contains an IPv6 claim, a record of unknown type,
  and a record whose name is truncated (not NUL-terminated);
* section 1 (big endian) claims the same 10.0.0.1 as 'beta.example'.

The view is then queried for 10.0.0.1: the conflicting claims are
reported with their origin, and the unknown/corrupted records are
listed separately -- none of them is turned into a trusted name, and
no online resolution is performed.

Optionally writes the demo capture to a file:

    python examples/name_evidence.py [outfile.pcapng]
"""

import io
import socket
import struct
import sys

from pcapng.name_evidence import NameEvidenceView

BYTE_ORDER_MAGIC = 0x1A2B3C4D
BLK_SECTION_HEADER = 0x0A0D0D0A
BLK_NAME_RESOLUTION = 0x00000004


def build_block(block_type, body, endianness="<"):
    padding = -len(body) % 4
    total = 12 + len(body) + padding
    return (
        struct.pack(endianness + "II", block_type, total)
        + body
        + b"\x00" * padding
        + struct.pack(endianness + "I", total)
    )


def build_shb(endianness="<"):
    body = struct.pack(endianness + "IHHq", BYTE_ORDER_MAGIC, 1, 0, -1)
    return build_block(BLK_SECTION_HEADER, body, endianness)


def nrb_record(record_type, value, endianness="<"):
    padding = -len(value) % 4
    return (
        struct.pack(endianness + "HH", record_type, len(value))
        + value
        + b"\x00" * padding
    )


def ipv4_record(address, names, endianness="<"):
    value = socket.inet_aton(address)
    value += b"".join(n.encode("utf-8") + b"\x00" for n in names)
    return nrb_record(0x0001, value, endianness)


def ipv6_record(address, names, endianness="<"):
    value = socket.inet_pton(socket.AF_INET6, address)
    value += b"".join(n.encode("utf-8") + b"\x00" for n in names)
    return nrb_record(0x0002, value, endianness)


def build_nrb(records, endianness="<"):
    body = b"".join(records) + b"\x00\x00\x00\x00"  # end-of-records
    return build_block(BLK_NAME_RESOLUTION, body, endianness)


def build_demo_capture():
    # Section 0: little endian.
    section0 = build_shb("<")
    section0 += build_nrb(
        [
            # Two names for the same address in a single record.
            ipv4_record("10.0.0.1", ["alpha.example", "alpha-alias.example"]),
            # A second, separate record for the same address.
            ipv4_record("10.0.0.1", ["alpha2.example"]),
            ipv6_record("2001:db8::1", ["v6alpha.example"]),
            # Unknown record type: cannot be interpreted.
            nrb_record(0x7777, b"\xde\xad\xbe\xef"),
            # Truncated name: the value ends without a NUL terminator.
            nrb_record(0x0001, socket.inet_aton("192.0.2.7") + b"webserv"),
        ],
        "<",
    )
    # Section 1: big endian, conflicting claim for the same address.
    section1 = build_shb(">")
    section1 += build_nrb([ipv4_record("10.0.0.1", ["beta.example"], ">")], ">")
    return section0 + section1


def main():
    capture = build_demo_capture()
    if len(sys.argv) > 1:
        with open(sys.argv[1], "wb") as fp:
            fp.write(capture)
        print("wrote {0} ({1} bytes)".format(sys.argv[1], len(capture)))

    view = NameEvidenceView.from_stream(io.BytesIO(capture))
    print(view)
    print("addresses with claims: {0}".format(view.addresses()))
    print()
    print(view.claims_for("10.0.0.1").explain())
    print()
    for record in view.problems:
        print(
            "{0}: {1} [{2}] raw={3!r}".format(
                record.status.upper(),
                record.describe_origin(),
                record.problem,
                record.raw,
            )
        )


if __name__ == "__main__":
    main()
