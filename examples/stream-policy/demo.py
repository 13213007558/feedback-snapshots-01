#!/usr/bin/env python3
"""
Compare dnfile stream-table policies on header-only mutations.

This script never rewrites stream bodies.  It copies tests/data/hello-world
and patches only the metadata stream table (name/offset/size fields), then
prints what the legacy name map, the forensic policy, and the strict policy
report for each sample.

Run from the repository root:

    .venv/bin/python examples/stream-policy/demo.py
"""

import struct
import sys
import tempfile
from pathlib import Path

import dnfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests" / "data" / "hello-world" / "hello-world.exe"
DUPLICATE_SOURCE = ROOT / "tests" / "data" / "invalid-streams" / "duplicate-stream.exe"


def _headers(dn):
    return {entry.struct.Name: entry.struct.get_file_offset() for entry in dn.net.metadata.streams_list}


def _write_header(path, header_offset, offset=None, size=None, name=None, name_field_size=None):
    buf = bytearray(path.read_bytes())
    if offset is not None:
        buf[header_offset:header_offset + 4] = struct.pack("<I", offset)
    if size is not None:
        buf[header_offset + 4:header_offset + 8] = struct.pack("<I", size)
    if name is not None:
        width = name_field_size or len(name) + 1
        width += (4 - width % 4) % 4
        field = name + b"\x00" * (width - len(name))
        buf[header_offset + 8:header_offset + 8 + width] = field
    path.write_bytes(buf)


def _make_sample(tmp_path, label, mutate, source=SOURCE):
    path = tmp_path / (label + ".exe")
    path.write_bytes(source.read_bytes())
    headers = _headers(dnfile.dnPE(path))
    mutate(path, headers)
    return path


def _describe(path, policy):
    dn = dnfile.dnPE(path, stream_policy=policy)
    print("  {}: metadata={} mdtables={} strings={} type_evidence={}".format(
        policy.value,
        dn.net.metadata is not None,
        dn.net.mdtables is not None,
        dn.net.strings is not None,
        dn.net.type_evidence,
    ))
    report = dn.net.stream_report
    if report is None:
        return
    for entry in report.entries:
        print(
            "    {index:>2} slot={slot} {name!r:<12} {resolution:<9} {statuses:<34} "
            "decl={decl} read={read} evidence={evidence}".format(
                index=entry.index,
                slot=entry.slot,
                name=entry.name,
                resolution=entry.resolution,
                statuses=",".join(entry.status_values()) or "-",
                decl=_range(entry.declared_range),
                read=_range(entry.read_range),
                evidence=entry.evidence,
            )
        )
    print("    table={} resources={} complete={}".format(
        report.table_evidence, report.resource_evidence, report.is_complete
    ))


def _range(value):
    start, end = value
    if start is None or end is None:
        return "?"
    return "0x{:x}..0x{:x}".format(start, end)


def main():
    if not SOURCE.exists():
        print("missing fixture: {}".format(SOURCE))
        return 1

    samples = []

    def exact_alias(path, headers):
        _write_header(path, headers[b"#US"], offset=0x170, size=0x104)

    def partial_overlap(path, headers):
        _write_header(path, headers[b"#US"], offset=0x178, size=0x20)

    def outside_metadata(path, headers):
        _write_header(path, headers[b"#Blob"], offset=0x2F8, size=0x58)

    def zero_length(path, headers):
        _write_header(path, headers[b"#GUID"], size=0)

    def bad_duplicate(path, headers):
        _write_header(path, headers[b"#Blob"], offset=0x2F8, size=0x58, name=b"#GUID")

    def duplicate_with_zero_length(path, headers):
        us = [
            entry.struct.get_file_offset()
            for entry in dnfile.dnPE(path).net.metadata.streams_list
            if entry.struct.Name == b"#US"
        ]
        # The last #US is a zero-length duplicate; the first still holds data.
        _write_header(path, us[-1], size=0)

    samples.append(("clean", lambda p, h: None))
    samples.append(("exact-alias", exact_alias))
    samples.append(("partial-overlap", partial_overlap))
    samples.append(("zero-length", zero_length))
    samples.append(("outside-metadata", outside_metadata))
    samples.append(("duplicate-bad-last", bad_duplicate))
    samples.append(("duplicate-zero-length", duplicate_with_zero_length, DUPLICATE_SOURCE))

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        for sample in samples:
            label, mutate = sample[0], sample[1]
            source = sample[2] if len(sample) > 2 else SOURCE
            print("=" * 100)
            print(label)
            path = _make_sample(tmp_path, label, mutate, source)
            baseline = dnfile.dnPE(path)
            report = baseline.net.stream_report
            print("  legacy last-wins name map:")
            for name, entry in report.legacy_name_winners().items():
                print("    {!r:<12} header=0x{:x} decl={} evidence={}".format(
                    name,
                    entry.header_offset or 0,
                    _range(entry.declared_range),
                    entry.evidence,
                ))
            _describe(path, dnfile.StreamPolicy.FORENSIC)
            _describe(path, dnfile.StreamPolicy.STRICT)
            print("  warnings:")
            for warning in baseline.get_warnings():
                if "Byte 0x00" in warning:
                    continue
                print("    - {}".format(warning))

    return 0


if __name__ == "__main__":
    sys.exit(main())
