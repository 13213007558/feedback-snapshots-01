"""Failure-localization tool for an Agile-encrypted OLE container.

Usage::

    python -m tests.ole_boundary.locate CONTAINER.bin [--password PW] \
        [--marker-file MARKER.bin] [--json]

Runs the independent structural validator, slack/leak checker and (optionally)
the MS-OFFCRYPTO decryption/integrity check against an arbitrary file, and
prints every defect with its exact stream/sector/byte offset. Exits non-zero if
any defect is found, so it doubles as a CI gate.

This is deliberately standalone: it imports nothing from msoffcrypto's read
path and works against any CFB container, not only fixtures produced here.
"""

from __future__ import annotations

import argparse
import json
import sys

from .fixtures import PASSWORD, TASK_MARKER
from .independent_crypto import decrypt_container
from .ole_validator import validate_container
from .slack_checker import check_leaks


def inspect_container(blob: bytes, password: str | None, marker: bytes):
    report = validate_container(blob)
    leaks = check_leaks(blob, report, marker)
    crypto = None
    crypto_error = None
    if password is not None:
        try:
            crypto = decrypt_container(blob, password)
        except Exception as exc:  # pragma: no cover - defensive
            crypto_error = f"{type(exc).__name__}: {exc}"
    return report, leaks, crypto, crypto_error


def _human(blob, report, leaks, crypto, crypto_error, password):
    lines = []
    lines.append("== OLE header / allocation ==")
    lines.append(f"  file_size={report.file_size} sectors={report.nb_sect} "
                 f"FAT_sectors={report.num_fat} DIFAT_sectors={report.num_difat} "
                 f"first_DIFAT={report.first_difat:#010x}")
    lines.append("")
    lines.append("== Streams (independent chain + length verification) ==")
    for s in report.streams:
        kind = "mini" if s.is_mini else "big"
        status = "OK" if s.readable_size == s.size and len(s.chain) == s.expected_chain_len else "FAIL"
        lines.append(f"  [{status}] {s.name!r:32s} size={s.size:8d} start={s.start:6d} "
                     f"{kind:4s} chain={len(s.chain)}/{s.expected_chain_len} read={s.readable_size}")
    lines.append("")
    lines.append("== Sector ownership ==")
    lines.append(f"  owned big sectors: {len(report.big_owners)} | "
                 f"free big sectors: {len(report.free_big_sectors)}")
    lines.append(f"  owned mini sectors: {len(report.mini_owners)} | "
                 f"free mini sectors: {len(report.free_mini_sectors)}")
    lines.append("")
    lines.append("== Structural defects ==")
    if report.defects:
        for d in report.defects:
            lines.append(f"  [DEFECT] {d.code:18s} stream={d.stream!r} :: {d.detail}")
    else:
        lines.append("  none")
    lines.append("")
    lines.append("== Slack / free-sector leaks ==")
    if leaks:
        for f in leaks:
            lines.append(f"  [LEAK] {f.code:22s} offset={f.offset} :: {f.detail}")
    else:
        lines.append("  none")
    if password is not None:
        lines.append("")
        lines.append("== Independent decryption / integrity ==")
        if crypto_error:
            lines.append(f"  [ERROR] {crypto_error}")
        else:
            lines.append(f"  password_verified={crypto.password_verified} "
                         f"hmac_integrity={crypto.integrity_ok} segments={crypto.segment_count} "
                         f"hash={crypto.hash_algorithm}")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Locate OLE layout failures in an encrypted container.")
    parser.add_argument("container", help="path to the OLE/CFB container")
    parser.add_argument("--password", default=PASSWORD,
                        help="password for Agile decryption (use '' to skip crypto checks)")
    parser.add_argument("--marker-file", help="file whose bytes are treated as the previous-task marker")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args(argv)

    with open(args.container, "rb") as fh:
        blob = fh.read()
    marker = open(args.marker_file, "rb").read() if args.marker_file else TASK_MARKER
    password = args.password if args.password != "" else None

    report, leaks, crypto, crypto_error = inspect_container(blob, password, marker)

    if args.json:
        payload = {
            "file_size": report.file_size,
            "nb_sect": report.nb_sect,
            "num_fat": report.num_fat,
            "num_difat": report.num_difat,
            "first_difat": report.first_difat,
            "streams": [s.__dict__ for s in report.streams],
            "defects": [d.__dict__ for d in report.defects],
            "leaks": [f.__dict__ for f in leaks],
            "free_big_sectors": report.free_big_sectors,
            "free_mini_sectors": report.free_mini_sectors,
        }
        if crypto is not None:
            payload["crypto"] = {
                "password_verified": crypto.password_verified,
                "integrity_ok": crypto.integrity_ok,
                "segments": crypto.segment_count,
                "hash_algorithm": crypto.hash_algorithm,
            }
        if crypto_error:
            payload["crypto_error"] = crypto_error
        print(json.dumps(payload, indent=2, default=str))
    else:
        print(_human(blob, report, leaks, crypto, crypto_error, password))

    failed = bool(report.defects or leaks or (crypto is not None and
                  (not crypto.integrity_ok or not crypto.password_verified)) or crypto_error)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
