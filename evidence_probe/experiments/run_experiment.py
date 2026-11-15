"""Runnable detection experiment.

Builds the four input classes required by the task and runs every probe path against
them, printing:

* the evidence level each detector reaches,
* conflicting candidates side by side,
* whether the stream offset survived every failure,
* the exact reason a guess is not promoted to a fact.

Usage:
    .venv/bin/python -m evidence_probe.experiments.run_experiment
"""

from __future__ import annotations

import gzip
import json
import os
import random
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from evidence_probe.contract import LEVEL_LABELS
from evidence_probe.entropy import shannon_entropy
from evidence_probe.probe import probe

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA = REPO_ROOT / "tests" / "_data"


@dataclass
class Case:
    name: str
    opener: object
    credentials: dict[str, str]
    expectation: str


def _high_entropy_ordinary_file(path: Path) -> None:
    # A random-looking but NON-VeraCrypt artefact: e.g. an encrypted/compressed blob an
    # upstream service might receive. Deliberately sector aligned to pass the size test.
    rng = random.Random(20261115)
    path.write_bytes(bytes(rng.getrandbits(8) for _ in range(64 * 1024)))


def _empty_file(path: Path) -> None:
    path.write_bytes(b"")


def _truncated_luks(path: Path) -> None:
    with gzip.open(DATA / "luks1" / "aes-ecb.bin.gz", "rb") as src:
        full = src.read()
    # Keep the LUKS magic but cut the header well before the keyslot/digest region.
    path.write_bytes(full[:128])


def _open(path: Path) -> BinaryIO:
    return path.open("rb")


def build_cases(workdir: Path) -> list[Case]:
    random_blob = workdir / "high_entropy_ordinary.bin"
    empty = workdir / "empty.bin"
    truncated = workdir / "truncated_luks_header.bin"
    _high_entropy_ordinary_file(random_blob)
    _empty_file(empty)
    _truncated_luks(truncated)

    luks_fixture = DATA / "luks1" / "aes-ecb.bin.gz"
    bde_fixture = DATA / "bde" / "aes_128.bin.gz"
    vc_fixture = DATA / "veracrypt" / "aes256-sha512.hc"

    return [
        Case(
            "high-entropy ordinary random file",
            lambda: _open(random_blob),
            {"veracrypt": "password"},
            "L1 smell at most; must NOT be declared VeraCrypt; wrong key cannot promote it",
        ),
        Case(
            "empty input",
            lambda: _open(empty),
            {},
            "INCONCLUSIVE (not 'unencrypted'); every detector stays at offset 0",
        ),
        Case(
            "truncated LUKS header (magic present, body cut)",
            lambda: _open(truncated),
            {"luks": "password"},
            "magic may still read but verification fails; never labelled unencrypted",
        ),
        Case(
            "valid LUKS1 volume + correct passphrase",
            lambda: gzip.open(luks_fixture, "rb"),
            {"luks": "password"},
            "L2 header then L3 key-verified",
        ),
        Case(
            "valid LUKS1 volume + WRONG passphrase",
            lambda: gzip.open(luks_fixture, "rb"),
            {"luks": "definitely-wrong"},
            "stays L2; failed auth recorded as error, not downgraded to plaintext",
        ),
        Case(
            "valid BitLocker volume + correct passphrase",
            lambda: gzip.open(bde_fixture, "rb"),
            {"bitlocker": "password12!@"},
            "L2 header then L3 key-verified",
        ),
        Case(
            "valid VeraCrypt container + correct passphrase",
            lambda: _open(vc_fixture),
            {"veracrypt": "password"},
            "L1 smell upgraded to L3 only after VERA magic confirmed on decrypt",
        ),
    ]


def main() -> int:
    workdir = Path(os.environ.get("EVIDENCE_PROBE_TMP", os.environ.get("TMPDIR", "/tmp"))) / "evidence_probe_exp"
    workdir.mkdir(parents=True, exist_ok=True)
    cases = build_cases(workdir)

    print("=" * 96)
    print("FVE DETECTION EXPERIMENT - evidence levels vs probe paths")
    print("=" * 96)

    failures = 0
    for case in cases:
        fh = case.opener()
        before = fh.tell()
        report = probe(fh, source=case.name, credentials=case.credentials)
        after = fh.tell()
        offset_ok = before == after and report.position_preserved
        sample = fh.read(4096) if fh.seekable() else b""
        measured_entropy = shannon_entropy(sample)
        fh.close()

        print(f"\n■ {case.name}")
        print(f"  size={report.size}  entropy(first 4KiB)={measured_entropy:.4f}  "
              f"offset {before}->{after} preserved={offset_ok}")
        print(f"  expectation: {case.expectation}")
        if not report.candidates:
            print(f"  candidates: none  -> strongest={LEVEL_LABELS[report.strongest_level]}")
        for candidate in report.candidates:
            detectors = ", ".join(f"{e.detector}[{LEVEL_LABELS[e.level]}]" for e in candidate.evidence)
            print(f"  candidate={candidate.format:<10} max={LEVEL_LABELS[candidate.max_level]:<24} "
                  f"key_verified={candidate.key_verified}  via: {detectors}")
        for error in report.errors:
            print(f"  error[{error['detector']}]: {error['error'][:110]}")
        print(f"  confirmed_formats(L3 only)={[c.format for c in report.confirmed]}")

        if not offset_ok:
            failures += 1
            print("  !! FAIL: stream position was not preserved")

    print("\n" + "=" * 96)
    print("Machine-readable sample report (valid VeraCrypt case):")
    vc_fh = _open(DATA / "veracrypt" / "aes256-sha512.hc")
    vc_report = probe(vc_fh, source="veracrypt_sample", credentials={"veracrypt": "password"})
    print(json.dumps(vc_report.to_dict(), indent=2, ensure_ascii=False))
    vc_fh.close()

    print("=" * 96)
    print(f"RESULT: position-preservation failures={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
