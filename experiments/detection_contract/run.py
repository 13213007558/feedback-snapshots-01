"""Runnable detection experiment for dissect.fve.

Compares the legacy ``is_*_volume`` smell tests with the evidence contract in
:mod:`dissect.fve.detect` over the same inputs:

* high entropy ordinary files (random bytes, compressed data, zeros, ASCII)
* empty input and truncated headers
* valid BitLocker / LUKS1 / LUKS2 / VeraCrypt test volumes
* spoofed headers (magic only, corrupted integrity fields)
* conflicting candidates (a stream that satisfies more than one weak detector)

For every case the harness records whether the stream position was preserved after each detector,
so a regression in failure handling is visible in the JSON report.

Assertions are expressed as safety properties rather than exact strings where the honest answer is
a range.  Concretely, a case declares which conclusions are acceptable, which are forbidden, and
which formats may never be claimed.  This is what prevents "random bytes" from ever becoming a
VeraCrypt finding.

Run from the repository root::

    python experiments/detection_contract/run.py --json experiments/detection_contract/results/report.json
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import random
import sys
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from dissect.fve.bde import is_bde_volume  # noqa: E402
from dissect.fve.detect import detect  # noqa: E402
from dissect.fve.luks import is_luks_volume  # noqa: E402
from dissect.fve.veracrypt.veracrypt import is_veracrypt_volume  # noqa: E402

DATA = REPO / "tests" / "_data"

LEGACY_DETECTORS: dict[str, Callable[[Any], bool]] = {
    "legacy_bde": is_bde_volume,
    "legacy_luks": is_luks_volume,
    "legacy_veracrypt": is_veracrypt_volume,
}


@dataclass
class Case:
    name: str
    category: str
    data: bytes
    allowed: frozenset[str]
    forbidden: frozenset[str] = frozenset()
    forbidden_formats: frozenset[str] = frozenset()
    expect_key_verified: bool = False
    key_material: dict[str, Any] | None = None
    notes: str = ""
    legacy: dict[str, Any] = field(default_factory=dict)
    contract: dict[str, Any] = field(default_factory=dict)


def _read(path: str) -> bytes:
    p = DATA / path
    if p.suffix == ".gz":
        with gzip.open(p, "rb") as fh:
            return fh.read()
    return p.read_bytes()


def build_cases() -> list[Case]:
    random.seed(20261116)
    cases: list[Case] = []

    def add(name: str, category: str, data: bytes, allowed: set[str] | frozenset[str], **kw: Any) -> None:
        cases.append(Case(name, category, data, frozenset(allowed), **kw))

    # --- high entropy ordinary files -------------------------------------------------
    # The only honest conclusion here is the generic "could be ciphertext" plus no format.
    add(
        "random-4096",
        "high_entropy_ordinary",
        random.randbytes(4096),
        {"possibly_encrypted"},
        forbidden={"not_encrypted", "header_recognized", "key_verified"},
        forbidden_formats={"veracrypt", "bitlocker", "luks"},
    )
    add(
        "random-1MiB",
        "high_entropy_ordinary",
        random.randbytes(1 << 20),
        {"possibly_encrypted"},
        forbidden={"not_encrypted", "header_recognized", "key_verified"},
        forbidden_formats={"veracrypt", "bitlocker", "luks"},
    )
    add(
        "random-4095",
        "high_entropy_ordinary",
        random.randbytes(4095),
        {"inconclusive", "possibly_encrypted"},
        forbidden_formats={"veracrypt", "bitlocker", "luks"},
        notes="not sector aligned; must never be called VeraCrypt",
    )
    add(
        "gzip-compressed",
        "high_entropy_ordinary",
        gzip.compress(random.randbytes(64 * 1024), mtime=0),
        {"inconclusive", "possibly_encrypted"},
        forbidden_formats={"veracrypt", "bitlocker", "luks"},
        notes="compressed payload, no container header",
    )
    add("zeros-4096", "high_entropy_ordinary", b"\x00" * 4096, {"inconclusive"})
    add("ascii-text", "high_entropy_ordinary", b"the quick brown fox\n" * 300, {"inconclusive"})

    # --- empty / tiny / truncated ----------------------------------------------------
    add("empty", "empty_truncated", b"", {"inconclusive"})
    add("one-byte", "empty_truncated", b"\x01", {"inconclusive"})

    vc = _read("veracrypt/aes256-sha512.hc")
    for n in (64, 100, 512, 575, 576, 1024):
        add(
            f"veracrypt-truncated-{n}",
            "empty_truncated",
            vc[:n],
            {"inconclusive", "possibly_encrypted"},
            forbidden={"not_encrypted", "header_recognized", "key_verified"},
            forbidden_formats={"veracrypt"},
            notes="truncated header is not a VeraCrypt identification",
        )
    add(
        "veracrypt-truncated-4096",
        "empty_truncated",
        vc[:4096],
        {"possibly_encrypted"},
        forbidden={"not_encrypted", "header_recognized", "key_verified"},
        forbidden_formats={"veracrypt"},
        notes="enough bytes for the entropy smell test, still no VeraCrypt claim",
    )

    bde = _read("bde/aes_128.bin.gz")
    for n in (0, 100, 511, 512, 4096):
        add(
            f"bitlocker-truncated-{n}",
            "empty_truncated",
            bde[:n],
            {"inconclusive"},
            notes="boot sector points past EOF; structure cannot be validated",
        )

    luks1 = _read("luks1/aes-ecb.bin.gz")
    for n in (6, 100, 512):
        add(
            f"luks1-truncated-{n}",
            "empty_truncated",
            luks1[:n],
            {"inconclusive"},
            notes="magic present but the 1024 byte header is incomplete",
        )
    add("luks1-truncated-1024", "empty_truncated", luks1[:1024], {"header_recognized", "unsupported_format"})

    luks2 = _read("luks2/aes-ecb.bin.gz")
    for n in (6, 100, 4096, 8192):
        add(
            f"luks2-truncated-{n}",
            "empty_truncated",
            luks2[:n],
            {"inconclusive"},
            notes="JSON area or checksum region incomplete; integrity cannot be verified",
        )

    # --- valid volumes ---------------------------------------------------------------
    add(
        "valid-bitlocker-aes128",
        "valid_volume",
        bde,
        {"header_recognized", "key_verified"},
        forbidden=frozenset(),
        key_material={"passphrase": "password12!@"},
        expect_key_verified=True,
    )
    add(
        "valid-bitlocker-vista",
        "valid_volume",
        _read("bde/vista.bin.gz"),
        {"header_recognized"},
        forbidden=frozenset(),
    )
    add(
        "valid-bitlocker-suspended",
        "valid_volume",
        _read("bde/suspended.bin.gz"),
        {"header_recognized"},
        forbidden=frozenset(),
        notes="paused volume with a clear VMK; still an encrypted BitLocker volume",
    )
    add(
        "valid-bitlocker-decrypted",
        "valid_volume",
        _read("bde/decrypted.bin.gz"),
        {"header_recognized"},
        forbidden=frozenset(),
        notes="BitLocker container in the DECRYPTED state, not an unsupported format",
    )
    add(
        "valid-luks1",
        "valid_volume",
        luks1,
        {"header_recognized", "key_verified"},
        forbidden=frozenset(),
        key_material={"passphrase": "password"},
        expect_key_verified=True,
    )
    add(
        "valid-luks2",
        "valid_volume",
        luks2,
        {"header_recognized", "unsupported_format"},
        forbidden=frozenset(),
        notes="Argon2 backend may be absent in this environment; the header is still recognized",
    )
    add(
        "valid-luks2-pbkdf2",
        "valid_volume",
        _read("luks2/aes-ecb-pbkdf2.bin.gz"),
        {"header_recognized", "key_verified"},
        forbidden=frozenset(),
        key_material={"passphrase": "password"},
        expect_key_verified=True,
    )
    add(
        "valid-veracrypt-sha512",
        "valid_volume",
        vc,
        {"key_verified"},
        forbidden=frozenset(),
        key_material={"passphrase": "password"},
        expect_key_verified=True,
    )
    add(
        "valid-veracrypt-sha256",
        "valid_volume",
        _read("veracrypt/aes256-sha256.hc"),
        {"key_verified"},
        forbidden=frozenset(),
        key_material={"passphrase": "password"},
        expect_key_verified=True,
    )

    # --- spoofed / corrupted ---------------------------------------------------------
    add(
        "luks1-magic-plus-zeros",
        "spoofed",
        b"LUKS\xba\xbe" + b"\x00" * 4096,
        {"inconclusive"},
        notes="magic with an invalid version; legacy detector says LUKS",
    )
    add(
        "luks1-magic-plus-garbage",
        "spoofed",
        b"LUKS\xba\xbe" + random.randbytes(8188),
        {"possibly_encrypted"},
        forbidden_formats={"luks", "veracrypt", "bitlocker"},
        notes="magic with an implausible version; legacy detector says LUKS",
    )
    add(
        "luks2-checksum-corrupted",
        "spoofed",
        luks2[:0x1D0] + b"\xff" * 16 + luks2[0x1E0:],
        {"inconclusive"},
        notes="LUKS2 header checksum no longer matches",
    )
    add(
        "veracrypt-magic-prefix",
        "spoofed",
        b"VERA" + random.randbytes(4092),
        {"possibly_encrypted"},
        forbidden={"not_encrypted", "header_recognized", "key_verified"},
        forbidden_formats={"veracrypt"},
        notes="VERA is not a plaintext VeraCrypt signature; the header is encrypted",
    )
    add(
        "bitlocker-oem-only",
        "spoofed",
        b"\xebR\x90-FVE-FS-" + b"\x00" * 500,
        {"inconclusive"},
        notes="OEM string without a parseable information block",
    )

    # --- conflicting candidates ------------------------------------------------------
    add(
        "luks-magic-high-entropy",
        "conflicting",
        b"LUKS\xba\xbe" + random.randbytes(4096 - 6),
        {"possibly_encrypted", "inconclusive"},
        forbidden={"not_encrypted", "header_recognized", "key_verified"},
        forbidden_formats={"veracrypt", "bitlocker"},
        notes="legacy VeraCrypt says True purely from entropy; the contract must keep it generic",
    )
    add(
        "ntfs-with-entropy-tail",
        "conflicting",
        b"\xebR\x90NTFS    " + b"\x00" * 500 + random.randbytes(4096),
        {"not_encrypted"},
        notes="plaintext filesystem marker outranks a high entropy tail",
    )
    return cases


def run_legacy(case: Case) -> dict[str, Any]:
    results: dict[str, Any] = {}
    for name, detector in LEGACY_DETECTORS.items():
        fh = io.BytesIO(case.data)
        try:
            results[name] = detector(fh)
        except Exception as exc:  # noqa: BLE001
            results[name] = f"EXC:{type(exc).__name__}"
        results[f"{name}_pos_ok"] = fh.tell() == 0
    return results


def run_contract(case: Case) -> dict[str, Any]:
    fh = io.BytesIO(case.data)
    try:
        payload = detect(fh, key_material=case.key_material).to_dict()
    except Exception:  # noqa: BLE001
        payload = {"conclusion": "EXC", "trace": traceback.format_exc()}
    payload["position_ok"] = fh.tell() == 0
    return payload


def check(case: Case) -> list[str]:
    """Return a list of violated assertions for one case."""
    contract = case.contract
    conclusion = contract.get("conclusion")
    fmt = contract.get("format")
    violations = []
    if conclusion not in case.allowed:
        violations.append(f"conclusion {conclusion!r} not in {sorted(case.allowed)}")
    if conclusion in case.forbidden:
        violations.append(f"forbidden conclusion {conclusion!r}")
    if fmt in case.forbidden_formats:
        violations.append(f"forbidden format claim {fmt!r}")
    if case.expect_key_verified and conclusion != "key_verified":
        violations.append(f"expected key_verified, got {conclusion!r}")
    return violations


def evaluate(cases: list[Case]) -> dict[str, Any]:
    failures = []
    for case in cases:
        case.legacy = run_legacy(case)
        case.contract = run_contract(case)
        violations = check(case)
        case.contract["violations"] = violations
        if violations:
            failures.append(
                {
                    "case": case.name,
                    "allowed": sorted(case.allowed),
                    "actual": case.contract.get("conclusion"),
                    "format": case.contract.get("format"),
                    "violations": violations,
                }
            )

    legacy_position_failures = sorted(
        {case.name for case in cases if any(not v for k, v in case.legacy.items() if k.endswith("_pos_ok"))}
    )
    contract_position_failures = [case.name for case in cases if not case.contract.get("position_ok")]
    legacy_exceptions = [
        {"case": case.name, "detector": k, "error": v}
        for case in cases
        for k, v in case.legacy.items()
        if isinstance(v, str) and v.startswith("EXC:")
    ]
    heuristic_categories = ("high_entropy_ordinary", "conflicting", "spoofed")
    legacy_veracrypt_false_positives = [
        case.name
        for case in cases
        if case.legacy.get("legacy_veracrypt") is True and case.category in heuristic_categories
    ]
    legacy_single_signal_luks = [
        case.name
        for case in cases
        if case.legacy.get("legacy_luks") is True and case.category in ("spoofed", "conflicting")
    ]

    return {
        "summary": {
            "cases": len(cases),
            "violations": len(failures),
            "legacy_position_failures": legacy_position_failures,
            "contract_position_failures": contract_position_failures,
            "legacy_exceptions": legacy_exceptions,
            "legacy_veracrypt_false_positives": legacy_veracrypt_false_positives,
            "legacy_single_signal_luks_positives": legacy_single_signal_luks,
        },
        "failures": failures,
        "cases": [
            {
                "name": case.name,
                "category": case.category,
                "bytes": len(case.data),
                "allowed": sorted(case.allowed),
                "notes": case.notes,
                "legacy": case.legacy,
                "contract": case.contract,
            }
            for case in cases
        ],
    }


def print_report(report: dict[str, Any]) -> None:
    summary = report["summary"]
    print("=" * 108)
    print("dissect.fve detection contract experiment")
    print("=" * 108)
    print(f"cases                          : {summary['cases']}")
    print(f"contract violations            : {summary['violations']}")
    print(f"legacy detectors that raised   : {len(summary['legacy_exceptions'])}")
    for item in summary["legacy_exceptions"]:
        print(f"    - {item['case']}: {item['detector']} -> {item['error']}")
    print(f"legacy VC false positives      : {len(summary['legacy_veracrypt_false_positives'])}")
    for name in summary["legacy_veracrypt_false_positives"]:
        print(f"    - {name}")
    print(f"legacy single-signal LUKS hits : {len(summary['legacy_single_signal_luks_positives'])}")
    for name in summary["legacy_single_signal_luks_positives"]:
        print(f"    - {name}")
    print(f"legacy position failures       : {summary['legacy_position_failures'] or 'none'}")
    print(f"contract position failures     : {summary['contract_position_failures'] or 'none'}")
    print()
    print(f"{'case':34} {'category':22} {'legacy V/B/L':13} {'contract':21} {'format':10} ok")
    print("-" * 108)
    for case in report["cases"]:
        legacy = case["legacy"]
        flags = "".join(
            "T" if legacy.get(k) is True else ("." if legacy.get(k) is False else "E")
            for k in ("legacy_veracrypt", "legacy_bde", "legacy_luks")
        )
        contract = case["contract"]
        ok = not contract.get("violations")
        print(
            f"{case['name']:34} {case['category']:22} {flags:13} "
            f"{contract.get('conclusion', '?'):21} {str(contract.get('format')):10} {ok}"
        )
    if report["failures"]:
        print("\nviolations:")
        for failure in report["failures"]:
            print(f"  - {failure}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", type=Path, help="write the full report as JSON")
    args = parser.parse_args(argv)

    cases = build_cases()
    report = evaluate(cases)
    print_report(report)

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2, sort_keys=True))
        print(f"\nwrote {args.json}")

    return 1 if report["summary"]["violations"] else 0


if __name__ == "__main__":
    sys.exit(main())
