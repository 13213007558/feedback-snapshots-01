"""Run the full boundary matrix and collect per-row evidence.

Each matrix row produces a :class:`RowResult` bundling:

* the independent OLE structural report (directory, FAT/miniFAT chains,
  stream lengths, sector overlaps);
* slack/free-sector leak findings (including the previous-task marker);
* an independent MS-OFFCRYPTO decryption + HMAC integrity result;
* an exact byte-equality check against the original plaintext payload.

The runner never uses msoffcrypto's own reader to validate a container it just
wrote; only ``olefile`` and ``cryptography`` are used for verification.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .fixtures import PASSWORD, TASK_MARKER, encrypt_fixture, make_payload
from .independent_crypto import decrypt_container
from .matrix import matrix_entries, package_length
from .ole_validator import validate_container
from .slack_checker import check_leaks


@dataclass
class RowResult:
    label: str
    plaintext_size: int
    region: str
    goes_mini: bool
    package_size: int
    file_size: int
    num_fat: int
    num_difat: int
    defect_codes: list = field(default_factory=list)
    leak_codes: list = field(default_factory=list)
    marker_leaks: list = field(default_factory=list)
    bytes_restored: bool = False
    integrity_ok: bool = False
    password_ok: bool = False
    segments: int = 0
    structural_ok: bool = False
    leak_ok: bool = False

    @property
    def fully_ok(self) -> bool:
        return (self.structural_ok and self.leak_ok and self.bytes_restored
                and self.integrity_ok and self.password_ok
                and not self.marker_leaks)


def run_row(label: str, plaintext_size: int, region: str, goes_mini: bool,
            payload=None) -> RowResult:
    if payload is None:
        payload = make_payload(plaintext_size)
    blob = encrypt_fixture(payload)

    report = validate_container(blob)
    leaks = check_leaks(blob, report, TASK_MARKER)
    crypto = decrypt_container(blob, PASSWORD)

    marker_leaks = [f for f in leaks if f.code.startswith("MARKER_")]
    return RowResult(
        label=label,
        plaintext_size=plaintext_size,
        region=region,
        goes_mini=goes_mini,
        package_size=package_length(plaintext_size),
        file_size=report.file_size,
        num_fat=report.num_fat,
        num_difat=report.num_difat,
        defect_codes=sorted({d.code for d in report.defects}),
        leak_codes=sorted({f.code for f in leaks}),
        marker_leaks=[f.code for f in marker_leaks],
        bytes_restored=crypto.plaintext == payload,
        integrity_ok=crypto.integrity_ok,
        password_ok=crypto.password_verified,
        segments=crypto.segment_count,
        structural_ok=report.ok,
        leak_ok=not marker_leaks,
    )


def run_matrix() -> list[RowResult]:
    rows = []
    for label, size, region, goes_mini in matrix_entries():
        rows.append(run_row(label, size, region, goes_mini))
    return rows
