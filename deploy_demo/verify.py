"""Independent verification of where bytes actually landed.

Two channels are checked:

* the install-generated ``RECORD`` is parsed and every row is re-hashed from
  the *actual* landing bytes (files read back from disk / objects read back
  from the WORM double through its read API, not from destination memory);
* the resulting ``(scheme, path)`` set is compared against the pre-touch plan,
  so "what review approved" equals "what is on the target".

Any tampering, truncation, wrong-location write or missing file shows up as a
failed check.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from installer.records import InvalidRecordEntry, RecordEntry, parse_record_file

from deploy_demo.paths import record_prefix_for_scheme, safe_resolve

if TYPE_CHECKING:
    from deploy_demo.plan import InstallPlan
    from deploy_demo.worm import WormStore


@dataclass
class LandingCheck:
    """One verified landing point."""

    scheme: str
    path: str
    landing: str
    exists: bool
    hash_ok: bool | None
    detail: str = ""

    @property
    def ok(self) -> bool:
        if not self.exists:
            return False
        return self.hash_ok is not False


@dataclass
class VerificationReport:
    """Aggregate result for one target."""

    target: str
    checks: list[LandingCheck] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems and all(check.ok for check in self.checks)

    def raise_if_failed(self) -> None:
        if not self.ok:
            from deploy_demo.errors import VerificationFailure

            raise VerificationFailure(
                self.problems
                + [
                    f"bad landing {check.landing} ({check.detail})"
                    for check in self.checks
                    if not check.ok
                ]
            )


def _prefix_to_scheme(scheme_dict: dict[str, str], root_scheme: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for scheme in scheme_dict:
        prefix = record_prefix_for_scheme(
            scheme, root_scheme=root_scheme, scheme_dict=scheme_dict
        )
        if prefix is not None:
            mapping[prefix] = scheme
    return mapping


def _split_row_path(
    row_path: str, prefix_to_scheme: dict[str, str], root_scheme: str
) -> tuple[str, str]:
    matches = sorted(
        (prefix for prefix in prefix_to_scheme if row_path.startswith(prefix)),
        key=len,
        reverse=True,
    )
    if matches:
        prefix = matches[0]
        return prefix_to_scheme[prefix], row_path[len(prefix) :]
    return root_scheme, row_path


def _parse_record(
    record_text: str, report: VerificationReport
) -> list[tuple[tuple[str, str, str], RecordEntry]]:
    parsed: list[tuple[tuple[str, str, str], RecordEntry]] = []
    try:
        rows = list(parse_record_file(record_text.splitlines()))
    except InvalidRecordEntry as exc:
        report.problems.append(f"RECORD is invalid: {exc}")
        return parsed
    for row in rows:
        try:
            entry = RecordEntry.from_elements(*row)
        except InvalidRecordEntry as exc:
            report.problems.append(f"invalid RECORD row {row!r}: {exc}")
            continue
        parsed.append((row, entry))
    return parsed


def _compare_plan(
    plan: "InstallPlan | None",
    found: set[tuple[str, str]],
    report: VerificationReport,
) -> None:
    if plan is None:
        return
    expected = plan.expected_path_set()
    missing = sorted(expected - found)
    unplanned = sorted(found - expected)
    for item in missing:
        report.problems.append(f"planned entry {item} missing from landed RECORD")
    for item in unplanned:
        report.problems.append(f"landed entry {item} absent from plan")


def verify_filesystem_installation(
    *,
    scheme_dict: dict[str, str],
    root_scheme: str,
    record_file_path: str,
    plan: "InstallPlan | None" = None,
    strict_extra: bool = False,
) -> VerificationReport:
    """Read installed files from their final paths and validate against RECORD."""
    report = VerificationReport(target="filesystem")
    root_record = safe_resolve(scheme_dict[root_scheme], record_file_path)
    if not root_record.exists():
        report.problems.append(f"RECORD not found at planned landing {root_record!s}")
        return report

    prefix_to_scheme = _prefix_to_scheme(scheme_dict, root_scheme)
    rows = _parse_record(root_record.read_text(encoding="utf-8"), report)
    found: set[tuple[str, str]] = set()

    for row, entry in rows:
        scheme, inner = _split_row_path(row[0], prefix_to_scheme, root_scheme)
        landing = safe_resolve(scheme_dict[scheme], inner)
        found.add((scheme, inner))
        if not landing.exists():
            report.checks.append(
                LandingCheck(scheme, inner, str(landing), False, None, "missing")
            )
            continue
        with landing.open("rb") as handle:
            hash_ok = entry.validate_stream(handle)
        detail = "hash/size match RECORD" if hash_ok else "hash/size MISMATCH"
        if entry.hash_ is None and entry.size is None:
            hash_ok = None
            detail = "unhashed row (RECORD itself)"
        report.checks.append(
            LandingCheck(scheme, inner, str(landing), True, hash_ok, detail)
        )
        if hash_ok is False:
            report.problems.append(f"checksum mismatch at {landing!s}")

    _compare_plan(plan, found, report)

    expected_by_scheme: dict[str, set[str]] = {}
    for scheme, inner in found:
        expected_by_scheme.setdefault(scheme, set()).add(inner)
    for scheme, root_text in scheme_dict.items():
        root = Path(root_text)
        if not root.exists():
            continue
        known = expected_by_scheme.get(scheme, set())
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            if relative not in known:
                report.extra.append(f"{scheme}:{relative} -> {path!s}")
    if strict_extra and report.extra:
        report.problems.append(f"unexpected extra files: {report.extra}")

    return report


def verify_worm_generation(
    store: "WormStore",
    generation: str,
    *,
    scheme_dict: dict[str, str],
    root_scheme: str,
    record_file_path: str,
    plan: "InstallPlan | None" = None,
) -> VerificationReport:
    """Read every object back from the WORM store and validate it."""
    report = VerificationReport(target=f"worm:{store.root}")
    prefix = f"generations/{generation}/"
    record_key = f"{prefix}{root_scheme}/{record_file_path}"

    if store.state_of(record_key) != "sealed":
        report.problems.append(
            f"RECORD key {record_key!r} state={store.state_of(record_key)!r}"
        )
        return report

    with store.open_read(record_key) as handle:
        record_text = handle.read().decode("utf-8")
    prefix_to_scheme = _prefix_to_scheme(scheme_dict, root_scheme)
    rows = _parse_record(record_text, report)
    found: set[tuple[str, str]] = set()

    for row, entry in rows:
        scheme, inner = _split_row_path(row[0], prefix_to_scheme, root_scheme)
        key = f"{prefix}{scheme}/{inner}"
        landing = str(store.actual_path(key))
        if store.state_of(key) != "sealed":
            report.checks.append(
                LandingCheck(
                    scheme, inner, landing, False, None, f"state={store.state_of(key)}"
                )
            )
            continue
        handle: BinaryIO
        with store.open_read(key) as handle:
            hash_ok = entry.validate_stream(handle)
        found.add((scheme, inner))
        detail = "read-back hash/size match RECORD" if hash_ok else "read-back MISMATCH"
        if entry.hash_ is None and entry.size is None:
            hash_ok = None
            detail = "unhashed row (RECORD itself)"
        report.checks.append(
            LandingCheck(scheme, inner, landing, True, hash_ok, detail)
        )
        if hash_ok is False:
            report.problems.append(f"checksum mismatch for {key!r} at {landing}")

    _compare_plan(plan, found, report)

    # Manifest cross-check (the platform's commit linearization point).
    from deploy_demo.worm import manifest_key_for

    manifest_key = manifest_key_for(generation)
    if store.state_of(manifest_key) != "sealed":
        report.problems.append(f"manifest {manifest_key!r} not sealed")
        return report
    manifest = json.loads(store.open_read(manifest_key).read())
    manifest_keys = {blob["key"] for blob in manifest["blobs"]}
    record_keys = {f"{prefix}{scheme}/{inner}" for scheme, inner in found}
    if manifest_keys != record_keys:
        only_manifest = sorted(manifest_keys - record_keys)
        only_record = sorted(record_keys - manifest_keys)
        report.problems.append(
            f"manifest/RECORD key sets differ "
            f"(manifest-only={only_manifest}, record-only={only_record})"
        )

    # Orphan detection: sealed generation keys referenced by neither.
    expected_keys = record_keys | {manifest_key}
    for key in store.keys("sealed"):
        if key.startswith(prefix) and key not in expected_keys:
            report.extra.append(key)

    return report
