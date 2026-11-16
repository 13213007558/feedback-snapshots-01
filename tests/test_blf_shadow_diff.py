from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from diagnostics import blf_shadow_diff as diff  # noqa: E402

INTACT = "tests/data/DRIVERS{53b39e70-18c4-11ea-a811-000d3aa4692b}.TM.blf"


def _by_item(report: dict) -> dict:
    return {f["item"]: f for f in report["findings"]}


def test_intact_blf_keeps_two_views_separate() -> None:
    report = diff.analyze(INTACT)
    gen = report["pairs"]["general"]
    assert gen["current"]["status"] == "parsed"
    assert gen["shadow"]["status"] == "parsed"
    # both views parsed independently; no merged list exists in the model
    assert {s["id"] for s in gen["current"]["streams"]} == {0}
    assert {c["id"] for c in gen["shadow"]["containers"]} == {0, 1}


def test_intact_blf_consistent_identity_fields() -> None:
    findings = _by_item(diff.analyze(INTACT))
    assert findings["log identity IdLog"]["classification"] == "consistent"
    assert findings["container id 0 identity"]["classification"] == "consistent"
    assert findings["container id 1 identity"]["classification"] == "consistent"
    assert findings["stream 0 lsn_last"]["classification"] == "consistent"


def test_lsn_difference_is_divergent_not_wallclock() -> None:
    findings = _by_item(diff.analyze(INTACT))
    base = findings["stream 0 lsn_base"]
    assert base["classification"] == "contradictory"
    assert base["note"] == "divergent"
    assert "wall-clock" in base["detail"]


def test_archive_tail_invalid_lsn_preserved() -> None:
    report = diff.analyze(INTACT)
    stream = report["pairs"]["general"]["current"]["streams"][0]
    tail = stream["lsn_archive_tail"]
    assert tail["physical_offset"] == 0xFFFFFFFF00000000
    assert tail["is_clfs_invalid"] is True
    assert tail["container_id"] == 0xFFFFFFFF


def test_readable_container_evidence_needs_one_good_view() -> None:
    report = diff.analyze(INTACT)
    evidence = report["readable_container_evidence"]
    assert evidence["metadata_evidence_established"] is True
    assert evidence["established_from_views"] == ["current", "shadow"]
    assert evidence["second_view_corroboration_available"] is True


def test_corrupt_blf_degrades_to_single_view(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = Path(INTACT).read_bytes()
    damaged = bytearray(src)
    # shadow general block header scribble
    damaged[0x8200 + 4] = 0xFF
    damaged[0x8200 + 6] = 0xFF
    # truncate scratch blocks away
    damaged = damaged[:0x8400]
    target = tmp_path / "corrupt.blf"
    target.write_bytes(bytes(damaged))

    report = diff.analyze(str(target))
    gen = report["pairs"]["general"]
    assert gen["current"]["status"] == "parsed"
    assert gen["shadow"]["status"] == "unparseable"
    assert report["pairs"]["scratch"]["current"]["status"] == "missing"

    evidence = report["readable_container_evidence"]
    # one readable view still satisfies the minimum metadata evidence
    assert evidence["metadata_evidence_established"] is True
    assert evidence["established_from_views"] == ["current"]
    assert evidence["second_view_corroboration_available"] is False

    # every cross-copy conclusion must be undecidable, never an invented merge
    assert all(
        f["classification"] in {"consistent", "undecidable"} for f in report["findings"]
    )
    assert any(
        "cannot be assumed equal or deleted" in f["detail"] or "snapshot difference" in f["detail"]
        for f in report["findings"]
    )


def test_primary_magic_failure_is_fatal() -> None:
    report = diff.analyze("tests/data/invalid_control_record.blf")
    assert "fatal" in report
    assert report["readable_container_evidence"] is None
