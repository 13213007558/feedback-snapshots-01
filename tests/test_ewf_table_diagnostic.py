"""Tests for the reproducible EWF table/table2 divergence diagnostic.

These tests exercise the diagnostic as a standalone forensic tool and assert the
three verdict classes, without changing how dissect.evidence itself parses EWF.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

DIAGNOSTIC_DIR = Path(__file__).resolve().parents[1] / "ewf_table_diagnostic"
SRC_DIR = DIAGNOSTIC_DIR / "src"


def _load(module_name: str, filename: str):
    spec = importlib.util.spec_from_file_location(module_name, SRC_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


builder = _load("ewf_diag_builder", "build_images.py")
diagnose = _load("ewf_diag_diagnose", "diagnose.py")


@pytest.fixture(scope="module")
def fixtures(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """Build every fixture in an isolated temp directory; no source file touched."""
    tmp = tmp_path_factory.mktemp("ewf_fixtures")
    built = {}
    scenarios = {
        "baseline.E01": (False, False),
        "case1_primary_corrupt.E01": (False, False),
        "case2_backup_corrupt.E01": (False, False),
        "case3_divergent_legal.E01": (True, True),
        "case4_both_tables_corrupt.E01": (False, False),
    }
    artifacts = {name: builder.build_layout(*args) for name, args in scenarios.items()}
    for name, artifact in artifacts.items():
        image = bytearray(artifact["image"])
        manifest = artifact["manifest"]
        if name == "case1_primary_corrupt.E01":
            builder.corrupt_table(image, manifest, "table")
        elif name == "case2_backup_corrupt.E01":
            builder.corrupt_table(image, manifest, "table2")
        elif name == "case4_both_tables_corrupt.E01":
            builder.corrupt_table(image, manifest, "table")
            builder.corrupt_table(image, manifest, "table2")
        path = tmp / name
        path.write_bytes(bytes(image))
        built[name] = path
    return built


def report(fixtures: dict[str, Path], name: str) -> dict:
    return diagnose.diagnose_image(fixtures[name])


def test_baseline_tables_corroborate(fixtures: dict[str, Path]) -> None:
    result = report(fixtures, "baseline.E01")
    assert result["verdict"] == diagnose.RECOVERABLE
    assert result["cross_table_comparison"]["all_chunks_agree"] is True
    assert result["tables"]["primary"]["structurally_valid"] is True
    assert result["tables"]["backup"]["structurally_valid"] is True


def test_primary_corruption_is_recoverable_from_backup(fixtures: dict[str, Path]) -> None:
    result = report(fixtures, "case1_primary_corrupt.E01")
    assert result["verdict"] == diagnose.RECOVERABLE
    assert result["tables"]["primary"]["structurally_valid"] is False
    assert result["tables"]["backup"]["structurally_valid"] is True
    failed = [block for block in result["blocks"]["primary"] if not block["decode_ok"]]
    assert failed and failed[0]["in_bounds"] is False
    assert all(block["decode_ok"] for block in result["blocks"]["backup"])


def test_backup_corruption_is_recoverable_from_primary(fixtures: dict[str, Path]) -> None:
    result = report(fixtures, "case2_backup_corrupt.E01")
    assert result["verdict"] == diagnose.RECOVERABLE
    assert result["tables"]["primary"]["structurally_valid"] is True
    assert result["tables"]["backup"]["structurally_valid"] is False
    assert all(block["decode_ok"] for block in result["blocks"]["primary"])


def test_divergent_legal_tables_are_a_conflict(fixtures: dict[str, Path]) -> None:
    result = report(fixtures, "case3_divergent_legal.E01")
    assert result["verdict"] == diagnose.CONFLICT
    assert result["tables"]["primary"]["structurally_valid"] is True
    assert result["tables"]["backup"]["structurally_valid"] is True
    assert result["cross_table_comparison"]["all_chunks_agree"] is False
    primary_hashes = [block["payload_sha256"] for block in result["blocks"]["primary"]]
    backup_hashes = [block["payload_sha256"] for block in result["blocks"]["backup"]]
    assert primary_hashes != backup_hashes
    # Every candidate read carries the table and absolute offset it came from.
    for side in ("primary", "backup"):
        for block in result["blocks"][side]:
            assert block["table"] in ("table", "table2")
            assert block["absolute_offset"] >= 0
            assert block["raw_entry"].startswith("0x")


def test_both_tables_corrupt_is_insufficient(fixtures: dict[str, Path]) -> None:
    result = report(fixtures, "case4_both_tables_corrupt.E01")
    assert result["verdict"] == diagnose.INSUFFICIENT
    assert result["tables"]["primary"]["structurally_valid"] is False
    assert result["tables"]["backup"]["structurally_valid"] is False
    # Partial decompression of untouched chunks must not upgrade the verdict.
    assert any(block["decode_ok"] for block in result["blocks"]["primary"])


def test_compression_flags_and_last_chunk_bounds(fixtures: dict[str, Path]) -> None:
    result = report(fixtures, "baseline.E01")
    blocks = result["blocks"]["primary"]
    assert [block["compressed"] for block in blocks] == [False, True, False, True]
    last = blocks[-1]
    table_end = result["tables"]["primary"]["descriptor_offset"]
    assert last["span_end"] == table_end
    assert all(block["span_start"] < block["span_end"] for block in blocks)
