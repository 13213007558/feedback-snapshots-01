"""Regression tests for the EWF table/table2 audit scenario set.

Run with the repository venv:
    .venv/bin/python -m pytest ewf-table-audit/test_table_audit.py -v
The generator runs in a temporary directory so no committed image is touched.
"""

from __future__ import annotations

import importlib.util
import hashlib
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SRC = HERE / "src"
sys.path.insert(0, str(SRC))

import ewf_builder as eb  # noqa: E402
from ewf_table_audit import EWFTableAudit  # noqa: E402
import generate_scenarios as gen  # noqa: E402


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> dict[str, EWFTableAudit]:
    tmp = tmp_path_factory.mktemp("ewf-audit")
    gen.IMAGES = tmp / "images"
    gen.REPORTS = tmp / "reports"
    gen.main()
    audits = {}
    for image in sorted(gen.IMAGES.glob("*.E01")):
        audits[image.name] = EWFTableAudit(image)
    return audits


def expected_verdict(prefix: str) -> str:
    return {
        "00": "RECOVERABLE_CONSISTENT",
        "01": "RECOVERABLE_CONSISTENT",
        "02": "INSUFFICIENT_EVIDENCE",
        "03": "INSUFFICIENT_EVIDENCE",
        "04": "CONFLICT",
        "05": "RECOVERABLE_SINGLE_TABLE",
        "06": "INSUFFICIENT_EVIDENCE",
        "07": "INSUFFICIENT_EVIDENCE",
        "08": "INSUFFICIENT_EVIDENCE",
    }[prefix]


def test_all_scenarios_present(generated: dict[str, EWFTableAudit]) -> None:
    assert len(generated) == 9
    assert all(set(audit.tables) == {"table", "table2"} for audit in generated.values())


@pytest.mark.parametrize("prefix", [f"{index:02d}" for index in range(9)])
def test_verdicts(generated: dict[str, EWFTableAudit], prefix: str) -> None:
    audit = next(value for name, value in generated.items() if name.startswith(prefix))
    assert audit.verdict == expected_verdict(prefix)


def test_baseline_tables_identical_and_roundtrips(generated: dict[str, EWFTableAudit]) -> None:
    audit = generated["00_baseline_uncompressed.E01"]
    primary, backup = audit.tables["table"], audit.tables["table2"]
    assert primary.structurally_valid and backup.structurally_valid
    assert primary.entry_words == backup.entry_words
    assert primary.candidate_sha256 == backup.candidate_sha256
    expected = hashlib.sha256(b"".join(gen.logical_chunks())).hexdigest()
    assert primary.candidate_sha256 == expected


def test_compressed_baseline_matches_uncompressed(generated: dict[str, EWFTableAudit]) -> None:
    uncompressed = generated["00_baseline_uncompressed.E01"]
    compressed = generated["01_baseline_compressed.E01"]
    assert (
        compressed.tables["table"].candidate_sha256
        == uncompressed.tables["table"].candidate_sha256
    )
    assert all(read.compressed for read in compressed.tables["table"].reads)


def test_entry_tampering_keeps_checksums_valid(generated: dict[str, EWFTableAudit]) -> None:
    audit = generated["02_primary_entry_tampered_checksums_valid.E01"]
    primary = audit.tables["table"]
    assert primary.descriptor_ok and primary.header_checksum_ok
    assert primary.structurally_valid
    assert primary.failed_reads, "tampered entry must fail on the read path, not at checksum time"
    assert not audit.tables["table2"].failed_reads


def test_divergent_tables_both_complete_but_distinct(generated: dict[str, EWFTableAudit]) -> None:
    audit = generated["04_tables_divergent_both_valid.E01"]
    primary, backup = audit.tables["table"], audit.tables["table2"]
    assert primary.structurally_valid and backup.structurally_valid
    assert primary.candidate_complete and backup.candidate_complete
    assert primary.candidate_sha256 != backup.candidate_sha256
    assert primary.base_offset != backup.base_offset


def test_stale_checksums_invalidate_structure(generated: dict[str, EWFTableAudit]) -> None:
    both = generated["06_both_tables_stale_checksums.E01"]
    assert not both.tables["table"].structurally_valid
    assert not both.tables["table2"].structurally_valid
    single = generated["05_primary_stale_checksums.E01"]
    assert not single.tables["table"].structurally_valid
    assert single.tables["table2"].structurally_valid


def test_wrong_base_offset_is_structural_failure(generated: dict[str, EWFTableAudit]) -> None:
    audit = generated["07_primary_wrong_base_offset.E01"]
    assert not audit.tables["table"].structurally_valid
    assert any("base_offset" in issue for issue in audit.tables["table"].issues)


def test_last_chunk_overflow_detected(generated: dict[str, EWFTableAudit]) -> None:
    audit = generated["08_primary_last_chunk_overflow.E01"]
    failed = audit.tables["table"].failed_reads
    assert failed and failed[-1].chunk_index == audit.number_of_chunks - 1


def test_every_read_is_traceable(generated: dict[str, EWFTableAudit]) -> None:
    for audit in generated.values():
        for table in audit.tables.values():
            for read in table.reads:
                assert read.table in ("table", "table2")
                assert read.table_offset is not None
                assert read.entry_index == read.chunk_index
                assert read.descriptor_word.startswith("0x")
                if read.status == "ok":
                    assert read.absolute_offset is not None and read.logical_sha256


def test_builder_outputs_are_deterministic() -> None:
    chunks = gen.logical_chunks()
    first = eb.build_image(chunks).image
    second = eb.build_image(chunks).image
    assert first == second
    divergent_a, info_a = eb.build_divergent_image(chunks, gen.alternate_chunks())
    divergent_b, info_b = eb.build_divergent_image(chunks, gen.alternate_chunks())
    assert divergent_a == divergent_b and info_a == info_b


def test_reports_serialize_with_verdict_fields(
    generated: dict[str, EWFTableAudit], tmp_path: Path
) -> None:
    target = tmp_path / "report.json"
    target.write_text(json.dumps(next(iter(generated.values())).to_dict()))
    payload = json.loads(target.read_text())
    assert "verdict" in payload and "verdict_reason" in payload
    for table in payload["tables"].values():
        assert "structurally_valid" in table and "failed_read_count" in table
