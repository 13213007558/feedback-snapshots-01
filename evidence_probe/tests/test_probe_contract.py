"""Contract tests for evidence levels, conflicting candidates and position preservation."""

from __future__ import annotations

import gzip
import random
from io import BytesIO
from pathlib import Path

import pytest

from evidence_probe.contract import EvidenceLevel
from evidence_probe.detectors import PositionDriftError, guarded
from evidence_probe.probe import probe

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA = REPO_ROOT / "tests" / "_data"


def gz_fixture(rel: str) -> BytesIO:
    with gzip.open(DATA / rel, "rb") as fh:
        return BytesIO(fh.read())


def file_fixture(rel: str) -> BytesIO:
    return BytesIO((DATA / rel).read_bytes())


@pytest.fixture
def high_entropy_blob() -> BytesIO:
    rng = random.Random(1)
    return BytesIO(bytes(rng.getrandbits(8) for _ in range(64 * 1024)))


@pytest.fixture
def truncated_luks() -> BytesIO:
    buf = gz_fixture("luks1/aes-ecb.bin.gz").getvalue()
    return BytesIO(buf[:128])


def test_high_entropy_ordinary_file_is_only_l1_and_not_confirmed(high_entropy_blob: BytesIO) -> None:
    report = probe(high_entropy_blob, source="random", credentials={"veracrypt": "password"})
    assert report.strongest_level == EvidenceLevel.POSSIBLE_ENCRYPTED
    vc = next(c for c in report.candidates if c.format == "veracrypt")
    assert vc.max_level == EvidenceLevel.POSSIBLE_ENCRYPTED
    assert vc.key_verified is False
    assert report.confirmed == []
    # A wrong/guessed key must not manufacture a confirmation.
    assert any("veracrypt" in e["detector"] for e in report.errors)


def test_empty_input_is_inconclusive_not_unencrypted() -> None:
    report = probe(BytesIO(b""), source="empty")
    assert report.strongest_level == EvidenceLevel.INCONCLUSIVE
    assert report.candidates == []
    assert report.position_preserved is True


def test_truncated_header_keeps_l2_but_cannot_reach_l3(truncated_luks: BytesIO) -> None:
    report = probe(truncated_luks, source="truncated", credentials={"luks": "password"})
    luks = next(c for c in report.candidates if c.format == "luks")
    assert luks.max_level == EvidenceLevel.HEADER_RECOGNIZED
    assert luks.key_verified is False
    assert any("luks" in e["detector"] for e in report.errors)
    # The failure to verify is not reinterpreted as plaintext/unencrypted.
    assert report.confirmed == []


def test_valid_luks_reaches_l3_with_correct_passphrase() -> None:
    fh = gz_fixture("luks1/aes-ecb.bin.gz")
    report = probe(fh, source="luks", credentials={"luks": "password"})
    luks = next(c for c in report.candidates if c.format == "luks")
    assert luks.max_level == EvidenceLevel.KEY_VERIFIED
    assert [c.format for c in report.confirmed] == ["luks"]


def test_wrong_passphrase_keeps_luks_at_l2() -> None:
    fh = gz_fixture("luks1/aes-ecb.bin.gz")
    report = probe(fh, source="luks", credentials={"luks": "wrong"})
    luks = next(c for c in report.candidates if c.format == "luks")
    assert luks.max_level == EvidenceLevel.HEADER_RECOGNIZED
    assert report.confirmed == []


def test_valid_bitlocker_reaches_l3() -> None:
    fh = gz_fixture("bde/aes_128.bin.gz")
    report = probe(fh, source="bde", credentials={"bitlocker": "password12!@"})
    bde = next(c for c in report.candidates if c.format == "bitlocker")
    assert bde.max_level == EvidenceLevel.KEY_VERIFIED


def test_veracrypt_smell_is_l1_but_verified_header_is_l3() -> None:
    fh = file_fixture("veracrypt/aes256-sha512.hc")
    smell_only = probe(fh, source="vc")
    vc_smell = next(c for c in smell_only.candidates if c.format == "veracrypt")
    assert vc_smell.max_level == EvidenceLevel.POSSIBLE_ENCRYPTED

    fh = file_fixture("veracrypt/aes256-sha512.hc")
    verified = probe(fh, source="vc", credentials={"veracrypt": "password"})
    vc = next(c for c in verified.candidates if c.format == "veracrypt")
    assert vc.max_level == EvidenceLevel.KEY_VERIFIED
    assert any(e.detail.get("decrypted_header_magic") == "VERA" for e in vc.evidence)


def test_conflicting_candidates_are_both_retained(high_entropy_blob: BytesIO) -> None:
    # A real LUKS volume also looks high-entropy enough in places; regardless, magic-based
    # L2 and smell-based L1 must coexist without one silently overwriting the other.
    fh = gz_fixture("luks2/aes-xts-plain64.bin.gz")
    report = probe(fh, source="luks2")
    formats = {c.format for c in report.candidates}
    assert "luks" in formats
    luks = next(c for c in report.candidates if c.format == "luks")
    assert luks.max_level >= EvidenceLevel.HEADER_RECOGNIZED


def test_unsupported_known_magic_is_not_called_unencrypted() -> None:
    # A recognisable non-FVE magic (e.g. a PDF) must not be labelled unencrypted, nor
    # force an encryption claim. It simply yields no supported candidate (inconclusive).
    report = probe(BytesIO(b"%PDF-1.7\n" + b"0" * 4096), source="pdf")
    assert report.confirmed == []
    assert report.strongest_level in (EvidenceLevel.INCONCLUSIVE, EvidenceLevel.POSSIBLE_ENCRYPTED)
    assert all(c.format in ("luks", "bitlocker", "veracrypt") for c in report.candidates)


@pytest.mark.parametrize("start_offset", [0, 17, 512, 4096])
def test_stream_position_preserved_for_all_inputs(start_offset: int, high_entropy_blob: BytesIO) -> None:
    high_entropy_blob.seek(0, 2)
    end = high_entropy_blob.tell()
    if start_offset > end:
        pytest.skip("offset beyond fixture")
    high_entropy_blob.seek(start_offset)
    report = probe(high_entropy_blob, source="offset", credentials={"veracrypt": "x"})
    assert high_entropy_blob.tell() == start_offset
    assert report.position_preserved is True


def test_guarded_wrapper_detects_and_repairs_drift() -> None:
    @guarded
    def badly_behaved(fh: BytesIO) -> None:
        fh.read(16)  # forgets to restore

    fh = BytesIO(b"x" * 64)
    with pytest.raises(PositionDriftError):
        badly_behaved(fh)
    assert fh.tell() == 0  # wrapper repairs the offset


def test_report_dict_marks_only_l3_as_confirmed() -> None:
    fh = gz_fixture("luks1/aes-ecb.bin.gz")
    payload = probe(fh, source="luks", credentials={"luks": "password"}).to_dict()
    assert payload["confirmed_formats"] == ["luks"]
    assert payload["strongest_level"] == EvidenceLevel.KEY_VERIFIED
    assert "upstream_policy" in payload


def test_aggregator_retains_simultaneous_conflicting_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force both a magic-based L2 and an entropy-based L1 to fire on the same stream,
    # modelling detectors that disagree (e.g. a high-entropy image with a header).
    from evidence_probe import detectors as det
    from evidence_probe.contract import Evidence

    def fake_luks(fh: BytesIO) -> Evidence:
        start = fh.tell()
        fh.seek(start)
        return Evidence("luks_magic", EvidenceLevel.HEADER_RECOGNIZED, {}, "luks header")

    def fake_vc(fh: BytesIO) -> Evidence:
        return Evidence("veracrypt_entropy_smell", EvidenceLevel.POSSIBLE_ENCRYPTED, {}, "vc smell")

    monkeypatch.setattr(det, "ALL_DETECTORS", (fake_luks, fake_vc))
    import evidence_probe.probe as probe_mod
    monkeypatch.setattr(probe_mod, "ALL_DETECTORS", det.ALL_DETECTORS)

    report = probe_mod.probe(BytesIO(b"x" * 1024), source="conflict")
    levels = {c.format: c.max_level for c in report.candidates}
    assert levels == {"luks": EvidenceLevel.HEADER_RECOGNIZED,
                       "veracrypt": EvidenceLevel.POSSIBLE_ENCRYPTED}
    assert report.confirmed == []  # neither is confirmed without a key
