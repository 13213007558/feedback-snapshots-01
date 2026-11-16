from __future__ import annotations

import gzip
import io
import json
import random
from typing import BinaryIO

import pytest

from dissect.fve.detect import detect, detect_veracrypt
from dissect.fve.detect.contract import (
    Candidate,
    Conclusion,
    DetectionResult,
    EvidenceKind,
    Format,
    VerificationResult,
    VerificationStatus,
    aggregate,
)
from dissect.fve.detect.probes import probe_bde, probe_luks, probe_veracrypt, probe_plaintext
from tests._util import absolute_path

VC_VOLUME = absolute_path("_data/veracrypt/aes256-sha512.hc")
BDE_VOLUME = absolute_path("_data/bde/aes_128.bin.gz")
LUKS1_VOLUME = absolute_path("_data/luks1/aes-ecb.bin.gz")
LUKS2_VOLUME = absolute_path("_data/luks2/aes-ecb.bin.gz")
LUKS2_PBKDF2_VOLUME = absolute_path("_data/luks2/aes-ecb-pbkdf2.bin.gz")


def _read(fh: BinaryIO) -> bytes:
    return fh.read()


def _gz(path) -> bytes:
    with gzip.open(path, "rb") as fh:
        return fh.read()


def _raw(path) -> bytes:
    return path.read_bytes()


@pytest.fixture(scope="session")
def bde_bytes() -> bytes:
    return _gz(BDE_VOLUME)


@pytest.fixture(scope="session")
def luks1_bytes() -> bytes:
    return _gz(LUKS1_VOLUME)


@pytest.fixture(scope="session")
def luks2_bytes() -> bytes:
    return _gz(LUKS2_VOLUME)


@pytest.fixture(scope="session")
def vc_bytes() -> bytes:
    return _raw(VC_VOLUME)


# --------------------------------------------------------------------------------------
# contract semantics
# --------------------------------------------------------------------------------------


def test_entropy_alone_never_claims_a_format() -> None:
    result = detect(io.BytesIO(random.Random(1).randbytes(1 << 20)))
    assert result.conclusion is Conclusion.POSSIBLY_ENCRYPTED
    assert result.format is None
    assert result.confirmed_format is None
    assert all(c.format is None for c in result.candidates if c.conclusion is Conclusion.POSSIBLY_ENCRYPTED)
    assert any("entropy alone" in warning for warning in result.warnings)


def test_unsupported_format_is_not_reported_as_plaintext() -> None:
    result = aggregate(
        [
            Candidate(
                conclusion=Conclusion.UNSUPPORTED_FORMAT,
                format=Format.LUKS,
                supported=False,
            )
        ]
    )
    assert result.conclusion is Conclusion.UNSUPPORTED_FORMAT
    assert result.format is Format.LUKS
    assert result.conclusion is not Conclusion.NOT_ENCRYPTED


def test_plaintext_marker_outranks_entropy_tail() -> None:
    data = b"\xebR\x90NTFS    " + b"\x00" * 500 + random.Random(2).randbytes(4096)
    result = detect(io.BytesIO(data))
    assert result.conclusion is Conclusion.NOT_ENCRYPTED
    assert result.plaintext_markers == ["NTFS"]


def test_conflicting_headers_are_reported_as_ambiguous() -> None:
    result = aggregate(
        [
            Candidate(Conclusion.HEADER_RECOGNIZED, Format.BITLOCKER),
            Candidate(Conclusion.HEADER_RECOGNIZED, Format.LUKS),
        ]
    )
    assert result.conclusion is Conclusion.HEADER_RECOGNIZED
    assert result.ambiguous
    assert result.format is None
    assert result.confirmed_format is None


def test_conflicting_verified_formats_do_not_pick_a_winner() -> None:
    result = aggregate(
        [],
        verifications=[
            VerificationResult(Format.BITLOCKER, VerificationStatus.VERIFIED, method="passphrase"),
            VerificationResult(Format.VERACRYPT, VerificationStatus.VERIFIED, method="passphrase"),
        ],
    )
    assert result.conclusion is Conclusion.HEADER_RECOGNIZED
    assert result.format is None
    assert not result.key_verified
    assert any("multiple formats verified" in warning for warning in result.warnings)


def test_aggregate_does_not_mutate_input_list() -> None:
    candidates = [Candidate(Conclusion.POSSIBLY_ENCRYPTED, None)]
    aggregate(candidates, verifications=[VerificationResult(Format.LUKS, VerificationStatus.VERIFIED, method="x")])
    assert len(candidates) == 1


def test_verified_key_wins_over_header_claim() -> None:
    result = aggregate(
        [Candidate(Conclusion.HEADER_RECOGNIZED, Format.LUKS)],
        verifications=[VerificationResult(Format.LUKS, VerificationStatus.VERIFIED, method="passphrase")],
    )
    assert result.conclusion is Conclusion.KEY_VERIFIED
    assert result.format is Format.LUKS
    assert result.key_verified


def test_result_is_json_serializable() -> None:
    result = detect(io.BytesIO(b""))
    payload = json.loads(result.to_json())
    assert payload["conclusion"] == "inconclusive"
    assert payload["position_preserved"] is True


# --------------------------------------------------------------------------------------
# edge cases
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        pytest.param(b"", Conclusion.INCONCLUSIVE, id="empty"),
        pytest.param(b"\x01", Conclusion.INCONCLUSIVE, id="one-byte"),
        pytest.param(b"\x00" * 4096, Conclusion.INCONCLUSIVE, id="zeros"),
        pytest.param(b"the quick brown fox\n" * 300, Conclusion.INCONCLUSIVE, id="ascii"),
    ],
)
def test_inconclusive_edge_cases(data: bytes, expected: Conclusion) -> None:
    assert detect(io.BytesIO(data)).conclusion is expected


def test_random_bytes_below_entropy_threshold_have_no_format() -> None:
    result = detect(io.BytesIO(random.Random(3).randbytes(4095)))
    assert result.format is None
    assert result.conclusion in (Conclusion.POSSIBLY_ENCRYPTED, Conclusion.INCONCLUSIVE)


def test_high_entropy_payload_reports_generic_candidate_only() -> None:
    result = detect(io.BytesIO(random.Random(4).randbytes(1 << 18)))
    assert result.conclusion is Conclusion.POSSIBLY_ENCRYPTED
    assert result.format is None
    assert not result.ambiguous
    generic = [c for c in result.candidates if c.conclusion is Conclusion.POSSIBLY_ENCRYPTED]
    assert len(generic) == 1
    assert generic[0].format is None


# --------------------------------------------------------------------------------------
# real volumes
# --------------------------------------------------------------------------------------


def test_bde_volume_header_recognized(bde_bytes: bytes) -> None:
    result = detect(io.BytesIO(bde_bytes))
    assert result.conclusion is Conclusion.HEADER_RECOGNIZED
    assert result.format is Format.BITLOCKER
    candidate = result.candidate_for(Format.BITLOCKER)
    assert candidate is not None
    assert any(e.kind is EvidenceKind.HEADER_INTEGRITY for e in candidate.evidence)


def test_bde_volume_key_verified(bde_bytes: bytes) -> None:
    result = detect(io.BytesIO(bde_bytes), key_material={"passphrase": "password12!@"})
    assert result.conclusion is Conclusion.KEY_VERIFIED
    assert result.format is Format.BITLOCKER
    assert result.key_verified


def test_bde_wrong_passphrase_stays_header_recognized(bde_bytes: bytes) -> None:
    result = detect(io.BytesIO(bde_bytes), key_material={"passphrase": "definitely-wrong"})
    assert result.conclusion is Conclusion.HEADER_RECOGNIZED
    assert not result.key_verified
    statuses = [v.status for v in result.verifications if v.format is Format.BITLOCKER]
    assert statuses == [VerificationStatus.REJECTED]


def test_luks1_header_and_key(luks1_bytes: bytes) -> None:
    header = detect(io.BytesIO(luks1_bytes))
    assert header.conclusion is Conclusion.HEADER_RECOGNIZED
    assert header.format is Format.LUKS

    verified = detect(io.BytesIO(luks1_bytes), key_material={"passphrase": "password"})
    assert verified.conclusion is Conclusion.KEY_VERIFIED
    assert verified.format is Format.LUKS


def test_luks2_header_recognized(luks2_bytes: bytes) -> None:
    result = detect(io.BytesIO(luks2_bytes))
    assert result.conclusion in (Conclusion.HEADER_RECOGNIZED, Conclusion.UNSUPPORTED_FORMAT)
    assert result.format is Format.LUKS


def test_luks2_pbkdf2_key_verified() -> None:
    data = _gz(LUKS2_PBKDF2_VOLUME)
    result = detect(io.BytesIO(data), key_material={"passphrase": "password"})
    assert result.conclusion is Conclusion.KEY_VERIFIED
    assert result.format is Format.LUKS


def test_veracrypt_without_key_is_only_possibly_encrypted(vc_bytes: bytes) -> None:
    result = detect(io.BytesIO(vc_bytes))
    assert result.conclusion is Conclusion.POSSIBLY_ENCRYPTED
    assert result.format is None
    assert result.confirmed_format is None


def test_veracrypt_with_key_is_verified(vc_bytes: bytes) -> None:
    result = detect(io.BytesIO(vc_bytes), key_material={"passphrase": "password"})
    assert result.conclusion is Conclusion.KEY_VERIFIED
    assert result.format is Format.VERACRYPT


def test_veracrypt_wrong_key_is_not_claimed(vc_bytes: bytes) -> None:
    result = detect(io.BytesIO(vc_bytes), key_material={"passphrase": "wrong"})
    assert result.conclusion is Conclusion.POSSIBLY_ENCRYPTED
    assert result.format is None


def test_detect_veracrypt_helper(vc_bytes: bytes) -> None:
    fh = io.BytesIO(vc_bytes)
    result = detect_veracrypt(fh, passphrase="password")
    assert result.status is VerificationStatus.VERIFIED
    assert fh.tell() == 0


def test_detect_veracrypt_helper_wrong_passphrase(vc_bytes: bytes) -> None:
    assert detect_veracrypt(io.BytesIO(vc_bytes), passphrase="nope").status is VerificationStatus.REJECTED


# --------------------------------------------------------------------------------------
# spoofed and truncated headers
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b"LUKS\xba\xbe" + b"\x00" * 4096, id="magic-zeros"),
        pytest.param(b"LUKS\xba\xbe" + random.Random(5).randbytes(8188), id="magic-garbage"),
    ],
)
def test_luks_magic_alone_is_not_a_header_claim(data: bytes) -> None:
    result = detect(io.BytesIO(data))
    # The bytes may still look like ciphertext, but no LUKS header may be claimed.
    assert result.format is None
    assert result.conclusion in (Conclusion.INCONCLUSIVE, Conclusion.POSSIBLY_ENCRYPTED)


def test_luks2_corrupted_checksum_is_not_a_header_claim(luks2_bytes: bytes) -> None:
    corrupted = luks2_bytes[:0x1D0] + b"\xff" * 16 + luks2_bytes[0x1E0:]
    result = detect(io.BytesIO(corrupted))
    assert result.conclusion is Conclusion.INCONCLUSIVE
    assert result.format is None


def test_veracrypt_magic_prefix_is_not_a_header_claim() -> None:
    result = detect(io.BytesIO(b"VERA" + random.Random(6).randbytes(4092)))
    assert result.format is None
    assert result.conclusion is Conclusion.POSSIBLY_ENCRYPTED


def test_bitlocker_oem_without_information_block_is_inconclusive() -> None:
    result = detect(io.BytesIO(b"\xebR\x90-FVE-FS-" + b"\x00" * 500))
    assert result.conclusion is Conclusion.INCONCLUSIVE
    assert result.format is None


@pytest.mark.parametrize("length", [0, 100, 511, 512, 4096])
def test_truncated_bitlocker_never_becomes_header_claim(bde_bytes: bytes, length: int) -> None:
    result = detect(io.BytesIO(bde_bytes[:length]))
    assert result.conclusion is Conclusion.INCONCLUSIVE
    assert result.format is None


@pytest.mark.parametrize("length", [6, 100, 512])
def test_truncated_luks1_never_becomes_header_claim(luks1_bytes: bytes, length: int) -> None:
    result = detect(io.BytesIO(luks1_bytes[:length]))
    assert result.conclusion is Conclusion.INCONCLUSIVE
    assert result.format is None


@pytest.mark.parametrize("length", [6, 100, 4096, 8192])
def test_truncated_luks2_never_becomes_header_claim(luks2_bytes: bytes, length: int) -> None:
    result = detect(io.BytesIO(luks2_bytes[:length]))
    assert result.conclusion is Conclusion.INCONCLUSIVE
    assert result.format is None


@pytest.mark.parametrize("length", [64, 100, 512, 575, 576, 1024])
def test_truncated_veracrypt_never_claims_veracrypt(vc_bytes: bytes, length: int) -> None:
    result = detect(io.BytesIO(vc_bytes[:length]))
    assert result.format is None
    assert result.conclusion in (Conclusion.INCONCLUSIVE, Conclusion.POSSIBLY_ENCRYPTED)


# --------------------------------------------------------------------------------------
# stream position handling
# --------------------------------------------------------------------------------------


PROBES = (probe_bde, probe_luks, probe_veracrypt)


@pytest.mark.parametrize("probe", PROBES, ids=lambda p: p.__name__)
@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"\x00" * 512, id="zeros"),
        pytest.param(b"\x01" * 100, id="short"),
        pytest.param(random.Random(7).randbytes(8192), id="random"),
    ],
)
def test_probe_restores_position(probe, data: bytes) -> None:
    fh = io.BytesIO(data)
    fh.seek(0)
    try:
        probe(fh)
    except Exception:  # noqa: BLE001 - the point is that position is restored even on error
        pass
    assert fh.tell() == 0


@pytest.mark.parametrize("probe", PROBES, ids=lambda p: p.__name__)
def test_probe_restores_position_on_real_volume(probe, bde_bytes: bytes) -> None:
    fh = io.BytesIO(bde_bytes)
    fh.seek(123)
    probe(fh)
    assert fh.tell() == 123


def test_probe_plaintext_restores_position() -> None:
    fh = io.BytesIO(b"\xebR\x90NTFS    " + b"\x00" * 600)
    fh.seek(50)
    probe_plaintext(fh)
    assert fh.tell() == 50


def test_detect_restores_position_on_all_inputs() -> None:
    for data in (b"", b"\x00" * 512, random.Random(8).randbytes(8192), _gz(BDE_VOLUME)[:4096]):
        fh = io.BytesIO(data)
        detect(fh)
        assert fh.tell() == 0


def test_detect_reports_failed_position_restoration() -> None:
    class Stubborn(io.BytesIO):
        def seek(self, *args, **kwargs):  # type: ignore[override]
            raise OSError("cannot seek")

    result = detect(Stubborn(b"\x00" * 512))
    assert result.position_preserved is False


def test_detect_does_not_crash_on_probe_errors(monkeypatch) -> None:
    import dissect.fve.detect as detect_module

    def boom(fh, **_kwargs):
        raise RuntimeError("probe exploded")

    monkeypatch.setitem(detect_module.PROBES, Format.BITLOCKER, boom)
    result = detect(io.BytesIO(b"\x00" * 512))
    assert "bitlocker" in result.probe_errors
    assert "probe exploded" in result.probe_errors["bitlocker"]
    assert result.position_preserved


# --------------------------------------------------------------------------------------
# offsets
# --------------------------------------------------------------------------------------


def test_detect_at_nonzero_offset(luks1_bytes: bytes) -> None:
    prefix = b"\xaa" * 4096
    result = detect(io.BytesIO(prefix + luks1_bytes), offset=4096, size=len(luks1_bytes))
    assert result.conclusion is Conclusion.HEADER_RECOGNIZED
    assert result.format is Format.LUKS
    assert result.offset == 4096


def test_detect_offset_preserves_outer_position(luks1_bytes: bytes) -> None:
    fh = io.BytesIO(b"\xaa" * 4096 + luks1_bytes)
    fh.seek(777)
    detect(fh, offset=4096)
    assert fh.tell() == 777


def test_detect_bounded_size_does_not_read_past_end(luks1_bytes: bytes) -> None:
    fh = io.BytesIO(luks1_bytes[:1024] + b"\x99" * 8192)
    result = detect(fh, size=1024)
    assert result.size == 1024
    assert result.conclusion is Conclusion.HEADER_RECOGNIZED


def test_detection_result_helpers() -> None:
    result = DetectionResult(conclusion=Conclusion.INCONCLUSIVE, format=None)
    assert not result.ambiguous
    assert not result.key_verified
    assert result.candidate_for(Format.LUKS) is None


# --------------------------------------------------------------------------------------
# verification status semantics
# --------------------------------------------------------------------------------------


def test_decrypted_bitlocker_volume_has_no_key_to_verify() -> None:
    data = _gz(absolute_path("_data/bde/decrypted.bin.gz"))
    result = detect(io.BytesIO(data), key_material={"passphrase": "password12!@"})
    assert result.conclusion is Conclusion.HEADER_RECOGNIZED
    statuses = [v.status for v in result.verifications if v.format is Format.BITLOCKER]
    assert statuses == [VerificationStatus.NOT_APPLICABLE]


def test_unsupported_backend_is_not_reported_as_key_rejection() -> None:
    data = _gz(LUKS2_VOLUME)
    result = detect(io.BytesIO(data), key_material={"passphrase": "password"})
    status = next(v.status for v in result.verifications if v.format is Format.LUKS)
    assert status in (VerificationStatus.UNSUPPORTED, VerificationStatus.VERIFIED, VerificationStatus.REJECTED)
    if status is VerificationStatus.UNSUPPORTED:
        assert result.conclusion is not Conclusion.KEY_VERIFIED
        assert result.format is Format.LUKS


def test_unsupported_format_detail_records_limitation() -> None:
    data = _gz(LUKS2_VOLUME)
    result = detect(io.BytesIO(data))
    candidate = result.candidate_for(Format.LUKS)
    if candidate is not None and candidate.supported is False:
        assert candidate.details.get("limitation") in ("implementation", "environment")


def test_key_material_for_absent_format_only_warns() -> None:
    result = detect(io.BytesIO(b"\x00" * 4096), key_material={"recovery_password": "000000-000000"})
    assert result.conclusion is Conclusion.INCONCLUSIVE
    assert any("BitLocker-specific key material" in warning for warning in result.warnings)


def test_recognized_but_environment_unsupported_is_not_plaintext() -> None:
    """A LUKS2 header we can parse but not unlock must stay recognized, with a reason."""
    from dissect.fve.crypto import argon2

    if argon2.HAS_ARGON2:
        pytest.skip("Argon2 backend present; cannot exercise the missing-backend path")

    data = _gz(LUKS2_VOLUME)
    result = detect(io.BytesIO(data))
    assert result.conclusion is Conclusion.HEADER_RECOGNIZED
    assert result.format is Format.LUKS
    candidate = result.candidate_for(Format.LUKS)
    assert candidate is not None
    assert candidate.supported is False
    assert candidate.details["limitation"] == "environment"
    assert result.conclusion is not Conclusion.NOT_ENCRYPTED


def test_unsupported_format_never_has_plaintext_marker() -> None:
    result = aggregate([Candidate(Conclusion.UNSUPPORTED_FORMAT, Format.LUKS, supported=False)])
    assert result.plaintext_markers == []
    assert result.conclusion is Conclusion.UNSUPPORTED_FORMAT


def test_conflicting_unsupported_formats_are_ambiguous() -> None:
    result = aggregate(
        [
            Candidate(Conclusion.UNSUPPORTED_FORMAT, Format.LUKS, supported=False),
            Candidate(Conclusion.UNSUPPORTED_FORMAT, Format.BITLOCKER, supported=False),
        ]
    )
    assert result.ambiguous
    assert result.format is None
    assert result.conclusion is Conclusion.UNSUPPORTED_FORMAT


def test_veracrypt_system_volume_with_header_key() -> None:
    from dissect.util.stream import MappingStream

    raw = absolute_path("_data/veracrypt/aes256-sha512.system").read_bytes()
    stream = MappingStream(size=31744 + 512 + 64)
    stream.add(offset=0, size=31744, fh=io.BytesIO(b"\x01" * 31744))
    stream.add(offset=0x7C00, size=512 + 64, fh=io.BytesIO(raw + (64 * b"\x01")))

    header_key = bytes.fromhex(
        "9b390d357149246a1ef0766d9b327dbb422631211f6ef37f722238d4a2b5fcaf"
        "9361c57d774c386baf806c4cb5097ee455997363a65c3eb684e8bc9ad3ee11e6"
    )
    result = detect(stream, veracrypt_is_system=True, key_material={"header_key": header_key})
    assert result.conclusion is Conclusion.KEY_VERIFIED
    assert result.format is Format.VERACRYPT


def test_veracrypt_system_header_not_found_without_flag() -> None:
    from dissect.util.stream import MappingStream

    raw = absolute_path("_data/veracrypt/aes256-sha512.system").read_bytes()
    stream = MappingStream(size=31744 + 512 + 64)
    stream.add(offset=0, size=31744, fh=io.BytesIO(b"\x01" * 31744))
    stream.add(offset=0x7C00, size=512 + 64, fh=io.BytesIO(raw + (64 * b"\x01")))

    result = detect(stream, key_material={"passphrase": "password"})
    assert result.conclusion is not Conclusion.KEY_VERIFIED
    assert result.format is None


def test_negative_offset_and_size_are_rejected() -> None:
    with pytest.raises(ValueError, match="offset must be non-negative"):
        detect(io.BytesIO(b"\x00" * 512), offset=-1)
    with pytest.raises(ValueError, match="size must be non-negative"):
        detect(io.BytesIO(b"\x00" * 512), size=-1)


def test_zero_size_is_inconclusive() -> None:
    result = detect(io.BytesIO(b"\x00" * 512), size=0)
    assert result.conclusion is Conclusion.INCONCLUSIVE
    assert result.size == 0


def test_formats_accept_string_values(luks1_bytes: bytes) -> None:
    result = detect(io.BytesIO(luks1_bytes), formats=["luks"])
    assert result.format is Format.LUKS
    assert len(result.candidates) == 1
    assert result.candidates[0].format is Format.LUKS


def test_formats_can_exclude_a_format() -> None:
    result = detect(io.BytesIO(b"\x00" * 512), formats=[Format.LUKS])
    assert result.format is None
    assert len(result.candidates) == 1
