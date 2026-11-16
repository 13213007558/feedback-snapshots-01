"""Structured fuzzing for BitLocker metadata boundaries.

The cases in this module walk three nested layers of the on-disk format:

1. ``Dataset``: a sequence of datums bounded by ``StartOffset``/``EndOffset``.
2. Nested datums: datums inside a complex datum (a VMK's properties).
3. Authenticated inner datums: the plaintext behind an AES-CCM encrypted datum.

All keys and bytes are synthetic. Assertions are made against read budgets, termination positions
and the datum that was actually selected, not merely against the presence of an exception.
"""

from __future__ import annotations

import random
import struct
from io import BytesIO

import pytest

from dissect.fve.bde import bde
from dissect.fve.bde.c_bde import FVE_DATUM_ROLE, FVE_DATUM_TYPE, FVE_KEY_TYPE, c_bde
from dissect.fve.bde.information import MAX_DATUM_DEPTH, Dataset, Information
from dissect.fve.exception import InvalidDatumError, InvalidHeaderError
from tests.bde import _fuzz as fz

VMK = fz.VMK_KEY
FVEK = fz.FVEK_KEY


def dataset_from_bytes(buf: bytes) -> Dataset:
    return Dataset(BytesIO(buf))


def test_valid_volume_selects_generated_keys() -> None:
    """The baseline volume is well-formed and unlock selects exactly the generated keys."""
    volume = fz.default_volume()
    recording = fz.RecordingReader(volume)
    bde_obj = bde.BDE(recording)

    assert bde_obj.information.is_valid()
    assert bde_obj.information.check_integrity(VMK)

    # Only the boot sector, the information block and its validation/integrity are read.
    assert recording.max_offset <= fz.INFORMATION_OFFSET + bde_obj.information.size + len(c_bde.FVE_VALIDATION) + 0x100
    assert recording.bytes_read < len(volume)

    bde_obj.unlock_with_clear_key()
    assert bde_obj._vmk_datum is not None
    assert bde_obj._fvek_datum is not None
    assert bde_obj._vmk == VMK
    assert bde_obj._fvek == FVEK
    assert bde_obj._vmk_datum.role == FVE_DATUM_ROLE.PROPERTY
    assert bde_obj._fvek_datum.role == FVE_DATUM_ROLE.PROPERTY


def test_zero_length_datum_does_not_loop() -> None:
    """A zero-sized datum must be rejected without looping, at a bounded offset."""
    buf = fz.dataset(fz.datum(FVE_DATUM_ROLE.VOLUME_MASTER_KEY_INFO, FVE_DATUM_TYPE.VOLUME_MASTER_KEY_INFO, size=0))
    ds = dataset_from_bytes(buf)

    with pytest.raises(InvalidDatumError) as excinfo:
        _ = ds.data

    assert excinfo.value.reason == "zero_size"
    assert excinfo.value.offset == 0


def test_undersized_datum_is_rejected() -> None:
    for size in (1, 4, c_bde.FVE_DATUM.size - 1):
        buf = fz.dataset(fz.datum(FVE_DATUM_ROLE.PROPERTY, FVE_DATUM_TYPE.KEY, size=size))

        with pytest.raises(InvalidDatumError) as excinfo:
            _ = dataset_from_bytes(buf).data

        assert excinfo.value.reason == "undersized"
        assert excinfo.value.offset == 0


def test_zero_length_datum_terminates_in_real_volume_shell() -> None:
    """A zero-sized nested datum is caught inside an otherwise valid, authenticated shell."""
    broken_properties = fz.key_datum(FVE_DATUM_ROLE.PROPERTY, VMK, FVE_KEY_TYPE.VMK) + fz.datum(
        FVE_DATUM_ROLE.PROPERTY, FVE_DATUM_TYPE.AES_CCM_ENCRYPTED_KEY, size=0
    )
    data = fz.dataset(fz.vmk_datum(broken_properties))
    bde_obj = bde.BDE(BytesIO(fz.build_volume(data)))

    with pytest.raises(InvalidDatumError) as excinfo:
        _ = bde_obj.information.dataset.data[0].properties

    assert excinfo.value.reason == "zero_size"
    assert excinfo.value.depth == 1
    # The offending nested datum is the second property of the VMK.
    assert excinfo.value.offset == len(fz.key_datum(FVE_DATUM_ROLE.PROPERTY, VMK, FVE_KEY_TYPE.VMK))


def test_datum_out_of_parent_bounds_is_rejected() -> None:
    """A datum larger than its parent must not consume the next datum."""
    good = fz.key_datum(FVE_DATUM_ROLE.PROPERTY, b"\x01" * 32, FVE_KEY_TYPE.VMK)
    oversized = fz.datum(
        FVE_DATUM_ROLE.VOLUME_MASTER_KEY_INFO,
        FVE_DATUM_TYPE.VOLUME_MASTER_KEY_INFO,
        size=len(good) + 0x100,
    )
    buf = fz.dataset(oversized + good)

    with pytest.raises(InvalidDatumError) as excinfo:
        _ = dataset_from_bytes(buf).data

    assert excinfo.value.reason == "out_of_bounds"
    assert excinfo.value.offset == 0


def test_oversized_nested_datum_cannot_use_sibling_key() -> None:
    """A VMK that claims its sibling FVEK parses it, but must never select it as its own key."""
    vmk = fz.vmk_datum(fz.clear_vmk_properties())
    fvek = fz.ccm_datum(
        FVE_DATUM_ROLE.FULL_VOLUME_ENCRYPTION_KEY,
        VMK,
        fz.key_datum(FVE_DATUM_ROLE.PROPERTY, FVEK, FVE_KEY_TYPE.AES_128),
        counter=3,
    )

    # Rebuild the VMK so its declared size covers the sibling FVEK.
    swallowed = bytearray(vmk)
    struct.pack_into("<H", swallowed, 0, len(swallowed) + len(fvek))
    dataset = dataset_from_bytes(fz.dataset(bytes(swallowed) + fvek))

    vmks = list(dataset.find_datum(FVE_DATUM_ROLE.VOLUME_MASTER_KEY_INFO, FVE_DATUM_TYPE.VOLUME_MASTER_KEY_INFO))
    assert len(vmks) == 1
    vmk_datum = vmks[0]

    # The FVEK is now inside the VMK's declared range. It must not be selectable as the VMK key.
    nested_ccm = [child for child in vmk_datum.properties if child.type == FVE_DATUM_TYPE.AES_CCM_ENCRYPTED_KEY]
    assert len(nested_ccm) == 2
    assert nested_ccm[-1].role == FVE_DATUM_ROLE.FULL_VOLUME_ENCRYPTION_KEY
    assert nested_ccm[-1] not in list(vmk_datum.find_property(FVE_DATUM_TYPE.AES_CCM_ENCRYPTED_KEY))
    selected = vmk_datum.aes_ccm_encrypted_key()
    assert selected is not None
    assert selected.role == FVE_DATUM_ROLE.PROPERTY
    assert selected.raw == fz.ccm_datum(
        FVE_DATUM_ROLE.PROPERTY, VMK, fz.key_datum(FVE_DATUM_ROLE.PROPERTY, VMK, FVE_KEY_TYPE.VMK), counter=2
    )


def test_dataset_bounds_are_enforced() -> None:
    datums = fz.key_datum(FVE_DATUM_ROLE.PROPERTY, b"\x01" * 32, FVE_KEY_TYPE.VMK)

    for start, end in ((0, c_bde.FVE_DATASET.size + len(datums)), (c_bde.FVE_DATASET.size, c_bde.FVE_DATASET.size - 1)):
        buf = fz.dataset(datums, start=start, end=end)

        with pytest.raises(InvalidHeaderError):
            _ = dataset_from_bytes(buf).data


def test_dataset_size_cannot_exceed_information() -> None:
    """A dataset header claiming more bytes than the information buffer is rejected up front."""
    information = bytearray(fz.build_information(fz.default_dataset()))
    dataset_offset = 64
    struct.pack_into("<I", information, dataset_offset, fz.INFORMATION_OFFSET + 0x10000)

    with pytest.raises(InvalidHeaderError):
        Dataset(BytesIO(bytes(information[dataset_offset:])))

    volume = bytearray(fz.default_volume())
    struct.pack_into("<I", volume, fz.INFORMATION_OFFSET + dataset_offset, 0x100000)
    with pytest.raises(InvalidHeaderError):
        Information(BytesIO(bytes(volume)), fz.INFORMATION_OFFSET)


def test_partial_datum_header_is_rejected() -> None:
    datums = fz.key_datum(FVE_DATUM_ROLE.PROPERTY, b"\x01" * 32, FVE_KEY_TYPE.VMK)
    buf = fz.dataset(datums + b"\x00\x01\x02")

    with pytest.raises(InvalidDatumError) as excinfo:
        _ = dataset_from_bytes(buf).data

    assert excinfo.value.reason == "truncated_header"
    assert excinfo.value.offset == len(datums)


def test_unknown_role_and_type_are_preserved() -> None:
    """Unknown datums keep their raw bytes and do not disturb their neighbours."""
    unknown_role = 0x1234
    unknown_type = 0x9999
    unknown = fz.datum(unknown_role, unknown_type, b"\xde\xad\xbe\xef")
    known = fz.vmk_datum(fz.clear_vmk_properties())
    buf = fz.dataset(unknown + known)
    data = dataset_from_bytes(buf).data

    assert len(data) == 2
    assert data[0].raw == unknown
    assert data[0].role.value == unknown_role
    assert data[0].type.value == unknown_type
    assert data[0].data_segment == b"\xde\xad\xbe\xef"
    # The known VMK is still parsed as a VMK and selects its own key.
    assert data[1].role == FVE_DATUM_ROLE.VOLUME_MASTER_KEY_INFO
    assert data[1].clear_key().data == VMK


def test_unknown_nested_datum_preserves_bytes() -> None:
    unknown = fz.datum(FVE_DATUM_ROLE.PROPERTY, 0xBEEF, b"opaque-nested")
    vmk = fz.vmk_datum(unknown + fz.key_datum(FVE_DATUM_ROLE.PROPERTY, VMK, FVE_KEY_TYPE.VMK))
    data = dataset_from_bytes(fz.dataset(vmk)).data

    assert data[0].properties[0].raw == unknown
    assert data[0].properties[0].data_segment == b"opaque-nested"
    assert data[0].clear_key().data == VMK


def test_nested_non_property_role_is_not_selected_as_key() -> None:
    """A nested AES-CCM datum with a foreign role must not be chosen as the VMK key."""
    foreign = fz.ccm_datum(
        FVE_DATUM_ROLE.FULL_VOLUME_ENCRYPTION_KEY,
        VMK,
        fz.key_datum(FVE_DATUM_ROLE.PROPERTY, b"\x02" * 32, FVE_KEY_TYPE.AES_128),
        counter=5,
    )
    own = fz.ccm_datum(
        FVE_DATUM_ROLE.PROPERTY,
        VMK,
        fz.key_datum(FVE_DATUM_ROLE.PROPERTY, VMK, FVE_KEY_TYPE.VMK),
        counter=2,
    )
    vmk = dataset_from_bytes(fz.dataset(fz.vmk_datum(foreign + own))).data[0]

    selected = vmk.aes_ccm_encrypted_key()
    assert selected is not None
    assert selected.role == FVE_DATUM_ROLE.PROPERTY
    assert selected.raw == own
    assert vmk.decrypt(VMK).data == VMK


@pytest.mark.parametrize(
    "inner",
    [
        b"",
        b"\x00",
        b"\x01\x00\x00\x00\x01\x00\x00\x00",
        b"\x0c\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00",
        fz.key_datum(FVE_DATUM_ROLE.PROPERTY, FVEK, FVE_KEY_TYPE.AES_128) + b"\x00" * 8,
    ],
    ids=["empty", "short", "header-only", "zero-length-key", "trailing-bytes"],
)
def test_authenticated_shell_with_bad_inner_structure(inner: bytes) -> None:
    """A valid AES-CCM shell with a malformed plaintext must fail at the inner framing boundary."""
    encrypted = fz.ccm_datum(FVE_DATUM_ROLE.PROPERTY, VMK, inner)
    vmk = fz.vmk_datum(encrypted)
    parsed = dataset_from_bytes(fz.dataset(vmk)).data[0]

    with pytest.raises(InvalidDatumError) as excinfo:
        parsed.decrypt(VMK)

    assert excinfo.value.reason in {
        "empty",
        "empty_key",
        "undersized",
        "zero_size",
        "truncated_header",
        "truncated_struct",
    }
    # The outer shell was authenticated, so the failure is deterministic and repeatable.
    with pytest.raises(InvalidDatumError) as second:
        parsed.decrypt(VMK)
    assert second.value.reason == excinfo.value.reason
    assert second.value.offset == excinfo.value.offset


def test_authenticated_shell_with_foreign_inner_datum_fails_in_unlock() -> None:
    """A valid shell whose plaintext is an FVEK-shaped datum must not be accepted as a VMK."""
    fvek_shaped = fz.key_datum(FVE_DATUM_ROLE.FULL_VOLUME_ENCRYPTION_KEY, FVEK, FVE_KEY_TYPE.AES_128)
    data = fz.dataset(
        fz.vmk_datum(
            fz.key_datum(FVE_DATUM_ROLE.PROPERTY, VMK, FVE_KEY_TYPE.VMK)
            + fz.ccm_datum(FVE_DATUM_ROLE.PROPERTY, VMK, fvek_shaped, counter=2)
        )
    )
    bde_obj = bde.BDE(BytesIO(fz.build_volume(data)))

    with pytest.raises(ValueError, match="Unable to unlock with clear key"):
        bde_obj.unlock_with_clear_key()

    assert not bde_obj.unlocked
    assert bde_obj._fvek_datum is None


def test_mac_failure_is_not_mistaken_for_framing_failure() -> None:
    encrypted = bytearray(
        fz.ccm_datum(FVE_DATUM_ROLE.PROPERTY, VMK, fz.key_datum(FVE_DATUM_ROLE.PROPERTY, VMK, FVE_KEY_TYPE.VMK))
    )
    # Flip a ciphertext byte.
    encrypted[-1] ^= 0xFF
    parsed = dataset_from_bytes(fz.dataset(fz.vmk_datum(bytes(encrypted)))).data[0]

    with pytest.raises(ValueError, match="Invalid AES-CCM encrypted datum"):
        parsed.decrypt(VMK)


def test_deep_nesting_is_bounded() -> None:
    """A deeply nested datum chain terminates at the configured depth, not by recursion error."""

    def nested_chain() -> bytes:
        chain = fz.key_datum(FVE_DATUM_ROLE.PROPERTY, VMK, FVE_KEY_TYPE.VMK)
        for _ in range(MAX_DATUM_DEPTH + 8):
            chain = fz.vmk_datum(chain)
        return chain

    def walk_depth(buf: bytes) -> int:
        node = dataset_from_bytes(buf).data[0]
        depth = 0
        while node.properties:
            node = node.properties[0]
            depth += 1
        return depth

    buf = fz.dataset(nested_chain())

    with pytest.raises(InvalidDatumError) as excinfo:
        walk_depth(buf)

    assert excinfo.value.reason == "too_deep"
    assert excinfo.value.depth == MAX_DATUM_DEPTH + 1

    # Every level must be bounded and deterministic across repeated parsing.
    with pytest.raises(InvalidDatumError) as second:
        walk_depth(buf)
    assert second.value.reason == excinfo.value.reason
    assert second.value.depth == excinfo.value.depth


def test_read_budget_for_nested_walk() -> None:
    """Walking nested properties reads each byte a bounded number of times."""
    data = fz.dataset(fz.vmk_datum(fz.clear_vmk_properties()))
    recording = fz.RecordingReader(data)
    dataset = Dataset(recording)
    _ = dataset.data
    first_reads = len(recording.reads)

    assert recording.bytes_read <= len(data)
    assert recording.max_offset <= len(data)

    # Accessing cached properties again must not cause additional reads of the dataset buffer.
    _ = dataset.data[0].properties
    assert len(recording.reads) == first_reads


def test_minimal_sample_for_zero_size_datum() -> None:
    """Reduce a richer malformed dataset to a minimal input that still reaches the same failure."""
    payload = fz.key_datum(FVE_DATUM_ROLE.PROPERTY, VMK, FVE_KEY_TYPE.VMK) + b"\x00" * 24
    broken = fz.vmk_datum(payload) + fz.datum(
        FVE_DATUM_ROLE.VOLUME_MASTER_KEY_INFO, FVE_DATUM_TYPE.VOLUME_MASTER_KEY_INFO, size=0
    )

    def mutate(candidate: bytes) -> bytes:
        return candidate

    def predicate(candidate: bytes) -> bool:
        try:
            _ = Dataset(BytesIO(fz.dataset(candidate))).data
        except InvalidDatumError as e:
            return e.reason == "zero_size"
        return False

    minimal = fz.minimize(mutate, predicate, broken)
    assert len(minimal) < len(broken)
    with pytest.raises(InvalidDatumError) as excinfo:
        _ = Dataset(BytesIO(fz.dataset(minimal))).data
    assert excinfo.value.reason == "zero_size"


def test_minimal_authenticated_shell_sample() -> None:
    """Reduce a real authenticated shell to the smallest plaintext that still fails inner parsing."""
    malformed = fz.key_datum(FVE_DATUM_ROLE.PROPERTY, FVEK, FVE_KEY_TYPE.AES_128)[:6] + b"\x00" * 8

    def mutate(candidate: bytes) -> bytes:
        return fz.dataset(fz.vmk_datum(fz.ccm_datum(FVE_DATUM_ROLE.PROPERTY, VMK, candidate)))

    def predicate(candidate: bytes) -> bool:
        try:
            dataset_from_bytes(mutate(candidate)).data[0].decrypt(VMK)
        except InvalidDatumError as e:
            return e.reason in {"truncated_header", "truncated_struct", "trailing_data", "empty"}
        return False

    minimal = fz.minimize(mutate, predicate, malformed)
    assert len(minimal) <= len(malformed)
    with pytest.raises(InvalidDatumError):
        dataset_from_bytes(mutate(minimal)).data[0].decrypt(VMK)


def _swallow(datum_bytes: bytes, sibling: bytes) -> bytes:
    """Return ``datum_bytes`` with its declared size extended to cover ``sibling``."""
    swallowed = bytearray(datum_bytes)
    struct.pack_into("<H", swallowed, 0, len(swallowed) + len(sibling))
    return bytes(swallowed)


def test_swallowed_first_fvek_does_not_become_vmk_property_and_unlock_uses_second_fvek() -> None:
    """An FVEK engulfed by a VMK must be ignored; the next real top-level FVEK is selected."""
    first_inner = fz.key_datum(FVE_DATUM_ROLE.PROPERTY, b"\x00" * 32, FVE_KEY_TYPE.AES_128)
    second_inner = fz.key_datum(FVE_DATUM_ROLE.PROPERTY, FVEK, FVE_KEY_TYPE.AES_128)
    first_fvek = fz.ccm_datum(FVE_DATUM_ROLE.FULL_VOLUME_ENCRYPTION_KEY, VMK, first_inner, counter=3)
    second_fvek = fz.ccm_datum(FVE_DATUM_ROLE.FULL_VOLUME_ENCRYPTION_KEY, VMK, second_inner, counter=9)

    vmk = fz.vmk_datum(fz.clear_vmk_properties())
    data = fz.dataset(_swallow(vmk, first_fvek) + first_fvek + second_fvek)
    bde_obj = bde.BDE(BytesIO(fz.build_volume(data)))

    bde_obj.unlock_with_clear_key()

    # The selected FVEK is the unboxed key of the second, top-level encrypted FVEK datum.
    assert bde_obj._fvek == FVEK
    assert bde_obj._fvek_datum is not None
    assert bde_obj._fvek_datum.key_type == FVE_KEY_TYPE.AES_128
    assert bde_obj._fvek_datum.data == FVEK
    selected_encrypted = bde_obj.information.dataset.find_fvek()
    assert selected_encrypted is not None
    assert selected_encrypted.raw == second_fvek
    assert selected_encrypted.nonce_counter == 9

    # The swallowed FVEK stays visible as a nested datum, but is not a PROPERTY and never selected.
    vmk_datum = bde_obj.information.dataset.data[0]
    nested = [child for child in vmk_datum.properties if child.type == FVE_DATUM_TYPE.AES_CCM_ENCRYPTED_KEY]
    assert any(child.raw == first_fvek for child in nested)
    assert all(
        child.role == FVE_DATUM_ROLE.PROPERTY for child in vmk_datum.find_property(FVE_DATUM_TYPE.AES_CCM_ENCRYPTED_KEY)
    )


def test_swallowed_only_fvek_is_not_used_by_unlock() -> None:
    """If the only FVEK is inside a VMK, unlock must fail instead of borrowing it."""
    fvek = fz.ccm_datum(
        FVE_DATUM_ROLE.FULL_VOLUME_ENCRYPTION_KEY,
        VMK,
        fz.key_datum(FVE_DATUM_ROLE.PROPERTY, FVEK, FVE_KEY_TYPE.AES_128),
        counter=3,
    )
    vmk = fz.vmk_datum(fz.clear_vmk_properties())
    data = fz.dataset(_swallow(vmk, fvek) + fvek)
    bde_obj = bde.BDE(BytesIO(fz.build_volume(data)))

    with pytest.raises(ValueError, match="No FVEK found"):
        bde_obj.unlock_with_clear_key()

    assert not bde_obj.unlocked
    assert bde_obj._fvek_datum is None
    assert bde_obj._fvek is None


def test_fvek_with_wrong_type_is_not_selected() -> None:
    """Role alone is not enough: an FVEK-role datum with a non-AES-CCM type is ignored."""
    wrong_type = fz.datum(
        FVE_DATUM_ROLE.FULL_VOLUME_ENCRYPTION_KEY,
        FVE_DATUM_TYPE.KEY,
        c_bde.FVE_DATUM_KEY(KeyType=int(FVE_KEY_TYPE.AES_128), KeyFlags=0).dumps() + FVEK,
    )
    data = fz.dataset(fz.vmk_datum(fz.clear_vmk_properties()) + wrong_type)
    bde_obj = bde.BDE(BytesIO(fz.build_volume(data)))

    with pytest.raises(ValueError, match="No FVEK found"):
        bde_obj.unlock_with_clear_key()


def test_malformed_input_read_budget_is_bounded() -> None:
    """A corrupt declared size must not trigger reads beyond the enclosing dataset."""
    datums = fz.datum(FVE_DATUM_ROLE.PROPERTY, 0x9999, b"\xaa" * 16, size=0xFFFF)
    buf = fz.dataset(datums)
    recording = fz.RecordingReader(buf)
    dataset = Dataset(recording)

    with pytest.raises(InvalidDatumError) as excinfo:
        _ = dataset.data

    assert excinfo.value.reason == "out_of_bounds"
    # The dataset is read exactly once and nothing beyond it is touched.
    assert recording.bytes_read == len(buf)
    assert recording.max_offset == len(buf)
    assert recording.tell() == len(buf)


def test_malformed_volume_does_not_scan_past_information() -> None:
    """Parsing a corrupt volume never reads beyond the information block it validated."""
    volume = bytearray(fz.default_volume())
    bde_obj = bde.BDE(BytesIO(bytes(volume)))
    dataset_offset = fz.INFORMATION_OFFSET + 64
    struct.pack_into("<H", volume, dataset_offset + 8, len(volume))  # StartOffset far out of range

    recording = fz.RecordingReader(bytes(volume))
    with pytest.raises(InvalidHeaderError):
        bde.BDE(recording)

    information_end = fz.INFORMATION_OFFSET + bde_obj.information.size
    assert recording.max_offset <= information_end + len(c_bde.FVE_VALIDATION) + 0x100
    assert recording.max_offset < len(volume)


def test_unknown_datum_with_known_key_types_is_not_selected() -> None:
    """Unknown role/type combinations that carry key-shaped payloads stay inert."""
    unknown = fz.datum(0x4242, 0x9999, fz.key_datum(FVE_DATUM_ROLE.PROPERTY, VMK, FVE_KEY_TYPE.VMK)[8:])
    fvek = fz.ccm_datum(
        FVE_DATUM_ROLE.FULL_VOLUME_ENCRYPTION_KEY,
        VMK,
        fz.key_datum(FVE_DATUM_ROLE.PROPERTY, FVEK, FVE_KEY_TYPE.AES_128),
        counter=3,
    )
    data = fz.dataset(fz.vmk_datum(fz.clear_vmk_properties()) + unknown + fvek)
    bde_obj = bde.BDE(BytesIO(fz.build_volume(data)))
    bde_obj.unlock_with_clear_key()

    assert bde_obj._fvek == FVEK
    assert bde_obj._fvek_datum.data == FVEK
    assert bde_obj.information.dataset.find_fvek().raw == fvek
    assert len(bde_obj.information.dataset.data) == 3
    assert bde_obj.information.dataset.data[1].raw == unknown


CORPUS = pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("zero_size.bin", "zero_size"),
        ("out_of_bounds.bin", "out_of_bounds"),
    ],
)


@CORPUS
def test_reduced_corpus_is_minimal_for_reason(name: str, reason: str) -> None:
    """Every shipped sample fails for its recorded reason and no single byte can be removed."""
    buf = (fz.CORPUS_DIR / name).read_bytes()
    dataset = Dataset(BytesIO(buf))

    with pytest.raises(InvalidDatumError) as excinfo:
        _ = dataset.data
    assert excinfo.value.reason == reason

    # One-minimality: removing any single byte must destroy this exact failure, either by parsing
    # successfully or by failing earlier for a different reason. Keeping the same reason after a
    # deletion would mean the sample is not reduced.
    for offset in range(len(buf)):
        candidate = buf[:offset] + buf[offset + 1 :]
        try:
            _ = Dataset(BytesIO(candidate)).data
        except InvalidDatumError as e:
            assert e.reason != reason, f"removing byte {offset} preserved the failure at {e.offset}"
        except InvalidHeaderError:
            pass


def test_reduced_swallowed_fvek_sample_never_selects_the_sibling() -> None:
    buf = (fz.CORPUS_DIR / "swallowed_fvek.bin").read_bytes()
    dataset = Dataset(BytesIO(buf))
    vmk = dataset.data[0]

    assert vmk.aes_ccm_encrypted_key().role == FVE_DATUM_ROLE.PROPERTY
    nested_roles = {child.role for child in vmk.properties if child.type == FVE_DATUM_TYPE.AES_CCM_ENCRYPTED_KEY}
    assert nested_roles == {FVE_DATUM_ROLE.PROPERTY, FVE_DATUM_ROLE.FULL_VOLUME_ENCRYPTION_KEY}


def test_reduced_unknown_sample_preserves_payload() -> None:
    buf = (fz.CORPUS_DIR / "unknown_datum.bin").read_bytes()
    unknown = Dataset(BytesIO(buf)).data[0]

    assert unknown.role.value == 0x1234
    assert unknown.type.value == 0x9999
    assert unknown.raw == fz.datum(0x1234, 0x9999, b"\xde\xad\xbe\xef")


def test_reduced_deep_nesting_sample_terminates() -> None:
    buf = (fz.CORPUS_DIR / "deep_nesting.bin").read_bytes()
    node = Dataset(BytesIO(buf)).data[0]
    depth = 0

    with pytest.raises(InvalidDatumError) as excinfo:
        while node.properties:
            node = node.properties[0]
            depth += 1

    assert excinfo.value.reason == "too_deep"
    assert depth == MAX_DATUM_DEPTH


def test_reduced_authenticated_sample_fails_inside_the_shell() -> None:
    buf = (fz.CORPUS_DIR / "authenticated_bad_inner.bin").read_bytes()
    vmk = Dataset(BytesIO(buf)).data[0]

    with pytest.raises(InvalidDatumError) as excinfo:
        vmk.decrypt(fz.CORPUS_KEY)

    assert excinfo.value.reason == "truncated_struct"


def _mutations(seed: int, count: int) -> list[bytes]:
    """Deterministic datum-level mutations of a valid dataset."""
    rng = random.Random(seed)
    base = fz.dataset(fz.vmk_datum(fz.clear_vmk_properties()))
    top_offset = c_bde.FVE_DATASET.size
    vmk_size = c_bde.FVE_DATUM(base[top_offset:]).Size

    result = []
    for _ in range(count):
        mutated = bytearray(base)
        field = rng.choice(["size", "role", "type", "flags", "payload", "start", "end"])
        if field in ("size", "role", "type", "flags"):
            field_offset = {"size": 0, "role": 2, "type": 4, "flags": 6}[field]
            struct.pack_into("<H", mutated, top_offset + field_offset, rng.randrange(0, 0x10000))
        elif field == "payload":
            position = top_offset + c_bde.FVE_DATUM.size + rng.randrange(max(1, vmk_size - c_bde.FVE_DATUM.size))
            mutated[position] = rng.randrange(0x100)
        elif field == "start":
            struct.pack_into("<I", mutated, 8, rng.randrange(0, 0x10000))
        else:
            struct.pack_into("<I", mutated, 12, rng.randrange(0, 0x10000))
        result.append(bytes(mutated))
    return result


def test_structured_mutations_terminate_with_bounded_reads() -> None:
    """A deterministic mutation corpus must terminate with bounded reads and a stable outcome."""
    reasons = {
        "truncated_header",
        "zero_size",
        "undersized",
        "out_of_bounds",
        "truncated",
        "truncated_struct",
    }
    seen = set()

    for index, buf in enumerate(_mutations(seed=0xB17, count=64)):
        recording = fz.RecordingReader(buf)
        try:
            data = Dataset(recording).data
        except InvalidDatumError as e:
            # Rejections happen at the framing layer with a stable reason and a local offset.
            assert e.reason in reasons, f"mutation {index} raised unexpected reason {e.reason}"
            assert e.offset is not None and 0 <= e.offset < len(buf)
            seen.add(e.reason)
        except InvalidHeaderError:
            # Header-level rejections happen before any datum is parsed.
            seen.add("header")
        else:
            # If the mutation still parses, its datums must stay inside the parent.
            assert sum(d.size for d in data) <= len(buf) - c_bde.FVE_DATASET.size

        assert recording.bytes_read <= len(buf) + 4, f"mutation {index} read too much"
        assert recording.max_offset <= len(buf), f"mutation {index} read outside the input"

    # The corpus must actually exercise framing failures and header rejections.
    assert "out_of_bounds" in seen
    assert "header" in seen


def test_structured_mutations_of_nested_properties_terminate() -> None:
    """Nested property mutations either parse fully or fail at a stable, bounded offset."""
    rng = random.Random(0x5EED)
    base = fz.dataset(fz.vmk_datum(fz.clear_vmk_properties()))
    start = c_bde.FVE_DATASET.size

    for _ in range(64):
        mutated = bytearray(base)
        position = start + rng.randrange(c_bde.FVE_DATUM.size, len(base) - start)
        mutated[position] ^= 1 << rng.randrange(8)

        recording = fz.RecordingReader(bytes(mutated))
        try:
            node = Dataset(recording).data[0]
            while node.properties:
                node = node.properties[0]
        except InvalidHeaderError as e:
            assert e.offset is None or e.offset >= 0
            if isinstance(e, InvalidDatumError):
                assert e.reason is not None
        assert recording.max_offset <= len(mutated)


def test_synthetic_volume_round_trips_through_fixture_style_unlock() -> None:
    """The generated volume behaves like a real one: state, description-free dataset, FVEK type."""
    bde_obj = bde.BDE(BytesIO(fz.default_volume()))

    assert bde_obj.version == 2
    assert bde_obj.sector_size == fz.SECTOR_SIZE
    assert bde_obj.encrypted
    assert not bde_obj.unlocked
    assert bde_obj.information.current_state.value == 4  # FVE_STATE.ENCRYPTED
    assert bde_obj.has_clear_key()

    bde_obj.unlock_with_clear_key()
    stream = bde_obj.open()
    assert stream.encrypted
    assert bde_obj.information.dataset.fvek_type == FVE_KEY_TYPE.AES_128
