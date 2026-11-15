"""Structured fuzz tests for Bitlocker metadata parsing.

Covers the boundary from Dataset to nested datum to decrypted inner datum.
Only self-made keys and harmless bytes are used; no real volume data is involved.

Acceptance is judged on:
- read budget: parsing never performs more reads or consumes more bytes than a bounded budget;
- termination position: parsing stops at the exact expected offset, never loops;
- selected key datum: the key datum actually selected is the expected one, or none at all.
"""

from __future__ import annotations

import io
import random
import struct
import threading
from typing import TYPE_CHECKING

import pytest
from Crypto.Cipher import AES

from dissect.fve.bde.c_bde import c_bde
from dissect.fve.bde.information import Dataset, Datum, KeyDatum

if TYPE_CHECKING:
    from collections.abc import Callable

DATASET_HEADER_SIZE = len(c_bde.FVE_DATASET)
DATUM_HEADER_SIZE = len(c_bde.FVE_DATUM)
VMK_INFO_SIZE = len(c_bde.FVE_DATUM_VMK_INFO)
STRETCH_KEY_SIZE = len(c_bde.FVE_DATUM_STRETCH_KEY)

# Self-made keys, harmless bytes only
CLEAR_KEY = bytes(range(0x00, 0x20))
VMK = bytes(range(0x20, 0x40))
FVEK = bytes(range(0x40, 0x60))
NONCE_VMK = b"\x01" * 12
NONCE_FVEK = b"\x02" * 12
WINTIME = 132514704000000000  # 2021-01-01T00:00:00Z

ROLE_PROPERTY = 0x0000
ROLE_VMK_INFO = 0x0002
ROLE_FVEK = 0x0003
ROLE_DESCRIPTION = 0x0007

TYPE_ERASED = 0x0000
TYPE_KEY = 0x0001
TYPE_UNICODE = 0x0002
TYPE_STRETCH_KEY = 0x0003
TYPE_AES_CCM = 0x0005
TYPE_VMK_INFO = 0x0008

KEY_TYPE_AES_CCM_256_0 = 0x2000
KEY_TYPE_VMK = 0x2003
KEY_TYPE_AES_XTS_128 = 0x8004

PRIORITY_CLEAR = 0x0000


class BudgetExceededError(Exception):
    """Raised when the parser exceeds its read budget."""


class BudgetStream(io.BytesIO):
    """BytesIO that enforces a read budget in number of calls and total bytes."""

    def __init__(self, data: bytes, max_reads: int = 1024, max_bytes: int | None = None) -> None:
        super().__init__(data)
        self.max_reads = max_reads
        self.max_bytes = len(data) * 2 + 64 if max_bytes is None else max_bytes
        self.reads = 0
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        self.reads += 1
        if self.reads > self.max_reads:
            raise BudgetExceededError(f"read call budget exceeded: {self.reads}")
        data = super().read(size)
        self.bytes_read += len(data)
        if self.bytes_read > self.max_bytes:
            raise BudgetExceededError(f"read byte budget exceeded: {self.bytes_read}")
        return data


def run_with_deadline(func: Callable[[], object], timeout: float = 10.0) -> object:
    """Run func in a daemon thread and fail if it does not terminate in time."""
    outcome: dict[str, object] = {}

    def _target() -> None:
        try:
            outcome["value"] = func()
        except Exception as e:
            outcome["error"] = e

    thread = threading.Thread(target=_target, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise TimeoutError("parser did not terminate within deadline")
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("value")


def make_datum(role: int, type_: int, payload: bytes = b"", size: int | None = None, flags: int = 0) -> bytes:
    if size is None:
        size = DATUM_HEADER_SIZE + len(payload)
    return struct.pack("<HHHH", size, role, type_, flags) + payload


def make_dataset(*datums: bytes, fvek_type: int = KEY_TYPE_AES_XTS_128) -> bytes:
    body = b"".join(datums)
    end = DATASET_HEADER_SIZE + len(body)
    header = struct.pack("<IIII", end, 1, DATASET_HEADER_SIZE, end)
    header += b"\x00" * 16  # Identification
    header += struct.pack("<IHHQ", 0, fvek_type, fvek_type, WINTIME)
    return header + body


def make_key_datum(role: int, key: bytes, key_type: int) -> bytes:
    return make_datum(role, TYPE_KEY, struct.pack("<HH", key_type, 0) + key)


def make_aes_ccm_datum(role: int, key: bytes, plaintext: bytes, nonce: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
    ciphertext, mac = cipher.encrypt_and_digest(plaintext)
    return make_datum(role, TYPE_AES_CCM, nonce + mac + ciphertext)


def make_vmk_info_datum(properties: list[bytes], priority: int = PRIORITY_CLEAR) -> bytes:
    payload = b"\x11" * 16  # Identifier
    payload += struct.pack("<QHH", WINTIME, 0, priority)
    payload += b"".join(properties)
    return make_datum(ROLE_VMK_INFO, TYPE_VMK_INFO, payload)


def make_stretch_key_datum(role: int, nested: bytes = b"") -> bytes:
    return make_datum(role, TYPE_STRETCH_KEY, struct.pack("<HH", 0x1000, 0) + b"\x00" * 16 + nested)


def make_description_datum(text: str = "FuzzVolume") -> bytes:
    return make_datum(ROLE_DESCRIPTION, TYPE_UNICODE, (text + "\x00").encode("utf-16-le"))


def make_clear_vmk_datum(properties: list[bytes] | None = None) -> bytes:
    if properties is None:
        properties = [
            make_key_datum(ROLE_PROPERTY, CLEAR_KEY, KEY_TYPE_AES_CCM_256_0),
            make_aes_ccm_datum(ROLE_PROPERTY, CLEAR_KEY, make_key_datum(ROLE_PROPERTY, VMK, KEY_TYPE_VMK), NONCE_VMK),
        ]
    return make_vmk_info_datum(properties)


def make_fvek_datum() -> bytes:
    return make_aes_ccm_datum(ROLE_FVEK, VMK, make_key_datum(ROLE_PROPERTY, FVEK, KEY_TYPE_AES_XTS_128), NONCE_FVEK)


def build_valid_sample() -> tuple[bytes, list[int]]:
    """Build a valid dataset and return it with the absolute offsets of every datum header."""
    description = make_description_datum()
    vmk_info = make_clear_vmk_datum()
    fvek = make_fvek_datum()
    sample = make_dataset(description, vmk_info, fvek)

    d_description = DATASET_HEADER_SIZE
    d_vmk_info = d_description + len(description)
    d_fvek = d_vmk_info + len(vmk_info)
    n_clear_key = d_vmk_info + DATUM_HEADER_SIZE + VMK_INFO_SIZE
    n_enc_vmk = n_clear_key + DATUM_HEADER_SIZE + 4 + len(CLEAR_KEY)
    return sample, [d_description, d_vmk_info, d_fvek, n_clear_key, n_enc_vmk]


def parse_dataset(sample: bytes, max_reads: int = 1024) -> Dataset:
    return Dataset(BudgetStream(sample, max_reads=max_reads))


def consumed_size(dataset: Dataset) -> int:
    """Termination position: amount of datum bytes consumed relative to the first datum."""
    return sum(d.size for d in dataset.data)


def declared_size(dataset: Dataset) -> int:
    return dataset.header.EndOffset - dataset.header.StartOffset


def evaluate_clear_key_chain(dataset: Dataset) -> tuple[Datum, Datum, Datum] | None:
    """Walk the full clear key chain: Dataset -> nested property -> decrypted inner datum."""
    vmk_info = dataset.find_clear_vmk()
    if vmk_info is None:
        return None
    clear_key = vmk_info.clear_key()
    enc_vmk = vmk_info.aes_ccm_encrypted_key()
    if clear_key is None or enc_vmk is None:
        return None
    vmk = enc_vmk.unbox(clear_key)
    fvek_datum = dataset.find_fvek()
    if fvek_datum is None:
        return None
    fvek = fvek_datum.unbox(vmk)
    return clear_key, vmk, fvek


def assert_valid_chain(dataset: Dataset) -> None:
    chain = evaluate_clear_key_chain(dataset)
    assert chain is not None
    clear_key, vmk, fvek = chain
    assert isinstance(clear_key, KeyDatum)
    assert clear_key.data == CLEAR_KEY
    assert isinstance(vmk, KeyDatum)
    assert vmk.data == VMK
    assert isinstance(fvek, KeyDatum)
    assert fvek.data == FVEK


# ======== Control tests ========


def test_valid_dataset_control() -> None:
    """Control: a valid dataset parses fully, terminates at EndOffset and selects our own keys."""
    sample, _ = build_valid_sample()
    stream = BudgetStream(sample)
    dataset = Dataset(stream)

    assert len(dataset.data) == 3
    assert consumed_size(dataset) == declared_size(dataset)
    # Read budget: header is read twice (header parse + full buffer), never more than that
    assert stream.bytes_read <= len(sample) + DATASET_HEADER_SIZE

    assert_valid_chain(dataset)


def test_valid_shell_valid_inner_control() -> None:
    """Control: a valid authenticated shell unboxes to exactly our own inner key datum."""
    datum = Datum.from_bytes(make_fvek_datum())
    inner = datum.unbox(VMK)
    assert isinstance(inner, KeyDatum)
    assert inner.key_type == c_bde.FVE_KEY_TYPE.AES_XTS_128
    assert inner.data == FVEK


# ======== Zero-length and undersized datums ========


def test_zero_length_datum_after_valid_datums() -> None:
    """A zero-length datum must stop iteration; already parsed valid datums stay usable."""
    sample, _ = build_valid_sample()
    bad = make_datum(0, 0, b"", size=0)
    dataset = parse_dataset(_dataset_with_extra(sample, bad))

    assert len(dataset.data) == 3
    # Termination position: stops exactly at the zero-length datum header
    assert consumed_size(dataset) == declared_size(dataset) - DATUM_HEADER_SIZE
    assert_valid_chain(dataset)


def _dataset_with_extra(sample: bytes, extra: bytes) -> bytes:
    """Append extra bytes to a dataset sample, fixing up Size and EndOffset."""
    size, version, start, _end = struct.unpack_from("<IIII", sample)
    end = start + (size - start) + len(extra)
    return struct.pack("<IIII", end, version, start, end) + sample[16:] + extra


def test_zero_length_datum_before_valid_vmk() -> None:
    """A zero-length datum must not make the parser skip into or misparse the neighbouring VMK."""
    description = make_description_datum()
    bad = make_datum(0, 0, b"", size=0)
    sample = make_dataset(description, bad, make_clear_vmk_datum(), make_fvek_datum())
    dataset = parse_dataset(sample)

    assert len(dataset.data) == 1
    assert consumed_size(dataset) == len(description)
    # No key datum may be selected from the unreachable remainder
    assert dataset.find_clear_vmk() is None
    assert evaluate_clear_key_chain(dataset) is None


@pytest.mark.parametrize("bad_size", [0, 1, 4, DATUM_HEADER_SIZE - 1])
def test_undersized_datum_terminates(bad_size: int) -> None:
    """Undersized datums must terminate parsing, never loop, within a strict read budget."""
    sample, _ = build_valid_sample()
    bad = make_datum(0, 0, b"", size=bad_size)
    dataset = run_with_deadline(lambda: parse_dataset(_dataset_with_extra(sample, bad), max_reads=64))
    assert len(dataset.data) == 3
    assert consumed_size(dataset) == declared_size(dataset) - DATUM_HEADER_SIZE


def test_zero_length_everywhere_terminates() -> None:
    """A dataset full of zero-length datums must not cause infinite iteration."""
    sample = make_dataset(make_datum(0, 0, b"", size=0) * 64)
    dataset = run_with_deadline(lambda: parse_dataset(sample, max_reads=64))
    assert dataset.data == []
    assert consumed_size(dataset) == 0


# ======== Datums exceeding their parent ========


def test_oversized_datum_after_valid_datums() -> None:
    """A datum claiming more than the dataset has left must be rejected, valid datums stay."""
    sample, _ = build_valid_sample()
    bad = make_datum(0, 0, b"", size=0x7FFF)
    dataset = parse_dataset(_dataset_with_extra(sample, bad))

    assert len(dataset.data) == 3
    assert consumed_size(dataset) == declared_size(dataset) - DATUM_HEADER_SIZE
    assert_valid_chain(dataset)


def test_oversized_datum_before_valid_vmk() -> None:
    """An oversized datum may hide the rest of the dataset, but must not select a wrong key."""
    description = make_description_datum()
    bad = make_datum(0, 0, b"", size=0x7FFF)
    sample = make_dataset(description, bad, make_clear_vmk_datum(), make_fvek_datum())
    dataset = parse_dataset(sample)

    assert len(dataset.data) == 1
    assert dataset.find_clear_vmk() is None
    assert evaluate_clear_key_chain(dataset) is None


def test_truncated_dataset_buffer() -> None:
    """A physically truncated dataset must stop cleanly and keep the intact datums."""
    sample, _ = build_valid_sample()
    truncated = sample[:-20]  # cut mid-FVEK payload, header stays intact
    dataset = parse_dataset(truncated)

    assert len(dataset.data) == 3
    fvek_datum = dataset.find_fvek()
    assert fvek_datum is not None
    # The truncated FVEK shell fails authentication, no inner datum materializes
    vmk_info = dataset.find_clear_vmk()
    vmk = vmk_info.aes_ccm_encrypted_key().unbox(vmk_info.clear_key())
    with pytest.raises(ValueError, match="MAC"):
        fvek_datum.unbox(vmk)


def test_oversized_declared_dataset_size() -> None:
    """A huge declared Size/EndOffset must not cause reads beyond the actual input."""
    sample, _ = build_valid_sample()
    mutated = struct.pack("<IIII", 0xFFFFFFFF, 1, DATASET_HEADER_SIZE, 0xFFFFFFFE) + sample[16:]
    stream = BudgetStream(mutated)
    dataset = Dataset(stream)

    assert len(dataset.data) == 3
    assert stream.bytes_read <= len(mutated) + DATASET_HEADER_SIZE
    assert_valid_chain(dataset)


# ======== Nested datum boundaries ========


def test_zero_length_nested_property_after_valid() -> None:
    """A zero-length nested property stops property parsing; valid properties stay selected."""
    vmk_info = make_clear_vmk_datum(
        [
            make_key_datum(ROLE_PROPERTY, CLEAR_KEY, KEY_TYPE_AES_CCM_256_0),
            make_aes_ccm_datum(ROLE_PROPERTY, CLEAR_KEY, make_key_datum(ROLE_PROPERTY, VMK, KEY_TYPE_VMK), NONCE_VMK),
            make_datum(0, 0, b"", size=0),
        ]
    )
    dataset = parse_dataset(make_dataset(vmk_info, make_fvek_datum()))

    vmk = dataset.find_clear_vmk()
    assert vmk is not None
    assert len(vmk.properties) == 2
    assert_valid_chain(dataset)


def test_zero_length_nested_property_before_valid() -> None:
    """A leading zero-length property hides the rest, but must not select a wrong key."""
    vmk_info = make_clear_vmk_datum(
        [
            make_datum(0, 0, b"", size=0),
            make_key_datum(ROLE_PROPERTY, CLEAR_KEY, KEY_TYPE_AES_CCM_256_0),
        ]
    )
    dataset = parse_dataset(make_dataset(vmk_info, make_fvek_datum()))

    vmk = dataset.find_clear_vmk()
    assert vmk is not None
    assert vmk.properties == []
    assert vmk.clear_key() is None
    assert evaluate_clear_key_chain(dataset) is None


def test_oversized_nested_property() -> None:
    """A nested datum claiming more than its parent has left must be rejected."""
    vmk_info = make_clear_vmk_datum(
        [
            make_key_datum(ROLE_PROPERTY, CLEAR_KEY, KEY_TYPE_AES_CCM_256_0),
            make_datum(0, 0, b"", size=0x7FFF),
        ]
    )
    dataset = parse_dataset(make_dataset(vmk_info, make_fvek_datum()))

    vmk = dataset.find_clear_vmk()
    assert vmk is not None
    assert len(vmk.properties) == 1
    assert vmk.clear_key().data == CLEAR_KEY


def test_nested_property_cannot_escape_parent() -> None:
    """Nested parsing is bounded by the parent; the neighbouring FVEK stays a top-level datum."""
    vmk_info = make_clear_vmk_datum(
        [
            make_datum(ROLE_PROPERTY, TYPE_KEY, struct.pack("<HH", KEY_TYPE_AES_CCM_256_0, 0) + CLEAR_KEY),
            make_datum(0, 0, b"", size=0x7FFF),
        ]
    )
    dataset = parse_dataset(make_dataset(vmk_info, make_fvek_datum()))

    vmk = dataset.find_clear_vmk()
    assert sum(p.size for p in vmk.properties) <= vmk.data_size - VMK_INFO_SIZE
    assert dataset.find_fvek() is not None


def test_non_property_role_nested_datum_rejected() -> None:
    """A nested datum with a non-PROPERTY role must not be attributed to the current datum."""
    fake_key = make_key_datum(ROLE_FVEK, b"\xaa" * 32, KEY_TYPE_VMK)
    vmk_info = make_clear_vmk_datum(
        [
            fake_key,
            make_key_datum(ROLE_PROPERTY, CLEAR_KEY, KEY_TYPE_AES_CCM_256_0),
        ]
    )
    dataset = parse_dataset(make_dataset(vmk_info, make_fvek_datum()))

    vmk = dataset.find_clear_vmk()
    assert vmk is not None
    # The fake key stops property parsing; the valid key behind it is unreachable but
    # the fake key is never selected as this VMK's property either
    assert vmk.properties == []
    assert vmk.clear_key() is None


def test_swollen_parent_cannot_steal_neighbour_fvek() -> None:
    """A VMK datum sized over its neighbour must not attribute the valid FVEK as its property."""
    vmk_info = bytearray(make_clear_vmk_datum())
    fvek = make_fvek_datum()
    struct.pack_into("<H", vmk_info, 0, len(vmk_info) + len(fvek))  # swollen Size
    sample = make_dataset(bytes(vmk_info), fvek)
    dataset = parse_dataset(sample)

    vmk = dataset.find_clear_vmk()
    assert vmk is not None
    # The swallowed FVEK has a non-PROPERTY role, so it is not attributed to the VMK
    assert len(vmk.properties) == 2
    assert vmk.aes_ccm_encrypted_key() is vmk.properties[1]
    # Dataset-level desync is unavoidable, but the failure is safe: no FVEK, no wrong key
    assert dataset.find_fvek() is None
    vmk_key = vmk.aes_ccm_encrypted_key().unbox(vmk.clear_key())
    assert vmk_key.data == VMK


def test_deep_nesting() -> None:
    """Deeply nested complex datums parse iteratively and terminate within budget."""
    depth = 1000
    nested = make_key_datum(ROLE_PROPERTY, CLEAR_KEY, KEY_TYPE_AES_CCM_256_0)
    for _ in range(depth):
        nested = make_stretch_key_datum(ROLE_PROPERTY, nested)
    dataset = parse_dataset(make_dataset(make_stretch_key_datum(ROLE_PROPERTY, nested)), max_reads=16)

    datum = dataset.data[0]
    walked = 0
    while datum.properties:
        assert len(datum.properties) == 1
        datum = datum.properties[0]
        walked += 1
    assert walked == depth + 1
    assert isinstance(datum, KeyDatum)
    assert datum.data == CLEAR_KEY


def test_complex_datum_shorter_than_struct() -> None:
    """A complex datum too small for its own struct is rejected and does not hang."""
    vmk_info = make_datum(ROLE_VMK_INFO, TYPE_VMK_INFO, b"\x00" * 8)  # smaller than FVE_DATUM_VMK_INFO
    dataset = run_with_deadline(lambda: parse_dataset(make_dataset(vmk_info)))
    assert dataset.data == []
    assert dataset.find_clear_vmk() is None


# ======== Unknown role and type ========


def test_unknown_type_datum_preserved() -> None:
    """A valid datum with unknown type keeps its raw content and does not break iteration."""
    payload = b"\xde\xad\xbe\xef" * 4
    unknown = make_datum(ROLE_PROPERTY, 0xDEAD, payload)
    sample, _ = build_valid_sample()
    dataset = parse_dataset(_dataset_with_extra(sample, unknown))

    assert len(dataset.data) == 4
    datum = dataset.data[3]
    assert type(datum) is Datum
    assert datum.type not in tuple(c_bde.FVE_DATUM_TYPE)
    assert datum._data == payload
    assert datum.data_segment == payload
    assert_valid_chain(dataset)


def test_unknown_role_datum_preserved() -> None:
    """A valid datum with unknown role keeps its raw content and stays queryable by type."""
    text = "UnknownRole\x00".encode("utf-16-le")
    unknown = make_datum(0xBEEF, TYPE_UNICODE, text)
    sample, _ = build_valid_sample()
    dataset = parse_dataset(_dataset_with_extra(sample, unknown))

    datum = dataset.data[3]
    assert datum.role not in tuple(c_bde.FVE_DATUM_ROLE)
    assert datum._data == text
    found = list(dataset.find_datum(None, c_bde.FVE_DATUM_TYPE.UNICODE))
    assert datum in found
    assert_valid_chain(dataset)


def test_unknown_nested_property_preserved() -> None:
    """A valid unknown-typed nested property keeps its raw content inside its parent."""
    payload = b"\x01\x02\x03\x04"
    vmk_info = make_clear_vmk_datum(
        [
            make_key_datum(ROLE_PROPERTY, CLEAR_KEY, KEY_TYPE_AES_CCM_256_0),
            make_datum(ROLE_PROPERTY, 0xDEAD, payload),
        ]
    )
    dataset = parse_dataset(make_dataset(vmk_info))

    vmk = dataset.find_clear_vmk()
    assert len(vmk.properties) == 2
    unknown = vmk.properties[1]
    assert type(unknown) is Datum
    assert unknown._data == payload
    assert unknown.data_segment == payload


# ======== Valid authenticated shell, bad inner structure ========


def _unbox_fvek_shell(plaintext: bytes) -> Datum:
    datum = Datum.from_bytes(make_aes_ccm_datum(ROLE_FVEK, VMK, plaintext, NONCE_FVEK))
    return datum.unbox(VMK)


@pytest.mark.parametrize(
    "plaintext",
    [
        b"",  # empty inner
        b"\x00" * 4,  # shorter than a datum header
        make_datum(0, 0, b"", size=0),  # zero-length inner datum
        make_datum(ROLE_PROPERTY, TYPE_KEY, b"\x00" * 12, size=44),  # declared size exceeds plaintext
        make_datum(ROLE_PROPERTY, TYPE_KEY, b"\x00" * 2),  # truncated key struct
        make_datum(ROLE_PROPERTY, TYPE_KEY, struct.pack("<HH", KEY_TYPE_VMK, 0) + VMK) + b"\xff",  # trailing garbage
    ],
    ids=["empty", "short", "zero-length", "size-mismatch", "truncated-struct", "trailing-garbage"],
)
def test_valid_shell_bad_inner(plaintext: bytes) -> None:
    """A valid authenticated shell with a bad inner structure must fail with a clean error."""
    with pytest.raises(ValueError, match="[Uu]nboxed|truncated"):
        run_with_deadline(lambda: _unbox_fvek_shell(plaintext))


def test_valid_shell_empty_key_inner() -> None:
    """A valid shell with a key-less inner key datum parses, but yields no usable key."""
    inner = _unbox_fvek_shell(make_datum(ROLE_PROPERTY, TYPE_KEY, struct.pack("<HH", KEY_TYPE_VMK, 0)))
    assert isinstance(inner, KeyDatum)
    assert inner.data == b""


def test_valid_shell_bad_inner_does_not_select_key() -> None:
    """A bad inner FVEK must not fall back to a neighbouring valid datum as key."""
    inner_fvek = make_key_datum(ROLE_PROPERTY, FVEK, KEY_TYPE_AES_XTS_128)
    bad_inner = inner_fvek[:-4]  # truncated inner key datum
    fvek = make_aes_ccm_datum(ROLE_FVEK, VMK, bad_inner, NONCE_FVEK)
    dataset = parse_dataset(make_dataset(make_clear_vmk_datum(), fvek))

    vmk_info = dataset.find_clear_vmk()
    vmk = vmk_info.aes_ccm_encrypted_key().unbox(vmk_info.clear_key())
    assert vmk.data == VMK
    with pytest.raises(ValueError, match="[Uu]nboxed"):
        dataset.find_fvek().unbox(vmk)


def test_wrong_key_shell_rejected() -> None:
    """A shell unboxed with the wrong key fails authentication, selecting nothing."""
    datum = Datum.from_bytes(make_fvek_datum())
    with pytest.raises(ValueError, match="MAC"):
        datum.unbox(b"\x00" * 32)


# ======== Minimized failing samples ========


def minimize(sample: bytes, predicate: Callable[[bytes], bool]) -> bytes:
    """Delta-minimize a sample while the predicate holds (greedy chunk elimination)."""
    changed = True
    while changed:
        changed = False
        granularity = max(1, len(sample) // 2)
        while granularity >= 1:
            offset = 0
            while offset < len(sample):
                candidate = sample[:offset] + sample[offset + granularity :]
                if candidate and predicate(candidate):
                    sample = candidate
                    changed = True
                else:
                    offset += granularity
            granularity //= 2
    return sample


def _stops_before_end_offset(sample: bytes) -> bool:
    """Predicate: dataset header parses, but datum iteration does not consume the declared range."""
    try:
        dataset = parse_dataset(sample, max_reads=64)
    except Exception:
        return False
    try:
        consumed = consumed_size(dataset)
    except Exception:
        return True
    return consumed != declared_size(dataset)


MINIMAL_ZERO_LENGTH_DATASET = make_dataset(make_datum(0, 0, b"", size=0))

MINIMAL_NESTED_ZERO_LENGTH_DATASET = make_dataset(make_vmk_info_datum([make_datum(0, 0, b"", size=0)]))


def test_minimize_zero_length_datum_sample() -> None:
    """Minimize a failing sample with a zero-length datum down to its essential bytes."""
    sample, _ = build_valid_sample()
    failing = _dataset_with_extra(sample, make_datum(0, 0, b"", size=0))
    assert _stops_before_end_offset(failing)

    minimized = minimize(failing, _stops_before_end_offset)
    assert _stops_before_end_offset(minimized)
    assert len(minimized) <= len(MINIMAL_ZERO_LENGTH_DATASET)


def test_minimize_nested_zero_length_sample() -> None:
    """Minimize a failing sample with a zero-length nested property."""

    def clear_key_not_selected(sample: bytes) -> bool:
        try:
            dataset = parse_dataset(sample, max_reads=64)
        except Exception:
            return False
        vmk = dataset.find_clear_vmk()
        if vmk is None:
            return False
        try:
            key = vmk.clear_key()
        except Exception:
            return True
        return key is None or key.data != CLEAR_KEY

    failing = make_dataset(
        make_vmk_info_datum(
            [
                make_datum(0, 0, b"", size=0),
                make_key_datum(ROLE_PROPERTY, CLEAR_KEY, KEY_TYPE_AES_CCM_256_0),
                make_aes_ccm_datum(
                    ROLE_PROPERTY, CLEAR_KEY, make_key_datum(ROLE_PROPERTY, VMK, KEY_TYPE_VMK), NONCE_VMK
                ),
            ]
        ),
        make_fvek_datum(),
    )
    assert clear_key_not_selected(failing)

    minimized = minimize(failing, clear_key_not_selected)
    assert clear_key_not_selected(minimized)
    assert len(minimized) <= len(MINIMAL_NESTED_ZERO_LENGTH_DATASET)


def test_minimized_zero_length_dataset_regression() -> None:
    """Regression: the minimized zero-length dataset stops immediately, selecting nothing."""
    dataset = parse_dataset(MINIMAL_ZERO_LENGTH_DATASET)
    assert dataset.data == []
    assert consumed_size(dataset) == 0
    assert declared_size(dataset) == DATUM_HEADER_SIZE
    assert dataset.find_clear_vmk() is None


def test_minimized_nested_zero_length_dataset_regression() -> None:
    """Regression: the minimized nested zero-length sample yields no clear key."""
    dataset = parse_dataset(MINIMAL_NESTED_ZERO_LENGTH_DATASET)
    vmk = dataset.find_clear_vmk()
    assert vmk is not None
    assert vmk.properties == []
    assert vmk.clear_key() is None


# ======== Structured fuzz ========


def _mutate(rng: random.Random, sample: bytes, datum_offsets: list[int]) -> bytes:
    """Apply one structural mutation; key payload bytes are never rewritten."""
    buf = bytearray(sample)
    candidates = [o for o in datum_offsets if o + DATUM_HEADER_SIZE <= len(buf)]
    if not candidates:
        return bytes(buf)
    offset = rng.choice(candidates)
    kind = rng.randrange(5)
    if kind == 0:  # perturb the Size field
        size = rng.choice([0, 1, 7, 8, 0xFFFF, rng.randrange(0x10000)])
        struct.pack_into("<H", buf, offset, size)
    elif kind == 1:  # perturb the Role field
        struct.pack_into("<H", buf, offset + 2, rng.randrange(0x10000))
    elif kind == 2:  # perturb the Type field
        struct.pack_into("<H", buf, offset + 4, rng.randrange(0x10000))
    elif kind == 3:  # inject a bad datum header at a datum boundary
        bad = rng.choice(
            [
                make_datum(0, 0, b"", size=0),
                make_datum(0, 0, b"", size=0xFFFF),
                make_datum(0, 0xDEAD, b"\x00" * 8),
            ]
        )
        buf[offset:offset] = bad
    else:  # truncate at a datum boundary
        del buf[offset:]
    return bytes(buf)


def test_structured_fuzz() -> None:
    """Fuzz structural fields; parsing must terminate in budget and never select a wrong key."""
    rng = random.Random(0xFBE)
    sample, datum_offsets = build_valid_sample()

    for _ in range(250):
        mutated = sample
        for _ in range(rng.randrange(1, 4)):
            mutated = _mutate(rng, mutated, datum_offsets)

        try:
            dataset = parse_dataset(mutated, max_reads=256)
            # Termination position never exceeds the declared range
            assert consumed_size(dataset) <= declared_size(dataset)
            for datum in dataset.data:
                if datum.__complex__:
                    assert sum(p.size for p in datum.properties) <= datum.data_size - len(datum.__struct__)
            chain = evaluate_clear_key_chain(dataset)
        except (EOFError, ValueError):
            continue

        if chain is not None:
            # A fully successful chain is cryptographically bound to our self-made keys
            clear_key, vmk, fvek = chain
            assert clear_key.data == CLEAR_KEY
            assert vmk.data == VMK
            assert fvek.data == FVEK
