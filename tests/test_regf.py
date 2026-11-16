from __future__ import annotations

import logging
import struct
from io import BytesIO
from typing import BinaryIO

import pytest

from dissect.regf import regf
from dissect.regf.exceptions import Error, HiveIntegrityError, HiveStructureError, RegistryKeyNotFoundError
from tests.conftest import (
    HBIN_SIZE_OFFSET,
    build_hive,
    read_file_gz,
    recalculate_checksum,
)


def test_regf(system_hive: BinaryIO) -> None:
    hive = regf.RegistryHive(system_hive)

    root = hive.root()

    assert len(list(root.subkeys())) == 17
    assert root.name == "ROOT"
    assert root.path == ""
    assert hive.open("Software") is root.subkey("Software") is root.subkey("software")

    key_path = "ControlSet001\\Control\\Lsa"
    lsa = hive.open(key_path)

    assert lsa.name == "Lsa"
    assert lsa.path == key_path
    assert lsa.subkey("JD").class_name == "cdebfed5"
    assert lsa.subkey("Skew1").class_name == "7db4e11c"
    assert lsa.subkey("GBG").class_name == "b185f3f2"
    assert lsa.subkey("Data").class_name == "a282942c"

    assert hive.open("ControlSet001\\Services\\Tcpip\\Parameters\\DNSRegisteredAdapters").class_name == "DynDRootClass"

    assert list(hive.walk())


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (
            b"",
            "",
        ),
        (
            b"The Quick Brown Fox\x00Jumped Over The Lazy Dog",
            "The Quick Brown Fox",
        ),
        (
            b"The Quick Brown Fox\x00Jumped Over The Lazy Dog\x00",
            "The Quick Brown Fox",
        ),
        (
            b"The Quick Brown Fox",
            "The Quick Brown Fox",
        ),
        (
            "The Quick Brown Fox\x00Jumped Over The Lazy Dog".encode("utf-16-le"),
            "The Quick Brown Fox",
        ),
        (
            "The Quick Brown Fox\x00Jumped Over The Lazy Dog\x00".encode("utf-16-le"),
            "The Quick Brown Fox",
        ),
        (
            "The Quick Brown Fox\x00Jumped Over The Lazy Dog".encode("utf-16-le") + b"\x00",
            "The Quick Brown Fox",
        ),
        (
            "The Quick Brown Fox".encode("utf-16-le"),
            "The Quick Brown Fox",
        ),
        (
            b"\xe4bcd\x00",  # interpreted as latin1
            "äbcd",
        ),
        (
            b"\xe4bcd",  # interpreted as utf-16-le
            "拤摣",
        ),
        (
            b"\x41\x00\x00\x01\x42\x00",
            "AĀB",
        ),
    ],
)
def test_try_decode_sz(data: bytes, expected: str) -> None:
    assert regf.try_decode_sz(data) == expected


def test_bad_keyvalue_cell_entry(bad_key_value_cell_hive: BinaryIO, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, regf.log.name):
        hive = regf.RegistryHive(bad_key_value_cell_hive)
        root = hive.root()

        assert len(list(root.subkeys())) == 1
        svc = root.subkey("Service")

        values = list(svc.values())

        assert len(values) == 2
        value_dict = {v.name: v for v in values}

        assert "Type" in value_dict
        assert value_dict["Type"].type == 4  # REG_DWORD
        assert value_dict["Type"].value == 224

        assert "Start" in value_dict
        assert value_dict["Start"].type == 4  # REG_DWORD
        assert value_dict["Start"].value == 3

    assert "Invalid cell signature b'6\\x00' at offset 0x130" in caplog.text


def test_fastleaf_non_ascii_subkey(fastleaf_hive: BinaryIO) -> None:
    hive = regf.RegistryHive(fastleaf_hive)
    root = hive.root()

    assert isinstance(root._subkey_list, regf.FastLeaf)

    key = root.subkey("Администратор")
    assert key.name == "Администратор"

    key = root.subkey("Гость")
    assert key.name == "Гость"

    with pytest.raises(RegistryKeyNotFoundError):
        root.subkey("Missing")


def test_integrity_state_is_independent() -> None:
    assert regf.HiveState.OK == 0
    assert regf.HiveState.OK | regf.HiveState.CHECKSUM_MISMATCH == regf.HiveState.CHECKSUM_MISMATCH

    state = regf.HiveState.CHECKSUM_MISMATCH | regf.HiveState.IN_TRANSACTION | regf.HiveState.STRUCTURE_OUT_OF_BOUNDS
    assert state & regf.HiveState.CHECKSUM_MISMATCH
    assert state & regf.HiveState.IN_TRANSACTION
    assert state & regf.HiveState.STRUCTURE_OUT_OF_BOUNDS


def test_integrity_ok(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, regf.log.name):
        hive = regf.RegistryHive(build_hive())

    assert hive.integrity.ok
    assert hive.state == regf.HiveState.OK
    assert hive.integrity.checksum_ok
    assert hive.integrity.sequences_match
    assert hive.integrity.structure_ok
    assert "checksum OK" in caplog.text
    assert "not undergoing any transactions" in caplog.text
    assert "integrity OK" in caplog.text
    assert not hive.dirty
    assert not hive.in_transaction

    # A clean hive is readable, including through the bound-checking cell path.
    assert hive.root().name == ""
    assert len(list(hive.root().subkeys())) == 1


def test_integrity_checksum_mismatch_only(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, regf.log.name):
        hive = regf.RegistryHive(build_hive(checksum_ok=False))

    assert not hive.integrity.ok
    assert hive.state == regf.HiveState.CHECKSUM_MISMATCH
    assert hive.state & regf.HiveState.CHECKSUM_MISMATCH
    assert not hive.state & regf.HiveState.IN_TRANSACTION
    assert not hive.state & regf.HiveState.STRUCTURE_OUT_OF_BOUNDS
    assert not hive.integrity.checksum_ok
    assert hive.integrity.sequences_match
    assert hive.integrity.structure_ok
    assert hive.dirty
    assert not hive.in_transaction

    assert "checksum mismatch: stored 0x" in caplog.text
    assert "computed 0x" in caplog.text
    assert "dirty" not in caplog.text.lower()
    assert "not undergoing any transactions" in caplog.text

    # Lenient default: the read is still allowed, with the state attached.
    assert len(list(hive.root().subkeys())) == 1
    assert "checksum mismatch" in hive.integrity.summary()


def test_integrity_sequence_mismatch_only(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, regf.log.name):
        hive = regf.RegistryHive(build_hive(sequences_match=False))

    assert not hive.integrity.ok
    assert hive.state == regf.HiveState.IN_TRANSACTION
    assert hive.state & regf.HiveState.IN_TRANSACTION
    assert not hive.state & regf.HiveState.CHECKSUM_MISMATCH
    assert not hive.state & regf.HiveState.STRUCTURE_OUT_OF_BOUNDS
    assert hive.integrity.checksum_ok
    assert not hive.integrity.sequences_match
    assert hive.integrity.structure_ok
    assert not hive.dirty
    assert hive.in_transaction

    assert "checksum OK" in caplog.text
    assert "unfinished transaction" in caplog.text
    assert "Sequence1 1 != Sequence2 305419896" in caplog.text

    # Lenient default: readable, but the state is still reported.
    assert len(list(hive.root().subkeys())) == 1
    assert "transaction in progress" in hive.integrity.summary()


def test_integrity_hbin_out_of_bounds(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, regf.log.name):
        hive = regf.RegistryHive(build_hive(hbin_out_of_bounds=True))

    assert not hive.integrity.ok
    assert hive.state == regf.HiveState.STRUCTURE_OUT_OF_BOUNDS
    assert hive.state & regf.HiveState.STRUCTURE_OUT_OF_BOUNDS
    assert not hive.state & regf.HiveState.CHECKSUM_MISMATCH
    assert not hive.state & regf.HiveState.IN_TRANSACTION
    assert hive.integrity.checksum_ok
    assert hive.integrity.sequences_match
    assert not hive.integrity.structure_ok
    assert hive.integrity.structure_errors
    assert any("extends to 0xa000" in error for error in hive.integrity.structure_errors)
    assert any("declared hive end" in error for error in hive.integrity.structure_errors)
    assert not hive.dirty
    assert not hive.in_transaction

    assert "structure out of bounds" in caplog.text
    assert "extends to 0xa000" in caplog.text

    # Lenient default: the accessible part is still readable.
    assert len(list(hive.root().subkeys())) == 1
    assert "structure out of bounds" in hive.integrity.summary()


def test_integrity_states_can_coexist() -> None:
    hive = regf.RegistryHive(build_hive(checksum_ok=False, sequences_match=False, hbin_out_of_bounds=True))

    expected = regf.HiveState.CHECKSUM_MISMATCH | regf.HiveState.IN_TRANSACTION | regf.HiveState.STRUCTURE_OUT_OF_BOUNDS
    assert hive.state == expected
    assert hive.dirty
    assert hive.in_transaction
    assert not hive.integrity.ok

    summary = hive.integrity.summary()
    assert "checksum mismatch" in summary
    assert "transaction in progress" in summary
    assert "structure out of bounds" in summary


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"checksum_ok": False}, "checksum mismatch"),
        ({"sequences_match": False}, "transaction in progress"),
        ({"hbin_out_of_bounds": True}, "structure out of bounds"),
    ],
)
def test_strict_open_rejects_untrusted_hive(
    kwargs: dict[str, bool], reason: str, caplog: pytest.LogCaptureFixture
) -> None:
    with (
        caplog.at_level(logging.DEBUG, regf.log.name),
        pytest.raises(HiveIntegrityError) as excinfo,
    ):
        regf.RegistryHive(build_hive(**kwargs), strict=True)

    assert reason in str(excinfo.value)
    assert excinfo.value.integrity.state
    # The individual condition is still logged, not a single ambiguous dirty line.
    assert "dirty" not in caplog.text.lower()
    assert reason in caplog.text or "structure out of bounds" in caplog.text


def test_strict_open_allows_clean_hive() -> None:
    hive = regf.RegistryHive(build_hive(), strict=True)

    assert hive.integrity.ok
    assert len(list(hive.root().subkeys())) == 1


def test_cell_out_of_bounds_is_reported_and_ignored() -> None:
    hive = regf.RegistryHive(build_hive())

    # Offset 0 points into the hbin header and can never be a cell.
    with pytest.raises(HiveStructureError):
        regf.RegistryHive(build_hive(), strict=True).cell(0)

    assert hive.cell_data(0) == b""


def test_legacy_dirty_semantics() -> None:
    """``dirty`` must mean checksum mismatch, never checksum success."""
    clean = regf.RegistryHive(build_hive())
    dirty = regf.RegistryHive(build_hive(checksum_ok=False))

    assert clean.dirty is False
    assert dirty.dirty is True
    assert clean.in_transaction is False
    assert regf.RegistryHive(build_hive(sequences_match=False)).in_transaction is True


def test_integrity_hbin_chain_break() -> None:
    """A hbin whose size lands mid-bin leaves an invalid next hbin."""
    data = bytearray(read_file_gz("_data/SYSTEM.gz"))

    # The hbin at 0x3000 is 0x2000 bytes, so a first hbin of 0x3000 makes the
    # walk resume at 0x4000, in the middle of that bin, where no signature is.
    data[HBIN_SIZE_OFFSET : HBIN_SIZE_OFFSET + 4] = struct.pack("<I", 0x3000)
    recalculate_checksum(data)

    hive = regf.RegistryHive(BytesIO(bytes(data)))
    assert hive.state & regf.HiveState.STRUCTURE_OUT_OF_BOUNDS
    assert any("invalid signature" in error for error in hive.integrity.structure_errors)

    # The lenient walk still covers the bins it could validate.
    assert list(hive.walk())


def test_truncated_header_is_rejected() -> None:
    with pytest.raises(Error, match="header truncated"):
        regf.RegistryHive(BytesIO(b"regf" + b"\x00" * 100))
