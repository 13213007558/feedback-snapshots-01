from __future__ import annotations

import hashlib
import io
import random
import tarfile

import pytest

from dissect.archive.xva.xva import BLOCK_SIZE, XVA, UnsupportedChecksumError, _iter_block_files


def _ova_xml(disks: list[tuple[str, int]]) -> bytes:
    records = []
    for ref, size in disks:
        records.append(
            '<member><name>VDI</name><value class="collection">'
            '<member><value class="collection">'
            f'<member><name>id</name><value class="string">{ref}</value></member>'
            f'<member><name>VDI</name><value class="string">{ref}</value></member>'
            '<member><name>type</name><value class="string">Disk</value></member>'
            f'<member><name>virtual_size</name><value class="string">{size}</value></member>'
            "</value></member></value></member>"
        )
    return (
        '<?xml version="1.0" ?><ova><member><name>VM</name><value class="collection">'
        + '<member><name>oid</name><value class="string">vm-1</value></member>'
        + "".join(records)
        + "</value></member></ova>"
    ).encode()


def _add_member(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


def build_xva(
    disks: dict[str, list[bytes | None]],
    *,
    checksums: dict[str, dict[int, str | None]] | None = None,
    extra_members: list[tuple[str, bytes]] | None = None,
    seed: int = 1234,
) -> io.BytesIO:
    """Build an XVA tar with deliberately shuffled member order.

    ``disks`` maps a reference to an ordered list of block payloads. ``None`` entries are zero-sized blocks
    (the member exists but is empty). Gaps in numbering are produced by ``build_numbered_xva``.
    """
    checksums = checksums or {}
    extra_members = extra_members or []

    entries: list[tuple[str, bytes]] = [
        ("ova.xml", _ova_xml([(ref, len(blocks) * BLOCK_SIZE) for ref, blocks in disks.items()]))
    ]
    for ref, blocks in disks.items():
        for number, payload in enumerate(blocks):
            data = b"" if payload is None else payload
            entries.append((f"{ref}/{number}", data))
            if number in checksums.get(ref, {}):
                custom = checksums[ref][number]
                checksum_data = custom.encode() if custom is not None else hashlib.sha1(data).hexdigest().encode()
                entries.append((f"{ref}/{number}.checksum", checksum_data))

    entries.extend(extra_members)
    random.Random(seed).shuffle(entries)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in entries:
            _add_member(tar, name, data)
    buf.seek(0)
    return buf


def build_numbered_xva(
    layout: dict[str, dict[int, bytes | None]],
    *,
    checksums: set[tuple[str, int]] | None = None,
    checksum_algo: str = "checksum",
    seed: int = 99,
) -> io.BytesIO:
    """Build an XVA whose blocks are keyed by explicit (possibly non-contiguous) block numbers."""
    checksums = checksums or set()
    sizes = [(ref, (max(numbers) + 1) * BLOCK_SIZE) for ref, numbers in ((r, list(m)) for r, m in layout.items())]

    entries: list[tuple[str, bytes]] = [("ova.xml", _ova_xml(sizes))]
    for ref, members in layout.items():
        for number, payload in members.items():
            data = b"" if payload is None else payload
            entries.append((f"{ref}/{number}", data))
            if (ref, number) in checksums:
                digest = hashlib.sha1(data).hexdigest().encode()
                entries.append((f"{ref}/{number}.{checksum_algo}", digest))

    random.Random(seed).shuffle(entries)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in entries:
            _add_member(tar, name, data)
    buf.seek(0)
    return buf


def block(marker: int, size: int = BLOCK_SIZE) -> bytes:
    return bytes([marker & 0xFF]) * size


def test_disk_membership_prefix_refs_and_shuffled_order() -> None:
    # "Ref:1" is a prefix of "Ref:10". Members are shuffled and checksums live away from their blocks.
    disk_one = [block(0x11), block(0x12), block(0x13), block(0x14), block(0x15)]
    disk_ten = [block(0xAA), block(0xBB), block(0xCC), block(0xDD)]
    fh = build_xva(
        {"Ref:1": disk_one, "Ref:10": disk_ten},
        checksums={"Ref:1": {i: None for i in range(5)}, "Ref:10": {i: None for i in range(4)}},
    )

    xva = XVA(fh)
    assert xva.disks() == ["Ref:1", "Ref:10"]

    refs_one = {m.name for _, m, _ in _iter_block_files(xva, "Ref:1")}
    refs_ten = {m.name for _, m, _ in _iter_block_files(xva, "Ref:10")}
    assert refs_one == {f"Ref:1/{i}" for i in range(5)} | {f"Ref:1/{i}.checksum" for i in range(5)}
    assert refs_ten == {f"Ref:10/{i}" for i in range(4)} | {f"Ref:10/{i}.checksum" for i in range(4)}
    assert refs_one.isdisjoint(refs_ten)


def test_open_and_random_reads_round_trip() -> None:
    disk_one = [block(0x11), None, block(0x13), block(0x14), block(0x15)]
    disk_ten = [block(0xAA), block(0xBB), None, block(0xDD)]
    fh = build_xva({"Ref:1": disk_one, "Ref:10": disk_ten})

    xva = XVA(fh)

    # A zero-sized block contributes no data and does not advance the data offset, so the data blocks are
    # concatenated compactly. This mirrors the format semantics documented on XVAStream.
    for ref, blocks in (("Ref:1", disk_one), ("Ref:10", disk_ten)):
        data_blocks = [payload for payload in blocks if payload is not None]
        stream = xva.open(ref)
        rng = random.Random(ref)
        for data_index in range(len(data_blocks)):
            for _ in range(5):
                jitter = rng.randrange(0, BLOCK_SIZE, 4096)
                stream.seek(data_index * BLOCK_SIZE + jitter)
                read_back = stream.read(BLOCK_SIZE - jitter)
                assert read_back == data_blocks[data_index][jitter:]

        # Data blocks are concatenated compactly; the remaining declared virtual size reads back as zeros.
        stream.seek(0)
        assert stream.read() == b"".join(data_blocks) + b"\x00" * (len(blocks) - len(data_blocks)) * BLOCK_SIZE


def test_gap_numbering_is_zero_filled() -> None:
    # Blocks 0, 2 and 4 present; 1 and 3 are missing numbers -> zero holes.
    fh = build_numbered_xva({"Ref:1": {0: block(0x01), 2: block(0x03), 4: block(0x05)}})
    stream = XVA(fh).open("Ref:1")
    stream.seek(0)
    data = stream.read()

    assert data[0:BLOCK_SIZE] == block(0x01)
    assert data[BLOCK_SIZE : 2 * BLOCK_SIZE] == b"\x00" * BLOCK_SIZE
    assert data[2 * BLOCK_SIZE : 3 * BLOCK_SIZE] == block(0x03)
    assert data[3 * BLOCK_SIZE : 4 * BLOCK_SIZE] == b"\x00" * BLOCK_SIZE
    assert data[4 * BLOCK_SIZE : 5 * BLOCK_SIZE] == block(0x05)


def test_zero_sized_block_is_skipped_without_shifting_offsets() -> None:
    # Block 1 is zero sized: it adds nothing and the following data keeps the current offset (compact data).
    fh = build_xva({"Ref:1": [block(0x01), None, block(0x03)]})
    stream = XVA(fh).open("Ref:1")
    data = stream.read()

    assert data == block(0x01) + block(0x03) + b"\x00" * BLOCK_SIZE
    stream.seek(BLOCK_SIZE)
    assert stream.read(BLOCK_SIZE) == block(0x03)


def test_gap_and_zero_block_combined() -> None:
    # Number 0 has data, number 1 is missing (zero hole), number 2 is zero sized (skipped), number 3 has data.
    fh = build_numbered_xva({"Ref:1": {0: block(0x01), 2: None, 3: block(0x04)}})
    stream = XVA(fh).open("Ref:1")
    data = stream.read()

    assert data[0:BLOCK_SIZE] == block(0x01)
    assert data[BLOCK_SIZE : 2 * BLOCK_SIZE] == b"\x00" * BLOCK_SIZE
    # The zero-sized block 2 takes no slot; block 3 lands right after the hole.
    assert data[2 * BLOCK_SIZE : 3 * BLOCK_SIZE] == block(0x04)


def test_verify_supported_checksum_passes() -> None:
    fh = build_xva({"Ref:1": [block(0x01), block(0x02)]}, checksums={"Ref:1": {0: None, 1: None}})
    stream = XVA(fh).open("Ref:1", verify=True)
    assert stream.read() == block(0x01) + block(0x02)


def test_verify_missing_checksum_raises_value_error() -> None:
    fh = build_xva({"Ref:1": [block(0x01), block(0x02)]}, checksums={"Ref:1": {0: None}})
    stream = XVA(fh).open("Ref:1", verify=True)
    stream.read(BLOCK_SIZE)
    with pytest.raises(ValueError, match="No checksum"):
        stream.read(BLOCK_SIZE)


def test_verify_invalid_checksum_raises_value_error() -> None:
    fh = build_xva({"Ref:1": [block(0x01)]}, checksums={"Ref:1": {0: "deadbeef"}})
    stream = XVA(fh).open("Ref:1", verify=True)
    with pytest.raises(ValueError, match="Invalid checksum"):
        stream.read(BLOCK_SIZE)


def test_verify_unsupported_algorithm_raises_not_implemented() -> None:
    fh = build_numbered_xva({"Ref:1": {0: block(0x01)}}, checksums={("Ref:1", 0)}, checksum_algo="xxhash")
    stream = XVA(fh).open("Ref:1", verify=True)
    with pytest.raises(UnsupportedChecksumError, match="Unsupported checksum"):
        stream.read(BLOCK_SIZE)


def test_removing_checksum_only_affects_its_own_block() -> None:
    blocks = [block(0x01), block(0x02), block(0x03), block(0x04)]
    fh = build_xva({"Ref:1": blocks}, checksums={"Ref:1": {i: None for i in range(4)}})

    # Drop only the checksum member for block 2 from the tar.
    tar = tarfile.open(fileobj=fh)
    surviving = [m for m in tar.getmembers() if m.name != "Ref:1/2.checksum"]
    rebuilt = io.BytesIO()
    with tarfile.open(fileobj=rebuilt, mode="w") as out:
        for member in surviving:
            payload = tar.extractfile(member).read() if member.isfile() else b""
            info = tarfile.TarInfo(member.name)
            info.size = len(payload)
            out.addfile(info, io.BytesIO(payload))
    rebuilt.seek(0)

    xva = XVA(rebuilt)

    plain = xva.open("Ref:1")
    assert plain.read() == b"".join(blocks)

    verified = xva.open("Ref:1", verify=True)
    verified.read(2 * BLOCK_SIZE)
    with pytest.raises(ValueError, match="No checksum"):
        verified.read(BLOCK_SIZE)

    # Block 3 still has its checksum and verifies fine.
    verified.seek(3 * BLOCK_SIZE)
    assert verified.read(BLOCK_SIZE) == blocks[3]


def test_duplicate_members_last_one_wins() -> None:
    entries = [("ova.xml", _ova_xml([("Ref:1", BLOCK_SIZE)]))]
    entries.append(("Ref:1/0", block(0x01)))
    entries.append(("Ref:1/0", block(0x02)))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in entries:
            _add_member(tar, name, data)
    buf.seek(0)

    stream = XVA(buf).open("Ref:1")
    assert stream.read(BLOCK_SIZE) == block(0x02)


def test_empty_disk_reads_as_zeros() -> None:
    fh = build_xva({"Ref:1": []})
    stream = XVA(fh).open("Ref:1")
    assert stream.size == 0
    assert stream.read() == b""
