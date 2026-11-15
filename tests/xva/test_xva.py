from __future__ import annotations

import hashlib
import io
import random
import tarfile
from typing import TYPE_CHECKING

import pytest

from dissect.archive.xva.xva import BLOCK_SIZE, XVA, UnsupportedChecksumError, _iter_block_files

if TYPE_CHECKING:
    from collections.abc import Iterable


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
        '<member><name>oid</name><value class="string">vm-1</value></member>'
        + "".join(records)
        + "</value></member></ova>"
    ).encode()


def _add_member(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


def build_xva(
    disks: dict[str, dict[int, bytes | None]],
    *,
    checksums: Iterable[tuple[str, int]] = (),
    checksum_data: dict[tuple[str, int], bytes] | None = None,
    checksum_algo: str = "checksum",
    sizes: dict[str, int] | None = None,
    extra_members: Iterable[tuple[str, bytes]] = (),
    drop: Iterable[str] = (),
    seed: int = 1234,
) -> io.BytesIO:
    """Build an XVA tar with deliberately shuffled member order."""
    checksums = set(checksums)
    checksum_data = checksum_data or {}
    sizes = sizes or {}
    dropped = set(drop)

    entries: list[tuple[str, bytes]] = [
        (
            "ova.xml",
            _ova_xml(
                [
                    (ref, sizes.get(ref, (max(blocks) + 1) * BLOCK_SIZE if blocks else 0))
                    for ref, blocks in disks.items()
                ]
            ),
        )
    ]

    for ref, blocks in disks.items():
        for number, payload in blocks.items():
            data = b"" if payload is None else payload
            entries.append((f"{ref}/{number}", data))

            if (ref, number) in checksums or (ref, number) in checksum_data:
                checksum = checksum_data.get((ref, number), hashlib.sha1(data).hexdigest().encode())
                entries.append((f"{ref}/{number}.{checksum_algo}", checksum))

    entries.extend(extra_members)
    entries = [entry for entry in entries if entry[0] not in dropped]
    random.Random(seed).shuffle(entries)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in entries:
            _add_member(tar, name, data)
    buf.seek(0)
    return buf


def block(marker: int, size: int = BLOCK_SIZE) -> bytes:
    return bytes([marker & 0xFF]) * size


def expected(blocks: list[bytes | None], size: int) -> bytes:
    data = b"".join(payload for payload in blocks if payload is not None)
    return data + b"\x00" * (size - len(data))


def test_dual_disk_shuffled_members_prefix_refs() -> None:
    disk_one = [block(0x11), block(0x12), block(0x13)]
    disk_ten = [block(0xAA), block(0xBB)]
    fh = build_xva(
        {"Ref:1": dict(enumerate(disk_one)), "Ref:10": dict(enumerate(disk_ten))},
        checksums={
            (ref, number)
            for ref, blocks in (("Ref:1", disk_one), ("Ref:10", disk_ten))
            for number in range(len(blocks))
        },
    )
    xva = XVA(fh)

    assert xva.disks() == ["Ref:1", "Ref:10"]

    # Membership is scoped to the full ref path, so a prefix ref cannot read the other disk's members.
    one = {member.name for _, member, _ in _iter_block_files(xva, "Ref:1")}
    ten = {member.name for _, member, _ in _iter_block_files(xva, "Ref:10")}
    assert one == {f"Ref:1/{i}" for i in range(3)}
    assert ten == {f"Ref:10/{i}" for i in range(2)}
    assert one.isdisjoint(ten)

    for ref, blocks in (("Ref:1", disk_one), ("Ref:10", disk_ten)):
        want = b"".join(blocks)
        stream = xva.open(ref, verify=True)
        stream.seek(0)
        data = stream.read()
        assert hashlib.sha256(data).hexdigest() == hashlib.sha256(want).hexdigest()

        rng = random.Random(ref)
        for _ in range(20):
            start = rng.randrange(0, len(want))
            length = rng.randrange(1, len(want) - start + 1)
            assert stream.readoffset(start, length) == want[start : start + length]


def test_zero_sized_block_is_compact() -> None:
    blocks = [block(0x01), None, block(0x03)]
    stream = XVA(build_xva({"Ref:1": dict(enumerate(blocks))})).open("Ref:1")

    assert stream.read() == expected(blocks, 3 * BLOCK_SIZE)
    stream.seek(BLOCK_SIZE)
    assert stream.read(BLOCK_SIZE) == block(0x03)


def test_leading_zero_sized_block_does_not_shift_data() -> None:
    # A zero-sized block consumes a block number but no data, so block 1 holds the data for offset 0.
    blocks = [None, block(0x02)]
    stream = XVA(build_xva({"Ref:1": dict(enumerate(blocks))})).open("Ref:1")

    assert stream.read(BLOCK_SIZE) == block(0x02)
    assert stream.read(BLOCK_SIZE) == b"\x00" * BLOCK_SIZE


def test_trailing_zero_sized_block_reads_as_zero() -> None:
    blocks = [block(0x01), None]
    stream = XVA(build_xva({"Ref:1": dict(enumerate(blocks))}, sizes={"Ref:1": 2 * BLOCK_SIZE})).open("Ref:1")

    assert stream.read() == block(0x01) + b"\x00" * BLOCK_SIZE


def test_missing_numbering_is_zero_filled() -> None:
    blocks = [block(0x01), block(0x03), block(0x05)]
    stream = XVA(build_xva({"Ref:1": {0: blocks[0], 2: blocks[1], 4: blocks[2]}})).open("Ref:1")
    data = stream.read()

    assert data[0:BLOCK_SIZE] == block(0x01)
    assert data[BLOCK_SIZE : 2 * BLOCK_SIZE] == b"\x00" * BLOCK_SIZE
    assert data[2 * BLOCK_SIZE : 3 * BLOCK_SIZE] == block(0x03)
    assert data[3 * BLOCK_SIZE : 4 * BLOCK_SIZE] == b"\x00" * BLOCK_SIZE
    assert data[4 * BLOCK_SIZE : 5 * BLOCK_SIZE] == block(0x05)


def test_leading_missing_block_does_not_borrow_data_or_checksum() -> None:
    # Only block 1 exists. Reading block 0 must be a hole and must not touch block 1's member or checksum.
    fh = build_xva({"Ref:1": {1: block(0x42)}}, checksums={("Ref:1", 1)}, sizes={"Ref:1": 2 * BLOCK_SIZE})
    stream = XVA(fh).open("Ref:1", verify=True)

    assert stream.read(BLOCK_SIZE) == b"\x00" * BLOCK_SIZE
    assert stream.read(BLOCK_SIZE) == block(0x42)


@pytest.mark.parametrize("first_block", [1, 2])
@pytest.mark.parametrize("verify", [False, True])
def test_leading_missing_blocks_read_only_holes(first_block: int, verify: bool) -> None:
    # A disk whose lowest block number is not 0: every preceding block is a hole, with or without verify.
    payload = block(0x42)
    size = (first_block + 1) * BLOCK_SIZE
    fh = build_xva(
        {"Ref:1": {first_block: payload}},
        checksums={("Ref:1", first_block)} if verify else (),
        sizes={"Ref:1": size},
    )
    stream = XVA(fh).open("Ref:1", verify=verify)

    assert stream.read() == b"\x00" * (first_block * BLOCK_SIZE) + payload


def test_leading_hole_without_checksum_does_not_require_one() -> None:
    # Reading a hole must never demand a checksum from a later block.
    fh = build_xva({"Ref:1": {1: block(0x42)}}, sizes={"Ref:1": 2 * BLOCK_SIZE})
    stream = XVA(fh).open("Ref:1", verify=True)

    assert stream.read(BLOCK_SIZE) == b"\x00" * BLOCK_SIZE
    with pytest.raises(ValueError, match="No checksum"):
        stream.read(BLOCK_SIZE)


def test_gap_and_zero_sized_block_combined() -> None:
    # Block 0 has data, block 1 is missing, block 2 is present but zero sized, block 3 has data.
    fh = build_xva({"Ref:1": {0: block(0x01), 2: None, 3: block(0x04)}}, sizes={"Ref:1": 4 * BLOCK_SIZE})
    data = XVA(fh).open("Ref:1").read()

    assert data[0:BLOCK_SIZE] == block(0x01)
    assert data[BLOCK_SIZE : 2 * BLOCK_SIZE] == b"\x00" * BLOCK_SIZE
    assert data[2 * BLOCK_SIZE : 3 * BLOCK_SIZE] == block(0x04)


def test_last_group_is_not_dropped() -> None:
    # A checksum member that sorts after every block must still be paired with the last block.
    blocks = [block(0x01), block(0x02)]
    fh = build_xva(
        {"Ref:1": dict(enumerate(blocks))},
        checksums={("Ref:1", 0), ("Ref:1", 1)},
        extra_members=[("Ref:1/1.checksum", hashlib.sha1(blocks[1]).hexdigest().encode())],
    )
    assert XVA(fh).open("Ref:1", verify=True).read() == b"".join(blocks)


def test_unshuffled_final_group_is_included() -> None:
    # The original reader only yielded a group when the block number changed, so the final group was lost.
    blocks = [block(0x01), block(0x02)]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        _add_member(tar, "ova.xml", _ova_xml([("Ref:1", 2 * BLOCK_SIZE)]))
        for index, payload in enumerate(blocks):
            _add_member(tar, f"Ref:1/{index}", payload)
            _add_member(tar, f"Ref:1/{index}.checksum", hashlib.sha1(payload).hexdigest().encode())
    buf.seek(0)

    assert XVA(buf).open("Ref:1", verify=True).read() == b"".join(blocks)


def test_unrelated_suffixed_member_is_ignored() -> None:
    # Per-block files that are not a known checksum suffix are not data or checksum members.
    payload = block(0x5A)
    fh = build_xva(
        {"Ref:1": {0: payload}},
        checksums={("Ref:1", 0)},
        extra_members=[("Ref:1/0.metadata", b"not a checksum")],
    )
    assert XVA(fh).open("Ref:1", verify=True).read() == payload


def test_checksum_before_its_block_is_paired() -> None:
    # A checksum can precede its block file in the tar; adjacency or ordering must not decide the pairing.
    payload = block(0x5A)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        _add_member(tar, "ova.xml", _ova_xml([("Ref:1", BLOCK_SIZE)]))
        _add_member(tar, "Ref:1/0.checksum", hashlib.sha1(payload).hexdigest().encode())
        _add_member(tar, "Ref:1/0", payload)
    buf.seek(0)

    assert XVA(buf).open("Ref:1", verify=True).read() == payload


def test_partial_final_block_and_trailing_hole() -> None:
    tail = b"tail-data"
    fh = build_xva({"Ref:1": {0: block(0x01), 1: tail}}, sizes={"Ref:1": 3 * BLOCK_SIZE})
    data = XVA(fh).open("Ref:1").read()

    assert data[:BLOCK_SIZE] == block(0x01)
    assert data[BLOCK_SIZE : BLOCK_SIZE + len(tail)] == tail
    assert data[BLOCK_SIZE + len(tail) :] == b"\x00" * (2 * BLOCK_SIZE - len(tail))


def test_data_beyond_declared_size_is_not_returned() -> None:
    # Block members that extend past the declared virtual size must not leak past the stream size.
    fh = build_xva({"Ref:1": {0: block(0x01)}}, sizes={"Ref:1": BLOCK_SIZE // 2})
    stream = XVA(fh).open("Ref:1")

    assert stream.size == BLOCK_SIZE // 2
    assert stream.read() == block(0x01)[: BLOCK_SIZE // 2]


def test_duplicate_members_last_one_wins() -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        _add_member(tar, "ova.xml", _ova_xml([("Ref:1", BLOCK_SIZE)]))
        _add_member(tar, "Ref:1/0", block(0x01))
        _add_member(tar, "Ref:1/0", block(0x02))
        _add_member(tar, "Ref:1/0.checksum", hashlib.sha1(block(0x01)).hexdigest().encode())
        _add_member(tar, "Ref:1/0.checksum", hashlib.sha1(block(0x02)).hexdigest().encode())
    buf.seek(0)

    assert XVA(buf).open("Ref:1", verify=True).read() == block(0x02)


def test_verify_supported_checksum_returns_data() -> None:
    blocks = [block(0x01), block(0x02)]
    fh = build_xva({"Ref:1": dict(enumerate(blocks))}, checksums={("Ref:1", 0), ("Ref:1", 1)})

    assert XVA(fh).open("Ref:1", verify=True).read() == b"".join(blocks)


def test_verify_missing_checksum_is_reported() -> None:
    blocks = [block(0x01), block(0x02)]
    fh = build_xva({"Ref:1": dict(enumerate(blocks))}, checksums={("Ref:1", 0)})
    stream = XVA(fh).open("Ref:1", verify=True)

    assert stream.read(BLOCK_SIZE) == block(0x01)
    with pytest.raises(ValueError, match="No checksum"):
        stream.read(BLOCK_SIZE)


def test_verify_invalid_checksum_is_reported() -> None:
    fh = build_xva(
        {"Ref:1": {0: block(0x01)}},
        checksum_data={("Ref:1", 0): b"deadbeef"},
    )
    with pytest.raises(ValueError, match="Invalid checksum"):
        XVA(fh).open("Ref:1", verify=True).read(BLOCK_SIZE)


def test_verify_malformed_checksum_is_reported_as_invalid() -> None:
    fh = build_xva(
        {"Ref:1": {0: block(0x01)}},
        checksum_data={("Ref:1", 0): b"\xff\xfe\x00checksum"},
    )
    with pytest.raises(ValueError, match="Invalid checksum"):
        XVA(fh).open("Ref:1", verify=True).read(BLOCK_SIZE)


def test_verify_unsupported_algorithm_is_distinct() -> None:
    fh = build_xva(
        {"Ref:1": {0: block(0x01)}},
        checksums={("Ref:1", 0)},
        checksum_algo="xxhash",
    )
    with pytest.raises(UnsupportedChecksumError, match="Unsupported checksum"):
        XVA(fh).open("Ref:1", verify=True).read(BLOCK_SIZE)


def test_removing_checksum_only_affects_its_own_block() -> None:
    disk_one = [block(0x11), block(0x12), block(0x13)]
    disk_ten = [block(0xAA), block(0xBB)]
    fh = build_xva(
        {"Ref:1": dict(enumerate(disk_one)), "Ref:10": dict(enumerate(disk_ten))},
        checksums={
            (ref, number)
            for ref, blocks in (("Ref:1", disk_one), ("Ref:10", disk_ten))
            for number in range(len(blocks))
        },
        drop={"Ref:1/1.checksum"},
    )
    xva = XVA(fh)

    # The disk itself is still readable without verification.
    assert xva.open("Ref:1").read() == b"".join(disk_one)

    stream = xva.open("Ref:1", verify=True)
    assert stream.read(BLOCK_SIZE) == disk_one[0]
    with pytest.raises(ValueError, match="No checksum"):
        stream.read(BLOCK_SIZE)
    stream.seek(2 * BLOCK_SIZE)
    assert stream.read(BLOCK_SIZE) == disk_one[2]

    # The other disk and its checksums are unaffected.
    assert xva.open("Ref:10", verify=True).read() == b"".join(disk_ten)


def test_empty_disk_reads_as_zeros() -> None:
    fh = build_xva({"Ref:1": {}}, sizes={"Ref:1": 0})
    stream = XVA(fh).open("Ref:1")
    assert stream.size == 0
    assert stream.read() == b""
