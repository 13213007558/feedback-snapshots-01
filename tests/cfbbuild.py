"""Minimal Compound File Binary (CFB/OLE) writer for format-detection tests.

olefile 0.47 cannot create OLE files from scratch, and
msoffcrypto.method.container.ecma376_encrypted only emits the fixed
EncryptionInfo/EncryptedPackage layout.  This module builds structurally
valid CFB containers with an arbitrary set of top-level streams so that
multi-candidate files (e.g. EncryptionInfo + WordDocument) can be
constructed for detection-boundary diagnostics.

Simplifications (all permitted by [MS-CFB] and accepted by olefile 0.47):

* 512-byte sectors, major version 3 (no 4 KiB sectors, no DIFAT chain
  beyond the 109 in-header entries).
* Every stream is stored in the regular FAT, so every stream's *recorded*
  size must be >= 4096 bytes (the mini-stream cutoff); stored data is
  padded to a sector boundary, exactly like real producers leave the
  tail of the last sector unused.
* Directory entries are chained as a linear right-sibling list instead of
  a balanced red-black tree; olefile only follows the child/sibling
  pointers and does not validate tree balance.
"""

import math
from struct import pack

SECTOR_SIZE = 512
MINI_CUTOFF = 4096

ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
FREESECT = 0xFFFFFFFF
NOSTREAM = 0xFFFFFFFF


def _dir_entry(name, obj_type, color, left, right, child, start, size):
    encoded = name.encode("utf-16-le") + b"\x00\x00"
    if len(encoded) > 64:
        raise ValueError("stream name too long: {!r}".format(name))
    entry = encoded.ljust(64, b"\x00")
    entry += pack("<H", len(encoded))  # name length incl. null terminator
    entry += pack("<B", obj_type)
    entry += pack("<B", color)
    entry += pack("<I", left)
    entry += pack("<I", right)
    entry += pack("<I", child)
    entry += b"\x00" * 16  # CLSID
    entry += pack("<I", 0)  # state bits
    entry += b"\x00" * 8  # creation time
    entry += b"\x00" * 8  # modification time
    entry += pack("<I", start)
    entry += pack("<Q", size)
    assert len(entry) == 128
    return entry


def build_cfb(streams):
    """Build a CFB container (as bytes) from an ordered mapping.

    Each value is either ``bytes`` (recorded size == len(data)) or a
    ``(data, size)`` tuple where ``size`` is the stream size recorded in
    the directory; ``data`` is padded with zero bytes up to ``size`` and
    then to a sector boundary.  The recorded size must be >= 4096 so the
    stream is stored in the regular FAT (no MiniFAT is emitted).
    """
    names = list(streams.keys())
    datas = []
    sizes = []
    for name in names:
        value = streams[name]
        if isinstance(value, tuple):
            data, size = value
        else:
            data, size = value, len(value)
        if size < MINI_CUTOFF:
            raise ValueError(
                "stream {!r} records {} bytes; must be >= {} (mini stream "
                "not supported)".format(name, size, MINI_CUTOFF)
            )
        # Bytes beyond the recorded size are the unused tail of the last
        # sector, exactly like real CFB producers leave them.
        stored = data[:size].ljust(size, b"\x00")
        stored = stored.ljust(-(-len(stored) // SECTOR_SIZE) * SECTOR_SIZE, b"\x00")
        datas.append(stored)
        sizes.append(size)

    num_entries = 1 + len(names)  # root + streams
    dir_sectors = math.ceil(num_entries * 128 / SECTOR_SIZE)
    data_sectors = sum(len(d) // SECTOR_SIZE for d in datas)

    # FAT sector count is self-referential; iterate to a fixpoint.
    fat_sectors = 1
    while True:
        total = dir_sectors + data_sectors + fat_sectors
        needed = math.ceil(total / (SECTOR_SIZE // 4))
        if needed == fat_sectors:
            break
        fat_sectors = needed
    if fat_sectors > 109:
        raise ValueError("container too large for in-header DIFAT")

    # Sector layout: directory | stream data | FAT
    fat = []
    sector = 0

    dir_start = sector
    for i in range(dir_sectors):
        fat.append(sector + 1 if i < dir_sectors - 1 else ENDOFCHAIN)
        sector += 1

    stream_starts = []
    for data in datas:
        count = len(data) // SECTOR_SIZE
        stream_starts.append(sector)
        for i in range(count):
            fat.append(sector + 1 if i < count - 1 else ENDOFCHAIN)
            sector += 1

    fat_start = sector
    for _ in range(fat_sectors):
        fat.append(FATSECT)
        sector += 1

    # Directory: root entry + one entry per stream, right-sibling chain.
    entries = [
        _dir_entry(
            "Root Entry", 5, 1,
            NOSTREAM, NOSTREAM, 1 if names else NOSTREAM,
            ENDOFCHAIN, 0,
        )
    ]
    for i, name in enumerate(names):
        entries.append(
            _dir_entry(
                name, 2, 1,
                NOSTREAM,
                i + 2 if i < len(names) - 1 else NOSTREAM,
                NOSTREAM,
                stream_starts[i],
                sizes[i],
            )
        )
    directory = b"".join(entries).ljust(dir_sectors * SECTOR_SIZE, b"\x00")

    header = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # signature
    header += b"\x00" * 16  # CLSID
    header += pack("<H", 0x003E)  # minor version
    header += pack("<H", 0x0003)  # major version (512-byte sectors)
    header += pack("<H", 0xFFFE)  # byte order
    header += pack("<H", 0x0009)  # sector shift
    header += pack("<H", 0x0006)  # mini sector shift
    header += b"\x00" * 6  # reserved
    header += pack("<I", 0)  # num directory sectors (0 for v3)
    header += pack("<I", fat_sectors)
    header += pack("<I", dir_start)
    header += pack("<I", 0)  # transaction signature
    header += pack("<I", MINI_CUTOFF)
    header += pack("<I", ENDOFCHAIN)  # first MiniFAT sector
    header += pack("<I", 0)  # num MiniFAT sectors
    header += pack("<I", ENDOFCHAIN)  # first DIFAT sector
    header += pack("<I", 0)  # num DIFAT sectors
    difat = [fat_start + i for i in range(fat_sectors)]
    difat += [FREESECT] * (109 - len(difat))
    header += b"".join(pack("<I", s) for s in difat)
    assert len(header) == SECTOR_SIZE

    fat_bytes = b"".join(pack("<I", e) for e in fat)
    fat_bytes = fat_bytes.ljust(fat_sectors * SECTOR_SIZE, b"\xff")

    return header + directory + b"".join(datas) + fat_bytes
