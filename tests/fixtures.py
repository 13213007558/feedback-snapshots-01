import shutil
import struct
from pathlib import Path

CD = Path(__file__).parent
DATA = CD / "data"


def get_data_path_by_name(name):
    if name == "hello-world.exe":
        return DATA / "hello-world" / "hello-world.exe"
    elif name == "ModuleCode_x86.exe":
        return DATA / "mixed-mode" / "ModuleCode" / "bin" / "ModuleCode_x86.exe"
    elif name == "EmptyClass_x86.exe":
        return DATA / "mixed-mode" / "EmptyClass" / "bin" / "EmptyClass_x86.exe"
    elif name == "EmptyClass_amd64.exe":
        return DATA / "mixed-mode" / "EmptyClass" / "bin" / "EmptyClass_amd64.exe"
    elif name == "1d41308bf4148b4c138f9307abc696a6e4c05a5a89ddeb8926317685abb1c241":
        return DATA / "malware" / "1d41308bf4148b4c138f9307abc696a6e4c05a5a89ddeb8926317685abb1c241"
    elif name == "387f15043f0198fd3a637b0758c2b6dde9ead795c3ed70803426fc355731b173.dll_":
        return DATA / "malware" / "387f15043f0198fd3a637b0758c2b6dde9ead795c3ed70803426fc355731b173.dll_"
    elif name == "7f4ba9fc95b30baf8922a6933a4ff1c6a7fef41fae487bb31014c4963357770f.dll_":
        return DATA / "malware" / "7f4ba9fc95b30baf8922a6933a4ff1c6a7fef41fae487bb31014c4963357770f.dll_"
    elif name == "minimal-res.exe":
        return DATA / "minimal-resource" / "bin" / "minimal-res.exe"

    raise ValueError("unknown test file")


def copy_fixture_to_tmp(tmp_path: Path, name: str) -> Path:
    src = get_data_path_by_name(name)
    dst = tmp_path / src.name
    shutil.copyfile(src, dst)
    return dst


def patch_bytes(path: Path, offset: int, data: bytes) -> Path:
    buf = bytearray(path.read_bytes())
    buf[offset:offset + len(data)] = data
    path.write_bytes(buf)
    return path


def truncate_file(path: Path, size: int) -> Path:
    with path.open("r+b") as handle:
        handle.truncate(size)
    return path


def write_manifest_resource_fixture(tmp_path: Path) -> Path:
    """
    Build a sample from minimal-res.exe that declares three ManifestResource
    rows with the same display name:

      * an embedded resource (content present in this file)
      * an external File reference (content in another file)
      * an external AssemblyRef reference (content in another assembly)

    The metadata tables stream is rebuilt so that the extra rows are
    accounted for in the table row counts.  No new string heap entries are
    needed: both external rows reuse the existing "sample.resources" string.
    """
    import dnfile

    src = get_data_path_by_name("minimal-res.exe")
    raw = bytearray(src.read_bytes())

    dn = dnfile.dnPE(str(src))
    metadata_offset = dn.net.metadata.struct.get_file_offset()
    tables = dn.net.mdtables
    stream_entry_offset = dn.net.metadata.streams_list[0].struct.get_file_offset()

    rows = {}
    counts = {}
    for table in tables.tables_list:
        rows[table.number] = b"".join(
            raw[row.struct.get_file_offset():row.struct.get_file_offset() + table.row_size]
            for row in table.rows
            if row is not None
        )
        counts[table.number] = table.num_rows

    header = bytearray(raw[tables.file_offset:tables.file_offset + 24])
    mask = struct.unpack_from("<Q", header, 8)[0]
    mask |= 1 << 38  # File table
    struct.pack_into("<Q", header, 8, mask)

    counts[38] = 1
    counts[40] = 3
    row_counts = b"".join(
        struct.pack("<I", counts.get(i, 0)) for i in range(64) if mask >> i & 1
    )

    # "sample.resources" lives at offset 0xC3 in the #Strings heap.
    name_index = 0xC3
    file_row = struct.pack("<IHH", 1, name_index, 0)  # Flags=mrPrivate, Name, HashValue
    manifest_rows = [
        # Offset, Flags(mrPublic), Name, Implementation(coded index)
        struct.pack("<IIHH", 0, 1, name_index, 0),  # embedded
        struct.pack("<IIHH", 0, 1, name_index, (1 << 2) | 0),  # File row 1
        struct.pack("<IIHH", 0, 1, name_index, (1 << 2) | 1),  # AssemblyRef row 1
    ]

    table_rows = bytearray()
    for i in range(64):
        if not mask >> i & 1:
            continue
        if i == 38:
            table_rows += file_row
        elif i == 40:
            # replace the single original ManifestResource row with our rows
            for manifest_row in manifest_rows:
                table_rows += manifest_row
        elif i in rows:
            table_rows += rows[i]

    new_tables = bytes(header) + row_counts + bytes(table_rows)
    # This fixture's existing metadata is 720 bytes; append the rebuilt tables
    # stream directly after it, inside the same section.
    tables_stream_offset = 720

    new_metadata_size = tables_stream_offset + len(new_tables)
    new_end = metadata_offset + new_metadata_size
    if new_end > len(raw):
        raw.extend(b"\x00" * (new_end - len(raw)))

    raw[metadata_offset + tables_stream_offset:metadata_offset + new_metadata_size] = new_tables
    struct.pack_into("<II", raw, stream_entry_offset, tables_stream_offset, len(new_tables))
    struct.pack_into(
        "<I", raw, dn.net.struct.get_field_absolute_offset("MetaDataSize"), new_metadata_size
    )

    dst = tmp_path / "manifest-resources.exe"
    dst.write_bytes(raw)
    dnfile.dnPE(str(src)).close()
    return dst


def write_bad_entry_resource_fixture(tmp_path: Path) -> Path:
    """
    Copy minimal-res.exe and corrupt the type code of the second entry in its
    embedded ResourceSet.  "Count" must remain readable; "Greeting" must be
    reported as invalid without hiding the resource that declared it.
    """
    import dnfile

    src = get_data_path_by_name("minimal-res.exe")
    dn = dnfile.dnPE(str(src))
    resource_set = dn.net.resources[0].data
    resource_data_offset = dn.net.resources[0].file_offset
    entry = resource_set.entries[1]
    bad_type_offset = resource_data_offset + entry.data_offset

    dn.close()
    dst = tmp_path / "bad-entry.exe"
    shutil.copyfile(src, dst)
    patch_bytes(dst, bad_type_offset, b"\x7f")
    return dst
