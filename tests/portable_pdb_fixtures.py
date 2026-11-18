"""Build tiny, deterministic Portable PDB fixtures for tests.

The fixture builder is intentionally independent of the reader under test.  It
encodes the same wire format from the specification so that a bug in the reader
is not hidden by reusing the reader's own width calculations.
"""

import struct


def compressed_uint(value):
    if not isinstance(value, int) or value < 0:
        raise ValueError("compressed integer must be a non-negative int")
    if value <= 0x7F:
        return bytes([value])
    if value <= 0x3FFF:
        return bytes([0x80 | (value >> 8), value & 0xFF])
    if value <= 0x1FFFFFFF:
        return bytes([0xC0 | (value >> 24), (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])
    raise ValueError("value too large for a compressed integer: %d" % value)


def compressed_signed(value):
    if -64 <= value <= 63:
        return bytes([((value & 0x3F) << 1) | (1 if value < 0 else 0)])
    if -8192 <= value <= 8191:
        encoded = ((value & 0x1FFF) << 1) | (1 if value < 0 else 0)
        return bytes([0x80 | (encoded >> 8), encoded & 0xFF])
    if -268435456 <= value <= 268435455:
        encoded = ((value & 0x0FFFFFFF) << 1) | (1 if value < 0 else 0)
        return bytes([0xC0 | (encoded >> 24), (encoded >> 16) & 0xFF, (encoded >> 8) & 0xFF, encoded & 0xFF])
    raise ValueError("signed value out of range: %d" % value)


def encode_sequence_points(points, initial_document_row_id):
    """Encode a sequence-points blob.

    Each point is a dict with: il_offset, start_line, start_column, end_line,
    end_column, document_row_id, and optionally is_hidden.
    """
    out = bytearray()
    out += compressed_uint(0)  # LocalSignature row id (nil)

    current_document = initial_document_row_id
    previous_il = 0
    previous_line = None
    previous_column = None
    first = True

    for point in points:
        document = point.get("document_row_id", current_document)
        if first:
            if current_document == 0:
                out += compressed_uint(document)
                current_document = document
            elif document != current_document:
                raise ValueError("the first point cannot change document without a nil row document")
            out += compressed_uint(point["il_offset"])
            first = False
        else:
            if document != current_document:
                out += compressed_uint(0)
                out += compressed_uint(document)
                current_document = document
            else:
                delta = point["il_offset"] - previous_il
                if delta <= 0:
                    raise ValueError("same-document points must have increasing IL offsets")
                out += compressed_uint(delta)

        if point.get("is_hidden"):
            out += compressed_uint(0)
            out += compressed_uint(0)
        else:
            delta_lines = point["end_line"] - point["start_line"]
            delta_columns = point["end_column"] - point["start_column"]
            if delta_lines < 0:
                raise ValueError("end_line must not be before start_line")
            if delta_lines == 0 and delta_columns == 0:
                raise ValueError("a zero-delta point is encoded as hidden")
            out += compressed_uint(delta_lines)
            if delta_lines != 0:
                out += compressed_signed(delta_columns)
            else:
                if delta_columns < 0:
                    raise ValueError("zero-line points must have non-negative column delta")
                out += compressed_uint(delta_columns)
            if previous_line is None:
                out += compressed_uint(point["start_line"])
                out += compressed_uint(point["start_column"])
            else:
                out += compressed_signed(point["start_line"] - previous_line)
                out += compressed_signed(point["start_column"] - previous_column)
            previous_line = point["start_line"]
            previous_column = point["start_column"]

        previous_il = point["il_offset"]

    return bytes(out)


def _stream_header(name, offset, size):
    padded_name = name + b"\x00"
    padded_name += b"\x00" * ((4 - len(padded_name) % 4) % 4)
    return struct.pack("<II", offset, size) + padded_name


def build_portable_pdb(
    pdb_id,
    external_counts,
    documents=(),
    method_debug_information=(),
    state_machine_methods=(),
    entry_point_token=0,
    include_document_table=True,
):
    """Build a Portable PDB byte string.

    documents: sequence of (separator: int, parts: sequence of bytes)
    method_debug_information: sequence of (document_row_id, sequence_blob_or_None)
    state_machine_methods: sequence of (move_next_method_rid, kickoff_method_rid)
    """
    if len(pdb_id) != 20:
        raise ValueError("pdb_id must be 20 bytes")

    external_counts = dict(external_counts)

    strings = bytearray(b"\x00")
    guids = bytearray()
    blobs = bytearray(b"\x00")

    def add_blob(data):
        offset = len(blobs)
        blobs.extend(compressed_uint(len(data)))
        blobs.extend(data)
        return offset

    document_name_offsets = []
    for separator, parts in documents:
        part_offsets = [add_blob(part) for part in parts]
        name_blob = bytes([separator]) + b"".join(compressed_uint(offset) for offset in part_offsets)
        document_name_offsets.append(add_blob(name_blob))

    sequence_blob_offsets = []
    for _, blob in method_debug_information:
        sequence_blob_offsets.append(add_blob(blob) if blob is not None else 0)

    heap_sizes = 0
    if len(strings) >= 0x10000:
        heap_sizes |= 0x01
    if len(guids) >= 0x10000:
        heap_sizes |= 0x02
    if len(blobs) >= 0x10000:
        heap_sizes |= 0x04

    strings_index_size = 4 if heap_sizes & 0x01 else 2
    guid_index_size = 4 if heap_sizes & 0x02 else 2
    blob_index_size = 4 if heap_sizes & 0x04 else 2
    del strings_index_size

    document_row_count = len(documents) if include_document_table else 0
    method_debug_information_row_count = len(method_debug_information)
    state_machine_row_count = len(state_machine_methods)

    document_index_size = 2 if document_row_count < 0x10000 else 4
    methoddef_row_count = external_counts.get(6, 0)
    methoddef_index_size = 2 if methoddef_row_count < 0x10000 else 4

    document_rows = bytearray()
    for offset in document_name_offsets:
        document_rows += offset.to_bytes(blob_index_size, "little")
        document_rows += (0).to_bytes(guid_index_size, "little")
        document_rows += (0).to_bytes(blob_index_size, "little")
        document_rows += (0).to_bytes(guid_index_size, "little")

    method_debug_information_rows = bytearray()
    for (document_row_id, _), offset in zip(method_debug_information, sequence_blob_offsets):
        method_debug_information_rows += document_row_id.to_bytes(document_index_size, "little")
        method_debug_information_rows += offset.to_bytes(blob_index_size, "little")

    state_machine_rows = bytearray()
    for move_next, kickoff in state_machine_methods:
        state_machine_rows += move_next.to_bytes(methoddef_index_size, "little")
        state_machine_rows += kickoff.to_bytes(methoddef_index_size, "little")

    pdb_stream = bytearray()
    pdb_stream += pdb_id
    pdb_stream += struct.pack("<I", entry_point_token)
    external_mask = 0
    for table_number in external_counts:
        external_mask |= 1 << table_number
    pdb_stream += struct.pack("<Q", external_mask)
    for table_number in range(64):
        if external_mask & (1 << table_number):
            pdb_stream += struct.pack("<I", external_counts[table_number])

    internal_mask = 1 << 49
    if include_document_table:
        internal_mask |= 1 << 48
    if state_machine_row_count:
        internal_mask |= 1 << 54
    sorted_mask = 0
    if state_machine_row_count:
        sorted_mask |= 1 << 54

    tables_stream = bytearray()
    tables_stream += struct.pack("<IBBBBQQ", 0, 2, 0, heap_sizes, 0, internal_mask, sorted_mask)
    for table_number in range(64):
        if not (internal_mask & (1 << table_number)):
            continue
        if table_number == 48:
            tables_stream += struct.pack("<I", document_row_count)
        elif table_number == 49:
            tables_stream += struct.pack("<I", method_debug_information_row_count)
        elif table_number == 54:
            tables_stream += struct.pack("<I", state_machine_row_count)
        else:
            tables_stream += struct.pack("<I", 0)
    if include_document_table:
        tables_stream += document_rows
    tables_stream += method_debug_information_rows
    tables_stream += state_machine_rows

    streams = (
        (b"#Pdb", bytes(pdb_stream)),
        (b"#~", bytes(tables_stream)),
        (b"#Strings", bytes(strings)),
        (b"#US", b"\x00"),
        (b"#GUID", bytes(guids)),
        (b"#Blob", bytes(blobs)),
    )

    version = b"PDB v1.0\x00\x00\x00\x00"
    root = bytearray()
    root += b"BSJB"
    root += struct.pack("<HHII", 1, 1, 0, len(version))
    root += version
    root += struct.pack("<HH", 0, len(streams))

    header_size = len(root) + sum(8 + len(name) + 1 + ((4 - (len(name) + 1) % 4) % 4) for name, _ in streams)
    data_offset = header_size
    headers = bytearray()
    payload = bytearray()
    for name, data in streams:
        headers += _stream_header(name, data_offset, len(data))
        payload += data
        data_offset += len(data)

    return bytes(root + headers + payload)


def read_codeview_rsds_id(pe):
    """Read the first CodeView RSDS identity from an already parsed dnPE."""
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6]
    raw_data = pe.__data__
    for index in range(directory.Size // 28):
        entry = pe.get_data(directory.VirtualAddress + index * 28, 28)
        if len(entry) < 28:
            continue
        _, _, _, _, debug_type, data_size, _, pointer = struct.unpack("<IIHHIIII", entry)
        if debug_type != 2 or not data_size:
            continue
        payload = raw_data[pointer:pointer + data_size]
        if payload[:4] != b"RSDS" or len(payload) < 24:
            continue
        return payload[4:24]
    raise AssertionError("assembly has no CodeView RSDS record")
