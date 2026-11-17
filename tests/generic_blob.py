"""Build tiny CLR metadata images used by the generic-constraint regression."""
import struct


def owner_code(table, row_index):
    """Encode a TypeOrMethodDef coded index."""
    return (row_index << 1) | {"TypeDef": 0, "MethodDef": 1}[table]


def type_token(table, row_index):
    """Encode a TypeDefOrRef coded index."""
    return (row_index << 2) | {"TypeDef": 0, "TypeRef": 1, "TypeSpec": 2}[table]


def _compressed_uint(value):
    if value <= 0x7F:
        return bytes((value,))
    if value <= 0x3FFF:
        return bytes((0x80 | (value >> 8), value & 0xFF))
    return bytes((0xC0 | (value >> 24), (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF))


def _pad4(data):
    return data + b"\x00" * ((4 - len(data) % 4) % 4)


def default_rows():
    """Rows for a valid fixture with both a type and a method F-bound.

    TypeDef Foo has two parameters: type T (!0) and type U (!1).
    MethodDef Bar, declared by Foo, has one parameter: method T (!!0).
    Both T parameters are constrained by the legal F-bound IFoo<T>.
    """
    return {
        "TypeDefs": (
            ("<Module>", ()),
            ("Foo", ("Bar",)),
            ("IFoo", ()),
        ),
        "Methods": (("Bar", 1),),
        # GENERICINST CLASS TypeDef IFoo <1> VAR 0 / MVAR 0
        "TypeSpecs": (
            bytes((0x15, 0x12, type_token("TypeDef", 3), 0x01, 0x13, 0x00)),
            bytes((0x15, 0x12, type_token("TypeDef", 3), 0x01, 0x1E, 0x00)),
        ),
        # (number, TypeOrMethodDef owner, name)
        "GenericParams": (
            (0, owner_code("MethodDef", 1), "TMethod"),
            (0, owner_code("TypeDef", 2), "TType"),
            (1, owner_code("TypeDef", 2), "UType"),
            (0, owner_code("TypeDef", 3), "TInterface"),
        ),
        # (GenericParam row owner, TypeDefOrRef constraint)
        "Constraints": (
            (1, type_token("TypeSpec", 2)),
            (2, type_token("TypeSpec", 1)),
        ),
    }


def _method_signature(generic_arity):
    flags = 0x10 if generic_arity else 0x00
    body = bytes((flags,))
    if generic_arity:
        body += _compressed_uint(generic_arity)
    body += bytes((0x00, 0x01))  # zero parameters, void return
    return body


def build_metadata(rows=None):
    """Build a minimal metadata root containing only the generic tables."""
    if rows is None:
        rows = default_rows()

    strings = bytearray(b"\x00")
    string_indexes = {}

    def string(value):
        if value in string_indexes:
            return string_indexes[value]
        index = len(strings)
        strings.extend(value.encode("ascii") + b"\x00")
        string_indexes[value] = index
        return index

    blobs = bytearray(b"\x00")
    blob_indexes = {}

    def blob(value):
        if value in blob_indexes:
            return blob_indexes[value]
        index = len(blobs)
        blobs.extend(_compressed_uint(len(value)) + value)
        blob_indexes[value] = index
        return index

    type_defs = rows["TypeDefs"]
    type_refs = rows.get("TypeRefs", ())
    methods = rows["Methods"]
    type_specs = rows["TypeSpecs"]
    generic_params = rows["GenericParams"]
    constraints = rows["Constraints"]

    table_data = bytearray()
    # Module: Generation, Name, Mvid, EncId, EncBaseId
    table_data += struct.pack("<HHHHH", 0, string("gen.exe"), 1, 0, 0)

    # TypeRef: ResolutionScope, TypeName, TypeNamespace
    for namespace, name in type_refs:
        table_data += struct.pack("<HHH", 0, string(name), string(namespace))

    method_index = 1
    for type_name, type_methods in type_defs:
        # TypeDef: Flags, Name, Namespace, Extends, FieldList, MethodList
        table_data += struct.pack("<IHHHHH", 0, string(type_name), 0, 0, 1, method_index)
        method_index += len(type_methods)

    for method_name, generic_arity in methods:
        # MethodDef: Rva, ImplFlags, Flags, Name, Signature, ParamList
        signature = blob(_method_signature(generic_arity))
        table_data += struct.pack("<IHHHHH", 0, 0, 0x06, string(method_name), signature, 1)

    # TypeSpec: Signature
    for signature in type_specs:
        table_data += struct.pack("<H", blob(signature))

    # GenericParam: Number, Flags, Owner, Name
    for number, owner, name in generic_params:
        table_data += struct.pack("<HHHH", number, 0, owner, string(name))

    # GenericParamConstraint: Owner, Constraint
    for owner, constraint in constraints:
        table_data += struct.pack("<HH", owner, constraint)

    counts = (
        (0, 1),
        (1, len(type_refs)),
        (2, len(type_defs)),
        (6, len(methods)),
        (27, len(type_specs)),
        (42, len(generic_params)),
        (44, len(constraints)),
    )
    valid = 0
    count_data = bytearray()
    for number, count in counts:
        if count:
            valid |= 1 << number
            count_data += struct.pack("<I", count)

    header = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 0, valid, 0) + bytes(count_data)
    tables = header + bytes(table_data)

    version = b"v4.0.30319\x00"
    root = struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version)) + version
    streams = (
        (b"#~", tables),
        (b"#Strings", bytes(strings)),
        (b"#GUID", bytes(range(16))),
        (b"#Blob", bytes(blobs)),
    )
    root += struct.pack("<HH", 0, len(streams))

    offset = len(root) + sum(8 + len(_pad4(name + b"\x00")) for name, _ in streams)
    headers = bytearray()
    data = bytearray()
    for name, payload in streams:
        headers += struct.pack("<II", offset, len(payload)) + _pad4(name + b"\x00")
        padded = _pad4(payload)
        data += padded
        offset += len(padded)
    return root + bytes(headers) + bytes(data)


def replace_item(rows, key, index, value):
    """Return a copy of rows with exactly one sequence item replaced."""
    result = dict(rows)
    sequence = list(result[key])
    sequence[index] = value
    result[key] = tuple(sequence)
    return result
