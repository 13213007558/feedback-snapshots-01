"""Deterministic synthetic .NET modules for identity-comparison tests.

The fixtures are written directly as PE + CLR metadata bytes.  Nothing is
compiled or executed.  All variants share one logical model, so tests can
assert exactly which physical rows moved or which signature changed.

Signature type descriptors are either a primitive element-type integer or a
tuple such as ``("class", "Inner")``.  The serializer resolves logical type
names to physical TypeDef/TypeRef row numbers, so a row reorder changes the raw
signature token even though the parsed signature stays the same.
"""

import copy
import struct

FILE_ALIGN = 0x200
SECTION_ALIGN = 0x2000
IMAGE_BASE = 0x400000

TAG_TYPEDEF = 0
TAG_TYPEREF = 1

ELEMENT_VOID = 0x01
ELEMENT_BOOLEAN = 0x02
ELEMENT_I4 = 0x08
ELEMENT_STRING = 0x0E
ELEMENT_CLASS = 0x12
ELEMENT_OBJECT = 0x1C

ROW_SIZES = {0: 10, 1: 6, 2: 14, 4: 6, 6: 14, 32: 22, 35: 20, 41: 4, 42: 8}


def compressed(value):
    if value <= 0x7F:
        return bytes([value])
    if value <= 0x3FFF:
        return bytes([0x80 | (value >> 8), value & 0xFF])
    if value <= 0x1FFFFFFF:
        return bytes([0xC0 | (value >> 24), (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])
    raise ValueError("value too large")


class Heap:
    def __init__(self):
        self.data = bytearray(b"\x00")
        self.offsets = {}

    def add(self, payload):
        if payload in self.offsets:
            return self.offsets[payload]
        offset = len(self.data)
        self.data += payload
        self.offsets[payload] = offset
        return offset

    def add_string(self, text):
        return self.add(text.encode("utf-8") + b"\x00")

    def add_blob(self, payload):
        return self.add(compressed(len(payload)) + payload)


def encode_type(descriptor, type_rid, typeref_rid):
    if isinstance(descriptor, int):
        return bytes([descriptor])
    kind = descriptor[0]
    if kind == "class":
        name = descriptor[1]
        if name in type_rid:
            coded = (type_rid[name] << 2) | TAG_TYPEDEF
        elif name in typeref_rid:
            coded = (typeref_rid[name] << 2) | TAG_TYPEREF
        else:
            raise KeyError("unknown type in signature: " + name)
        return bytes([ELEMENT_CLASS]) + compressed(coded)
    if kind == "valuetype":
        name = descriptor[1]
        if name in type_rid:
            coded = (type_rid[name] << 2) | TAG_TYPEDEF
        elif name in typeref_rid:
            coded = (typeref_rid[name] << 2) | TAG_TYPEREF
        else:
            raise KeyError("unknown type in signature: " + name)
        return bytes([0x11]) + compressed(coded)
    if kind == "szarray":
        return bytes([0x1D]) + encode_type(descriptor[1], type_rid, typeref_rid)
    if kind == "var":
        return bytes([0x13]) + compressed(descriptor[1])
    raise ValueError("unsupported type descriptor: " + repr(descriptor))


def method_sig(params, returns, generic, type_rid, typeref_rid):
    out = bytearray([0x20])
    if generic:
        out[0] |= 0x10
        out += compressed(generic)
    out += compressed(len(params))
    out += encode_type(returns, type_rid, typeref_rid)
    for param in params:
        out += encode_type(param, type_rid, typeref_rid)
    return bytes(out)


def field_sig(descriptor, type_rid, typeref_rid):
    return bytes([0x06]) + encode_type(descriptor, type_rid, typeref_rid)


class ModuleModel:
    """Logical metadata content shared by every fixture variant."""

    def __init__(self):
        self.assembly = "identity-sample"
        self.module = "identity-sample.exe"
        self.mscorlib = "mscorlib"
        self.namespace = "Ns"
        self.typedefs = [
            {"name": "<Module>", "namespace": "", "flags": 0, "extends": None, "methods": []},
            {"name": "Outer`1", "namespace": self.namespace, "flags": 0x100001,
             "extends": ("class", "Object"), "methods": ["Other"]},
            {"name": "Inner", "namespace": "", "flags": 0x100002,
             "extends": ("class", "Object"), "methods": ["Work#str", "Work#ii"]},
            {"name": "Demo", "namespace": self.namespace, "flags": 0x100001,
             "extends": ("class", "Object"), "methods": ["TakeInner", "Demo..ctor"]},
        ]
        self.typerefs = [
            {"name": "Object", "namespace": "System"},
            {"name": "String", "namespace": "System"},
        ]
        self.methods = {
            "Other": {"name": "Other", "params": [], "returns": ELEMENT_VOID, "generic": 0},
            "Work#str": {"name": "Work", "params": [ELEMENT_STRING], "returns": ELEMENT_VOID, "generic": 0},
            "Work#ii": {"name": "Work", "params": [ELEMENT_I4, ELEMENT_I4], "returns": ELEMENT_VOID, "generic": 0},
            "TakeInner": {"name": "TakeInner", "params": [("class", "Inner")], "returns": ELEMENT_VOID, "generic": 0},
            "Demo..ctor": {"name": ".ctor", "params": [], "returns": ELEMENT_VOID, "generic": 0},
        }
        self.fields = [{"name": "state", "type": ELEMENT_I4}]
        self.nested = [("Inner", "Outer`1")]
        self.generic_params = [{"owner": "Outer`1", "number": 0, "name": "T"}]

    def variant(self, type_order=None, typeref_order=None, method_order=None,
                signature_edits=None, namespace_edits=None, extra_methods=None):
        """Return a mutated copy for a fixture.

        * type_order/typeref_order are physical row orders (logical indices).
        * method_order is the global order of logical method keys.
        * signature_edits maps a method key to ``{"params":..., "returns":...}``.
        * namespace_edits maps a TypeDef name to a new namespace.
        * extra_methods is a list of ``{"key","owner","method"}`` additions.
        """
        clone = copy.deepcopy(self)
        if type_order is not None:
            clone.typedefs = [clone.typedefs[i] for i in type_order]
        if typeref_order is not None:
            clone.typerefs = [clone.typerefs[i] for i in typeref_order]
        if signature_edits:
            for key, edit in signature_edits.items():
                clone.methods[key] = dict(clone.methods[key], **edit)
        if namespace_edits:
            for typedef in clone.typedefs:
                if typedef["name"] in namespace_edits:
                    typedef["namespace"] = namespace_edits[typedef["name"]]
        if extra_methods:
            for extra in extra_methods:
                clone.methods[extra["key"]] = extra["method"]
                for typedef in clone.typedefs:
                    if typedef["name"] == extra["owner"]:
                        typedef["methods"] = list(typedef["methods"]) + [extra["key"]]
                        break
                else:
                    raise KeyError("unknown owner: " + extra["owner"])
        if method_order is not None:
            all_keys = [key for td in clone.typedefs for key in td["methods"]]
            if sorted(method_order) != sorted(all_keys):
                raise ValueError("method_order must list every method once")
            for td in clone.typedefs:
                td["methods"] = [key for key in method_order if key in td["methods"]]
        return clone


def build_variant(model):
    strings = Heap()
    blobs = Heap()
    guids = bytes.fromhex("00112233445566778899aabbccddeeff")

    s_assembly = strings.add_string(model.assembly)
    s_module = strings.add_string(model.module)
    s_mscorlib = strings.add_string(model.mscorlib)
    generic_strings = {gp["name"]: strings.add_string(gp["name"]) for gp in model.generic_params}

    type_rid = {td["name"]: i + 1 for i, td in enumerate(model.typedefs)}
    typeref_rid = {tr["name"]: i + 1 for i, tr in enumerate(model.typerefs)}

    # Method rows are serialized as the concatenation of each TypeDef's run in
    # physical TypeDef order.  This keeps MethodList ranges valid.
    method_keys = [key for td in model.typedefs for key in td["methods"]]
    if len(method_keys) != len(set(method_keys)):
        raise ValueError("a method is assigned to more than one type")

    signatures = {}
    for key in method_keys:
        method = model.methods[key]
        signatures[key] = blobs.add_blob(
            method_sig(method["params"], method["returns"], method["generic"], type_rid, typeref_rid)
        )
    field_sig_idx = blobs.add_blob(field_sig(model.fields[0]["type"], type_rid, typeref_rid))

    typedef_bytes = bytearray()
    method_cursor = 1
    for td in model.typedefs:
        typedef_bytes += struct.pack("<I", td["flags"])
        typedef_bytes += struct.pack("<H", strings.add_string(td["name"]))
        typedef_bytes += struct.pack("<H", strings.add_string(td["namespace"]))
        if td["extends"] is None:
            typedef_bytes += struct.pack("<H", 0)
        else:
            kind, name = td["extends"]
            if kind == "class":
                tag = TAG_TYPEDEF if name in type_rid else TAG_TYPEREF
                rid = type_rid[name] if name in type_rid else typeref_rid[name]
                typedef_bytes += struct.pack("<H", (rid << 2) | tag)
            else:
                raise ValueError("unsupported extends: " + repr(td["extends"]))
        typedef_bytes += struct.pack("<H", 1)  # one shared Field row
        typedef_bytes += struct.pack("<H", method_cursor)
        method_cursor += len(td["methods"])

    method_bytes = bytearray()
    for key in method_keys:
        method = model.methods[key]
        method_bytes += struct.pack("<I", 0x2050)
        method_bytes += struct.pack("<H", 0)
        method_bytes += struct.pack("<H", 0x1886 if method["name"] == ".ctor" else 0x96)
        method_bytes += struct.pack("<H", strings.add_string(method["name"]))
        method_bytes += struct.pack("<H", signatures[key])
        method_bytes += struct.pack("<H", 1)

    field_bytes = struct.pack("<HHH", 0x1, strings.add_string(model.fields[0]["name"]), field_sig_idx)

    typeref_bytes = bytearray()
    for tr in model.typerefs:
        typeref_bytes += struct.pack("<H", (1 << 2) | 2)  # AssemblyRef row 1
        typeref_bytes += struct.pack("<H", strings.add_string(tr["name"]))
        typeref_bytes += struct.pack("<H", strings.add_string(tr["namespace"]))

    module_bytes = struct.pack("<HHHHH", 0, s_module, 1, 0, 0)
    assembly_bytes = struct.pack("<IHHHHIHHH", 0x8004, 0, 0, 0, 0, 0, 0, s_assembly, 0)
    assemblyref_bytes = struct.pack("<HHHHIHHHH", 4, 0, 0, 0, 0, 0, s_mscorlib, 0, 0)

    nested_bytes = bytearray()
    for nested, enclosing in model.nested:
        nested_bytes += struct.pack("<HH", type_rid[nested], type_rid[enclosing])

    generic_bytes = bytearray()
    for gp in model.generic_params:
        generic_bytes += struct.pack("<H", gp["number"])
        generic_bytes += struct.pack("<H", 0)
        generic_bytes += struct.pack("<H", (type_rid[gp["owner"]] << 1) | 0)
        generic_bytes += struct.pack("<H", generic_strings[gp["name"]])

    tables = {
        0: module_bytes,
        1: bytes(typeref_bytes),
        2: bytes(typedef_bytes),
        4: field_bytes,
        6: bytes(method_bytes),
        32: assembly_bytes,
        35: assemblyref_bytes,
        41: bytes(nested_bytes),
        42: bytes(generic_bytes),
    }
    return write_pe(tables, strings, blobs, guids)


def write_pe(tables, strings, blobs, guids):
    tables_stream = bytearray()
    tables_stream += struct.pack("<I", 0)
    tables_stream += bytes([2, 0, 0, 0])
    tables_stream += struct.pack("<Q", sum(1 << number for number in tables))
    tables_stream += struct.pack("<Q", 0)
    for number in sorted(tables):
        tables_stream += struct.pack("<I", len(tables[number]) // ROW_SIZES[number])
    for number in sorted(tables):
        tables_stream += tables[number]
    while len(tables_stream) % 4:
        tables_stream.append(0)

    streams = [
        (b"#~", bytes(tables_stream)),
        (b"#Strings", bytes(strings.data)),
        (b"#US", b"\x00"),
        (b"#GUID", guids),
        (b"#Blob", bytes(blobs.data)),
    ]

    metadata = bytearray()
    metadata += struct.pack("<I", 0x424A5342)
    metadata += struct.pack("<HH", 1, 1)
    metadata += struct.pack("<I", 0)
    version = b"v4.0.30319\x00\x00"
    metadata += struct.pack("<I", len(version))
    metadata += version
    metadata += struct.pack("<H", 0)
    metadata += struct.pack("<H", len(streams))
    header_size = sum(8 + len(name) + 1 + ((4 - (len(name) + 1) % 4) % 4) for name, _ in streams)
    entries = bytearray()
    payload = bytearray()
    base = len(metadata) + header_size
    for name, body in streams:
        entries += struct.pack("<II", base + len(payload), len(body))
        entries += name + b"\x00"
        entries += b"\x00" * ((4 - (len(name) + 1) % 4) % 4)
        payload += body
        while len(payload) % 4:
            payload.append(0)
    metadata += entries + payload
    while len(metadata) % 4:
        metadata.append(0)

    metadata_offset = 0x48
    text_rva = SECTION_ALIGN
    metadata_rva = text_rva + metadata_offset
    section = bytearray(metadata_offset + len(metadata))
    section[metadata_offset:metadata_offset + len(metadata)] = bytes(metadata)
    clr_header = struct.pack("<IHHIIIIIIII", 0x48, 2, 5, metadata_rva, len(metadata), 1, 0, 0, 0, 0, 0)
    section[: len(clr_header)] = clr_header
    while len(section) % FILE_ALIGN:
        section.append(0)

    headers = bytearray(0x400)
    headers[0:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x80)
    headers[0x80:0x84] = b"PE\x00\x00"
    coff = 0x84
    struct.pack_into("<HHIIIHH", headers, coff, 0x14C, 1, 0, 0, 0, 0xE0, 0x2102)
    opt = coff + 20
    struct.pack_into("<HBBIIIIII", headers, opt, 0x10B, 2, 0,
                     len(section), 0, 0, 0, text_rva, 0)
    struct.pack_into("<III", headers, opt + 28, IMAGE_BASE, SECTION_ALIGN, FILE_ALIGN)
    struct.pack_into("<HHHHHHI", headers, opt + 40, 4, 0, 0, 0, 4, 0, 0)
    struct.pack_into("<IIIIII", headers, opt + 56, SECTION_ALIGN * 2, len(headers), 0, 2, 0, 0)
    struct.pack_into("<IIII", headers, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<II", headers, opt + 88, 0, 16)
    struct.pack_into("<II", headers, opt + 96 + 14 * 8, text_rva, 0x48)
    sec = opt + 0xE0
    headers[sec:sec + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", headers, sec + 8,
                     len(section), text_rva, len(section), len(headers),
                     0, 0, 0, 0, 0x60000020)
    return bytes(headers) + bytes(section)
