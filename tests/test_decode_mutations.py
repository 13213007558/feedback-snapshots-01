"""Fast, deterministic mutation tests for the CIM decoding path.

The backend ingests WMI repositories from untrusted sources. Instead of poking
isolated string helpers, these tests feed complete, minimized class definition
and class instance byte fixtures through the real decoders
(``ClassDefinition`` / ``ClassInstance``) and mutate exactly one field per
case: property indices, array counts, string encoding flags, data region sizes
and nested qualifier references. The surrounding structure stays valid enough
to reach the targeted decode path.

Decode levels used below:

1. STRUCTURE: fixed-layout parsing inside the object constructor.
2. REFERENCE: name/qualifier resolution through the class data region.
3. VALUE: instance property value resolution through the instance data region.

Every mutation category gets its own read budget (``BUDGET_*``): the decoder
may never pull more bytes out of the mutated object than its budget, and must
fail at the expected level instead of escaping the owning object or allocating
without bound. Valid Unicode and empty/null values must keep decoding.
"""

from __future__ import annotations

from io import BytesIO
import struct
from typing import BinaryIO

import pytest

from dissect.cim.cim import Class
from dissect.cim.classes import ClassDefinition, ClassInstance
from dissect.cim.exceptions import Error


def unhex(text: str) -> bytes:
    """Decode a whitespace-separated hex dump."""
    return bytes.fromhex("".join(text.split()))


# Minimized byte fixtures, kept frozen so the decode targets stay deterministic.
_CLASS_DEFINITION_HEX = """
    00000000 0000000000000000 ab000000 00 00000000 09000000 04000000
    00000000 02000000 0b000000 39000000 11000000 63000000
    00 26000000 2d000000
    75000000
    0054657374436c61737300 004e616d6500 0056616c75657300
    004465736372697074696f6e00 0137682c670000
    02000000 07000000 08000000
    08000000 0000 00000000 00000000
    18000000 01000080 00 0b000000 ffff 19000000 00080000 0026000000
    13200000 0100 04000000 00000000 00000000
    00000000
"""
_CLASS_INSTANCE_HEX = """
    0000000000000000 0000000000000000 0000000000000000 0000000000000000
    0000000000000000 0000000000000000 0000000000000000 0000000000000000
    0000000000000000 0000000000000000 0000000000000000 0000000000000000
    0000000000000000 0000000000000000 0000000000000000 0000000000000000
    0000000000000000 0000000000000000 3d000000 00000000 00
    00 0b000000 12000000 00000000 01
    22000000 0054657374436c61737300 0068656c6c6f00 03000000 01000000 02000000 03000000
"""

CLASS_DEFINITION_BYTES = unhex(_CLASS_DEFINITION_HEX)
CLASS_INSTANCE_BYTES = unhex(_CLASS_INSTANCE_HEX)

# Per-category read budgets: how many bytes the decoder may pull out of the
# mutated object before it must have either finished decoding or failed.
BUDGET_STRUCTURE = 38  # truncated class definition, cut inside the qualifier record
BUDGET_REFERENCE = len(CLASS_DEFINITION_BYTES)  # reference level may read the whole class definition
BUDGET_VALUE = len(CLASS_INSTANCE_BYTES)  # value level may read the whole instance


class BudgetExceededError(Exception):
    """The decoder read past its budget for the object under test."""


class BudgetedIO(BytesIO):
    """BytesIO that fails once the decoder pulls more bytes than allowed."""

    def __init__(self, data: bytes, budget: int):
        super().__init__(data)
        self.budget = budget
        self.spent = 0

    def read(self, size: int = -1) -> bytes:
        data = super().read(size)
        self.spent += len(data)
        if self.spent > self.budget:
            raise BudgetExceededError(f"decoder read {self.spent} bytes, budget is {self.budget}")
        return data


class _CimStub:
    """Minimal CIM stand-in; the instance decoder only consults ``type_xp``."""

    type_xp = False


def ansi(text: str) -> bytes:
    """Encode a data region string with the ANSI encoding flag (0)."""
    return b"\x00" + text.encode("latin1") + b"\x00"


def utf16(text: str) -> bytes:
    """Encode a data region string with the Unicode encoding flag (1)."""
    return b"\x01" + text.encode("utf-16-le") + b"\x00\x00"


def u32_array(*items: int) -> bytes:
    """Encode a data region uint32 array with its count prefix."""
    return struct.pack(f"<{len(items) + 1}I", len(items), *items)


def cim_type(type_: int, array_state: int = 0) -> bytes:
    return struct.pack("<BBH", type_, array_state, 0)


def qualifier(key_reference: int, type_: int, data: bytes) -> bytes:
    return struct.pack("<IB", key_reference, 0) + cim_type(type_) + data


def build_class_definition() -> tuple[bytes, dict[str, int]]:
    """Build the minimized class definition fixture and its absolute offsets."""
    region_offsets = {}
    region = b""
    region_offsets["class_name"] = len(region)
    region += ansi("TestClass")
    region_offsets["prop0_name"] = len(region)
    region += ansi("Name")
    region_offsets["prop1_name"] = len(region)
    region += ansi("Values")
    region_offsets["qualifier_key"] = len(region)
    region += ansi("Description")
    region_offsets["qualifier_value"] = len(region)
    region += utf16("样本")
    region_offsets["default_array"] = len(region)
    region += u32_array(7, 8)

    qual_builtin = qualifier(0x80000001, 0x0B, struct.pack("<H", 0xFFFF))  # builtin "key" = true
    qual_nested = qualifier(
        region_offsets["qualifier_key"], 0x08, struct.pack("<I", region_offsets["qualifier_value"])
    )
    region_offsets["prop0_def"] = len(region)
    region += (
        cim_type(0x08)  # STRING
        + struct.pack("<HII", 0, 0, 0)
        + struct.pack("<I", len(qual_builtin) + len(qual_nested))
        + qual_builtin
        + qual_nested
    )
    region_offsets["prop1_def"] = len(region)
    region += cim_type(0x13, 0x20) + struct.pack("<HII", 1, 4, 0) + struct.pack("<I", 0)  # UINT32[]
    region_offsets["qualifier2_key_ref"] = region_offsets["prop0_def"] + 14 + 4 + len(qual_builtin)
    region_offsets["qualifier2_value"] = region_offsets["qualifier2_key_ref"] + 9
    region_offsets["prop1_index"] = region_offsets["prop1_def"] + 4

    # one state byte, then one uint32 default per property
    default_values = b"\x00"
    default_values += struct.pack("<I", region_offsets["qualifier_value"])
    default_values += struct.pack("<I", region_offsets["default_array"])

    blob = struct.pack("<I", 0)  # super_class_name_size
    blob += struct.pack("<Q", 0)  # timestamp
    data_len_pos = len(blob)
    blob += struct.pack("<I", 0)  # data_len, patched below
    blob += b"\x00"  # unk0
    blob += struct.pack("<I", region_offsets["class_name"])
    blob += struct.pack("<I", len(default_values))
    blob += struct.pack("<I", 4)  # empty class_name_record
    offsets = {"class_qualifiers_len": len(blob)}
    blob += struct.pack("<I", 0)  # class qualifier reference list
    blob += struct.pack("<I", 2)  # property reference count
    blob += struct.pack("<II", region_offsets["prop0_name"], region_offsets["prop0_def"])
    blob += struct.pack("<II", region_offsets["prop1_name"], region_offsets["prop1_def"])
    blob += default_values
    region_base = len(blob) + 4
    blob += struct.pack("<I", len(region)) + region
    blob += struct.pack("<I", 0)  # method_data

    blob = bytearray(blob)
    struct.pack_into("<I", blob, data_len_pos, len(blob) - data_len_pos - 4)
    offsets.update({name: offset + region_base for name, offset in region_offsets.items()})
    offsets["region_base"] = region_base
    offsets["region_size"] = len(region)
    return bytes(blob), offsets


def build_class_instance(
    name: bytes | None = None,
    values: bytes | None = None,
    state: int = 0x00,
) -> tuple[bytes, dict[str, int]]:
    """Build the minimized class instance fixture and its absolute offsets."""
    if name is None:
        name = ansi("hello")
    if values is None:
        values = u32_array(1, 2, 3)
    region = ansi("TestClass")
    name_offset = len(region)
    region += name
    values_offset = len(region)
    region += values

    remaining = struct.pack("<B", state)
    remaining += struct.pack("<II", name_offset, values_offset)  # table of contents
    remaining += struct.pack("<I", 0)  # qualifier reference list
    remaining += b"\x01"  # dynprops: none
    remaining += struct.pack("<I", len(region)) + region

    blob = b"\x00" * 0x80  # name_hash
    blob += struct.pack("<QQ", 0, 0)  # ts1, ts2
    blob += struct.pack("<I", 9 + len(remaining))  # data_size
    blob += struct.pack("<I", 0)  # class_name_offset
    blob += b"\x00"  # unk0
    blob += remaining

    state_byte = 0x80 + 16 + 4 + 4 + 1
    offsets = {
        "state_byte": state_byte,
        "toc0": state_byte + 1,
        "region_size_pos": state_byte + 1 + 8 + 4 + 1,
        "region_size": len(region),
    }
    offsets["region_data"] = offsets["region_size_pos"] + 4
    offsets["name_flag"] = offsets["region_data"] + name_offset
    offsets["array_count"] = offsets["region_data"] + values_offset
    return blob, offsets


CD_OFFSETS = build_class_definition()[1]
CI_OFFSETS = build_class_instance()[1]


def mutate(blob: bytes, offset: int, data: bytes) -> bytes:
    mutated = bytearray(blob)
    mutated[offset : offset + len(data)] = data
    return bytes(mutated)


def decode_class_definition(stream: BinaryIO) -> ClassDefinition:
    return ClassDefinition(None, stream)


def decode_instance(class_definition: ClassDefinition, stream: BinaryIO) -> ClassInstance:
    class_ = Class(_CimStub(), None, class_definition)
    return ClassInstance(_CimStub(), class_, stream)


def test_fixtures_match_minimized_bytes() -> None:
    assert build_class_definition()[0] == CLASS_DEFINITION_BYTES
    assert build_class_instance()[0] == CLASS_INSTANCE_BYTES


def test_baseline_class_definition_decodes() -> None:
    cd = decode_class_definition(BudgetedIO(CLASS_DEFINITION_BYTES, BUDGET_REFERENCE))
    assert cd.class_name == "TestClass"
    assert cd.super_class_name == ""
    properties = cd.properties
    assert properties["Name"].index == 0
    assert properties["Values"].index == 1
    assert properties["Name"].qualifiers["PROP_QUALIFIER_KEY"].value is True
    assert properties["Name"].qualifiers["Description"].value == "样本"
    assert cd.keys == ["Name"]


def test_baseline_class_instance_decodes() -> None:
    cd = decode_class_definition(BytesIO(CLASS_DEFINITION_BYTES))
    ci = decode_instance(cd, BudgetedIO(CLASS_INSTANCE_BYTES, BUDGET_VALUE))
    assert ci.class_name == "TestClass"
    assert ci.properties["Name"].value == "hello"
    assert ci.properties["Values"].value == [1, 2, 3]


def test_valid_unicode_and_empty_values_are_accepted() -> None:
    cd = decode_class_definition(BytesIO(CLASS_DEFINITION_BYTES))
    blob, _ = build_class_instance(name=utf16("héllo✓样本"), values=u32_array())
    ci = decode_instance(cd, BudgetedIO(blob, len(blob)))
    assert ci.properties["Name"].value == "héllo✓样本"
    assert ci.properties["Values"].value == []

    blob, _ = build_class_instance(name=ansi(""))
    ci = decode_instance(cd, BudgetedIO(blob, len(blob)))
    assert ci.properties["Name"].value == ""


def test_null_property_state_is_accepted() -> None:
    cd = decode_class_definition(BytesIO(CLASS_DEFINITION_BYTES))
    blob, _ = build_class_instance(state=0x01)  # Name not initialized
    ci = decode_instance(cd, BudgetedIO(blob, len(blob)))
    properties = ci.properties
    assert properties["Name"].is_initialized is False
    assert properties["Values"].value == [1, 2, 3]


def test_default_values_resolve_from_class_definition() -> None:
    cd = decode_class_definition(BytesIO(CLASS_DEFINITION_BYTES))
    blob, _ = build_class_instance(state=0x0A)  # both properties use their default
    ci = decode_instance(cd, BudgetedIO(blob, len(blob)))
    assert ci.properties["Name"].value == "样本"
    assert ci.properties["Values"].value == [7, 8]


def test_mutated_property_index_fails_at_value_level() -> None:
    # budget: BUDGET_VALUE, expected failure level: 3 (VALUE)
    blob = mutate(CLASS_DEFINITION_BYTES, CD_OFFSETS["prop1_index"], struct.pack("<H", 7))
    cd = decode_class_definition(BytesIO(blob))  # level 1: structure parses
    assert cd.properties["Values"].index == 7  # level 2: reference resolution succeeds
    ci = decode_instance(cd, BudgetedIO(CLASS_INSTANCE_BYTES, BUDGET_VALUE))
    with pytest.raises(IndexError, match="Invalid property index"):
        _ = ci.properties  # level 3: value resolution must fail


def test_mutated_property_index_boundary_fails_at_value_level() -> None:
    # index == property count slips past the state guard and must still fail in the toc
    blob = mutate(CLASS_DEFINITION_BYTES, CD_OFFSETS["prop1_index"], struct.pack("<H", 2))
    cd = decode_class_definition(BytesIO(blob))
    ci = decode_instance(cd, BudgetedIO(CLASS_INSTANCE_BYTES, BUDGET_VALUE))
    with pytest.raises(IndexError, match="list index out of range"):
        _ = ci.properties


def test_mutated_array_count_fails_at_value_level() -> None:
    # budget: BUDGET_VALUE, expected failure level: 3 (VALUE)
    blob = mutate(CLASS_INSTANCE_BYTES, CI_OFFSETS["array_count"], struct.pack("<I", 0xFFFFFFFF))
    cd = decode_class_definition(BytesIO(CLASS_DEFINITION_BYTES))
    stream = BudgetedIO(blob, BUDGET_VALUE)
    ci = decode_instance(cd, stream)  # level 1: structure parses
    with pytest.raises(EOFError, match="expected"):
        _ = ci.properties  # level 3: the huge count is rejected without being served
    assert stream.spent <= len(blob)


def test_mutated_encoding_flag_fails_at_value_level() -> None:
    # budget: BUDGET_VALUE, expected failure level: 3 (VALUE)
    blob = mutate(CLASS_INSTANCE_BYTES, CI_OFFSETS["name_flag"], b"\x02")
    cd = decode_class_definition(BytesIO(CLASS_DEFINITION_BYTES))
    ci = decode_instance(cd, BudgetedIO(blob, BUDGET_VALUE))
    with pytest.raises(Error, match="Invalid encoding flag"):
        _ = ci.properties


def test_mutated_instance_region_size_fails_at_value_level() -> None:
    # budget: BUDGET_VALUE, expected failure level: 3 (VALUE)
    # declared region cuts the "hello" string off mid-value
    blob = mutate(CLASS_INSTANCE_BYTES, CI_OFFSETS["region_size_pos"], struct.pack("<I", 12))
    cd = decode_class_definition(BytesIO(CLASS_DEFINITION_BYTES))
    ci = decode_instance(cd, BudgetedIO(blob, BUDGET_VALUE))  # level 1: structure parses
    with pytest.raises(EOFError):
        _ = ci.properties  # level 3: unterminated string inside the shrunk region


def test_mutated_class_region_size_fails_at_reference_level() -> None:
    # budget: BUDGET_REFERENCE, expected failure level: 2 (REFERENCE)
    # declared property data region ends before the property records it must contain
    blob = mutate(CLASS_DEFINITION_BYTES, CD_OFFSETS["region_base"] - 4, struct.pack("<I", 11))
    cd = decode_class_definition(BudgetedIO(blob, BUDGET_REFERENCE))  # level 1: structure parses
    assert cd.class_name == "TestClass"  # level 2: the class name itself still resolves
    with pytest.raises((EOFError, IndexError)):
        _ = cd.properties  # level 2: property records live outside the shrunk region


def test_oversized_declared_region_stays_confined() -> None:
    # a declared size larger than the object is tolerated by the decoder, but
    # the short read must stay inside the owning object
    blob = mutate(CLASS_INSTANCE_BYTES, CI_OFFSETS["region_size_pos"], struct.pack("<I", 0xFFFF))
    cd = decode_class_definition(BytesIO(CLASS_DEFINITION_BYTES))
    stream = BudgetedIO(blob, BUDGET_VALUE)
    ci = decode_instance(cd, stream)
    assert ci.properties["Values"].value == [1, 2, 3]
    assert stream.spent <= len(blob)


def test_mutated_nested_qualifier_key_reference_fails_at_reference_level() -> None:
    # budget: BUDGET_REFERENCE, expected failure level: 2 (REFERENCE)
    # the nested (property-level) qualifier key points outside the data region
    blob = mutate(
        CLASS_DEFINITION_BYTES, CD_OFFSETS["qualifier2_key_ref"], struct.pack("<I", CD_OFFSETS["region_size"] + 0x100)
    )
    cd = decode_class_definition(BudgetedIO(blob, BUDGET_REFERENCE))  # level 1: structure parses
    with pytest.raises(IndexError, match="index out of range"):
        _ = cd.properties  # level 2: qualifier key string is unreachable


def test_mutated_nested_qualifier_value_fails_at_reference_level() -> None:
    # budget: BUDGET_REFERENCE, expected failure level: 2 (REFERENCE)
    blob = mutate(
        CLASS_DEFINITION_BYTES, CD_OFFSETS["qualifier2_value"], struct.pack("<I", CD_OFFSETS["region_size"] + 0x100)
    )
    cd = decode_class_definition(BudgetedIO(blob, BUDGET_REFERENCE))
    with pytest.raises(IndexError, match="index out of range"):
        _ = cd.properties  # level 2: qualifier value string is unreachable


def test_truncated_qualifier_record_fails_at_structure_level() -> None:
    # budget: BUDGET_STRUCTURE, expected failure level: 1 (STRUCTURE)
    # the class qualifier list claims 16 bytes but the object ends mid-record
    blob = mutate(CLASS_DEFINITION_BYTES, CD_OFFSETS["class_qualifiers_len"], struct.pack("<I", 0x10))
    blob = blob[:BUDGET_STRUCTURE]
    with pytest.raises(EOFError):
        decode_class_definition(BudgetedIO(blob, BUDGET_STRUCTURE))


def passes_outer_length_check(blob: bytes) -> bool:
    """Naive gate that only validates the declared outer lengths of an instance."""
    if len(blob) < 0x99:
        return False
    (data_size,) = struct.unpack_from("<I", blob, 0x90)
    remaining = blob[0x99:]
    if data_size - 9 != len(remaining):
        return False
    (region_size,) = struct.unpack_from("<I", remaining, 14)
    return region_size == len(remaining) - 18


def test_outer_length_only_check_misses_dangling_value_offset() -> None:
    # every declared outer length stays consistent, but the toc entry for the
    # "Name" value points past the end of the instance data region
    blob = mutate(CLASS_INSTANCE_BYTES, CI_OFFSETS["toc0"], struct.pack("<I", CI_OFFSETS["region_size"] + 0x40))
    assert passes_outer_length_check(CLASS_INSTANCE_BYTES)
    assert passes_outer_length_check(blob)  # a length-only gate waves it through

    cd = decode_class_definition(BytesIO(CLASS_DEFINITION_BYTES))
    ci = decode_instance(cd, BudgetedIO(blob, BUDGET_VALUE))
    with pytest.raises(IndexError, match="index out of range"):
        _ = ci.properties  # the real decoder rejects the dangling offset
