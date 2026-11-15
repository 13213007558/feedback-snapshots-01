from __future__ import annotations

import struct
from io import BytesIO
from typing import BinaryIO

import pytest

from dissect.cim.c_cim import ARRAY_STATES, CIM_TYPES, c_cim
from dissect.cim.cim import CIM
from dissect.cim.classes import DataRegion
from dissect.cim.exceptions import Error


def test_cim(index_bin: BinaryIO, objects_bin: BinaryIO, mappings_bin: list[BinaryIO]) -> None:
    repo = CIM(index_bin, objects_bin, mappings_bin)
    assert repo

    subscription_ns = repo.root.namespace("subscription")
    binding = next(subscription_ns.class_("__filtertoconsumerbinding").instances)
    consumer = subscription_ns.query(binding.properties["Consumer"].value)
    assert consumer.properties["SourceName"].value == "Service Control Manager"


def _encode_string(value: str) -> bytes:
    return b"\x00" + value.encode("latin1") + b"\x00"


def _encode_array(*elements: int) -> bytes:
    return struct.pack("<I", len(elements)) + b"".join(struct.pack("<I", element) for element in elements)


def _array_type(type_: int) -> c_cim.cim_type:
    return c_cim.cim_type(type_, ARRAY_STATES.ARRAY, 0)


@pytest.fixture
def array_sample() -> tuple[DataRegion, dict[str, int]]:
    strings = {}
    blob = b""
    for name, value in [("shared", "shared"), ("alpha", "alpha"), ("beta", "beta")]:
        strings[name] = len(blob)
        blob += _encode_string(value)

    offsets = dict(strings)

    offsets["string_array"] = len(blob)
    # shared string referenced twice, one out-of-bounds element at the end
    blob += _encode_array(strings["alpha"], strings["shared"], strings["shared"], 0xFFFFFF00)

    offsets["reference_array"] = len(blob)
    # duplicate references to the same string, one NULL element
    blob += _encode_array(strings["beta"], strings["beta"], DataRegion.NULL_OFFSET)

    offsets["uint32_array"] = len(blob)
    blob += _encode_array(0x41414141, 2, 3)

    offsets["empty_array"] = len(blob)
    blob += _encode_array()

    region = DataRegion(BytesIO(struct.pack("<I", len(blob)) + blob))
    return region, offsets


def test_string_array_decodes_elements(array_sample: tuple[DataRegion, dict[str, int]]) -> None:
    region, offsets = array_sample
    value = region.get_array(offsets["string_array"], _array_type(CIM_TYPES.STRING))

    assert value == ["alpha", "shared", "shared", None]
    # shared string elements resolve to the same value, order is preserved
    assert value[1] is not None and value[1] == value[2]
    # the out-of-bounds element is located at its own index and not resolved
    # into another property's string
    assert value[3] is None


def test_reference_array_decodes_elements(array_sample: tuple[DataRegion, dict[str, int]]) -> None:
    region, offsets = array_sample
    value = region.get_array(offsets["reference_array"], _array_type(CIM_TYPES.REFERENCE))

    assert value == ["beta", "beta", None]


def test_numeric_array_values_preserved(array_sample: tuple[DataRegion, dict[str, int]]) -> None:
    region, offsets = array_sample
    value = region.get_array(offsets["uint32_array"], _array_type(CIM_TYPES.UINT32))

    assert value == [0x41414141, 2, 3]


def test_empty_array(array_sample: tuple[DataRegion, dict[str, int]]) -> None:
    region, offsets = array_sample
    assert region.get_array(offsets["empty_array"], _array_type(CIM_TYPES.STRING)) == []


def test_null_array(array_sample: tuple[DataRegion, dict[str, int]]) -> None:
    region, _ = array_sample
    assert region.get_array(DataRegion.NULL_OFFSET, _array_type(CIM_TYPES.STRING)) is None


def test_array_offset_out_of_bounds(array_sample: tuple[DataRegion, dict[str, int]]) -> None:
    region, _ = array_sample
    with pytest.raises(Error, match="out of bounds"):
        region.get_array(len(region.data) + 4, _array_type(CIM_TYPES.STRING))


def test_string_offset_out_of_bounds(array_sample: tuple[DataRegion, dict[str, int]]) -> None:
    region, _ = array_sample
    with pytest.raises(Error, match="out of bounds"):
        region.get_string(len(region.data))


def test_get_value_decodes_string_array(array_sample: tuple[DataRegion, dict[str, int]]) -> None:
    region, offsets = array_sample
    value = region.get_value(offsets["string_array"], _array_type(CIM_TYPES.STRING))

    assert value == ["alpha", "shared", "shared", None]
