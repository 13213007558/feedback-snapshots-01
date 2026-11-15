from __future__ import annotations

import importlib
from typing import TYPE_CHECKING
from uuid import UUID
from xml.etree import ElementTree

import pytest

from dissect.cstruct import Structure
from dissect.cstruct.types.structure import Structure as HostStructure
from dissect.etl import manifest

if TYPE_CHECKING:
    from types import ModuleType

GUID = UUID("11111111-2222-3333-4444-555555555555")

MANIFEST_TEMPLATE = """
<EventManifest xmlns="http://schemas.microsoft.com/win/2004/08/events">
  <provider name="IsolationTest" guid="{{{guid}}}" symbol="ISOLATION_TEST"/>
  <templates>
    <template tid="FixedTemplate">
      <data name="First" inType="win:UInt32"/>
      <data name="Second" inType="win:UInt16"/>
      <data name="Third" inType="win:UInt32"/>
    </template>
    <template tid="VariableTemplate">
      <data name="Count" inType="win:UInt16"/>
      <data name="Name" inType="win:String"/>
      <data name="Payload" inType="win:UInt8" max="Count"/>
    </template>
    <template tid="PointerTemplate">
      <data name="Head" inType="win:UInt32"/>
      <data name="Ptr" inType="win:Pointer"/>
      <data name="Tail" inType="win:UInt32"/>
    </template>
  </templates>
  <events>
    <event value="1" version="0" symbol="FIXED" opcode="0" level="0" task="0" keyword="0"
           template="FixedTemplate"/>
    <event value="2" version="0" symbol="VARIABLE" opcode="0" level="0" task="0" keyword="0"
           template="VariableTemplate"/>
    <event value="3" version="0" symbol="POINTER" opcode="0" level="0" task="0" keyword="0"
           template="PointerTemplate"/>
  </events>
</EventManifest>
"""

FIXED_DEFINITION = """
struct Fixed {
    uint32 First;
    uint16 Second;
    uint32 Third;
};
"""

FIXED_BYTES = b"\x01\x00\x00\x00\x02\x00\x03\x00\x00\x00"
FIXED_VALUES = {"First": 1, "Second": 2, "Third": 3}

VARIABLE_BYTES = b"\x03\x00hi\x00\x01\x02\x03"
VARIABLE_VALUES = {"Count": 3, "Name": b"hi", "Payload": [1, 2, 3]}

POINTER_BYTES_32 = b"\x01\x00\x00\x00\x88\x77\x66\x55\x02\x00\x00\x00"
POINTER_BYTES_64 = b"\x01\x00\x00\x00\x88\x77\x66\x55\x44\x33\x22\x11\x02\x00\x00\x00"


def manifest_xml() -> str:
    return MANIFEST_TEMPLATE.format(guid=GUID)


def new_fixed_parser() -> object:
    from dissect.cstruct import cstruct

    return cstruct().load(FIXED_DEFINITION)


def assert_host_untouched() -> None:
    assert "_calc_offsets" not in vars(Structure)
    assert "_calc_offsets" not in vars(HostStructure)


def assert_fixed_parser(state: tuple) -> None:
    offsets, size, dynamic = state
    assert offsets == [("First", 0), ("Second", 4), ("Third", 6)]
    assert size == 10
    assert dynamic is False


def fixed_state(parser: object) -> tuple:
    return (
        [(name, field.offset) for name, field in parser.Fixed.lookup.items()],
        parser.Fixed.size,
        parser.Fixed.dynamic,
    )


def assert_fixed_roundtrip(parser: object) -> None:
    obj = parser.Fixed(FIXED_BYTES)
    assert obj.__values__ == FIXED_VALUES
    assert obj.dumps() == FIXED_BYTES

    written = parser.Fixed(**FIXED_VALUES)
    assert written.dumps() == FIXED_BYTES


def assert_variable_template(module: ModuleType) -> None:
    template = module.c_parser.VariableTemplate

    assert [(name, field.offset) for name, field in template.lookup.items()] == [
        ("Count", 0),
        ("Name", 2),
        ("Payload", None),
    ]
    assert template.size is None
    assert template.dynamic is True

    obj = template(VARIABLE_BYTES)
    assert obj.__values__ == VARIABLE_VALUES
    assert obj.__sizes__["Name"] == 3
    assert obj.__sizes__["Payload"] == 3
    assert len(obj) == len(VARIABLE_BYTES)
    assert obj.dumps() == VARIABLE_BYTES

    written = template(Count=3, Name=b"hi", Payload=[1, 2, 3])
    assert written.dumps() == VARIABLE_BYTES

    with pytest.raises(EOFError):
        template(VARIABLE_BYTES[:-1])


def assert_pointer_template(module: ModuleType, width: int) -> None:
    template = module.c_parser.PointerTemplate
    data = POINTER_BYTES_64 if width == 8 else POINTER_BYTES_32

    if width == 8:
        module.c_parser.EtwPointer.as_64bit()
    else:
        module.c_parser.EtwPointer.as_32bit()

    assert [(name, field.offset) for name, field in template.lookup.items()] == [
        ("Head", 0),
        ("Ptr", 4),
        ("Tail", 4 + width),
    ]
    assert template.size == 8 + width
    assert template.dynamic is False

    obj = template(data)
    assert obj.Head == 1
    assert obj.Ptr == int.from_bytes(data[4 : 4 + width], "little")
    assert obj.Tail == 2
    assert len(obj) == len(data)
    assert obj.dumps() == data


def assert_manifest_module(module: ModuleType) -> None:
    assert module.PROVIDER_NAME == "IsolationTest"
    assert module.PROVIDER_GUID == GUID
    assert {event.symbol for event in module.EVENTS.values()} == {"FIXED", "VARIABLE", "POINTER"}
    assert {event.value for event in module.EVENTS.values()} == {1, 2, 3}
    assert issubclass(module.ManifestStructure, Structure)
    assert module.ManifestStructure is not Structure
    assert_variable_template(module)
    assert_pointer_template(module, 8)
    assert_pointer_template(module, 4)


def test_plain_before_manifest() -> None:
    parser = new_fixed_parser()
    assert_fixed_parser(fixed_state(parser))

    module = manifest.compile_xml(GUID, manifest_xml())

    assert_host_untouched()
    assert_fixed_parser(fixed_state(parser))
    assert_fixed_roundtrip(parser)
    assert_fixed_roundtrip(new_fixed_parser())
    assert_manifest_module(module)
    assert_host_untouched()


def test_manifest_before_plain() -> None:
    module = manifest.compile_xml(GUID, manifest_xml())
    assert_manifest_module(module)

    assert_host_untouched()
    parser = new_fixed_parser()
    assert_fixed_parser(fixed_state(parser))
    assert_fixed_roundtrip(parser)
    assert_manifest_module(module)
    assert_host_untouched()


def test_repeated_compilation() -> None:
    parser = new_fixed_parser()

    first = manifest.compile_xml(GUID, manifest_xml())
    second = manifest.compile_xml(GUID, manifest_xml())
    first.EVENTS_EXTRA = "marker"

    assert first is not second
    assert not hasattr(second, "EVENTS_EXTRA")
    assert_host_untouched()

    assert_fixed_parser(fixed_state(parser))
    assert_fixed_roundtrip(parser)
    assert_manifest_module(first)
    assert_manifest_module(second)
    assert_host_untouched()


def test_failed_compilation_keeps_state() -> None:
    parser = new_fixed_parser()
    good = manifest.compile_xml(GUID, manifest_xml())

    broken_xml = manifest_xml().replace('tid="VariableTemplate"', 'tid="FixedTemplate"', 1)
    with pytest.raises(ValueError, match="Duplicate type"):
        manifest.compile_xml(GUID, broken_xml)

    with pytest.raises(ElementTree.ParseError):
        manifest.compile_xml(GUID, "<not-xml")

    assert_host_untouched()
    assert_fixed_parser(fixed_state(parser))
    assert_fixed_roundtrip(parser)
    assert_manifest_module(good)
    assert_host_untouched()

    recovered = manifest.compile_xml(GUID, manifest_xml())
    assert_manifest_module(recovered)
    assert_host_untouched()


def test_lookup_cache_does_not_patch_host() -> None:
    manifest.CACHE.pop(GUID, None)
    original = manifest.get_resource_string

    manifest.get_resource_string = lambda _: manifest_xml()
    try:
        first = manifest.lookup(GUID)
        second = manifest.lookup(GUID)
    finally:
        manifest.get_resource_string = original
        manifest.CACHE.pop(GUID, None)

    importlib.invalidate_caches()
    assert first is second
    assert_host_untouched()
    assert_manifest_module(first)


def test_real_manifest_dynamic_templates() -> None:
    parser = new_fixed_parser()
    path = "dissect/etl/manifests/xml/{68fdd900-4a3e-11d1-84f4-0000f80464e3}.xml"

    module = manifest.compile_file(UUID(path.split("{")[1].split("}")[0]), path)

    assert_host_untouched()
    assert_fixed_parser(fixed_state(parser))
    assert_fixed_roundtrip(parser)

    user_sid = module.c_parser.UserSID
    sid_bytes = b"\x01\x02" + b"\x00" * 6 + b"\x01\x00\x00\x00\x02\x00\x00\x00"
    assert user_sid.size is None
    assert user_sid.dynamic is True
    assert user_sid(sid_bytes).dumps() == sid_bytes

    header = module.c_parser.EventTrace_Header
    assert any(field.type.__name__ == "EtwPointer" for field in header.lookup.values())
    assert_host_untouched()


@pytest.mark.parametrize("first_width", [8, 4])
def test_pointer_width_switch_keeps_offsets(first_width: int) -> None:
    module = manifest.compile_xml(GUID, manifest_xml())
    template = module.c_parser.PointerTemplate

    for width in (8, 4, 8, 4):
        assert_pointer_template(module, width)
        assert template.size == 8 + width
        assert_host_untouched()


def test_real_manifest_nested_pointer_offsets() -> None:
    parser = new_fixed_parser()
    path = "dissect/etl/manifests/xml/{68fdd900-4a3e-11d1-84f4-0000f80464e3}.xml"
    module = manifest.compile_file(UUID(path.split("{")[1].split("}")[0]), path)
    header = module.c_parser.EventTrace_Header

    for width in (8, 4, 8):
        if width == 8:
            module.c_parser.EtwPointer.as_64bit()
        else:
            module.c_parser.EtwPointer.as_32bit()

        assert header.lookup["LoggerName"].offset == 56
        assert header.lookup["LogFileName"].offset == (64 if width == 8 else 60)
        assert header.lookup["TimeZoneInformation"].offset == (72 if width == 8 else 64)

    assert_fixed_parser(fixed_state(parser))
    assert_fixed_roundtrip(parser)
    assert_host_untouched()


def test_manifest_structure_does_not_alias_host() -> None:
    module = manifest.compile_xml(GUID, manifest_xml())
    assert module.ManifestStructure.__dict__["_calc_offsets"] is not Structure.__dict__.get("_calc_offsets")

    module.ManifestStructure._calc_offsets = staticmethod(lambda _: "local")
    assert module.ManifestStructure._calc_offsets(None) == "local"
    assert_host_untouched()
