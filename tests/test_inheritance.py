from __future__ import annotations

from io import BytesIO

import pytest

from dissect.cim.c_cim import (
    ARRAY_STATES,
    BOOLEAN_STATES,
    CIM_TYPES,
    CIM_TYPES_MAP,
    ClassDefinitionPropertyState,
    ClassInstancePropertyState,
    c_cim,
)
from dissect.cim.classes import (
    ClassInstance,
    PropertyDefaultValues,
    PropertyStates,
    PropertyValueOrigin,
)
from dissect.cim.exceptions import InheritanceError

# --------------------------------------------------------------------------- #
# Tiny, hand-built class model
#
# Three derivation layers are used:
#
#   Base          (level 1): BaseOnly, Shared        (base default on Shared)
#   Middle(Base)  (level 2): MidOnly, Toggle
#   Leaf(Middle)  (level 3): LeafOnly, Nullable, GapProp
#
# Properties are identified by their *global* index across the merged layout.
# Indices are contiguous, mirroring real repositories; the point is that the
# reader keys state flags and TOC entries by that real index instead of relying
# on a compacted positional list, so entries can never be shifted onto a
# neighbouring property.
# --------------------------------------------------------------------------- #


class FakeType:
    def __init__(self, cim_type: CIM_TYPES, array_state: ARRAY_STATES = ARRAY_STATES.NOT_ARRAY):
        self.type = cim_type
        self.array_state = array_state


class FakeProperty:
    """Mimics the surface of classes.Property used by ClassInstance."""

    def __init__(
        self,
        name: str,
        index: int,
        offset: int,
        level: int,
        cim_type: CIM_TYPES,
        array_state: ARRAY_STATES = ARRAY_STATES.NOT_ARRAY,
    ):
        self.name = name
        self.index = index
        self.offset = offset
        self.level = level
        self.type = FakeType(cim_type, array_state)
        self.ctype = c_cim.uint32 if array_state == ARRAY_STATES.ARRAY else CIM_TYPES_MAP[cim_type]
        self.qualifiers = {}
        self.is_inherited = False
        self.has_default_value = False
        self._default_value = None

    @property
    def default_value(self):
        if not self.has_default_value:
            raise ValueError("Property has no default value!")
        return self._default_value


class FakeClass:
    def __init__(self, name: str, properties: dict[str, FakeProperty]):
        self.name = name
        self._properties = properties

    @property
    def properties(self) -> dict[str, FakeProperty]:
        return self._properties


class FakeCim:
    type_xp = False


def _inst_field(initialized: bool, use_default: bool) -> int:
    bit0 = 0 if initialized else 1
    bit1 = 1 if use_default else 0
    return (bit1 << 1) | bit0


def _def_field(is_inherited: bool, has_default: bool) -> int:
    bit1 = 1 if is_inherited else 0
    bit0 = 0 if has_default else 1
    return (bit1 << 1) | bit0


def _state_byte_count(count: int) -> int:
    required_bits = 2 * count
    return (required_bits + 7) // 8


def _pack_states(fields: dict[int, int], count: int) -> bytes:
    packed = 0
    for idx, field in fields.items():
        packed |= field << (2 * idx)
    return packed.to_bytes(_state_byte_count(count), "little")


def _latin1_string(value: str) -> bytes:
    return b"\x00" + value.encode("latin1") + b"\x00"


class ThreeTierLayout:
    """Assembled global (leaf) layout and its expected provenance.

    Global indices are contiguous, exactly as on real WMI repositories. The
    point under test is that the reader keys the TOC and state flags by the
    property's real global index rather than relying on a compacted positional
    list, so the entries can never be shifted onto the wrong neighbour.
    """

    def __init__(self):
        # global index -> property
        self.props: dict[int, FakeProperty] = {}

        def add(prop: FakeProperty) -> FakeProperty:
            self.props[prop.index] = prop
            return prop

        # Base layer (level 1)
        add(FakeProperty("BaseOnly", 0, 0, 1, CIM_TYPES.STRING))
        add(FakeProperty("Shared", 1, 4, 1, CIM_TYPES.UINT32))
        # Middle layer (level 2)
        add(FakeProperty("MidOnly", 2, 8, 2, CIM_TYPES.STRING))
        add(FakeProperty("Toggle", 3, 12, 2, CIM_TYPES.BOOLEAN))
        # Leaf layer (level 3)
        add(FakeProperty("LeafOnly", 4, 14, 3, CIM_TYPES.STRING))
        add(FakeProperty("Nullable", 5, 18, 3, CIM_TYPES.STRING))
        add(FakeProperty("GapProp", 6, 22, 3, CIM_TYPES.UINT32))

        self.leaf = FakeClass("LeafConsumer", {p.name: p for p in self.props.values()})

        # Base layer defines a default for Shared (global index 1) which the
        # leaf instance can point at through the use-default state.
        shared = self.props[1]
        shared.has_default_value = True
        shared.is_inherited = False
        shared._default_value = 100

    @property
    def ordered(self) -> list[FakeProperty]:
        return [self.props[i] for i in sorted(self.props)]

    @property
    def state_count(self) -> int:
        return len(self.props)

    def build_instance(
        self,
        instance_states: dict[int, int],
        toc_values: dict[int, object],
        data_strings: dict[int, str],
        residual: bytes = b"",
    ) -> ClassInstance:
        props = self.ordered
        count = self.state_count

        body = BytesIO()

        # Build the data region first so reference-type TOC entries can carry
        # the real offsets into it. The class name lives at offset 0.
        region = BytesIO()
        region.write(_latin1_string("LeafConsumer"))
        string_offsets: dict[int, int] = {}
        for prop in props:
            if prop.type.type in (CIM_TYPES.STRING, CIM_TYPES.REFERENCE, CIM_TYPES.DATETIME):
                string_offsets[prop.index] = len(region.getvalue())
                region.write(_latin1_string(data_strings.get(prop.index, "")))
        region_bytes = region.getvalue()

        # 1) per-property state flags, indexed by global property index
        body.write(_pack_states(instance_states, count))

        # 2) TOC, one fixed-size entry per property, written in global-index
        # order; the reader looks entries up by index, not list position.
        for prop in props:
            if prop.type.type in (CIM_TYPES.STRING, CIM_TYPES.REFERENCE, CIM_TYPES.DATETIME):
                entry = string_offsets[prop.index]
            else:
                entry = toc_values.get(prop.index, 0)
                if prop.type.type == CIM_TYPES.BOOLEAN:
                    entry = BOOLEAN_STATES.TRUE if entry else BOOLEAN_STATES.FALSE
            body.write(prop.ctype.dumps(entry))

        # 3) no qualifier references, no dynamic properties
        body.write(c_cim.uint32.dumps(0))  # empty qualifier reference list
        body.write(bytes([0x1]))  # DYNPROPS_STATES.NO_DYNPROPS

        # 4) data region
        body.write(c_cim.uint32.dumps(len(region_bytes)))
        body.write(region_bytes)

        # 5) bytes the parser cannot explain; must be retained verbatim
        body.write(residual)

        header = c_cim.class_instance_header(
            name_hash="\x00" * 0x40,
            ts1=0,
            ts2=0,
            data_size=len(body.getvalue()) + 9,
            class_name_offset=0,
            unk0=0,
            remaining_data=body.getvalue(),
        )
        fh = BytesIO(header.dumps())
        return ClassInstance(FakeCim(), self.leaf, fh)


@pytest.fixture()
def layout() -> ThreeTierLayout:
    return ThreeTierLayout()


# --------------------------------------------------------------------------- #
# PropertyStates bit packing / boundaries
# --------------------------------------------------------------------------- #


def test_property_states_packing_and_boundaries() -> None:
    raw = _pack_states(
        {
            0: _inst_field(True, False),
            1: _inst_field(True, True),
            2: _inst_field(False, False),
            3: _inst_field(True, False),
        },
        4,
    )
    states = PropertyStates(BytesIO(raw), ClassInstancePropertyState, 4)
    assert states[0].is_initialized is True
    assert states[0].use_default_value is False
    assert states[1].is_initialized is True
    assert states[1].use_default_value is True
    assert states[2].is_initialized is False
    assert states[3].is_initialized is True
    assert len(states) == 4

    for bad in (-1, 4, 5):
        with pytest.raises(IndexError):
            states[bad]


def test_definition_states_bit_semantics() -> None:
    raw = _pack_states(
        {
            0: _def_field(is_inherited=True, has_default=False),
            1: _def_field(is_inherited=False, has_default=True),
            2: _def_field(is_inherited=False, has_default=False),
        },
        3,
    )
    states = PropertyStates(BytesIO(raw), ClassDefinitionPropertyState, 3)
    assert states[0].is_inherited is True
    assert states[0].has_default_value is False
    assert states[1].is_inherited is False
    assert states[1].has_default_value is True
    assert states[2].has_default_value is False


# --------------------------------------------------------------------------- #
# PropertyDefaultValues must follow the real global index, never compact
# --------------------------------------------------------------------------- #


def test_default_values_indexed_by_global_index() -> None:
    # Two properties whose global indices differ from their position in the
    # sorted input order. Default values are stored on disk in that order but
    # must be retrievable through the real global index.
    p1 = FakeProperty("A", 3, 0, 1, CIM_TYPES.UINT32)
    p2 = FakeProperty("B", 7, 4, 2, CIM_TYPES.UINT32)
    props = sorted([p1, p2], key=lambda p: p.index)
    state_fields = {
        3: _def_field(False, True),
        7: _def_field(False, True),
    }
    # PropertyStates is sized by property count; pack only the two slots.
    state_raw = _pack_states({0: state_fields[3], 1: state_fields[7]}, count=2)
    buf = BytesIO(state_raw + c_cim.uint32.dumps(11) + c_cim.uint32.dumps(22))
    pdv = PropertyDefaultValues(buf, props)
    assert pdv.default_values[3] == 11
    assert pdv.default_values[7] == 22
    # a compacted positional list would expose these at 0 and 1 instead
    with pytest.raises(KeyError):
        pdv.default_values[0]
    with pytest.raises(KeyError):
        pdv.default_values[1]


# --------------------------------------------------------------------------- #
# End-to-end instance provenance across the three-layer fixture
# --------------------------------------------------------------------------- #


def test_instance_provenance_three_tiers(layout: ThreeTierLayout) -> None:
    states = {
        # BaseOnly: instance stores its own string
        0: _inst_field(True, False),
        # Shared: instance uses the inherited class default (100)
        1: _inst_field(True, True),
        # MidOnly: explicit NULL (initialized, own value, empty string)
        2: _inst_field(True, False),
        # Toggle: uninitialized
        3: _inst_field(False, False),
        # LeafOnly: own string value
        4: _inst_field(True, False),
        # Nullable: explicit NULL string
        5: _inst_field(True, False),
        # GapProp: own inline scalar, looked up by its real index
        6: _inst_field(True, False),
    }
    # Scalar TOC values (literals); reference-type entries are filled with the
    # real data-region offsets by the builder.
    toc = {
        6: 777,  # inline uint32 literal
    }
    strings = {
        0: "base-value",
        2: "",  # explicit NULL
        4: "leaf-value",
        5: "",  # explicit NULL
    }
    ci = layout.build_instance(states, toc, strings, residual=b"UNEXPLAINED")
    props = ci.properties

    # TOC keyed by real global index for every merged property
    assert set(ci.toc) == {0, 1, 2, 3, 4, 5, 6}
    assert ci.toc[6] == 777

    # INSTANCE storage
    assert props["BaseOnly"].origin == PropertyValueOrigin.INSTANCE
    assert props["BaseOnly"].value == "base-value"
    assert props["LeafOnly"].origin == PropertyValueOrigin.INSTANCE
    assert props["LeafOnly"].value == "leaf-value"
    assert props["GapProp"].origin == PropertyValueOrigin.INSTANCE
    assert props["GapProp"].value == 777

    # INHERITED DEFAULT (base class default, not instance storage)
    assert props["Shared"].origin == PropertyValueOrigin.DEFAULT
    assert props["Shared"].value == 100
    assert props["Shared"].is_default_value is True

    # EXPLICIT NULL (distinct from uninitialized); value stays faithful to the
    # on-disk empty string while provenance marks it as NULL.
    assert props["MidOnly"].origin == PropertyValueOrigin.NULL
    assert props["MidOnly"].value == ""
    assert props["Nullable"].origin == PropertyValueOrigin.NULL
    assert props["Nullable"].value == ""

    # UNINITIALIZED
    assert props["Toggle"].origin == PropertyValueOrigin.UNINITIALIZED
    assert props["Toggle"].is_initialized is False
    with pytest.raises(ValueError, match="not initialized"):
        props["Toggle"].value

    # NONEXISTENT name does not borrow an adjacent field
    missing = ci.nonexistent_property("Ghost")
    assert missing.origin == PropertyValueOrigin.NONEXISTENT
    with pytest.raises(ValueError, match="does not exist"):
        missing.value

    # unexplained raw bytes are preserved
    assert ci.residual_data == b"UNEXPLAINED"


def test_instance_default_value_does_not_use_toc(layout: ThreeTierLayout) -> None:
    # Even when a stale/garbage TOC entry exists, a defaulted property must
    # resolve from the class default rather than instance storage.
    layout.props[1].has_default_value = True
    layout.props[1]._default_value = 555
    states = {1: _inst_field(True, True)}
    ci = layout.build_instance(states, {1: 0xDEADBEEF}, {})
    prop = ci.properties["Shared"]
    assert prop.origin == PropertyValueOrigin.DEFAULT
    assert prop.is_default_value is True
    assert prop.value == 555


def test_toc_lookup_uses_real_index_not_position(layout: ThreeTierLayout) -> None:
    # Only GapProp (the last property, index 6) holds an own value. The state
    # flags and TOC entry must be read at index 6 instead of being shifted to a
    # lower positional slot, and every other property must stay uninitialized.
    states = {idx: _inst_field(idx == 6, False) for idx in layout.props}
    ci = layout.build_instance(states, {6: 4242}, {})
    assert ci.property_states[6].is_initialized is True
    assert ci.toc[6] == 4242
    assert ci.properties["GapProp"].value == 4242
    for idx, prop in layout.props.items():
        if idx == 6:
            continue
        assert ci.properties[prop.name].origin == PropertyValueOrigin.UNINITIALIZED


# --------------------------------------------------------------------------- #
# Inheritance chain errors (exercise the real Class.derivation)
# --------------------------------------------------------------------------- #


class _FakeDefinition:
    def __init__(self, name: str, super_class_name: str):
        self.class_name = name
        self.super_class_name = super_class_name
        self.properties = {}
        self.keys = []


class _FakeNamespace:
    def __init__(self, chain: dict[str, str], available: set[str] | None = None):
        self.chain = chain
        self.available = available if available is not None else set(chain)

    def class_(self, name: str):
        if name not in self.available:
            raise IndexError(name)
        from dissect.cim.cim import Class

        return Class(cim=None, namespace=self, class_definition=_FakeDefinition(name, self.chain[name]))


def _make_class(name: str, super_name: str, namespace: _FakeNamespace):
    from dissect.cim.cim import Class

    return Class(cim=None, namespace=namespace, class_definition=_FakeDefinition(name, super_name))


def test_derivation_detects_cycle() -> None:
    ns = _FakeNamespace({"A": "B", "B": "A"})
    leaf = _make_class("A", "B", ns)
    with pytest.raises(InheritanceError) as exc:
        _ = leaf.derivation
    assert exc.value.class_name in {"A", "B"}


def test_derivation_missing_base_class() -> None:
    ns = _FakeNamespace({"A": "B"}, available={"A"})  # B referenced but unresolvable
    leaf = _make_class("A", "B", ns)
    with pytest.raises(InheritanceError) as exc:
        _ = leaf.derivation
    assert exc.value.super_class_name == "B"
    assert exc.value.class_name == "A"


def test_derivation_root_to_leaf_order() -> None:
    ns = _FakeNamespace({"Root": "", "Mid": "Root", "Leaf": "Mid"})
    leaf = _make_class("Leaf", "Mid", ns)
    assert [c.name for c in leaf.derivation] == ["Root", "Mid", "Leaf"]


class _OverrideNamespace:
    """Namespace whose class definitions each expose a small own-property map."""

    def __init__(self, definitions: dict[str, _FakeDefinition]):
        self._definitions = definitions

    def class_(self, name: str):
        from dissect.cim.cim import Class

        return Class(cim=None, namespace=self, class_definition=self._definitions[name])


class _OverrideDefinition(_FakeDefinition):
    def __init__(self, name: str, super_class_name: str, own_properties: dict[str, object]):
        super().__init__(name, super_class_name)
        self.properties = own_properties
        self.default_values_data = b""


def test_same_name_override_uses_derived_property() -> None:
    # "Shared" exists on every layer with the same global index but distinct
    # level markers. The merged leaf layout must keep only the leaf's version.
    base_shared = FakeProperty("Shared", 1, 4, 1, CIM_TYPES.UINT32)
    mid_shared = FakeProperty("Shared", 1, 4, 2, CIM_TYPES.UINT32)
    leaf_shared = FakeProperty("Shared", 1, 4, 3, CIM_TYPES.UINT32)
    leaf_own = FakeProperty("LeafOnly", 2, 8, 3, CIM_TYPES.STRING)

    definitions = {
        "Root": _OverrideDefinition("Root", "", {"Shared": base_shared}),
        "Mid": _OverrideDefinition("Mid", "Root", {"Shared": mid_shared}),
        "Leaf": _OverrideDefinition("Leaf", "Mid", {"Shared": leaf_shared, "LeafOnly": leaf_own}),
    }
    ns = _OverrideNamespace(definitions)
    leaf = ns.class_("Leaf")

    merged = leaf.properties
    assert set(merged) == {"Shared", "LeafOnly"}
    # derived (level 3) definition shadows the base and middle ones
    assert merged["Shared"].level == 3
    assert merged["Shared"].index == 1
    assert merged["LeafOnly"].level == 3

