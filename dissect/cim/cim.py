# Heavily inspired from https://github.com/fireeye/flare-wmi
#
# Information about e.g. data structures can also be found in:
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wmio/b44d0581-5bd3-40fc-95d7-01c1b1239820

from __future__ import annotations

from functools import cached_property
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.cim.c_cim import (
    ARRAY_STATES,
    CIM_TYPES,
    NAMESPACE_CLASS_NAME,
    ROOT_NAMESPACE_NAME,
    SYSTEM_NAMESPACE_NAME,
    c_cim,
)
from dissect.cim.classes import (
    ClassDefinition,
    ClassInstance,
    PropertyDefaultValues,
)
from dissect.cim.exceptions import (
    AmbiguousInstanceError,
    Error,
    InstanceNotFoundError,
    InvalidDatabaseError,
    InvalidInstancePathError,
    ObjectPathSyntaxError,
    UnsupportedHostError,
)
from dissect.cim.index import Index, Key
from dissect.cim.mappings import Mapping
from dissect.cim.objects import Objects
from dissect.cim.utils import (
    find_current_mapping,
    parse_hostname,
    parse_instance_keys,
    parse_object_path,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.cim.c_cim import (
        CimType,
    )
    from dissect.cim.classes import (
        ClassDefinitionProperty,
        ClassInstanceProperty,
        InstanceKey,
        Qualifier,
    )
    from dissect.cstruct import BaseType


class CIM:
    """Common Information Model."""

    def __init__(self, index: BinaryIO, objects: BinaryIO, mappings: list[BinaryIO]):
        self._findex = index
        self._fobjects = objects
        self._fmappings = mappings

        if not len(mappings):
            raise Error("No mappings")

        self.type_xp, self._current_map = find_current_mapping(self._fmappings)

        if not self._current_map:
            raise Error("Couldn't find current map file")

        if self.type_xp:
            self._map_header = c_cim.mapping_header_xp
            self._map_type = c_cim.mapping_xp
        else:
            self._map_header = c_cim.mapping_header
            self._map_type = c_cim.mapping
        self.map_type = self._map_type

        self.objects = Objects(self, objects, Mapping(self, self._current_map))

        # In some Windows 10 mappings, the index mapping doesn't seem to have a footer signature (0xdcba)
        # However, the objects mapping still has it, so we just read it here and check it
        footer_signature = c_cim.uint32(self._current_map)
        if footer_signature != 0xDCBA:
            raise Error("Invalid footer signature in objects mapping")

        try:
            self.index = Index(self, index, Mapping(self, self._current_map))
        except EOFError:
            raise InvalidDatabaseError("Invalid CIM database, possibly corrupt")

        self.root = self.namespace(ROOT_NAMESPACE_NAME)
        self.system = self.namespace(SYSTEM_NAMESPACE_NAME)

    @classmethod
    def from_directory(cls, path: Path | str) -> CIM:
        if not isinstance(path, Path):
            path = Path(path)

        path = path.resolve()
        if not path.is_dir():
            raise ValueError(f"Path {path} is not a directory")

        findex = path.joinpath("INDEX.BTR").open("rb")
        fobjects = path.joinpath("OBJECTS.DATA").open("rb")
        fmappings = [path.joinpath(f"MAPPING{i}.MAP").open("rb") for i in range(1, 4)]

        return cls(findex, fobjects, fmappings)

    def key(self, *args) -> Key:
        return Key(self, *args)

    def query(self, path: str, ns: Namespace | None = None) -> Namespace | Class | Instance:
        """Query an object path.

        Supports relative and absolute local object paths, namespaces, classes
        and instances. Instance keys are punctuation-aware, so key values that
        contain commas, equals signs, quotes or backslashes are matched exactly.

        Paths pointing at a remote host are parsed but not queried: this method
        raises :class:`UnsupportedHostError` and never performs network I/O.

        Args:
            path: Textual object path.
            ns: Namespace to resolve relative paths against.

        Raises:
            ObjectPathSyntaxError: If the path is malformed.
            UnsupportedHostError: If the path refers to a remote host.
            InstanceNotFoundError: If an instance path does not match.
            AmbiguousInstanceError: If an instance path matches more than once.
        """
        if ns is not None and not isinstance(ns, Namespace):
            raise TypeError("namespace should be an instance of Namespace")

        hostname = parse_hostname(path)
        if hostname is not None and hostname not in ("localhost", "."):
            raise UnsupportedHostError(
                f"Unsupported hostname {hostname!r}: only local object paths are supported"
            )

        object_path = parse_object_path(path, ns)

        if object_path.hostname != "localhost":
            raise UnsupportedHostError(
                f"Unsupported hostname {object_path.hostname!r}: only local object paths are supported"
            )

        if not object_path.namespace:
            raise ObjectPathSyntaxError(f"Invalid ObjectPath: {object_path!r}", path, 0)

        obj = self.namespace(object_path.namespace)

        if object_path.class_:
            obj = obj.class_(object_path.class_)

        if object_path.instance:
            obj = obj.instance(object_path.instance)

        return obj

    def namespace(self, name: str) -> Namespace:
        return Namespace(self, name)

    def _parse_instance(self, class_: Class, buf: BytesIO) -> ClassInstance:
        return ClassInstance(self, class_, buf)

    def get_class_definition(self, q: Key) -> ClassDefinition:
        if not q.reference():
            q = self.key().NS(SYSTEM_NAMESPACE_NAME).CD(q["CD"])
        return ClassDefinition(self, q.object())

    def get_class_instance(self, class_: Class, q: Key) -> ClassInstance:
        return self._parse_instance(class_, q.object())


class Namespace:
    def __init__(self, cim: CIM, name: str, class_instance: ClassInstance | None = None):
        self.cim = cim
        self.name = name
        self.class_instance = class_instance

    def __repr__(self) -> str:
        return f"<Namespace {self.name}>"

    def query(self, path: str) -> Namespace | Class | Instance:
        return self.cim.query(path, self)

    @property
    def ci(self) -> ClassInstance | None:
        return self.class_instance

    def parent(self) -> Namespace:
        raise NotImplementedError

    def class_(self, class_name: str) -> Class:
        q = self.cim.key().NS(self.name).CD(class_name)
        class_def = self.cim.get_class_definition(q)

        return Class(self.cim, self, class_def)

    @property
    def classes(self) -> Iterator[Class]:
        yielded = set()

        if self.name != SYSTEM_NAMESPACE_NAME:
            for class_ in self.cim.system.classes:
                class_.namespace = self
                if class_.name not in yielded:
                    yield class_
                    yielded.add(class_.name)

        q = self.cim.key().NS(self.name).CD()
        for ref in q.references():
            class_def = self.cim.get_class_definition(ref)
            class_ = Class(self.cim, self, class_def)

            if class_.name not in yielded:
                yield class_
                yielded.add(class_.name)

    def namespace(self, name: str) -> Namespace:
        main_name = f"{self.name}\\{name}".lower()
        for ns in self.namespaces:
            if ns.name.lower() == main_name:
                return ns

        raise IndexError

    @property
    def namespaces(self) -> Iterator[Namespace]:
        yielded = set()

        q = self.cim.key().NS(self.name).CI(NAMESPACE_CLASS_NAME).IL()
        class_def = self.cim.system.class_(NAMESPACE_CLASS_NAME)

        for ref in q.references():
            class_instance = self.cim.get_class_instance(class_def, ref)
            ns = Namespace(self.cim, f"{self.name}\\{class_instance.properties['Name'].value}", class_instance)

            if ns.name not in yielded:
                yield ns
                yielded.add(ns)

        if self.name == ROOT_NAMESPACE_NAME:
            yield self.cim.system  # Why do this?


class Class:
    def __init__(self, cim: CIM, namespace: Namespace, class_definition: ClassDefinition):
        self.cim = cim
        self.namespace = namespace
        self.class_definition = class_definition

        self._properties = None

    def __getattr__(self, attr: str) -> Any:
        try:
            return getattr(self.class_definition, attr)
        except AttributeError:
            return object.__getattribute__(self, attr)

    @property
    def name(self) -> str:
        return self.class_definition.class_name

    @property
    def ns(self) -> Namespace:
        return self.namespace

    @property
    def cd(self) -> ClassDefinition:
        return self.class_definition

    @property
    def derivation(self) -> list[Class]:
        """List from root to leaf of class layouts."""
        derivation = []

        class_ = self
        while True:
            derivation.append(class_)
            super_class_name = class_.class_definition.super_class_name
            if super_class_name == "":
                break

            class_ = self.namespace.class_(super_class_name)

        derivation.reverse()
        return derivation

    @cached_property
    def properties(self) -> dict[str, Property]:
        props = {}
        for class_ in self.derivation:
            for prop in class_.class_definition.properties.values():
                props[prop.name] = Property(self, prop)
        return props

    @property
    def property_default_values(self) -> PropertyDefaultValues:
        props = self.properties.values()
        props = sorted(props, key=lambda p: p.index)
        return PropertyDefaultValues(BytesIO(self.class_definition.default_values_data), props)

    @property
    def properties_length(self) -> int:
        off = 0
        for prop in self.properties.values():
            if prop.type.array_state == ARRAY_STATES.ARRAY:
                off += 0x4
            else:
                off += len(prop.ctype)
        return off

    def instance(self, key: str | dict[str, Any]) -> Instance:
        """Return the instance with the given key.

        The key can be an :class:`InstanceKey`, a dictionary of key property
        names to values, or a textual ``key1=value1;key2=value2`` string. Lookup
        uses the instance index and compares the parsed key with the class's key
        properties, so values containing commas, equals signs, quotes or
        backslashes are matched exactly.

        Raises:
            InstanceNotFoundError: If no instance matches the key.
            AmbiguousInstanceError: If more than one instance matches the key.
        """
        candidates = self._instances_for_key(key)
        if not candidates:
            raise InstanceNotFoundError(f"No instance of {self.name} with key {key!r}")
        if len(candidates) > 1:
            raise AmbiguousInstanceError(f"Multiple instances of {self.name} match key {key!r}")
        return candidates[0]

    def _instances_for_key(self, key: str | dict[str, Any]) -> list[Instance]:
        key_values = self._normalize_key(key)
        key_names = self.class_definition.keys
        if not key_names:
            raise InstanceNotFoundError(f"Class {self.name} has no key properties")

        canonical = {name.lower(): name for name in key_names}
        normalized = {}
        for name, value in key_values.items():
            canonical_name = canonical.get(name.lower())
            if canonical_name is None:
                raise InstanceNotFoundError(f"Unknown key property {name!r} for {self.name}")
            normalized[canonical_name] = value

        missing = [name for name in key_names if name not in normalized]
        if missing:
            raise InstanceNotFoundError(f"Missing key properties for {self.name}: {', '.join(missing)}")

        typed = {}
        for name in key_names:
            prop = self.properties[name]
            typed[name] = _coerce_key_value(prop, normalized[name])

        lookup_key = self.cim.key().NS(self.namespace.name).CI(self.name).IL(typed)
        found = []
        for ref in lookup_key.references():
            try:
                class_instance = self.cim.get_class_instance(self, ref)
            except (Error, IndexError, ValueError):
                continue

            if _instance_matches(class_instance, typed):
                found.append(Instance(self.cim, self.namespace, self, class_instance))

        return found

    def _normalize_key(self, key: str | dict[str, Any]) -> dict[str, Any]:
        if isinstance(key, str):
            key = parse_instance_keys(key, key, 0)
        elif not isinstance(key, dict):
            raise TypeError("key must be a string or dictionary")

        return dict(key)

    @property
    def instances(self) -> Iterator[Instance]:
        yielded = set()

        q = self.cim.key().NS(self.namespace.name).CI(self.name).IL()

        for ref in q.references():
            class_instance = self.cim.get_class_instance(self, ref)
            instance = Instance(self.cim, self.namespace, self, class_instance)
            ikey = str(instance.key)

            if ikey not in yielded:
                yield instance
                yielded.add(ikey)


class Instance:
    def __init__(self, cim: CIM, namespace: Namespace, class_: Class, class_instance: ClassInstance):
        self.cim = cim
        self.namespace = namespace
        self.class_ = class_
        self.class_definition = class_.class_definition
        self.class_instance = class_instance

    def __repr__(self) -> str:
        return f"<Instance {self.class_.name} {self.key}>"

    def __str__(self) -> str:
        return f"{self.namespace.name}:{self.class_.name}.{self.key}"

    @property
    def key(self) -> InstanceKey:
        return self.class_instance.key

    @property
    def name(self) -> str:
        return self.class_instance.class_name

    @property
    def ns(self) -> Namespace:
        return self.namespace

    @property
    def cd(self) -> ClassDefinition:
        return self.class_definition

    @property
    def ci(self) -> ClassInstance:
        return self.class_instance

    @property
    def properties(self) -> dict[str, ClassInstanceProperty]:
        return self.class_instance.properties


def _coerce_key_value(prop: Property, value: Any) -> Any:
    """Coerce a textual key value to the type of its key property."""
    type_ = prop.type.type

    if type_ == CIM_TYPES.BOOLEAN:
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.lower() in ("true", "false"):
            return value.lower() == "true"
        raise InvalidInstancePathError(f"Invalid boolean value {value!r} for key {prop.name!r}")

    if type_ in (
        CIM_TYPES.INT8,
        CIM_TYPES.UINT8,
        CIM_TYPES.INT16,
        CIM_TYPES.UINT16,
        CIM_TYPES.INT32,
        CIM_TYPES.UINT32,
        CIM_TYPES.INT64,
        CIM_TYPES.UINT64,
    ):
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        try:
            return int(value, 0)
        except (TypeError, ValueError):
            raise InvalidInstancePathError(f"Invalid integer value {value!r} for key {prop.name!r}")

    if type_ in (CIM_TYPES.REAL32, CIM_TYPES.REAL64):
        if isinstance(value, float):
            return value
        try:
            return float(value)
        except (TypeError, ValueError):
            raise InvalidInstancePathError(f"Invalid real value {value!r} for key {prop.name!r}")

    if isinstance(value, str):
        return value
    raise InvalidInstancePathError(f"Invalid value {value!r} for key {prop.name!r}")


def _instance_matches(class_instance: ClassInstance, expected: dict[str, Any]) -> bool:
    """Compare the key of a parsed class instance with the expected key."""
    try:
        actual = class_instance.key
    except (Error, IndexError, ValueError):
        return False

    if set(actual) != set(expected):
        return False

    return all(_key_value_matches(actual[name], value) for name, value in expected.items())


def _key_value_matches(actual: Any, expected: Any) -> bool:
    if isinstance(expected, bool) or isinstance(actual, bool):
        return bool(actual) == bool(expected)

    if isinstance(expected, float) or isinstance(actual, float):
        return float(actual) == float(expected)

    return actual == expected


class Property:
    def __init__(self, class_: Class, prop: ClassDefinitionProperty):
        self.class_ = class_
        self._prop = prop

    @property
    def type(self) -> c_cim.cim_type:
        return self._prop.type

    @property
    def ctype(self) -> BaseType:
        return self._prop.ctype

    @property
    def qualifiers(self) -> dict[str, Qualifier]:
        return self._prop.qualifiers

    @property
    def name(self) -> str:
        return self._prop.name

    @property
    def index(self) -> int:
        return self._prop.index

    @property
    def offset(self) -> int:
        return self._prop.offset

    @property
    def level(self) -> int:
        return self._prop.level

    @property
    def is_inherited(self) -> bool:
        return self.class_.property_default_values.state[self.index].is_inherited

    @property
    def has_default_value(self) -> bool:
        return self.class_.property_default_values.state[self.index].has_default_value

    @property
    def default_value(self) -> CimType | list[CimType]:
        if not self.has_default_value:
            raise ValueError("Property has no default value!")

        if not self.is_inherited:
            # then the data is stored nicely in the CD prop data section
            v = self.class_.property_default_values.default_values[self.index]
            return self.class_.class_definition.property_data.get_value(v, self.type)

        # we have to walk up the derivation path looking for the default value
        rderivation = self.class_.derivation[:]
        rderivation.reverse()

        for ancestor_cl in rderivation:
            defaults = ancestor_cl.property_default_values
            state = defaults.state[self.index]
            if not state.has_default_value:
                raise Error("Property with inherited default value has bad ancestor (no default value)")

            if state.is_inherited:
                # keep trucking! look further up the ancestry tree.
                continue

            # else, this must be where the default value is defined
            v = defaults.default_values[self.index]
            return ancestor_cl.class_definition.property_data.get_value(v, self.type)

        raise Error("Unable to find ancestor class with default value")
