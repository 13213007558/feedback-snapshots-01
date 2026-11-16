from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from dissect.cim.cim import Class, Instance, Namespace, keys_match
from dissect.cim.utils import parse_object_path

if TYPE_CHECKING:
    from dissect.cim.cim import CIM
    from dissect.cim.classes import ClassInstance
    from dissect.cim.index import Key


@dataclass
class BatchResult:
    """Outcome of a single path in a :meth:`CIM.query_many` call.

    ``value`` is the resolved namespace, class or instance when ``ok`` is true,
    otherwise ``error`` holds the exception raised while resolving exactly this
    path. Results stay independent: one bad reference never changes the others.
    """

    path: str
    ok: bool
    value: Any = None
    error: Exception | None = None


class BatchResolver:
    """Resolves a batch of object paths while sharing read-only parse facts.

    All caches are local to one batch and to a single :class:`CIM` (mapping view).
    Distinct references are never merged into one answer; only identical references
    and class layouts are reused as read-only facts.
    """

    def __init__(self, cim: CIM, base_namespace: Namespace | None):
        self.cim = cim
        self.base_namespace = base_namespace

        self._instance_maps: dict[tuple[str, str], dict[Any, Key]] = {}
        self._instances: dict[tuple[str, str], ClassInstance] = {}
        self._bad_references: dict[str, Exception] = {}

    def resolve(self, paths: list[str]) -> list[BatchResult]:
        return [self._resolve_one(path) for path in paths]

    def _resolve_one(self, path: str) -> BatchResult:
        try:
            value = self._query(path)
        except Exception as e:  # noqa: BLE001 - failures stay isolated per input path
            return BatchResult(path=path, ok=False, error=e)
        return BatchResult(path=path, ok=True, value=value)

    def _query(self, path: str) -> Any:
        object_path = parse_object_path(path, self.base_namespace)

        if object_path.hostname != "localhost":
            raise ValueError(f"Unsupported hostname: {object_path.hostname}")
        if not object_path.namespace:
            raise ValueError(f"Invalid ObjectPath: {object_path}")

        obj: Any = self.cim.namespace(object_path.namespace)

        if object_path.class_:
            obj = obj.class_(object_path.class_)

        if object_path.instance:
            obj = self._instance(obj, object_path.instance)

        return obj

    def _instance(self, class_: Class, requested: dict[str, str]) -> Instance:
        instance_map = self._instance_map(class_)
        matched_key = self._match_key(instance_map, requested)
        if matched_key is None:
            raise IndexError(requested)

        class_instance = self._parse_instance(class_, instance_map[matched_key])
        return Instance(self.cim, class_.namespace, class_, class_instance)

    @staticmethod
    def _match_key(instance_map: dict[Any, Key], requested: dict[str, str]) -> Any:
        for instance_key in instance_map:
            if keys_match(instance_key, requested):
                return instance_key
        return None

    def _instance_map(self, class_: Class) -> dict[Any, Key]:
        layout_key = (class_.namespace.name.lower(), class_.name.lower())
        instance_map = self._instance_maps.get(layout_key)
        if instance_map is not None:
            return instance_map

        q = self.cim.key().NS(class_.namespace.name).CI(class_.name).IL()

        instance_map = {}
        seen: set[str] = set()
        for ref in q.references():
            # A corrupt object only drops that one reference; the remaining objects
            # for this class are still mapped and keep returning their own results.
            try:
                class_instance = self._parse_instance(class_, ref)
            except Exception as e:  # noqa: BLE001 - isolate a single bad reference
                self._bad_references[str(ref)] = e
                continue

            key = class_instance.key
            # Mirror Class.instances: keep the first occurrence of a duplicated key.
            key_str = str(key)
            if key_str not in seen:
                seen.add(key_str)
                instance_map[key] = ref

        self._instance_maps[layout_key] = instance_map
        return instance_map

    def _parse_instance(self, class_: Class, ref: Key) -> ClassInstance:
        cache_key = (str(class_.class_definition), str(ref))
        class_instance = self._instances.get(cache_key)
        if class_instance is None:
            class_instance = self.cim._parse_instance(class_, self.cim.objects.get(ref))
            self._instances[cache_key] = class_instance
        return class_instance
