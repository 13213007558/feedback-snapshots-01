"""Offline diagnosis of same-GUID / different-manifest conflicts in dissect.etl.

The module never touches the network or the real package resources. Instead it redirects
:func:`dissect.etl.manifest.get_resource_string` at in-memory collector repositories, drives the
genuine :func:`dissect.etl.manifest.lookup` / :func:`dissect.etl.etl.parse_payload` code path and
records exactly where a chosen manifest enters the parsing chain.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import patch
from uuid import UUID

from dissect.etl import manifest
from dissect.etl.etl import ETL
from dissect.etl.exceptions import ManifestNotFoundError

from .manifests import VARIANTS

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.etl.headers.headers import Header


@dataclass
class TraceLog:
    """Observed calls while resolving a manifest for a GUID."""

    cache_hits: list[UUID] = field(default_factory=list)
    resource_requests: list[str] = field(default_factory=list)
    compiled_sources: list[str] = field(default_factory=list)
    import_attempts: list[str] = field(default_factory=list)


class SourceRouter:
    """An in-memory stand-in for the ``manifests/xml`` resource directory.

    A single collector is active at any time, modelling one repository on the lookup path.
    :meth:`resource_string` raises :class:`IOError` for unknown GUIDs, exactly like the production
    :func:`dissect.etl.manifest.get_resource_string`, so ``lookup`` falls through as designed.
    """

    def __init__(self, sources: dict[str, dict[str, str]]):
        self._sources = sources
        self.active_collector: str | None = None
        self.trace = TraceLog()

    def use(self, collector: str) -> None:
        self.active_collector = collector

    def resource_string(self, path: str) -> str:
        self.trace.resource_requests.append(path)
        guid = Path(path).stem
        source = f"{self.active_collector}:{path}"
        if self.active_collector not in self._sources:
            raise IOError(f"unknown collector {self.active_collector}")
        if guid not in self._sources[self.active_collector]:
            raise IOError(f"Can't find resource {path}")
        self.trace.compiled_sources.append(source)
        return self._sources[self.active_collector][guid]

    def import_module(self, name: str) -> None:
        self.trace.import_attempts.append(name)
        raise ImportError(f"no precompiled module {name} (offline diagnosis)")


def repair_variable_type_bindings(module: object) -> list[str]:
    """Rebind the custom-width classmethods on a generated manifest module.

    cstruct's ``add_custom_type`` derives a new MetaType that does not retain the ``classmethod``
    binding of :class:`dissect.etl.manifest.CLASS_FMT`'s ``EtwPointer`` / ``UserSID_blob``. On the
    32-bit branch of :func:`dissect.etl.etl.parse_payload` this raises ``TypeError`` before a single
    payload field is read. The diagnosis uses fixed-width fields only, but the call is unconditional,
    so the bindings are repaired here purely to let the genuine parse chain run. This is a local
    shim around a pre-existing upstream defect, not a fix to the library.
    """
    repaired = []
    for type_name, width in (("EtwPointer", 4), ("UserSID_blob", 8)):
        custom_type = getattr(module.c_parser, type_name)
        if not isinstance(getattr(custom_type, "as_32bit", None), classmethod):
            custom_type.as_32bit = classmethod(lambda cls, width=width: setattr(cls, "size", width))
            repaired.append(type_name)
    return repaired


@contextlib.contextmanager
def instrumented_lookup(router: SourceRouter) -> Iterator[None]:
    """Route manifest resolution through ``router`` while recording every cache/resource step."""
    cache = manifest.CACHE

    def traced_lookup(guid: UUID):
        try:
            mod = cache[guid]
            router.trace.cache_hits.append(guid)
            return mod
        except KeyError:
            pass
        try:
            router.import_module(f"{manifest.MODPATH}.{{{guid}}}")
        except ImportError:
            pass
        try:
            mod = manifest.compile_xml(guid, router.resource_string(f"manifests/xml/{{{guid}}}.xml"))
        except IOError:
            pass
        else:
            repair_variable_type_bindings(mod)
            cache[guid] = mod
            return mod
        raise ManifestNotFoundError(guid)

    with patch.object(manifest, "lookup", traced_lookup), patch.object(manifest, "CACHE", cache):
        yield


@dataclass
class EventDiagnosis:
    """Everything an investigator can extract for one parsed provider event."""

    collector: str | None
    provider_guid: UUID
    descriptor: dict[str, object]
    manifest_origin: dict[str, object]
    layout: list[dict[str, object]]
    parsed_values: dict[str, object]
    payload_hex: str
    payload_size: int
    consumed_bytes: int
    unconsumed_bytes: int
    unconsumed_hex: str
    exception: str | None
    no_exception: bool


def _descriptor(header: Header) -> dict[str, object]:
    return {
        "marker": f"0x{header.marker:08x}",
        "header_type": type(header).__name__,
        "id": getattr(header, "Id", None),
        "version": header.version,
        "opcode": getattr(header, "opcode", None),
        "level": getattr(header, "Level", None),
        "channel": getattr(header, "Channel", None),
        "task": getattr(header, "Task", None),
        "keywords": getattr(header, "Keywords", None),
        "record_size": header.size,
        "payload_size": len(header.payload),
    }


def _layout(structure: object | None) -> list[dict[str, object]]:
    if structure is None:
        return []
    values = structure.__values__
    sizes = getattr(structure, "__sizes__", {})
    layout = []
    for name, value in values.items():
        field_size = sizes.get(name)
        layout.append({"field": name, "python_type": type(value).__name__, "value": value, "size": field_size})
    return layout


def diagnose_event(etl_blob: bytes, guid: UUID, router: SourceRouter, collector: str | None) -> EventDiagnosis:
    """Parse the single provider event in ``etl_blob`` against one active collector source."""
    router.trace = TraceLog()
    if collector is not None:
        router.use(collector)

    record = list(ETL(BytesIO(etl_blob)))[1]
    header = record.header
    descriptor = _descriptor(header)
    payload = bytes(header.payload)

    exception: Exception | None = None
    event = None
    try:
        with instrumented_lookup(router):
            event = record.event
    except Exception as exc:  # documented: record what escaped instead of pretending success
        exception = exc

    if event is None or event._manifest is None or event._struct is None:
        resolved_manifest = event._manifest if event is not None else None
        origin = {
            "cache_hit": bool(router.trace.cache_hits),
            "resource_requests": list(router.trace.resource_requests),
            "compiled_sources": list(router.trace.compiled_sources),
            "module_name": getattr(resolved_manifest, "__name__", None),
            "provider_name": event.provider_name() if event is not None else None,
            "event_symbol": None,
            "silent_path": "EVENTS[(opcode, version)] KeyError swallowed -> _struct=None"
            if resolved_manifest is not None
            else "no manifest resolved",
        }
        return EventDiagnosis(
            collector=collector,
            provider_guid=guid,
            descriptor=descriptor,
            manifest_origin=origin,
            layout=[],
            parsed_values={},
            payload_hex=payload.hex(),
            payload_size=len(payload),
            consumed_bytes=0,
            unconsumed_bytes=len(payload),
            unconsumed_hex=payload.hex(),
            exception=repr(exception) if exception else "silent-none (KeyError/ManifestNotFound swallowed)",
            no_exception=exception is None,
        )

    structure = event._struct
    consumed = len(structure) if structure is not None else 0
    unconsumed = len(payload) - consumed
    return EventDiagnosis(
        collector=collector,
        provider_guid=guid,
        descriptor=descriptor,
        manifest_origin={
            "cache_hit": bool(router.trace.cache_hits),
            "resource_requests": list(router.trace.resource_requests),
            "compiled_sources": list(router.trace.compiled_sources),
            "module_name": event._manifest.__name__,
            "provider_name": event.provider_name(),
            "event_symbol": event.symbol(),
            "binding_shim": "repaired EtwPointer/UserSID_blob as_32bit (upstream cstruct binding defect)",
        },
        layout=_layout(structure),
        parsed_values=dict(structure.__values__),
        payload_hex=payload.hex(),
        payload_size=len(payload),
        consumed_bytes=consumed,
        unconsumed_bytes=unconsumed,
        unconsumed_hex=payload[consumed:].hex(),
        exception=repr(exception) if exception else None,
        no_exception=exception is None,
    )


def build_router(guid: UUID) -> SourceRouter:
    """Compile every collector manifest once into an in-memory repository keyed by collector."""
    sources = {collector: {f"{{{guid}}}": factory(guid)} for collector, factory in VARIANTS.items()}
    return SourceRouter(sources)


def clear_cache() -> None:
    manifest.CACHE.clear()
