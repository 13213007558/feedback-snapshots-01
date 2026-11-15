from __future__ import annotations

from io import BytesIO

import pytest

from diagnostics.manifest_conflict.diagnose import (
    build_router,
    clear_cache,
    diagnose_event,
    repair_variable_type_bindings,
)
from diagnostics.manifest_conflict.manifests import manifest_a, manifest_b, manifest_c
from diagnostics.manifest_conflict.run_diagnosis import OPCODE, PAYLOAD, PROVIDER_GUID, run
from diagnostics.manifest_conflict.synthetic_etl import build_etl
from dissect.etl import manifest
from dissect.etl import c_etl as real_c_etl_module
from dissect.etl.etl import ETL
import dissect.etl.etl as etl_module


@pytest.fixture(autouse=True)
def _isolate_global_state():
    # tests/test_etl_buffer.py monkeypatches dissect.etl.etl.c_etl with a MagicMock and never
    # restores it. Re-bind the genuine module from its source package and isolate the manifest
    # cache so test ordering cannot influence these tests.
    etl_module.c_etl = real_c_etl_module.c_etl
    saved_cache = dict(manifest.CACHE)
    manifest.CACHE.clear()
    yield
    etl_module.c_etl = real_c_etl_module.c_etl
    manifest.CACHE.clear()
    manifest.CACHE.update(saved_cache)


@pytest.fixture
def etl_blob() -> bytes:
    return build_etl(PROVIDER_GUID, OPCODE, 0, PAYLOAD)


@pytest.fixture
def router():
    return build_router(PROVIDER_GUID)


def test_synthetic_etl_roundtrip(etl_blob: bytes) -> None:
    etl = ETL(BytesIO(etl_blob))
    records = list(etl)
    assert etl.is_64bit is False
    assert etl.logfile_header.buffers_written == 1
    assert len(records) == 2
    header = records[1].header
    assert header.provider_id == PROVIDER_GUID
    assert header.version == 0
    assert header.opcode == OPCODE
    assert bytes(header.payload) == PAYLOAD


def test_manifests_share_guid_but_diverge() -> None:
    for factory in (manifest_a, manifest_b, manifest_c):
        module = manifest.compile_xml(PROVIDER_GUID, factory(PROVIDER_GUID))
        assert module.PROVIDER_GUID == PROVIDER_GUID
    module_a = manifest.compile_xml(PROVIDER_GUID, manifest_a(PROVIDER_GUID))
    module_b = manifest.compile_xml(PROVIDER_GUID, manifest_b(PROVIDER_GUID))
    assert module_a.PROVIDER_NAME != module_b.PROVIDER_NAME
    assert list(module_a.EVENTS) == list(module_b.EVENTS) == [(OPCODE, 0)]
    struct_a = module_a.c_parser.TmplA(PAYLOAD)
    struct_b = module_b.c_parser.TmplB(PAYLOAD)
    assert [field.name for field in struct_a.__fields__] == ["Counter", "Label"]
    assert [field.name for field in struct_b.__fields__] == ["Counter", "NextDword", "TrailingWord"]


def test_same_bytes_get_incompatible_interpretations(etl_blob: bytes, router) -> None:
    clear_cache()
    result_a = diagnose_event(etl_blob, PROVIDER_GUID, router, "collector-a")
    clear_cache()
    result_b = diagnose_event(etl_blob, PROVIDER_GUID, router, "collector-b")

    assert result_a.parsed_values == {"Counter": 7, "Label": "AB"}
    assert result_b.parsed_values == {"Counter": 7, "NextDword": 4325441, "TrailingWord": 0}
    assert result_a.parsed_values != result_b.parsed_values
    assert result_a.no_exception and result_b.no_exception
    assert result_a.unconsumed_bytes == result_b.unconsumed_bytes == 2
    assert result_a.unconsumed_hex == "ccdd"


def test_cold_cache_load_order_selects_active_source(etl_blob: bytes, router) -> None:
    clear_cache()
    first = diagnose_event(etl_blob, PROVIDER_GUID, router, "collector-a")
    assert first.manifest_origin["cache_hit"] is False
    assert first.manifest_origin["compiled_sources"][0].startswith("collector-a:")

    clear_cache()
    second = diagnose_event(etl_blob, PROVIDER_GUID, router, "collector-b")
    assert second.manifest_origin["cache_hit"] is False
    assert second.manifest_origin["provider_name"] == "ConflictProvider-CollectorB"


def test_sticky_cache_ignores_later_source_switch(etl_blob: bytes, router) -> None:
    clear_cache()
    first = diagnose_event(etl_blob, PROVIDER_GUID, router, "collector-a")
    second = diagnose_event(etl_blob, PROVIDER_GUID, router, "collector-b")

    assert second.manifest_origin["cache_hit"] is True
    assert second.manifest_origin["compiled_sources"] == []
    assert second.manifest_origin["provider_name"] == first.manifest_origin["provider_name"]
    assert second.parsed_values == first.parsed_values
    assert PROVIDER_GUID in manifest.CACHE


def test_missing_event_entry_is_silent(etl_blob: bytes, router) -> None:
    clear_cache()
    result = diagnose_event(etl_blob, PROVIDER_GUID, router, "collector-c")
    assert result.no_exception is True
    assert result.manifest_origin["provider_name"] == "ConflictProvider-CollectorC"
    assert result.parsed_values == {}
    assert result.consumed_bytes == 0
    assert result.unconsumed_bytes == len(PAYLOAD)
    assert "KeyError" in result.manifest_origin["silent_path"]


def test_no_exception_is_not_evidence_of_correct_template(etl_blob: bytes, router) -> None:
    outcomes = []
    for collector in ("collector-a", "collector-b"):
        clear_cache()
        outcomes.append(diagnose_event(etl_blob, PROVIDER_GUID, router, collector))
    assert all(result.no_exception for result in outcomes)
    assert outcomes[0].parsed_values != outcomes[1].parsed_values


def test_binding_shim_only_changes_broken_methods(etl_blob: bytes) -> None:
    module = manifest.compile_xml(PROVIDER_GUID, manifest_a(PROVIDER_GUID))
    with pytest.raises(TypeError):
        module.c_parser.EtwPointer.as_32bit()
    repaired = repair_variable_type_bindings(module)
    assert "EtwPointer" in repaired and "UserSID_blob" in repaired
    module.c_parser.EtwPointer.as_32bit()
    assert module.c_parser.EtwPointer.size == 4


def test_production_lookup_cache_is_guid_only_and_first_wins() -> None:
    # Drives the real manifest.lookup/CACHE, not the diagnosis instrumentation.
    from unittest.mock import patch

    xml_a = manifest_a(PROVIDER_GUID)
    xml_b = manifest_b(PROVIDER_GUID)
    requests: list[str] = []

    def fake_resource(path: str) -> str:
        requests.append(path)
        return xml_a if len(requests) == 1 else xml_b

    clear_cache()
    with patch.object(manifest, "get_resource_string", fake_resource):
        first = manifest.lookup(PROVIDER_GUID)
        second = manifest.lookup(PROVIDER_GUID)

    assert first is second
    assert len(requests) == 1  # the second, different manifest is never even read
    assert list(manifest.CACHE) == [PROVIDER_GUID]
    assert second.PROVIDER_NAME == "ConflictProvider-CollectorA"
    clear_cache()


def test_full_report_artifacts(tmp_path, etl_blob: bytes) -> None:
    report = run(tmp_path)
    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "report.txt").exists()
    assert (tmp_path / "collector-a-events.etl").exists()
    assert (tmp_path / "collector-b-events.etl").read_bytes() == etl_blob
    assert report["etl_files_byte_identical"] is True
    sticky = report["scenarios"]["sticky_cache_a_then_b"]
    assert sticky[1]["manifest_origin"]["cache_hit"] is True
    assert sticky[1]["parsed_values"] == sticky[0]["parsed_values"]
