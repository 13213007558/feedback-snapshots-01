from __future__ import annotations

import io
from uuid import UUID

import pytest

import dissect.etl.etl as etl_module
from diagnostics import diagnose
from diagnostics.diagnose import Candidate, apply_pointer_width, parse_counted
from dissect.etl import manifest
from dissect.etl.c_etl import c_etl
from dissect.etl.etl import ETL
from dissect.etl.exceptions import ManifestNotFoundError

GUID = UUID("13976d09-a327-438c-950b-7f03192815c7")


@pytest.fixture(autouse=True)
def restore_etl_cstruct() -> None:
    """Keep this module independent of other tests that monkeypatch the module global."""
    etl_module.c_etl = c_etl


def load_fixture(name: str) -> tuple[ETL, list]:
    data = (diagnose.REPO_ROOT / "diagnostics" / "fixtures" / name).read_bytes()
    etl = ETL(io.BytesIO(data))
    return etl, diagnose.iter_records(etl)


def candidate(name: str, filename: str) -> Candidate:
    path = diagnose.REPO_ROOT / "diagnostics" / "manifests" / filename
    return Candidate(name, "file", str(path))


def test_same_bytes_two_manifest_versions_are_indistinguishable_by_fit() -> None:
    """Both versions consume the payload exactly; only field names differ."""
    _, records = load_fixture("manifest_v1_v2.etl")
    header = records[1][1].header
    payload = bytes(header.payload)
    assert len(payload) == 29

    results = {}
    for name, filename in (("v1", "provider_v1.xml"), ("v2", "provider_v2.xml")):
        module, _ = candidate(name, filename).load(GUID)
        entry = module.EVENTS[(32, 2)]
        results[name] = parse_counted(entry.template, payload)

    assert all(result["ok"] for result in results.values())
    assert all(result["unconsumed"] == 0 for result in results.values())
    assert set(results["v1"]["values"]) == {"Component", "Level", "Message"}
    assert set(results["v2"]["values"]) == {"SessionId", "Sequence", "Bytes", "Detail"}


def test_opcode_lookup_can_select_an_unrelated_event() -> None:
    """Shell-Core event id 6206 with OpCode 2 resolves (2, 0), not (6206, 0)."""
    _, records = load_fixture("shellcore_collision.etl")
    header = records[1][1].header
    assert header.descriptor.id == 6206
    assert header.opcode == 2

    module, _ = Candidate("repo", "resource").load(header.provider_id)
    lookup_entry = module.EVENTS[(header.opcode, header.version)]
    id_entry = module.EVENTS[(header.descriptor.id, header.descriptor.version)]

    assert lookup_entry.symbol == "AggregatePropertyProvider_GetValueStop"
    assert id_entry.symbol == "Thumbnails_CacheLookupStop"
    assert lookup_entry.symbol != id_entry.symbol
    # A 20-byte payload makes the wrong template look perfectly successful.
    assert parse_counted(lookup_entry.template, bytes(header.payload))["unconsumed"] == 0


def test_32bit_pointer_path_raises_before_parsing() -> None:
    _, records = load_fixture("pointer_width.etl")
    module, _ = candidate("ptr", "pointer_provider.xml").load(records[2][1].header.provider_id)

    assert apply_pointer_width(module, True)["error"] is None
    error = apply_pointer_width(module, False)["error"]
    assert error is not None
    assert "as_32bit" in error


def test_manifest_cache_is_first_wins_across_files(tmp_path) -> None:
    data = (diagnose.REPO_ROOT / "diagnostics" / "fixtures" / "manifest_v1_v2.etl").read_bytes()
    guid = GUID
    original = dict(manifest.CACHE)
    try:
        v1, _ = candidate("v1", "provider_v1.xml").load(guid)
        manifest.CACHE.clear()
        manifest.CACHE[guid] = v1

        first = list(ETL(io.BytesIO(data)))[1].event
        assert first._manifest.PROVIDER_SYMBOL == "ContosoFleetTelemetry"

        # Even a freshly created manifest object for the same GUID is ignored:
        # lookup returns the cached module.
        v2, _ = candidate("v2", "provider_v2.xml").load(guid)
        assert v2 is not v1
        assert manifest.lookup(guid) is v1
    finally:
        manifest.CACHE.clear()
        manifest.CACHE.update(original)


def test_unknown_provider_is_reported_not_guessed() -> None:
    assert load_fixture("unknown_provider.etl")[0].pointer_size == 8
    with pytest.raises(ManifestNotFoundError):
        manifest.lookup(UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"))


def test_broken_bundled_manifest_raises_keyerror_through_record_event() -> None:
    """A bundled XML that fails to compile escapes as KeyError, not ManifestNotFoundError."""
    _, records = load_fixture("broken_manifest.etl")
    event_record = records[1][1]
    with pytest.raises(KeyError):
        _ = event_record.event


def test_two_machine_exports_collide_in_one_process() -> None:
    """Reading exporter_b after exporter_a reuses the v1 template silently."""
    guid = GUID
    original = dict(manifest.CACHE)
    try:
        v1, _ = candidate("v1", "provider_v1.xml").load(guid)
        manifest.CACHE.clear()
        manifest.CACHE[guid] = v1

        data_a = (diagnose.REPO_ROOT / "diagnostics" / "fixtures" / "exporter_a.etl").read_bytes()
        data_b = (diagnose.REPO_ROOT / "diagnostics" / "fixtures" / "exporter_b.etl").read_bytes()

        first = [record for buffer in ETL(io.BytesIO(data_a)).buffers() for record in buffer][1].event
        second = [record for buffer in ETL(io.BytesIO(data_b)).buffers() for record in buffer][1].event

        assert first._manifest is second._manifest
        assert second._manifest.PROVIDER_SYMBOL == "ContosoFleetTelemetry"
        assert second.symbol() == "Sync/Complete"
        assert set(dict(second._struct.__values__)) == {"Component", "Level", "Message"}
    finally:
        manifest.CACHE.clear()
        manifest.CACHE.update(original)
