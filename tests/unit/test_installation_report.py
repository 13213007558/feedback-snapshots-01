from __future__ import annotations

from unittest import mock

from pip._internal.cache import CacheProvenance
from pip._internal.models.installation_report import InstallationReport
from pip._internal.req.constructors import install_req_from_line


def _make_ireq() -> object:
    ireq = install_req_from_line("simple==1.0")
    ireq.download_info = mock.Mock()
    ireq.download_info.to_dict_compat.return_value = {
        "url": "https://packages.example/simple-1.0.tar.gz",
        "archive_info": {"hashes": {"sha256": "a" * 64}},
    }
    ireq.get_dist = mock.Mock(
        return_value=mock.Mock(metadata_dict={"name": "simple", "version": "1.0"})
    )
    return ireq


def test_report_omits_cache_provenance_without_cached_wheel() -> None:
    item = InstallationReport._install_req_to_dict(_make_ireq())  # type: ignore[arg-type]
    assert "cache_provenance" not in item


def test_report_names_cached_wheel_source() -> None:
    ireq = _make_ireq()
    ireq.cached_wheel_provenance = CacheProvenance(  # type: ignore[attr-defined]
        persistent=True,
        verified=True,
        source_url="https://user:secret@packages.example/simple-1.0.tar.gz",
        source_hashes={"sha256": "a" * 64},
    )

    item = InstallationReport._install_req_to_dict(ireq)  # type: ignore[arg-type]

    provenance = item["cache_provenance"]
    assert provenance["used"] is True
    assert provenance["persistent"] is True
    assert provenance["verified"] is True
    assert provenance["source_url"] == (
        "https://user:****@packages.example/simple-1.0.tar.gz"
    )
    assert provenance["source_hashes"] == {"sha256": "a" * 64}
    assert "secret" not in str(provenance)


def test_report_records_unverified_cache_origin() -> None:
    ireq = _make_ireq()
    ireq.cached_wheel_provenance = CacheProvenance(  # type: ignore[attr-defined]
        persistent=True,
        verified=False,
        source_url="https://packages.example/simple-1.0.tar.gz",
        source_hashes=None,
    )

    item = InstallationReport._install_req_to_dict(ireq)  # type: ignore[arg-type]

    assert item["cache_provenance"]["verified"] is False
    assert "source_hashes" not in item["cache_provenance"]
