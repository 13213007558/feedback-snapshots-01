import hashlib
import os
from pathlib import Path
from typing import NoReturn

import pytest

from pip._vendor.packaging.tags import Tag, interpreter_name, interpreter_version

from pip._internal.cache import (
    CacheProvenancePolicy,
    SimpleWheelCache,
    WheelCache,
    _hash_dict,
)
from pip._internal.exceptions import CacheProvenanceError
from pip._internal.models.direct_url import ArchiveInfo, DirectUrl
from pip._internal.models.link import Link
from pip._internal.utils.misc import ensure_dir
from pip._internal.utils.urls import path_to_url

_SUPPORTED_TAGS = [Tag("py3", "none", "any")]
_SHA256 = "a" * 64


def _seed_cached_wheel(
    cache: WheelCache,
    source: Link,
    name: str,
    *,
    origin_url: str | None = None,
    hashes: dict[str, str] | None = None,
    write_origin: bool = True,
) -> Path:
    cache_dir = Path(cache.get_path_for_link(source))
    ensure_dir(cache_dir)
    (cache_dir / f"{name}-1.0-py3-none-any.whl").write_bytes(b"wheel")
    if write_origin:
        (cache_dir / "origin.json").write_text(
            DirectUrl(
                url=origin_url or source.url_without_fragment,
                archive_info=ArchiveInfo(hashes=hashes or {"sha256": _SHA256}),
            ).to_json(),
            encoding="utf-8",
        )
    return cache_dir


def test_falsey_path_none() -> None:
    wc = WheelCache("")
    assert wc.cache_dir is None


def test_subdirectory_fragment(tmp_path: Path) -> None:
    """
    Test the subdirectory URL fragment is part of the cache key.
    """
    wc = WheelCache(os.fspath(tmp_path))
    link1 = Link("git+https://g.c/o/r#subdirectory=d1")
    link2 = Link("git+https://g.c/o/r#subdirectory=d2")
    assert wc.get_path_for_link(link1) != wc.get_path_for_link(link2)


def test_wheel_name_filter(tmpdir: Path) -> None:
    """
    Test the wheel cache filters on wheel name when several wheels
    for different package are stored under the same cache directory.
    """
    wc = WheelCache(os.fspath(tmpdir))
    link = Link("https://g.c/package.tar.gz")
    cache_path = wc.get_path_for_link(link)
    ensure_dir(cache_path)
    with open(os.path.join(cache_path, "package-1.0-py3-none-any.whl"), "w"):
        pass
    # package matches wheel name
    cached_link = wc.get(link, "package", [Tag("py3", "none", "any")])
    assert cached_link is not link
    assert os.path.exists(cached_link.file_path)
    # package2 does not match wheel name
    assert wc.get(link, "package2", [Tag("py3", "none", "any")]) is link


def test_cache_hash() -> None:
    h = _hash_dict({"url": "https://g.c/o/r"})
    assert h == "72aa79d3315c181d2cc23239d7109a782de663b6f89982624d8c1e86"
    h = _hash_dict({"url": "https://g.c/o/r", "subdirectory": "sd"})
    assert h == "8b13391b6791bf7f3edeabb41ea4698d21bcbdbba7f9c7dc9339750d"
    h = _hash_dict({"subdirectory": "/\xe9e"})
    assert h == "f83b32dfa27a426dec08c21bf006065dd003d0aac78e7fc493d9014d"


def test_link_to_cache(tmpdir: Path) -> None:
    """
    Test that Link.from_json() produces Links with consistent cache
    locations
    """
    wc = WheelCache(os.fspath(tmpdir))
    # Define our expectations for stable cache path.
    i_name = interpreter_name()
    i_version = interpreter_version()
    key_parts = {
        "url": "https://files.pythonhosted.org/packages/a6/91/"
        "86a6eac449ddfae239e93ffc1918cf33fd9bab35c04d1e963b311e347a73/"
        "netifaces-0.11.0.tar.gz",
        "sha256": "043a79146eb2907edf439899f262b3dfe41717d34124298ed281139a8b93ca32",
        "interpreter_name": i_name,
        "interpreter_version": i_version,
    }
    expected_hash = _hash_dict(key_parts)
    parts = [
        expected_hash[:2],
        expected_hash[2:4],
        expected_hash[4:6],
        expected_hash[6:],
    ]
    pathed_hash = os.path.join(*parts)
    # Check working from a Link produces the same result.
    file_data = {
        "filename": "netifaces-0.11.0.tar.gz",
        "hashes": {
            "sha256": key_parts["sha256"],
        },
        "requires-python": "",
        "url": key_parts["url"],
        "yanked": False,
    }
    page_url = "https://pypi.org/simple/netifaces/"
    link = Link.from_json(file_data=file_data, page_url=page_url)
    assert link
    path = wc.get_path_for_link(link)
    assert pathed_hash in path


def test_get_cache_entry(tmpdir: Path) -> None:
    wc = WheelCache(os.fspath(tmpdir))
    persi_link = Link("https://g.c/o/r/persi")
    persi_path = wc.get_path_for_link(persi_link)
    ensure_dir(persi_path)
    with open(os.path.join(persi_path, "persi-1.0.0-py3-none-any.whl"), "w"):
        pass
    ephem_link = Link("https://g.c/o/r/ephem")
    ephem_path = wc.get_ephem_path_for_link(ephem_link)
    ensure_dir(ephem_path)
    with open(os.path.join(ephem_path, "ephem-1.0.0-py3-none-any.whl"), "w"):
        pass
    other_link = Link("https://g.c/o/r/other")
    supported_tags = [Tag("py3", "none", "any")]
    entry = wc.get_cache_entry(persi_link, "persi", supported_tags)
    assert entry is not None
    assert entry.persistent

    entry = wc.get_cache_entry(ephem_link, "ephem", supported_tags)
    assert entry is not None
    assert not entry.persistent

    assert wc.get_cache_entry(other_link, "other", supported_tags) is None


def test_simple_wheel_cache_ignores_cache_for_existing_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    link = Link(path_to_url(str(project_dir)))
    cache = SimpleWheelCache(str(tmp_path / "cache"))

    def fail_if_called(*args: object, **kwargs: object) -> NoReturn:
        raise AssertionError("local directory links should not check wheel cache")

    monkeypatch.setattr(cache, "_get_candidates", fail_if_called)

    assert cache.get(link, "example", supported_tags=[]) is link


def test_wheel_cache_entry_none_for_existing_directory(tmpdir: Path) -> None:
    wc = WheelCache(os.fspath(tmpdir))
    project_dir = tmpdir / "project"
    project_dir.mkdir()
    link = Link(path_to_url(str(project_dir)))
    supported_tags = [Tag("py3", "none", "any")]
    cache_path = wc.get_path_for_link(link)
    ensure_dir(cache_path)
    with open(os.path.join(cache_path, "example-1.0-py3-none-any.whl"), "w"):
        pass

    assert wc.get_cache_entry(link, "example", supported_tags) is None
    assert wc.get(link, "example", supported_tags) is link


def test_record_download_origin_ignores_stripped_auth_difference(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    download_info = DirectUrl(
        url="https://user:secret@example.com/pkg.tar.gz",
        archive_info=ArchiveInfo(),
    )

    WheelCache.record_download_origin(str(tmp_path), download_info)
    WheelCache.record_download_origin(str(tmp_path), download_info)

    assert caplog.records == []


def test_record_download_origin_redacts_auth_from_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    old_info = DirectUrl(
        url="https://old-user:old-secret@old.example/pkg.tar.gz",
        archive_info=ArchiveInfo(),
    )
    new_info = DirectUrl(
        url="https://new-user:new-secret@new.example/pkg.tar.gz",
        archive_info=ArchiveInfo(),
    )
    WheelCache.record_download_origin(str(tmp_path), old_info)

    WheelCache.record_download_origin(str(tmp_path), new_info)

    assert len(caplog.records) == 1
    message = caplog.records[0].getMessage()
    assert "old-secret" not in message
    assert "new-secret" not in message
    assert "https://old.example/pkg.tar.gz" in message
    assert "https://new.example/pkg.tar.gz" in message


def test_cache_provenance_default_policy_keeps_legacy_entries(tmp_path: Path) -> None:
    """Without a policy, cache hits behave exactly as before."""
    wc = WheelCache(os.fspath(tmp_path))
    source = Link("https://packages.example/simple-1.0.tar.gz")
    _seed_cached_wheel(wc, source, "simple", write_origin=False)

    entry = wc.get_cache_entry(source, "simple", _SUPPORTED_TAGS)

    assert entry is not None
    assert entry.persistent
    # Nothing is checked, but the missing evidence does not block the hit.
    assert entry.provenance is not None
    assert entry.provenance.verified is None
    assert entry.provenance.source_url is None


def test_cache_provenance_accepts_matching_origin_and_hash(tmp_path: Path) -> None:
    wc = WheelCache(
        os.fspath(tmp_path),
        provenance_policy=CacheProvenancePolicy(action="error"),
    )
    source = Link("https://packages.example/simple-1.0.tar.gz")
    _seed_cached_wheel(
        wc, source, "simple", hashes={"sha256": _SHA256, "md5": "b" * 32}
    )

    entry = wc.get_cache_entry(source, "simple", _SUPPORTED_TAGS)

    assert entry is not None
    assert entry.provenance is not None
    assert entry.provenance.verified
    # Only strong hashes are reported as content evidence.
    assert entry.provenance.source_hashes == {"sha256": _SHA256}


def test_cache_provenance_ignores_source_url_with_credentials(tmp_path: Path) -> None:
    wc = WheelCache(
        os.fspath(tmp_path),
        provenance_policy=CacheProvenancePolicy(action="error"),
    )
    source = Link("https://packages.example/simple-1.0.tar.gz")
    _seed_cached_wheel(
        wc,
        source,
        "simple",
        origin_url="https://user:secret@packages.example/simple-1.0.tar.gz",
    )

    entry = wc.get_cache_entry(source, "simple", _SUPPORTED_TAGS)

    assert entry is not None
    assert entry.provenance is not None
    assert entry.provenance.verified
    assert "secret" not in str(entry.provenance.to_dict())


def test_cache_provenance_redacts_credentials_in_report(tmp_path: Path) -> None:
    """A legacy origin.json that still embeds credentials is redacted."""
    wc = WheelCache(
        os.fspath(tmp_path),
        provenance_policy=CacheProvenancePolicy(action="error"),
    )
    source = Link("https://packages.example/simple-1.0.tar.gz")
    cache_dir = Path(wc.get_path_for_link(source))
    ensure_dir(cache_dir)
    (cache_dir / "simple-1.0-py3-none-any.whl").write_bytes(b"wheel")
    (cache_dir / "origin.json").write_text(
        '{"url": "https://user:secret@packages.example/simple-1.0.tar.gz", '
        '"archive_info": {"hashes": {"sha256": "' + _SHA256 + '"}}}',
        encoding="utf-8",
    )

    entry = wc.get_cache_entry(source, "simple", _SUPPORTED_TAGS)

    assert entry is not None
    assert entry.provenance is not None
    assert entry.provenance.verified
    assert entry.provenance.to_dict()["source_url"] == (
        "https://user:****@packages.example/simple-1.0.tar.gz"
    )
    assert "secret" not in str(entry.provenance.to_dict())


def test_cache_provenance_refetches_on_mismatched_origin(tmp_path: Path) -> None:
    wc = WheelCache(
        os.fspath(tmp_path),
        provenance_policy=CacheProvenancePolicy(action="refetch"),
    )
    source = Link("https://packages.example/simple-1.0.tar.gz")
    _seed_cached_wheel(
        wc, source, "simple", origin_url="https://other.example/simple-1.0.tar.gz"
    )

    assert wc.get_cache_entry(source, "simple", _SUPPORTED_TAGS) is None


def test_cache_provenance_rejects_on_missing_origin(tmp_path: Path) -> None:
    wc = WheelCache(
        os.fspath(tmp_path),
        provenance_policy=CacheProvenancePolicy(action="error"),
    )
    source = Link("https://packages.example/simple-1.0.tar.gz")
    _seed_cached_wheel(wc, source, "simple", write_origin=False)

    with pytest.raises(CacheProvenanceError, match="missing origin.json"):
        wc.get_cache_entry(source, "simple", _SUPPORTED_TAGS)


def test_cache_provenance_rejects_on_invalid_origin(tmp_path: Path) -> None:
    wc = WheelCache(
        os.fspath(tmp_path),
        provenance_policy=CacheProvenancePolicy(action="error"),
    )
    source = Link("https://packages.example/simple-1.0.tar.gz")
    cache_dir = Path(wc.get_path_for_link(source))
    ensure_dir(cache_dir)
    (cache_dir / "simple-1.0-py3-none-any.whl").write_bytes(b"wheel")
    (cache_dir / "origin.json").write_text("{", encoding="utf-8")

    with pytest.raises(CacheProvenanceError, match="invalid origin.json"):
        wc.get_cache_entry(source, "simple", _SUPPORTED_TAGS)


def test_cache_provenance_refetches_without_strong_hash(tmp_path: Path) -> None:
    wc = WheelCache(
        os.fspath(tmp_path),
        provenance_policy=CacheProvenancePolicy(action="refetch"),
    )
    source = Link("https://packages.example/simple-1.0.tar.gz")
    _seed_cached_wheel(wc, source, "simple", hashes={"md5": "b" * 32})

    assert wc.get_cache_entry(source, "simple", _SUPPORTED_TAGS) is None


def test_cache_provenance_refetches_on_hash_mismatch(tmp_path: Path) -> None:
    wc = WheelCache(
        os.fspath(tmp_path),
        provenance_policy=CacheProvenancePolicy(action="refetch"),
    )
    source = Link(f"https://packages.example/simple-1.0.tar.gz#sha256={'b' * 64}")
    _seed_cached_wheel(wc, source, "simple", hashes={"sha256": _SHA256})

    assert wc.get_cache_entry(source, "simple", _SUPPORTED_TAGS) is None


def test_cache_provenance_accepts_matching_source_hash(tmp_path: Path) -> None:
    wc = WheelCache(
        os.fspath(tmp_path),
        provenance_policy=CacheProvenancePolicy(action="error"),
    )
    source = Link(f"https://packages.example/simple-1.0.tar.gz#sha256={_SHA256}")
    _seed_cached_wheel(wc, source, "simple", hashes={"sha256": _SHA256})

    entry = wc.get_cache_entry(source, "simple", _SUPPORTED_TAGS)

    assert entry is not None
    assert entry.provenance is not None
    assert entry.provenance.verified


def test_cache_provenance_does_not_apply_to_ephemeral_cache(tmp_path: Path) -> None:
    wc = WheelCache(
        os.fspath(tmp_path),
        provenance_policy=CacheProvenancePolicy(action="error"),
    )
    source = Link("https://packages.example/simple-1.0.tar.gz")
    ephem_dir = Path(wc.get_ephem_path_for_link(source))
    ensure_dir(ephem_dir)
    (ephem_dir / "simple-1.0-py3-none-any.whl").write_bytes(b"wheel")

    entry = wc.get_cache_entry(source, "simple", _SUPPORTED_TAGS)

    assert entry is not None
    assert not entry.persistent
    # The persistent cache had no entry, so the ephemeral hit is unaffected.
    assert entry.provenance is None


def test_cache_provenance_local_source_is_rehashed(tmp_path: Path) -> None:
    """A local source's current bytes must match the recorded digest."""
    sdist = tmp_path / "simple-1.0.tar.gz"
    sdist.write_bytes(b"original source")
    digest = hashlib.sha256(sdist.read_bytes()).hexdigest()
    source = Link(sdist.as_uri())

    wc = WheelCache(
        os.fspath(tmp_path / "cache"),
        provenance_policy=CacheProvenancePolicy(action="error"),
    )
    _seed_cached_wheel(wc, source, "simple", hashes={"sha256": digest})
    entry = wc.get_cache_entry(source, "simple", _SUPPORTED_TAGS)
    assert entry is not None
    assert entry.provenance is not None
    assert entry.provenance.verified

    # Changing the file behind the same URL invalidates the evidence.
    sdist.write_bytes(b"silently replaced source")
    refetch_cache = WheelCache(
        os.fspath(tmp_path / "cache"),
        provenance_policy=CacheProvenancePolicy(action="refetch"),
    )
    assert refetch_cache.get_cache_entry(source, "simple", _SUPPORTED_TAGS) is None
    with pytest.raises(CacheProvenanceError, match="does not match the current"):
        wc.get_cache_entry(source, "simple", _SUPPORTED_TAGS)
