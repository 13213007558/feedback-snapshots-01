import email.utils
import io
import json
import os
from pathlib import Path
from unittest import mock

import pretend  # type: ignore
import pytest
import requests
import urllib3
from packaging.version import Version
from platformdirs import user_cache_path

import pip_audit._cache as cache
from pip_audit._cache import _get_cache_dir, _get_pip_cache
from pip_audit._service import PyPIService
from pip_audit._service import interface as service


def test_get_cache_dir(monkeypatch):
    # When we supply a cache directory, always use that
    cache_dir = Path("/tmp/foo/cache_dir")
    assert _get_cache_dir(cache_dir) == cache_dir

    cache_dir = Path("/fake/pip/cache/dir")
    get_pip_cache = pretend.call_recorder(lambda: cache_dir)
    monkeypatch.setattr(cache, "_get_pip_cache", get_pip_cache)

    # When `pip cache dir` works, we use it. In this case, it's mocked.
    assert _get_cache_dir(None, use_pip=True) == cache_dir


def test_get_pip_cache():
    # Actually running `pip cache dir` gets us some path that ends with "http"
    cache_dir = _get_pip_cache()
    assert cache_dir.stem == "http"


def test_get_cache_dir_do_not_use_pip():
    expected = user_cache_path("pip-audit", appauthor=False)

    # Even with None, we never use the pip cache if we're told not to.
    assert _get_cache_dir(None, use_pip=False) == expected


def test_get_cache_dir_pip_disabled_in_environment(monkeypatch):
    monkeypatch.setenv("PIP_NO_CACHE_DIR", "1")

    expected = user_cache_path("pip-audit", appauthor=False)

    # Even with use_pip=True, we avoid pip's cache if the environment tells us to.
    assert _get_cache_dir(None, use_pip=True) == expected


def test_get_cache_dir_old_pip(monkeypatch):
    # Check the case where we have an old `pip`
    monkeypatch.setattr(cache, "_PIP_VERSION", Version("1.0.0"))

    # In this case, we can't query `pip` to figure out where its HTTP cache is
    # Instead, we use `~/.pip-audit-cache`
    cache_dir = _get_cache_dir(None)
    expected = user_cache_path("pip-audit", appauthor=False)
    assert cache_dir == expected


def test_cache_warns_about_old_pip(monkeypatch, cache_dir):
    monkeypatch.setattr(cache, "_PIP_VERSION", Version("1.0.0"))
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(cache, "logger", logger)

    # If we supply a cache directory, we're not relying on finding the `pip` cache so no need to log
    # a warning
    _get_cache_dir(cache_dir)
    assert len(logger.warning.calls) == 0

    # However, if we're not specifying a cache directory, we'll try to call `pip cache dir`. If we
    # have an old `pip`, then we should expect a warning to be logged
    _get_cache_dir(None)
    assert len(logger.warning.calls) == 1


def test_delete_legacy_cache_dir(monkeypatch, tmp_path):
    legacy = tmp_path / "pip-audit-cache"
    legacy.mkdir()
    assert legacy.exists()
    monkeypatch.setattr(cache, "_PIP_AUDIT_LEGACY_INTERNAL_CACHE", legacy)

    _get_cache_dir(None, use_pip=False)
    assert not legacy.exists()


# --- Cache directory ownership and fallback tests -------------------------


def _fake_pypi_response(payload=None):
    """
    A fake PyPI JSON response body that closes itself once drained, matching
    the behavior CacheControl relies on to persist a response.
    """
    if payload is None:
        payload = {"vulnerabilities": []}

    class _ClosingBody(io.BytesIO):
        def __init__(self, data):
            super().__init__(data)
            self.fp = self

        def read(self, *args, **kwargs):
            data = super().read(*args, **kwargs)
            if not data:
                self.fp = None
            return data

    return _ClosingBody(json.dumps(payload).encode())


def _fake_pypi_send(payload=None):
    def send(self, request, *args, **kwargs):
        raw = urllib3.HTTPResponse(
            body=_fake_pypi_response(payload),
            headers={
                "Content-Type": "application/json",
                "Date": email.utils.formatdate(usegmt=True),
                "Cache-Control": "max-age=3600",
            },
            status=200,
            preload_content=False,
            decode_content=False,
            reason="OK",
        )
        return self.build_response(request, raw)

    return send


def _cached_files(directory):
    if not directory.exists():
        return set()
    return {p for p in directory.rglob("*") if p.is_file()}


def test_check_cache_dir_accepts_private_directory(tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    usable, reason = cache._check_cache_dir(cache_dir, create=False)
    assert usable, reason


def test_check_cache_dir_creates_missing_directory(tmp_path):
    cache_dir = tmp_path / "nested" / "cache"

    usable, reason = cache._check_cache_dir(cache_dir, create=True)
    assert usable, reason
    assert cache_dir.is_dir()


def test_check_cache_dir_rejects_group_or_other_writable(tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    cache_dir.chmod(0o777)

    usable, reason = cache._check_cache_dir(cache_dir, create=False)
    assert not usable
    assert "other users" in reason


def test_check_cache_dir_rejects_non_directory(tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.write_text("not a directory")

    usable, reason = cache._check_cache_dir(cache_dir, create=False)
    assert not usable
    assert "not a directory" in reason


def test_check_cache_dir_rejects_symlink(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "cache"
    link.symlink_to(real, target_is_directory=True)

    usable, reason = cache._check_cache_dir(link, create=False)
    assert not usable
    assert "symlink" in reason


def test_check_cache_dir_rejects_other_owner(monkeypatch, tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    monkeypatch.setattr(cache, "_geteuid", lambda: os.geteuid() + 1)

    usable, reason = cache._check_cache_dir(cache_dir, create=False)
    assert not usable
    assert "owned by uid" in reason


def test_check_cache_dir_rejects_unwritable(monkeypatch, tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    monkeypatch.setattr(cache, "_is_writable", lambda _: False)

    usable, reason = cache._check_cache_dir(cache_dir, create=False)
    assert not usable
    assert "not writable" in reason


def test_check_cache_dir_rejects_writable_parent(tmp_path):
    parent = tmp_path / "public"
    parent.mkdir()
    parent.chmod(0o777)

    usable, reason = cache._check_cache_dir(parent / "cache", create=True)
    assert not usable
    assert "parent" in reason
    assert not (parent / "cache").exists()


def test_safe_file_cache_default_allows(monkeypatch, tmp_path):
    payload = {"vulnerabilities": [{"id": "VULN-0", "aliases": [], "fixed_in": []}]}
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    pypi = PyPIService(cache_dir)
    with mock.patch.object(requests.adapters.HTTPAdapter, "send", _fake_pypi_send(payload)):
        dep = service.ResolvedDependency("foo", Version("1.0.0"))
        pypi.query(dep)
        assert _cached_files(cache_dir)

    # A second query is served from cache, so the fake transport isn't hit.
    with mock.patch.object(
        requests.adapters.HTTPAdapter, "send", pretend.raiser(AssertionError("network used"))
    ):
        dep = service.ResolvedDependency("foo", Version("1.0.0"))
        spec, vulns = pypi.query(dep)

    assert spec == dep
    assert len(vulns) == 1


def test_safe_file_cache_unusable_directory_is_uncached(monkeypatch, tmp_path):
    # A cache directory writable by other accounts must be rejected up front.
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    cache_dir.chmod(0o777)

    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None), debug=lambda s: None)
    monkeypatch.setattr(cache, "logger", logger)

    pypi = PyPIService(cache_dir)
    adapter = pypi.session.get_adapter("https://pypi.org")
    assert not adapter.cache.enabled

    with mock.patch.object(requests.adapters.HTTPAdapter, "send", _fake_pypi_send()):
        dep = service.ResolvedDependency("foo", Version("1.0.0"))
        spec, vulns = pypi.query(dep)

    assert spec == dep
    assert vulns == []
    assert not _cached_files(cache_dir)
    assert logger.warning.calls
    assert "continuing without a cache" in logger.warning.calls[0].args[0]


def test_safe_file_cache_default_allows_explicitly_named_directory(tmp_path):
    # An explicitly approved directory with normal permissions is used, and
    # the audit reports a cache hit on the second query.
    cache_dir = tmp_path / "approved"
    cache_dir.mkdir()

    pypi = PyPIService(cache_dir)
    adapter = pypi.session.get_adapter("https://pypi.org")
    assert adapter.cache.enabled
    assert Path(adapter.cache.directory) == cache_dir


def test_safe_file_cache_disables_on_runtime_permission_change(tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    safe_cache = cache._SafeFileCache(cache_dir)
    assert not safe_cache._disabled

    # The directory becomes writable by other accounts after initialization.
    cache_dir.chmod(0o777)

    safe_cache.set("key", b"value")
    assert safe_cache._disabled
    assert safe_cache.get("key") is None
    assert not _cached_files(cache_dir)


def test_safe_file_cache_disables_on_runtime_owner_change(monkeypatch, tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    safe_cache = cache._SafeFileCache(cache_dir)
    assert not safe_cache._disabled

    # Simulate the directory being replaced by one owned by another account.
    monkeypatch.setattr(cache, "_geteuid", lambda: os.geteuid() + 1)

    safe_cache.set("key", b"value")
    assert safe_cache._disabled
    assert not _cached_files(cache_dir)


def test_safe_file_cache_rejection_does_not_relocate(tmp_path):
    rejected = tmp_path / "rejected"
    rejected.mkdir()
    rejected.chmod(0o777)
    other = tmp_path / "other"
    other.mkdir()

    pypi = PyPIService(rejected)
    with mock.patch.object(requests.adapters.HTTPAdapter, "send", _fake_pypi_send()):
        dep = service.ResolvedDependency("foo", Version("1.0.0"))
        pypi.query(dep)

    # Nothing was written to the rejected directory, nor was a cache
    # silently created anywhere else under the temporary root.
    assert not _cached_files(rejected)
    assert not _cached_files(other)
    assert not _cached_files(tmp_path / "pip-audit")
    assert not _cached_files(tmp_path / "cache")


def test_caching_session_uncached_without_a_directory(tmp_path):
    # When no usable directory is known, the session is still constructed and
    # performs requests without touching the rejected path.
    rejected = tmp_path / "rejected"
    rejected.write_text("not a directory")

    session = cache.caching_session(rejected)
    with mock.patch.object(requests.adapters.HTTPAdapter, "send", _fake_pypi_send()):
        response = session.get("https://pypi.org/pypi/foo/1.0.0/json")

    assert response.status_code == 200
    assert not _cached_files(rejected)


def test_default_cache_directory_is_used_when_approved(monkeypatch, tmp_path):
    # With no explicit cache directory, the platform default is used as long
    # as it passes the ownership/writability checks.
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.delenv("PIP_NO_CACHE_DIR", raising=False)

    pypi = PyPIService(cache_dir=None)
    session = pypi.session
    adapter = session.get_adapter("https://pypi.org")
    assert adapter.cache.enabled
    assert Path(adapter.cache.directory) == tmp_path / "pip-audit"

    with mock.patch.object(requests.adapters.HTTPAdapter, "send", _fake_pypi_send()):
        dep = service.ResolvedDependency("foo", Version("1.0.0"))
        pypi.query(dep)

    assert _cached_files(tmp_path / "pip-audit")


def test_default_cache_directory_rejected_without_relocation(monkeypatch, tmp_path):
    # Simulate a default cache directory owned by another account: the audit
    # proceeds uncached, and no sibling directory is created as a fallback.
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.delenv("PIP_NO_CACHE_DIR", raising=False)
    monkeypatch.setattr(cache, "_geteuid", lambda: os.geteuid() + 1)

    pypi = PyPIService(cache_dir=None)
    adapter = pypi.session.get_adapter("https://pypi.org")
    assert not adapter.cache.enabled

    with mock.patch.object(requests.adapters.HTTPAdapter, "send", _fake_pypi_send()):
        dep = service.ResolvedDependency("foo", Version("1.0.0"))
        pypi.query(dep)

    assert not _cached_files(tmp_path)


def test_caching_session_survives_unresolvable_default(monkeypatch):
    # If the platform cache path can't even be resolved, constructing the
    # service still succeeds and just runs uncached.
    def boom(*args, **kwargs):
        raise PermissionError("no cache for you")

    monkeypatch.setattr(cache, "user_cache_path", boom)

    session = cache.caching_session(None, use_pip=False)
    adapter = session.get_adapter("https://pypi.org")
    assert adapter.cache.enabled is False
    assert adapter.cache.directory is None


def test_service_disables_cache_mid_audit_on_permission_change(tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    pypi = PyPIService(cache_dir)
    adapter = pypi.session.get_adapter("https://pypi.org")
    assert adapter.cache.enabled

    with mock.patch.object(requests.adapters.HTTPAdapter, "send", _fake_pypi_send()):
        pypi.query(service.ResolvedDependency("foo", Version("1.0.0")))
    assert _cached_files(cache_dir)

    # The cache directory becomes writable by other accounts between queries.
    cache_dir.chmod(0o777)

    with mock.patch.object(requests.adapters.HTTPAdapter, "send", _fake_pypi_send()):
        spec, vulns = pypi.query(service.ResolvedDependency("bar", Version("1.0.0")))

    assert spec.name == "bar"
    assert vulns == []
    assert not adapter.cache.enabled

    # The earlier cache entry is untouched, and no new entry was written for
    # the second dependency.
    cached = _cached_files(cache_dir)
    assert len(cached) == 1
