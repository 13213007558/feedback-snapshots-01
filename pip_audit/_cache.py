"""
Caching middleware for `pip-audit`.
"""

from __future__ import annotations

import logging
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

import pip_api
import requests
from cachecontrol import CacheControl
from cachecontrol.cache import BaseCache
from cachecontrol.caches import FileCache
from packaging.version import Version
from platformdirs import user_cache_path

from pip_audit._service.interface import ServiceError

logger = logging.getLogger(__name__)

# The `cache dir` command was added to `pip` as of 20.1 so we should check before trying to use it
# to discover the `pip` HTTP cache
_MINIMUM_PIP_VERSION = Version("20.1")

_PIP_VERSION = Version(str(pip_api.PIP_VERSION))

_PIP_AUDIT_LEGACY_INTERNAL_CACHE = Path.home() / ".pip-audit-cache"

# Cache directories are only trusted when they are owned by the account running
# the audit. This matters on machines shared by multiple service accounts:
# honoring a cache directory owned by somebody else would let that account
# seed the audit results.
_GROUP_OR_OTHER_WRITABLE = stat.S_IWGRP | stat.S_IWOTH


def _geteuid() -> int | None:
    """
    Return the effective UID, or `None` on platforms without one.
    """
    geteuid = getattr(os, "geteuid", None)
    return geteuid() if geteuid is not None else None


def _is_writable(path: Path) -> bool:
    """
    Return whether `path` is writable by the effective user.
    """
    if os.access in os.supports_effective_ids:
        return os.access(path, os.W_OK | os.X_OK, effective_ids=True)

    return os.access(path, os.W_OK | os.X_OK)


def _check_cache_dir(directory: Path, *, create: bool) -> tuple[bool, str]:
    """
    Check whether `directory` may be used as a cache directory.

    A usable cache directory must be a real directory (not a symlink), must be
    owned by the effective user, must not be writable by other users, and must
    be writable by the effective user. Missing directories are created (with
    private permissions) when `create` is set, provided that their nearest
    existing ancestor already passes the same checks.

    Returns a `(usable, reason)` pair; `reason` is suitable for logging.
    """
    directory = Path(directory).expanduser()
    if not directory.is_absolute():
        directory = Path.cwd() / directory

    def check_existing(path: Path) -> tuple[bool, str]:
        try:
            st = path.lstat()
        except OSError as e:
            return False, f"cannot stat {path}: {e}"

        if stat.S_ISLNK(st.st_mode):
            return False, f"{path} is a symlink"

        if not stat.S_ISDIR(st.st_mode):
            return False, f"{path} is not a directory"

        euid = _geteuid()
        if euid is not None:
            expected_uid = 0 if euid == 0 else euid
            if st.st_uid != expected_uid:
                return False, f"{path} is owned by uid {st.st_uid}, not uid {expected_uid}"

            # Windows reports synthetic mode bits, so only check this on
            # platforms with real POSIX permissions.
            if st.st_mode & _GROUP_OR_OTHER_WRITABLE:
                return False, f"{path} is writable by other users"

        if not _is_writable(path):
            return False, f"{path} is not writable by the current user"

        return True, "ok"

    if os.path.lexists(directory):
        return check_existing(directory)

    # The directory doesn't exist yet. Find the nearest existing ancestor and
    # make sure that creating the directory there cannot be redirected by
    # another account.
    ancestor = directory.parent
    while not os.path.lexists(ancestor):
        if ancestor == ancestor.parent:
            return False, f"no existing ancestor for {directory}"
        ancestor = ancestor.parent

    usable, reason = check_existing(ancestor)
    if not usable:
        return False, f"parent {reason}"

    if not create:
        return False, f"{directory} does not exist"

    try:
        directory.mkdir(mode=0o700, parents=True)
    except OSError as e:
        return False, f"cannot create {directory}: {e}"

    # Re-check after creation: another process could have raced us.
    return check_existing(directory)


def _get_pip_cache() -> Path:
    # Unless the cache directory is specifically set by the `--cache-dir` option, we try to share
    # the `pip` HTTP cache
    cmd = [sys.executable, "-m", "pip", "cache", "dir"]
    try:
        process = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as cpe:  # pragma: no cover
        # NOTE: This should only happen if pip's cache has been explicitly disabled,
        # which we check for in the caller (via `PIP_NO_CACHE_DIR`).
        raise ServiceError(f"Failed to query the `pip` HTTP cache directory: {cmd}") from cpe
    cache_dir = process.stdout.decode("utf-8").strip("\n")
    http_cache_dir = Path(cache_dir) / "http"
    return http_cache_dir


def _get_cache_dir(custom_cache_dir: Path | None, *, use_pip: bool = True) -> Path:
    """
    Returns a directory path suitable for HTTP caching.

    The directory is **not** guaranteed to exist.

    `use_pip` tells the function to prefer `pip`'s pre-existing cache,
    **unless** `PIP_NO_CACHE_DIR` is present in the environment.
    """

    # If the user has explicitly requested a directory, pass it through unscathed.
    # Ownership and writability are validated separately, by `_SafeFileCache`.
    if custom_cache_dir is not None:
        return custom_cache_dir

    # Retrieve pip-audit's default internal cache using `platformdirs`.
    pip_audit_cache_dir = user_cache_path("pip-audit", appauthor=False, ensure_exists=True)

    # If the retrieved cache isn't the legacy one, try to delete the old cache if it exists.
    if (
        _PIP_AUDIT_LEGACY_INTERNAL_CACHE.exists()
        and pip_audit_cache_dir != _PIP_AUDIT_LEGACY_INTERNAL_CACHE
    ):
        shutil.rmtree(_PIP_AUDIT_LEGACY_INTERNAL_CACHE)

    # Respect pip's PIP_NO_CACHE_DIR environment setting.
    if use_pip and not os.getenv("PIP_NO_CACHE_DIR"):
        pip_cache_dir = _get_pip_cache() if _PIP_VERSION >= _MINIMUM_PIP_VERSION else None
        if pip_cache_dir is not None:
            return pip_cache_dir
        else:
            logger.warning(
                f"pip {_PIP_VERSION} doesn't support the `cache dir` subcommand, "
                f"using {pip_audit_cache_dir} instead"
            )
            return pip_audit_cache_dir
    else:
        return pip_audit_cache_dir


class _DisabledCache(BaseCache):
    """
    A cache that stores nothing.

    Used when the requested cache directory cannot be trusted: the audit still
    proceeds, but results are never written anywhere (and never read from the
    rejected directory either).
    """

    directory: None = None
    enabled = False

    def get(self, key: str) -> bytes | None:
        return None

    def set(self, key: str, value: bytes, expires: Any | None = None) -> None:
        pass

    def delete(self, key: str) -> None:
        pass


class _SafeFileCache(FileCache):
    """
    A rough mirror of `pip`'s `SafeFileCache` that *should* be runtime-compatible
    with `pip` (i.e., does not interfere with `pip` when it shares the same
    caching directory as a running `pip` process).

    The cache is only enabled when its directory passes `_check_cache_dir`.
    If the directory is unusable at construction time, no cache is used. If it
    becomes unusable later (for example, because its ownership or permissions
    change while the audit is running), the cache disables itself and the
    audit continues without caching; it never falls back to a different
    directory.
    """

    directory: Path
    _disabled: bool

    def __init__(self, directory: Path):
        directory = Path(directory)
        usable, reason = _check_cache_dir(directory, create=True)
        self._logged_warning = False
        self._disabled = not usable

        if usable:
            logger.debug(f"Using cache directory: {directory}")
        else:
            logger.warning(
                f"Cache directory {directory} is unusable ({reason}); "
                "continuing without a cache"
            )

        super().__init__(str(directory))
        self.directory = directory

    @property
    def enabled(self) -> bool:
        return not self._disabled

    def _disable(self, reason: str) -> None:
        if not self._disabled:
            self._disabled = True
            logger.warning(f"Disabling cache directory {self.directory} ({reason})")

    def _check_still_usable(self) -> bool:
        if self._disabled:
            return False

        usable, reason = _check_cache_dir(self.directory, create=False)
        if not usable:
            self._disable(reason)
            return False

        return True

    def get(self, key: str) -> Any | None:
        if not self._check_still_usable():
            return None

        try:
            return super().get(key)
        except Exception as e:  # pragma: no cover
            if not self._logged_warning:
                logger.warning(
                    f"Failed to read from cache directory, performance may be degraded: {e}"
                )
                self._logged_warning = True
            return None

    def set(self, key: str, value: bytes, expires: Any | None = None) -> None:
        if not self._check_still_usable():
            return

        try:
            self._set_impl(key, value)
        except Exception as e:  # pragma: no cover
            if not self._logged_warning:
                logger.warning(
                    f"Failed to write to cache directory, performance may be degraded: {e}"
                )
                self._logged_warning = True

    def _set_impl(self, key: str, value: bytes) -> None:
        name: str = super()._fn(key)

        # Make sure the directory exists
        try:
            os.makedirs(os.path.dirname(name), self.dirmode)
        except OSError:  # pragma: no cover
            pass

        # We don't want to use lock files since `pip` isn't going to recognise those. We should
        # write to the cache in a similar way to how `pip` does it. We create a temporary file,
        # then atomically replace the actual cache key's filename with it. This ensures
        # that other concurrent `pip` or `pip-audit` instances don't read partial data.
        with NamedTemporaryFile(delete=False, dir=os.path.dirname(name)) as io:
            io.write(value)

            # NOTE(ww): Similar to what `pip` does in `adjacent_tmp_file`.
            io.flush()
            os.fsync(io.fileno())

        # NOTE(ww): Windows won't let us rename the temporary file until it's closed,
        # which is why we call `os.replace()` here rather than in the `with` block above.
        os.replace(io.name, name)

    def delete(self, key: str) -> None:  # pragma: no cover
        if not self._check_still_usable():
            return

        try:
            super().delete(key)
        except Exception as e:
            if not self._logged_warning:
                logger.warning(
                    f"Failed to delete file from cache directory, performance may be degraded: {e}"
                )
                self._logged_warning = True


def caching_session(cache_dir: Path | None, *, use_pip: bool = False) -> requests.Session:
    """
    Return a `requests` style session, with suitable caching middleware.

    Uses the given `cache_dir` for the HTTP cache. The directory is only used
    if it is owned by the current user and writable by it; otherwise the
    session proceeds without a cache. The session never switches to a
    different cache directory on its own.

    `use_pip` determines how the fallback cache directory is determined, if `cache_dir` is None.
    When `use_pip` is `False`, `caching_session` will use a `pip-audit` internal cache directory.
    When `use_pip` is `True`, `caching_session` will attempt to discover `pip`'s cache
    directory, falling back on the internal `pip-audit` cache directory if the user's
    version of `pip` is too old.
    """

    # We limit the number of redirects to 5, since the services we connect to
    # should really never redirect more than once or twice.
    inner_session = requests.Session()
    inner_session.max_redirects = 5

    cache: BaseCache
    try:
        cache = _SafeFileCache(_get_cache_dir(cache_dir, use_pip=use_pip))
    except (OSError, ServiceError) as e:
        # Resolving a default cache directory can fail before we ever get to
        # validate one (e.g. the platform cache root isn't writable, or `pip`
        # reports that its cache is disabled). Continue uncached rather than
        # relocating the cache to a directory the task didn't approve.
        logger.warning(f"Failed to initialize cache: {e}; continuing without a cache")
        cache = _DisabledCache()

    return CacheControl(inner_session, cache=cache)
