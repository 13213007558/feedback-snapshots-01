"""Cache Management"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import string
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Mapping

from pip._vendor.packaging.tags import Tag, interpreter_name, interpreter_version
from pip._vendor.packaging.utils import canonicalize_name

from pip._internal.exceptions import CacheProvenanceError, InvalidWheelFilename
from pip._internal.models.direct_url import DirectUrl
from pip._internal.models.link import Link, links_equivalent
from pip._internal.models.wheel import Wheel
from pip._internal.utils.hashes import STRONG_HASHES
from pip._internal.utils.misc import redact_auth_from_url
from pip._internal.utils.temp_dir import TempDirectory, TempDirectoryKind
from pip._internal.utils.urls import path_to_url

logger = logging.getLogger(__name__)

ORIGIN_JSON_NAME = "origin.json"

# Expected digest lengths for the hash algorithms that we accept as content
# evidence for a cached wheel.
_STRONG_HASH_LENGTHS = {"sha256": 64, "sha384": 96, "sha512": 128}

_HEX_DIGITS = frozenset(string.hexdigits)


@dataclass(frozen=True)
class CacheProvenancePolicy:
    """Policy applied when a cached wheel is supposed to be reused.

    ``action`` controls what happens when a cache entry cannot prove that it
    was built from the requested source with a verifiable content digest:

    * ``refetch``: ignore the entry and fetch the source again.
    * ``error``: refuse the installation instead of silently re-fetching.
    """

    action: Literal["refetch", "error"] = "refetch"


@dataclass(frozen=True)
class CacheProvenance:
    """What a cached wheel can say about where it came from."""

    persistent: bool
    # ``None`` means no provenance policy was active, so the evidence was not
    # checked; ``True``/``False`` are the result of an actual check.
    verified: bool | None
    source_url: str | None = None
    source_hashes: Mapping[str, str] | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "used": True,
            "persistent": self.persistent,
        }
        if self.verified is not None:
            result["verified"] = self.verified
        if self.source_url is not None:
            result["source_url"] = redact_auth_from_url(self.source_url)
        if self.source_hashes:
            result["source_hashes"] = dict(self.source_hashes)
        if self.error is not None:
            result["error"] = self.error
        return result


def _urls_match(origin_url: str, source_link: Link) -> bool:
    """Return whether two URLs identify the same source location.

    Fragments are ignored because ``origin.json`` stores the subdirectory
    separately, and credentials are ignored by :func:`links_equivalent`.
    """
    origin_link = Link(origin_url)
    if source_link.is_vcs:
        # ``origin.url`` for VCS sources is the plain repository URL without
        # the ``vcs+`` prefix or the requested revision, so compare the base.
        source = urllib.parse.urlsplit(source_link.url_without_fragment)
        scheme = source.scheme.split("+", 1)[-1]
        path = source.path
        if "@" in path:
            path = path.rsplit("@", 1)[0]
        base_url = urllib.parse.urlunsplit(
            (scheme, source.netloc, path, source.query, "")
        )
        return links_equivalent(Link(base_url), origin_link)
    return links_equivalent(Link(source_link.url_without_fragment), origin_link)


def _strong_hashes(hashes: Mapping[str, str] | None) -> dict[str, str]:
    """Return the usable, strong content hashes from ``hashes``."""
    if not hashes:
        return {}
    usable: dict[str, str] = {}
    for algorithm, digest in hashes.items():
        algorithm = algorithm.lower()
        digest = digest.lower()
        if algorithm not in STRONG_HASHES:
            continue
        if len(digest) != _STRONG_HASH_LENGTHS[algorithm]:
            continue
        if not digest or not set(digest) <= _HEX_DIGITS:
            continue
        usable[algorithm] = digest
    return usable


def _hash_local_file(path: str, algorithms: Mapping[str, str]) -> dict[str, str]:
    """Compute the requested digests of a local file."""
    hashers = {algorithm: hashlib.new(algorithm) for algorithm in algorithms}
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1 << 20), b""):
            for hasher in hashers.values():
                hasher.update(chunk)
    return {algorithm: hasher.hexdigest() for algorithm, hasher in hashers.items()}


def verify_cache_provenance(
    origin: DirectUrl | None,
    source_link: Link,
    *,
    rehash_local_source: bool = True,
) -> tuple[bool, str | None, dict[str, str]]:
    """Check that ``origin`` proves the cache entry came from ``source_link``.

    Returns ``(verified, error, hashes)`` where ``hashes`` are the strong
    content digests recorded in the cache entry. When ``rehash_local_source``
    is true and the source is a local file, its current bytes are hashed too.
    """
    if origin is None:
        return False, "the cache entry has no readable origin.json", {}

    if not _urls_match(origin.url, source_link):
        return (
            False,
            "the recorded origin "
            f"{redact_auth_from_url(origin.url)} does not match the requested "
            f"source {redact_auth_from_url(source_link.url)}",
            {},
        )

    if origin.vcs_info is not None:
        commit_id = origin.vcs_info.commit_id
        if len(commit_id) != 40 or not set(commit_id) <= _HEX_DIGITS:
            return (
                False,
                "the cache entry does not record an immutable revision",
                {},
            )
        # The URL comparison above already checked the repository; the
        # recorded commit identifies the exact source revision.
        return True, None, {}

    if origin.archive_info is None:
        return False, "the cache entry does not record an archive origin", {}

    hashes = _strong_hashes(origin.archive_info.hashes)
    if not hashes:
        return (
            False,
            "the cache entry does not record a strong content hash "
            f"(expected one of {', '.join(STRONG_HASHES)})",
            {},
        )

    if source_link.hash_name is not None and source_link.hash is not None:
        expected = source_link.hash.lower()
        actual = hashes.get(source_link.hash_name.lower())
        if actual is None:
            return (
                False,
                "the requested source is pinned to a "
                f"{source_link.hash_name} hash that the cache entry does not "
                "record",
                hashes,
            )
        if actual != expected:
            return (
                False,
                "the cache entry records a "
                f"{source_link.hash_name} hash that does not match the "
                "requested source",
                hashes,
            )

    if (
        rehash_local_source
        and source_link.is_file
        and not source_link.is_existing_dir()
    ):
        # A local source is available, so the recorded digests can be checked
        # against its current bytes instead of being trusted at face value.
        try:
            actual_hashes = _hash_local_file(source_link.file_path, hashes)
        except OSError as e:
            return False, f"the local source could not be read ({e})", hashes
        if actual_hashes != hashes:
            return (
                False,
                "the cache entry's content hash does not match the current "
                "bytes of the local source",
                hashes,
            )

    return True, None, hashes


def _hash_dict(d: dict[str, str]) -> str:
    """Return a stable sha224 of a dictionary."""
    s = json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha224(s.encode("ascii")).hexdigest()


class Cache:
    """An abstract class - provides cache directories for data from links

    :param cache_dir: The root of the cache.
    """

    def __init__(self, cache_dir: str) -> None:
        super().__init__()
        assert not cache_dir or os.path.isabs(cache_dir)
        self.cache_dir = cache_dir or None

    def _get_cache_path_parts(self, link: Link) -> list[str]:
        """Get parts of part that must be os.path.joined with cache_dir"""

        # We want to generate an url to use as our cache key, we don't want to
        # just reuse the URL because it might have other items in the fragment
        # and we don't care about those.
        key_parts = {"url": link.url_without_fragment}
        if link.hash_name is not None and link.hash is not None:
            key_parts[link.hash_name] = link.hash
        if link.subdirectory_fragment:
            key_parts["subdirectory"] = link.subdirectory_fragment

        # Include interpreter name, major and minor version in cache key
        # to cope with ill-behaved sdists that build a different wheel
        # depending on the python version their setup.py is being run on,
        # and don't encode the difference in compatibility tags.
        # https://github.com/pypa/pip/issues/7296
        key_parts["interpreter_name"] = interpreter_name()
        key_parts["interpreter_version"] = interpreter_version()

        # Encode our key url with sha224, we'll use this because it has similar
        # security properties to sha256, but with a shorter total output (and
        # thus less secure). However the differences don't make a lot of
        # difference for our use case here.
        hashed = _hash_dict(key_parts)

        # We want to nest the directories some to prevent having a ton of top
        # level directories where we might run out of sub directories on some
        # FS.
        parts = [hashed[:2], hashed[2:4], hashed[4:6], hashed[6:]]

        return parts

    def _get_candidates(self, link: Link, canonical_package_name: str) -> list[Any]:
        can_not_cache = not self.cache_dir or not canonical_package_name or not link
        if can_not_cache:
            return []

        path = self.get_path_for_link(link)
        if os.path.isdir(path):
            return [(candidate, path) for candidate in os.listdir(path)]
        return []

    def get_path_for_link(self, link: Link) -> str:
        """Return a directory to store cached items in for link."""
        raise NotImplementedError()

    def get(
        self,
        link: Link,
        package_name: str | None,
        supported_tags: list[Tag],
    ) -> Link:
        """Returns a link to a cached item if it exists, otherwise returns the
        passed link.
        """
        raise NotImplementedError()


class SimpleWheelCache(Cache):
    """A cache of wheels for future installs."""

    def __init__(self, cache_dir: str) -> None:
        super().__init__(cache_dir)

    def get_path_for_link(self, link: Link) -> str:
        """Return a directory to store cached wheels for link

        Because there are M wheels for any one sdist, we provide a directory
        to cache them in, and then consult that directory when looking up
        cache hits.

        We only insert things into the cache if they have plausible version
        numbers, so that we don't contaminate the cache with things that were
        not unique. E.g. ./package might have dozens of installs done for it
        and build a version of 0.0...and if we built and cached a wheel, we'd
        end up using the same wheel even if the source has been edited.

        :param link: The link of the sdist for which this will cache wheels.
        """
        parts = self._get_cache_path_parts(link)
        assert self.cache_dir
        # Store wheels within the root cache_dir
        return os.path.join(self.cache_dir, "wheels", *parts)

    def get(
        self,
        link: Link,
        package_name: str | None,
        supported_tags: list[Tag],
    ) -> Link:
        candidates = []

        if link.is_existing_dir():
            return link
        if not package_name:
            return link

        canonical_package_name = canonicalize_name(package_name)
        supported_tags_set = set(supported_tags)
        for wheel_name, wheel_dir in self._get_candidates(link, canonical_package_name):
            try:
                wheel = Wheel(wheel_name)
            except InvalidWheelFilename:
                continue
            if wheel.name != canonical_package_name:
                logger.debug(
                    "Ignoring cached wheel %s for %s as it "
                    "does not match the expected distribution name %s.",
                    wheel_name,
                    link,
                    package_name,
                )
                continue
            if not wheel.supported(supported_tags_set):
                # Built for a different python/arch/etc
                continue
            candidates.append(
                (
                    wheel.support_index_min(supported_tags),
                    wheel_name,
                    wheel_dir,
                )
            )

        if not candidates:
            return link

        _, wheel_name, wheel_dir = min(candidates)
        return Link(path_to_url(os.path.join(wheel_dir, wheel_name)))


class EphemWheelCache(SimpleWheelCache):
    """A SimpleWheelCache that creates it's own temporary cache directory"""

    def __init__(self) -> None:
        self._temp_dir = TempDirectory(
            kind=TempDirectoryKind.EPHEM_WHEEL_CACHE,
            globally_managed=True,
        )

        super().__init__(self._temp_dir.path)


class CacheEntry:
    def __init__(
        self,
        link: Link,
        persistent: bool,
    ):
        self.link = link
        self.persistent = persistent
        self.origin: DirectUrl | None = None
        self.origin_error: str | None = None
        self.provenance: CacheProvenance | None = None
        origin_direct_url_path = Path(self.link.file_path).parent / ORIGIN_JSON_NAME
        if origin_direct_url_path.exists():
            try:
                self.origin = DirectUrl.from_json(
                    origin_direct_url_path.read_text(encoding="utf-8")
                )
            except Exception as e:
                self.origin_error = f"invalid origin.json ({e})"
                logger.warning(
                    "Ignoring invalid cache entry origin file %s for %s (%s)",
                    origin_direct_url_path,
                    link.filename,
                    e,
                )
        else:
            self.origin_error = "missing origin.json"

    def check_provenance(self, source_link: Link) -> CacheProvenance:
        """Evaluate the evidence recorded for this cache entry."""
        if self.origin_error is not None:
            verified = False
            error = self.origin_error
            hashes: dict[str, str] = {}
        else:
            verified, error, hashes = verify_cache_provenance(
                self.origin, source_link
            )
        return CacheProvenance(
            persistent=self.persistent,
            verified=verified,
            source_url=self.origin.url if self.origin is not None else None,
            source_hashes=hashes or None,
            error=error,
        )

    def describe_origin(self) -> CacheProvenance:
        """Describe the recorded origin without applying any policy."""
        hashes: dict[str, str] = {}
        if self.origin is not None and self.origin.archive_info is not None:
            hashes = _strong_hashes(self.origin.archive_info.hashes)
        return CacheProvenance(
            persistent=self.persistent,
            verified=None,
            source_url=self.origin.url if self.origin is not None else None,
            source_hashes=hashes or None,
        )


class WheelCache(Cache):
    """Wraps EphemWheelCache and SimpleWheelCache into a single Cache

    This Cache allows for gracefully degradation, using the ephem wheel cache
    when a certain link is not found in the simple wheel cache first.
    """

    def __init__(
        self,
        cache_dir: str,
        provenance_policy: CacheProvenancePolicy | None = None,
    ) -> None:
        super().__init__(cache_dir)
        self._wheel_cache = SimpleWheelCache(cache_dir)
        self._ephem_cache = EphemWheelCache()
        self.provenance_policy = provenance_policy

    def get_path_for_link(self, link: Link) -> str:
        return self._wheel_cache.get_path_for_link(link)

    def get_ephem_path_for_link(self, link: Link) -> str:
        return self._ephem_cache.get_path_for_link(link)

    def get(
        self,
        link: Link,
        package_name: str | None,
        supported_tags: list[Tag],
    ) -> Link:
        cache_entry = self.get_cache_entry(link, package_name, supported_tags)
        if cache_entry is None:
            return link
        return cache_entry.link

    def get_cache_entry(
        self,
        link: Link,
        package_name: str | None,
        supported_tags: list[Tag],
    ) -> CacheEntry | None:
        """Returns a CacheEntry with a link to a cached item if it exists or
        None. The cache entry indicates if the item was found in the persistent
        or ephemeral cache.

        When a provenance policy is configured, persistent entries must prove
        they were built from ``link`` with a verifiable content digest. An
        entry that cannot prove this is either ignored (so the source is
        fetched again) or rejected, depending on the configured action.
        """
        retval = self._wheel_cache.get(
            link=link,
            package_name=package_name,
            supported_tags=supported_tags,
        )
        if retval is not link:
            entry = CacheEntry(retval, persistent=True)
            if self.provenance_policy is not None:
                provenance = entry.check_provenance(link)
                entry.provenance = provenance
                if not provenance.verified:
                    reason = (
                        f"Cached wheel for {package_name or link.filename} "
                        f"cannot prove its source ({provenance.error})."
                    )
                    if self.provenance_policy.action == "error":
                        raise CacheProvenanceError(
                            f"{reason} Refusing to use it as requested."
                        )
                    logger.warning(
                        "%s Ignoring it and fetching the source again.", reason
                    )
                    return None
            else:
                # Without an active policy cache hits keep the fast path; the
                # origin is still recorded so reports can name the source.
                entry.provenance = entry.describe_origin()
            return entry

        retval = self._ephem_cache.get(
            link=link,
            package_name=package_name,
            supported_tags=supported_tags,
        )
        if retval is not link:
            return CacheEntry(retval, persistent=False)

        return None

    @staticmethod
    def record_download_origin(cache_dir: str, download_info: DirectUrl) -> None:
        origin_path = Path(cache_dir) / ORIGIN_JSON_NAME
        if origin_path.exists():
            try:
                origin = DirectUrl.from_json(origin_path.read_text(encoding="utf-8"))
            except Exception as e:
                logger.warning(
                    "Could not read origin file %s in cache entry (%s). "
                    "Will attempt to overwrite it.",
                    origin_path,
                    e,
                )
            else:
                # TODO: use DirectUrl.equivalent when
                # https://github.com/pypa/pip/pull/10564 is merged.
                # origin.url is already stripped because it came from the
                # serialized origin.json file.
                download_url = download_info.to_dict_compat()["url"]
                if origin.url != download_url:
                    logger.warning(
                        "Origin URL %s in cache entry %s does not match download URL "
                        "%s. This is likely a pip bug or a cache corruption issue. "
                        "Will overwrite it with the new value.",
                        origin.url,
                        cache_dir,
                        download_url,
                    )
        origin_path.write_text(download_info.to_json(), encoding="utf-8")
