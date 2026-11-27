from __future__ import annotations

__lazy_modules__ = [
    "packaging.pylock",
    "tomllib",
    "tox.tox_env.errors",
]

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

from packaging.pylock import Package, PylockValidationError
from packaging.pylock import Pylock as PackagingPylock

from tox.tox_env.errors import Fail

if TYPE_CHECKING:
    from pathlib import Path

    from packaging.pylock import PackageArchive, PackageVcs


@dataclass(frozen=True, kw_only=True, slots=True)
class LockedArtifact:
    """A source-bearing artifact selected from a lock file."""

    name: str
    version: str | None
    location: str
    hashes: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, kw_only=True, slots=True)
class Pylock:
    """A ``pylock.toml`` lock file, from which the requirements are installed.

    :param path: the path of the lock file
    :param extras: the extras to install from the lock file
    :param groups: the dependency groups to install from the lock file
    :param marker_env: the environment markers to resolve the lock file with

    """

    path: Path
    extras: frozenset[str] = frozenset()
    groups: frozenset[str] = frozenset()
    marker_env: dict[str, str] = field(default_factory=dict)

    def install_lines(self) -> list[str]:
        """Return pip requirement lines for the packages this environment locks.

        :returns: the requirement lines of the locked packages

        :raises Fail: when the lock file cannot be parsed

        """
        try:
            parsed: Final[PackagingPylock] = PackagingPylock.from_dict(
                tomllib.loads(self.path.read_text(encoding="utf-8-sig"))
            )
        except (UnicodeDecodeError, tomllib.TOMLDecodeError, PylockValidationError) as exc:
            msg = f"invalid pylock file {self.path}: {exc}"
            raise Fail(msg) from exc
        # PEP 751: when no dependency groups are selected, the lock's default-groups apply
        groups: Final[frozenset[str]] = self.groups or frozenset(parsed.default_groups or ())
        entries: Final[list[tuple[str, list[str]]]] = [
            self._to_entry(pkg) for pkg in parsed.packages if self._is_active(pkg, groups)
        ]
        if all(hashes for _, hashes in entries):
            # pip's hash-checking mode is all-or-nothing for a requirements file: verify when every line can carry
            # a hash, otherwise fall back to unverified installs (directory/VCS sources cannot be hashed)
            return [f"{line} {' '.join(f'--hash={h}' for h in hashes)}" for line, hashes in entries]
        return [line for line, _ in entries]

    def selected_artifacts(self) -> list[LockedArtifact]:
        """Return source-bearing artifacts for the packages selected by this target environment.

        :returns: locked artifact references
        :raises Fail: when the lock file cannot be parsed
        """
        try:
            parsed: Final[PackagingPylock] = PackagingPylock.from_dict(
                tomllib.loads(self.path.read_text(encoding="utf-8-sig"))
            )
        except (UnicodeDecodeError, tomllib.TOMLDecodeError, PylockValidationError) as exc:
            msg = f"invalid pylock file {self.path}: {exc}"
            raise Fail(msg) from exc
        groups: Final[frozenset[str]] = self.groups or frozenset(parsed.default_groups or ())
        result: list[LockedArtifact] = []
        for pkg in parsed.packages:
            if not self._is_active(pkg, groups):
                continue
            result.extend(self._package_artifacts(pkg))
        return result

    def _package_artifacts(self, pkg: Package) -> list[LockedArtifact]:
        def hash_tuple(values: object) -> tuple[tuple[str, str], ...]:
            if not isinstance(values, Mapping):
                return ()
            return tuple(sorted((str(key).lower(), str(value)) for key, value in values.items()))

        version = str(pkg.version) if pkg.version is not None else None
        if pkg.archive is not None:
            return [
                LockedArtifact(
                    name=str(pkg.name),
                    version=version,
                    location=self._to_archive_url(pkg.archive),
                    hashes=hash_tuple(pkg.archive.hashes),
                )
            ]
        if pkg.wheels:
            wheel = self._select_wheel(pkg)
            wheel_location = wheel.path or wheel.filename or str(pkg.name)
            location = wheel.url if wheel.url is not None else self._to_uri(wheel_location)
            return [
                LockedArtifact(
                    name=str(pkg.name),
                    version=version,
                    location=location,
                    hashes=hash_tuple(wheel.hashes),
                )
            ]
        if pkg.sdist is not None:
            source = pkg.sdist
            location = getattr(source, "url", None)
            source_path = getattr(source, "path", None)
            if location is None and source_path:
                location = self._to_uri(source_path)
            if location is None:
                location = str(pkg.name)
            return [
                LockedArtifact(
                    name=str(pkg.name),
                    version=version,
                    location=location,
                    hashes=hash_tuple(getattr(source, "hashes", None)),
                )
            ]
        if pkg.directory is not None:
            return [
                LockedArtifact(
                    name=str(pkg.name),
                    version=version,
                    location=self._to_uri(pkg.directory.path, pkg.directory.subdirectory),
                )
            ]
        if pkg.vcs is not None:
            return [LockedArtifact(name=str(pkg.name), version=version, location=self._to_vcs_url(pkg.vcs))]
        return [LockedArtifact(name=str(pkg.name), version=version, location=str(pkg.name))]

    def _select_wheel(self, pkg: Package) -> Any:
        wheels = pkg.wheels or ()
        if len(wheels) == 1:
            return wheels[0]
        # Pylock callers that need deterministic cross-host wheel selection use Pylock.select. The install path
        # has the host tags available through pip; for approval evidence prefer an architecture-independent wheel.
        for wheel in wheels:
            filename = wheel.filename
            if "-none-any.whl" in filename:
                return wheel
        return wheels[0]

    def _to_entry(self, pkg: Package) -> tuple[str, list[str]]:
        if pkg.directory is not None:
            uri: Final[str] = self._to_uri(pkg.directory.path, pkg.directory.subdirectory)
            return (f"-e {uri}" if pkg.directory.editable else f"{pkg.name} @ {uri}"), []
        if pkg.vcs is not None:
            vcs: Final[PackageVcs] = pkg.vcs
            self._check_tokens(
                pkg,
                {
                    "vcs type": vcs.type,
                    "vcs url": vcs.url,
                    "vcs commit-id": vcs.commit_id,
                    "vcs subdirectory": vcs.subdirectory or None,
                },
            )
            return f"{pkg.name} @ {self._to_vcs_url(vcs)}", []
        if pkg.archive is not None:
            archive: Final[PackageArchive] = pkg.archive
            self._check_tokens(pkg, {"archive url": archive.url, "archive subdirectory": archive.subdirectory or None})
            return f"{pkg.name} @ {self._to_archive_url(archive)}", self._hash_options(pkg, archive.hashes)
        hashes: Final[list[str]] = [
            h
            for dist in (pkg.sdist, *(pkg.wheels or []))
            if dist is not None
            for h in self._hash_options(pkg, dist.hashes)
        ]
        return (str(pkg.name) if pkg.version is None else f"{pkg.name}=={pkg.version}"), hashes

    def _to_uri(self, path: str | Path, subdirectory: str | None = None) -> str:
        # PEP 751 stores paths relative to the lock file; the subdirectory is the project root within it
        target = self.path.parent / path
        if subdirectory is not None:
            target /= subdirectory
        return target.resolve().as_uri()

    def _check_tokens(self, pkg: Package, fields: Mapping[str, str | None]) -> None:
        # pip reads whitespace here as another requirement or option.
        for name, value in fields.items():
            if value is not None and (not value or any(char.isspace() or not char.isprintable() for char in value)):
                msg = (
                    f"invalid pylock file {self.path}: package {pkg.name!r} {name} {value!r}"
                    " must be non-empty and contain no whitespace or control characters"
                )
                raise Fail(msg)

    def _to_vcs_url(self, vcs: PackageVcs) -> str:
        location: Final[str] = vcs.url if vcs.url is not None else self._to_uri(vcs.path or ".")
        url: Final[str] = f"{vcs.type}+{location}@{vcs.commit_id}"
        return url if vcs.subdirectory is None else f"{url}#subdirectory={vcs.subdirectory}"

    def _to_archive_url(self, archive: PackageArchive) -> str:
        url: Final[str] = archive.url if archive.url is not None else self._to_uri(archive.path or ".")
        return url if archive.subdirectory is None else f"{url}#subdirectory={archive.subdirectory}"

    def _hash_options(self, pkg: Package, hashes: Mapping[str, str] | None) -> list[str]:
        options: Final[list[str]] = []
        for algorithm, value in (hashes or {}).items():
            self._check_tokens(pkg, {"hash algorithm": algorithm, f"{algorithm} hash": value})
            options.append(f"{algorithm}:{value}")
        return options

    def _is_active(self, pkg: Package, groups: frozenset[str]) -> bool:
        env: dict[str, str | frozenset[str]] = {**self.marker_env}
        if self.extras:
            env["extras"] = self.extras
        if groups:
            env["dependency_groups"] = groups
        if pkg.marker is not None and not pkg.marker.evaluate(env, context="lock_file"):
            return False
        full_version = self.marker_env.get("python_full_version")
        if pkg.requires_python is not None and full_version is not None:
            return pkg.requires_python.contains(full_version, prereleases=True)
        return True


__all__ = [
    "LockedArtifact",
    "Pylock",
]
