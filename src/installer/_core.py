"""Core wheel installation logic."""

import posixpath
import warnings
from collections.abc import Collection
from dataclasses import dataclass
from io import BytesIO
from typing import TYPE_CHECKING, Literal, cast

from installer.destinations import WheelDestination
from installer.exceptions import (
    InvalidWheelSource,
    MissingRequirement,
    UninstallableDistribution,
)
from installer.records import RecordEntry
from installer.sources import WheelSource
from installer.utils import SCHEME_NAMES, Scheme, parse_entrypoints, parse_metadata_file

if TYPE_CHECKING:
    from installer.scripts import ScriptSection

__all__ = [
    "OmittedMember",
    "PartialInstallResult",
    "install",
    "install_partial",
]

_LIBRARY_SCHEMES = frozenset(("purelib", "platlib"))


@dataclass(frozen=True)
class OmittedMember:
    """A wheel member intentionally left out of an installation.

    The values describe the location the member *would* have been written to,
    after applying the wheel's ``.data`` relocation rules.
    """

    scheme: Scheme
    """Installation scheme that would have received the member."""

    path: str
    """Path within ``scheme`` that would have received the member."""

    source_path: str
    """Path of the member inside the wheel archive."""

    kind: Literal["file", "entry_point"] = "file"
    """Kind of omitted member."""


@dataclass(frozen=True)
class PartialInstallResult:
    """Outcome of a partial installation.

    :attr:`record_entries` is the exact list passed to
    :any:`WheelDestination.finalize_installation`. Callers can therefore
    reconcile the ``RECORD`` written by the destination with
    :attr:`omitted`: omitted members never appear in either.
    """

    distribution: str
    """Name of the installed distribution."""

    version: str
    """Version of the installed distribution."""

    approved_schemes: frozenset[Scheme]
    """Schemes that were allowed to receive files."""

    omitted: tuple[OmittedMember, ...]
    """Members skipped because they were optional and unapproved."""

    record_file_path: str
    """Path of the completion record within the root scheme."""

    record_entries: tuple[tuple[Scheme, RecordEntry], ...]
    """Entries passed to the destination when writing the completion record."""


@dataclass(frozen=True)
class _PlannedFile:
    source_path: str
    scheme: Scheme
    path: str
    is_executable: bool


@dataclass(frozen=True)
class _PlannedScript:
    name: str
    module: str
    attr: str
    section: "ScriptSection"


@dataclass(frozen=True)
class _InstallPlan:
    root_scheme: Scheme
    approved_schemes: frozenset[Scheme]
    record_file_path: str
    files_by_source_path: dict[str, _PlannedFile]
    skipped_source_paths: frozenset[str]
    scripts: tuple[_PlannedScript, ...]
    additional_metadata: tuple[tuple[str, bytes], ...]
    omitted: tuple[OmittedMember, ...]
    missing: tuple[MissingRequirement, ...]


def _process_WHEEL_file(source: WheelSource) -> Scheme:  # noqa: N802
    """Process the WHEEL file, from ``source``.

    Returns the scheme that the archive root should go in.
    """
    stream = source.read_dist_info("WHEEL")
    metadata = parse_metadata_file(stream)

    # Ensure compatibility with this wheel version.
    if not (metadata["Wheel-Version"] and metadata["Wheel-Version"].startswith("1.")):
        message = "Incompatible Wheel-Version {}, only support version 1.x wheels."
        raise InvalidWheelSource(source, message.format(metadata["Wheel-Version"]))

    # Determine where archive root should go.
    if metadata["Root-Is-Purelib"] == "true":
        return cast("Scheme", "purelib")
    else:
        return cast("Scheme", "platlib")


def _determine_scheme(
    path: str, source: WheelSource, root_scheme: Scheme
) -> tuple[Scheme, str]:
    """Determine which scheme to place given path in, from source."""
    data_dir = source.data_dir

    # If it's in not `{distribution}-{version}.data`, then it's in root_scheme.
    if posixpath.commonpath([data_dir, path]) != data_dir:
        return root_scheme, path

    # Figure out which scheme this goes to.
    parts = []
    scheme_name = None
    left = path
    while True:
        left, right = posixpath.split(left)
        parts.append(right)
        if left == source.data_dir:
            scheme_name = right
            break

    if scheme_name not in SCHEME_NAMES:
        msg_fmt = "{path} is not contained in a valid .data subdirectory."
        raise InvalidWheelSource(source, msg_fmt.format(path=path))

    return cast("Scheme", scheme_name), posixpath.join(*reversed(parts[:-1]))


def _normalise_schemes(schemes: Collection[str]) -> frozenset[Scheme]:
    unknown = sorted(set(schemes) - set(SCHEME_NAMES))
    if unknown:
        message = (
            f"Unknown installation scheme(s): {', '.join(unknown)}. "
            f"Valid schemes are: {', '.join(SCHEME_NAMES)}."
        )
        raise ValueError(message)
    return frozenset(cast("Scheme", scheme) for scheme in schemes)


def _plan_installation(
    source: WheelSource,
    additional_metadata: dict[str, bytes],
    *,
    approved_schemes: frozenset[Scheme],
    optional_schemes: frozenset[Scheme],
    optional_members: frozenset[str],
) -> _InstallPlan:
    root_scheme = _process_WHEEL_file(source)
    record_file_path = posixpath.join(source.dist_info_dir, "RECORD")

    missing: list[MissingRequirement] = []
    omitted: list[OmittedMember] = []
    planned_files: list[_PlannedFile] = []
    planned_scripts: list[_PlannedScript] = []

    # Entry points generate launchers in the "scripts" scheme, regardless of
    # where the distribution's library content lives.
    if "entry_points.txt" in source.dist_info_filenames:
        entry_points_text = source.read_dist_info("entry_points.txt")
        for name, module, attr, section in parse_entrypoints(entry_points_text):
            if "scripts" in approved_schemes:
                planned_scripts.append(
                    _PlannedScript(
                        name=name,
                        module=module,
                        attr=attr,
                        section=section,
                    )
                )
            else:
                missing.append(
                    MissingRequirement(
                        kind="entry_point",
                        name=name,
                        scheme="scripts",
                        path=name,
                    )
                )

    for record_elements, _stream, is_executable in source.get_contents():
        source_record = RecordEntry.from_elements(*record_elements)
        source_path = source_record.path

        # The archive's RECORD is replaced by the one written at the end.
        if source_path == record_file_path:
            continue

        if "__pycache__" in source_path.split("/")[:-1]:
            continue

        scheme, path = _determine_scheme(
            path=source_path,
            source=source,
            root_scheme=root_scheme,
        )

        if scheme in approved_schemes:
            planned_files.append(
                _PlannedFile(
                    source_path=source_path,
                    scheme=scheme,
                    path=path,
                    is_executable=is_executable,
                )
            )
        elif scheme in _LIBRARY_SCHEMES:
            # Skipping library content would leave a distribution that cannot
            # be imported, even if the caller marked the scheme as optional.
            missing.append(
                MissingRequirement(
                    kind="library",
                    name=source_path,
                    scheme=scheme,
                    path=path,
                )
            )
        elif scheme in optional_schemes or source_path in optional_members:
            omitted.append(
                OmittedMember(
                    scheme=scheme,
                    path=path,
                    source_path=source_path,
                )
            )
        else:
            missing.append(
                MissingRequirement(
                    kind="member",
                    name=source_path,
                    scheme=scheme,
                    path=path,
                )
            )

    planned_metadata: list[tuple[str, bytes]] = []
    for filename, contents in additional_metadata.items():
        path = posixpath.join(source.dist_info_dir, filename)
        if root_scheme in approved_schemes:
            planned_metadata.append((path, contents))
        else:
            missing.append(
                MissingRequirement(
                    kind="metadata",
                    name=filename,
                    scheme=root_scheme,
                    path=path,
                )
            )

    if root_scheme not in approved_schemes:
        missing.append(
            MissingRequirement(
                kind="record",
                name=record_file_path,
                scheme=root_scheme,
                path=record_file_path,
            )
        )

    return _InstallPlan(
        root_scheme=root_scheme,
        approved_schemes=approved_schemes,
        record_file_path=record_file_path,
        files_by_source_path={
            planned_file.source_path: planned_file for planned_file in planned_files
        },
        skipped_source_paths=frozenset(
            omitted_member.source_path for omitted_member in omitted
        ),
        scripts=tuple(planned_scripts),
        additional_metadata=tuple(planned_metadata),
        omitted=tuple(omitted),
        missing=tuple(missing),
    )


def _write_plan(
    source: WheelSource,
    destination: WheelDestination,
    plan: _InstallPlan,
) -> PartialInstallResult:
    written_records: list[tuple[Scheme, RecordEntry]] = []

    for script in plan.scripts:
        record = destination.write_script(
            name=script.name,
            module=script.module,
            attr=script.attr,
            section=script.section,
        )
        written_records.append((Scheme("scripts"), record))

    for record_elements, stream, is_executable in source.get_contents():
        source_record = RecordEntry.from_elements(*record_elements)
        source_path = source_record.path

        if source_path == plan.record_file_path:
            continue

        if "__pycache__" in source_path.split("/")[:-1]:
            warnings.warn(
                (
                    f"Skip installing {source_path} from {source.distribution}."
                    " Installing files in a __pycache__ directory poses a security risk."
                    " __pycache__ directories should not be included in wheels."
                    f" This is probably an issue in the build process of '{source.distribution}'."
                ),
                RuntimeWarning,
                stacklevel=2,
            )
            continue

        planned_file = plan.files_by_source_path.get(source_path)
        if planned_file is None:
            if source_path in plan.skipped_source_paths:
                continue
            raise InvalidWheelSource(
                source,
                f"{source_path} changed between planning and installation",
            )

        record = destination.write_file(
            scheme=planned_file.scheme,
            path=planned_file.path,
            stream=stream,
            is_executable=planned_file.is_executable,
        )
        written_records.append((planned_file.scheme, record))

    for path, contents in plan.additional_metadata:
        with BytesIO(contents) as other_stream:
            record = destination.write_file(
                scheme=plan.root_scheme,
                path=path,
                stream=other_stream,
                is_executable=False,
            )
        written_records.append((plan.root_scheme, record))

    written_records.append(
        (plan.root_scheme, RecordEntry(plan.record_file_path, None, None))
    )
    destination.finalize_installation(
        scheme=plan.root_scheme,
        record_file_path=plan.record_file_path,
        records=written_records,
    )

    return PartialInstallResult(
        distribution=source.distribution,
        version=source.version,
        approved_schemes=plan.approved_schemes,
        omitted=plan.omitted,
        record_file_path=plan.record_file_path,
        record_entries=tuple(written_records),
    )


def _install_full(
    source: WheelSource,
    destination: WheelDestination,
    additional_metadata: dict[str, bytes],
) -> None:
    root_scheme = _process_WHEEL_file(source)

    # RECORD handling
    record_file_path = posixpath.join(source.dist_info_dir, "RECORD")
    written_records = []

    # Write the entry_points based scripts.
    if "entry_points.txt" in source.dist_info_filenames:
        entrypoints_text = source.read_dist_info("entry_points.txt")
        for name, module, attr, section in parse_entrypoints(entrypoints_text):
            record = destination.write_script(
                name=name,
                module=module,
                attr=attr,
                section=section,
            )
            written_records.append((Scheme("scripts"), record))

    # Write all the files from the wheel.
    for record_elements, stream, is_executable in source.get_contents():
        source_record = RecordEntry.from_elements(*record_elements)
        path = source_record.path
        # Skip the RECORD, which is written at the end, based on this info.
        if path == record_file_path:
            continue

        if "__pycache__" in path.split("/")[:-1]:
            warnings.warn(
                (
                    f"Skip installing {path} from {source.distribution}."
                    " Installing files in a __pycache__ directory poses a security risk."
                    " __pycache__ directories should not be included in wheels."
                    f" This is probably an issue in the build process of '{source.distribution}'."
                ),
                RuntimeWarning,
                stacklevel=2,
            )
            continue

        # Figure out where to write this file.
        scheme, destination_path = _determine_scheme(
            path=path,
            source=source,
            root_scheme=root_scheme,
        )
        record = destination.write_file(
            scheme=scheme,
            path=destination_path,
            stream=stream,
            is_executable=is_executable,
        )
        written_records.append((scheme, record))

    # Write all the installation-specific metadata
    for filename, contents in additional_metadata.items():
        path = posixpath.join(source.dist_info_dir, filename)

        with BytesIO(contents) as other_stream:
            record = destination.write_file(
                scheme=root_scheme,
                path=path,
                stream=other_stream,
                is_executable=False,
            )
        written_records.append((root_scheme, record))

    written_records.append((root_scheme, RecordEntry(record_file_path, None, None)))
    destination.finalize_installation(
        scheme=root_scheme,
        record_file_path=record_file_path,
        records=written_records,
    )


def install(
    source: WheelSource,
    destination: WheelDestination,
    additional_metadata: dict[str, bytes],
    *,
    approved_schemes: Collection[str] | None = None,
    optional_schemes: Collection[str] = (),
    optional_members: Collection[str] = (),
) -> PartialInstallResult | None:
    """Install wheel described by ``source`` into ``destination``.

    When ``approved_schemes`` is omitted, this performs a full installation and
    returns ``None`` -- the original behaviour.

    When ``approved_schemes`` is provided, this delegates to
    :any:`install_partial` and returns its :any:`PartialInstallResult`.

    :param source: wheel to install.
    :param destination: where to write the wheel.
    :param additional_metadata: additional metadata files to generate, usually
                                generated by the caller.
    :param approved_schemes: schemes that may receive files. Defaults to all.
    :param optional_schemes: schemes whose unapproved members may be omitted.
    :param optional_members: wheel member paths that may be omitted when their
        scheme is not approved.
    """
    if approved_schemes is None:
        if optional_schemes or optional_members:
            raise ValueError(
                "optional_schemes and optional_members require approved_schemes"
            )
        _install_full(source, destination, additional_metadata)
        return None

    return install_partial(
        source,
        destination,
        additional_metadata,
        approved_schemes=approved_schemes,
        optional_schemes=optional_schemes,
        optional_members=optional_members,
    )


def install_partial(
    source: WheelSource,
    destination: WheelDestination,
    additional_metadata: dict[str, bytes],
    *,
    approved_schemes: Collection[str],
    optional_schemes: Collection[str] = (),
    optional_members: Collection[str] = (),
) -> PartialInstallResult:
    """Install approved parts of a wheel when they still form a usable install.

    Callers list the schemes they allow to receive files. They may also list
    ``optional_schemes`` and/or ``optional_members`` (wheel member paths). When
    such a member is not approved, it is skipped and reported in
    :attr:`PartialInstallResult.omitted`. Skipped members are not added to the
    destination's ``RECORD``.

    Library schemes (``purelib`` and ``platlib``) are never treated as
    optional. Entry points are required whenever the wheel advertises them,
    because they are part of the functionality promised by the distribution.
    If a required library member, entry point, installation metadata file, or
    the completion record cannot be written, this raises
    :any:`UninstallableDistribution` *before* touching ``destination``.

    The same ``WheelSource`` is iterated twice: once to plan and admit the
    installation, and once to write it. Sources must therefore support the
    repeatable iteration required by :any:`WheelSource.get_contents`.

    :param source: wheel to install.
    :param destination: where to write the approved files.
    :param additional_metadata: additional metadata files to generate.
    :param approved_schemes: schemes that may receive files.
    :param optional_schemes: schemes whose unapproved members may be omitted.
    :param optional_members: wheel member paths that may be omitted when their
        scheme is not approved. Library members are always required.
    :return: what was installed and what was omitted.
    :raises UninstallableDistribution: if a required part cannot be installed.
    """
    approved = _normalise_schemes(approved_schemes)
    optional = _normalise_schemes(optional_schemes)

    plan = _plan_installation(
        source,
        additional_metadata,
        approved_schemes=approved,
        optional_schemes=optional,
        optional_members=frozenset(optional_members),
    )
    if plan.missing:
        raise UninstallableDistribution(
            distribution=source.distribution,
            version=source.version,
            missing=plan.missing,
        )

    return _write_plan(source, destination, plan)
