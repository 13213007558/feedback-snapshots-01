"""Handles all file writing and post-installation processing."""

import contextlib
import importlib.util
import io
import os
import shutil
import struct
import tempfile
from collections.abc import Collection, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    BinaryIO,
    Union,
    cast,
)

from installer.exceptions import BytecodeCompilationError
from installer.records import Hash, RecordEntry, parse_record_file
from installer.scripts import Script
from installer.utils import (
    _WINDOWS,
    Scheme,
    construct_record_file,
    copyfileobj_with_hashing,
    fix_shebang,
    make_file_executable,
    parse_metadata_file,
)

if TYPE_CHECKING:
    from installer.scripts import LauncherKind, ScriptSection

__all__ = [
    "ADMITTED",
    "BYTECODE_CURRENT",
    "BYTECODE_MISSING",
    "BYTECODE_STALE",
    "INCOMPLETE",
    "NOT_INSTALLED",
    "BytecodeArtifact",
    "InstallationReport",
    "SchemeDictionaryDestination",
    "WheelDestination",
    "inspect_installation",
]

ADMITTED = "admitted"
"""The distribution was fully installed, including all required bytecode."""

NOT_INSTALLED = "not_installed"
"""There is no ``RECORD`` for the distribution: no install was ever admitted."""

INCOMPLETE = "incomplete"
"""A ``RECORD`` exists, but the on-disk files or bytecode no longer match it."""

BYTECODE_CURRENT = "current"
"""The cached bytecode is bound to the current source file."""

BYTECODE_MISSING = "missing"
"""Required cached bytecode does not exist."""

BYTECODE_STALE = "stale"
"""Cached bytecode exists, but it was produced from different source content."""


@dataclass(frozen=True)
class BytecodeArtifact:
    """State of one cached bytecode file, derived from the artifact itself."""

    source: str
    """Path of the ``.py`` file, as recorded in ``RECORD``."""

    optimization_level: int
    """Optimization level this bytecode was compiled for."""

    path: Path
    """Expected location of the cached bytecode file."""

    state: str
    """One of :data:`BYTECODE_CURRENT`, :data:`BYTECODE_MISSING` or
    :data:`BYTECODE_STALE`."""


@dataclass(frozen=True)
class InstallationReport:
    """A description of an installation, verified from the installed artifacts.

    This is computed by reading ``RECORD``, hashing the installed files and
    inspecting the headers of the cached bytecode files. It does not trust any
    in-memory state, so it can be used to audit a directory after the process
    that performed the installation has exited.
    """

    status: str
    """One of :data:`ADMITTED`, :data:`NOT_INSTALLED` or :data:`INCOMPLETE`."""

    record_path: Path | None
    """Location of the ``RECORD`` file backing this report, if any."""

    distribution: str | None
    """Distribution name read from the accompanying ``METADATA`` file."""

    version: str | None
    """Version read from the accompanying ``METADATA`` file."""

    official_files: dict[str, RecordEntry]
    """Entries of the last admitted install, keyed by their ``RECORD`` path.

    These are the only files that count as the result of a successful install.
    """

    bytecode: tuple[BytecodeArtifact, ...]
    """Expected cached bytecode for the files in :attr:`official_files`."""

    unexpected_bytecode: tuple[Path, ...]
    """Cached bytecode found in the target directories that is not owned by this
    installation, such as leftovers from other installs."""

    issues: tuple[str, ...]
    """Human-readable problems that prevented admission, if any."""


class WheelDestination:
    """Handles writing the unpacked files, script generation and ``RECORD`` generation.

    Subclasses provide the concrete script generation logic, as well as the RECORD file
    (re)writing.
    """

    def write_script(
        self, name: str, module: str, attr: str, section: "ScriptSection"
    ) -> RecordEntry:
        """Write a script in the correct location to invoke given entry point.

        :param name: name of the script
        :param module: module path, to load the entry point from
        :param attr: final attribute access, for the entry point
        :param section: Denotes the "entry point section" where this was specified.
            Valid values are ``"gui"`` and ``"console"``.
        :type section: str

        Example usage/behaviour::

            >>> dest.write_script("pip", "pip._internal.cli", "main", "console")

        """
        raise NotImplementedError

    def write_file(
        self,
        scheme: Scheme,
        path: Union[str, "os.PathLike[str]"],
        stream: BinaryIO,
        is_executable: bool,
    ) -> RecordEntry:
        """Write a file to correct ``path`` within the ``scheme``.

        :param scheme: scheme to write the file in (like "purelib", "platlib" etc).
        :param path: path within that scheme
        :param stream: contents of the file
        :param is_executable: whether the file should be made executable

        The stream would be closed by the caller, after this call.

        Example usage/behaviour::

            >>> with open("__init__.py") as stream:
            ...     dest.write_file("purelib", "pkg/__init__.py", stream)

        """
        raise NotImplementedError

    def finalize_installation(
        self,
        scheme: Scheme,
        record_file_path: str,
        records: Iterable[tuple[Scheme, RecordEntry]],
    ) -> None:
        """Finalize installation, after all the files are written.

        Handles (re)writing of the ``RECORD`` file.

        :param scheme: scheme to write the ``RECORD`` file in
        :param record_file_path: path of the ``RECORD`` file with that scheme
        :param records: entries to write to the ``RECORD`` file

        Example usage/behaviour::

            >>> dest.finalize_installation("purelib")

        """
        raise NotImplementedError


@dataclass
class SchemeDictionaryDestination(WheelDestination):
    """Destination, based on a mapping of {scheme: file-system-path}."""

    scheme_dict: dict[str, str]
    """A mapping of {scheme: file-system-path}"""

    interpreter: str
    """The interpreter to use for generating scripts."""

    script_kind: "LauncherKind"
    """The "kind" of launcher script to use."""

    hash_algorithm: str = "sha256"
    """
    The hashing algorithm to use, which is a member of
    :any:`hashlib.algorithms_available` (ideally from
    :any:`hashlib.algorithms_guaranteed`).
    """

    bytecode_optimization_levels: Collection[int] = ()
    """
    Compile cached bytecode for installed .py files with these optimization
    levels. The bytecode is specific to the minor version of Python (e.g. 3.10)
    used to generate it.
    """

    destdir: str | None = None
    """
    A staging directory in which to write all files. This is expected to be the
    filesystem root at runtime, so embedded paths will be written as though
    this was the root.
    """

    overwrite_existing: bool = False
    """Silently overwrite existing files."""

    _created_files: list[Path] = field(
        default_factory=list, init=False, repr=False, compare=False
    )
    _created_dirs: list[Path] = field(
        default_factory=list, init=False, repr=False, compare=False
    )
    _backed_up_files: dict[Path, Path] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _work_dir: Path | None = field(default=None, init=False, repr=False, compare=False)
    _staged_index: int = field(default=0, init=False, repr=False, compare=False)

    def _path_with_destdir(self, scheme: Scheme, path: str) -> Path:
        # See https://docs.python.org/3/library/zipfile.html#zipfile.Path:
        #  When handling untrusted archives,
        #  consider resolving filenames using os.path.abspath()
        #  and checking against the target directory with os.path.commonpath().
        #
        # Attention: Path.absolute() is not sufficient because it does not
        #  normalize, i.e. does not remove "..".
        #
        # We want to avoid Path.resolve() because it is significantly slower
        # than os.path.abspath()!
        target_dir = Path(os.path.abspath(self.scheme_dict[scheme]))  # noqa: PTH100
        file = Path(os.path.abspath(target_dir / path))  # noqa: PTH100

        if not file.is_relative_to(target_dir):
            raise ValueError(
                f"Attempting to write {path} outside of the target directory"
            )

        if self.destdir is not None:
            rel_path = file.relative_to(file.anchor)
            return Path(self.destdir) / rel_path
        return file

    def write_to_fs(
        self,
        scheme: Scheme,
        path: str,
        stream: BinaryIO,
        is_executable: bool,
    ) -> RecordEntry:
        """Write contents of ``stream`` to the correct location on the filesystem.

        :param scheme: scheme to write the file in (like "purelib", "platlib" etc).
        :param path: path within that scheme
        :param stream: contents of the file
        :param is_executable: whether the file should be made executable

        - Ensures that an existing file is not being overwritten.
        - Hashes the written content, to determine the entry in the ``RECORD`` file.
        """
        target_path = self._path_with_destdir(scheme, path)
        if not self.overwrite_existing and target_path.exists():
            message = f"File already exists: {target_path!s}"
            raise FileExistsError(message)

        self._ensure_parent(target_path.parent)
        self._track_target(target_path)

        with target_path.open("wb") as f:
            hash_, size = copyfileobj_with_hashing(stream, f, self.hash_algorithm)

        if is_executable:
            make_file_executable(target_path)

        return RecordEntry(path, Hash(self.hash_algorithm, hash_), size)

    def write_file(
        self,
        scheme: Scheme,
        path: Union[str, "os.PathLike[str]"],
        stream: BinaryIO,
        is_executable: bool,
    ) -> RecordEntry:
        """Write a file to correct ``path`` within the ``scheme``.

        :param scheme: scheme to write the file in (like "purelib", "platlib" etc).
        :param path: path within that scheme
        :param stream: contents of the file
        :param is_executable: whether the file should be made executable

        - Changes the shebang for files in the "scripts" scheme.
        - Uses :py:meth:`SchemeDictionaryDestination.write_to_fs` for the
          filesystem interaction.
        """
        path_ = os.fspath(path)

        if scheme == "scripts":
            with fix_shebang(stream, self.interpreter) as stream_with_different_shebang:
                return self.write_to_fs(
                    scheme, path_, stream_with_different_shebang, is_executable
                )

        return self.write_to_fs(scheme, path_, stream, is_executable)

    def write_script(
        self, name: str, module: str, attr: str, section: "ScriptSection"
    ) -> RecordEntry:
        """Write a script to invoke an entrypoint.

        :param name: name of the script
        :param module: module path, to load the entry point from
        :param attr: final attribute access, for the entry point
        :param section: Denotes the "entry point section" where this was specified.
            Valid values are ``"gui"`` and ``"console"``.
        :type section: str

        - Generates a launcher using :any:`Script.generate`.
        - Writes to the "scripts" scheme.
        - Uses :py:meth:`SchemeDictionaryDestination.write_to_fs` for the
          filesystem interaction.
        """
        script = Script(name, module, attr, section)
        script_name, data = script.generate(self.interpreter, self.script_kind)

        with io.BytesIO(data) as stream:
            entry = self.write_to_fs(
                Scheme("scripts"), script_name, stream, is_executable=True
            )

            path = self._path_with_destdir(Scheme("scripts"), script_name)
            mode = path.stat().st_mode
            mode |= (mode & 0o444) >> 2
            path.chmod(mode)

            return entry

    def _ensure_parent(self, parent: Path) -> None:
        if parent.exists():
            return

        missing = []
        current = parent
        while not current.exists():
            missing.append(current)
            if current == current.parent:
                break
            current = current.parent

        parent.mkdir(parents=True, exist_ok=True)
        self._created_dirs.extend(reversed(missing))

    def _track_target(self, target_path: Path, *, force_backup: bool = False) -> None:
        """Record ``target_path`` so that it can be restored or removed on failure.

        An existing file is moved aside into a backup location instead of being
        overwritten, so a failed installation can put the previous bytes back.
        Bytecode artifacts are backed up even when ``overwrite_existing`` is
        false: bytecode is not part of the wheel, so an existing ``.pyc`` must
        never abort an install, nor be trusted as this job's result.
        """
        if target_path in self._backed_up_files or target_path in self._created_files:
            return

        if target_path.exists():
            if not (self.overwrite_existing or force_backup):
                return
            backup = self._work_directory() / "backup" / str(len(self._backed_up_files))
            backup.parent.mkdir(parents=True, exist_ok=True)
            target_path.replace(backup)
            self._backed_up_files[target_path] = backup
        else:
            self._created_files.append(target_path)

    def _work_directory(self) -> Path:
        if self._work_dir is None:
            self._work_dir = Path(tempfile.mkdtemp(prefix="installer-"))
        return self._work_dir

    def _rollback(self) -> None:
        """Undo everything written by this installation attempt."""
        for path in reversed(self._created_files):
            with contextlib.suppress(OSError):
                path.unlink()

        for path, backup in reversed(list(self._backed_up_files.items())):
            with contextlib.suppress(OSError):
                if path.exists():
                    path.unlink()
                if backup.exists():
                    backup.replace(path)

        for path in reversed(self._created_dirs):
            with contextlib.suppress(OSError):
                path.rmdir()

        self._created_files.clear()
        self._backed_up_files.clear()
        self._created_dirs.clear()

    def _cleanup_work_directory(self) -> None:
        if self._work_dir is not None:
            shutil.rmtree(self._work_dir, ignore_errors=True)
            self._work_dir = None

    def _source_targets(
        self, records: Iterable[tuple[Scheme, RecordEntry]]
    ) -> list[tuple[Scheme, RecordEntry, Path]]:
        """Return ``(scheme, record, source path)`` for compilable files."""
        if not self.bytecode_optimization_levels:
            return []

        targets = []
        for scheme, record in records:
            if scheme not in ("purelib", "platlib"):
                continue
            if not record.path.endswith(".py"):
                continue
            targets.append(
                (scheme, record, self._path_with_destdir(scheme, record.path))
            )
        return targets

    def _bytecode_plan(
        self, scheme: Scheme, record: RecordEntry, source: Path
    ) -> list[tuple[Path, Path, int, str]]:
        """Compute ``(staged path, final path, level, embedded name)`` tuples."""
        embedded_name = os.path.join(str(Path(self.scheme_dict[scheme]) / record.path))

        plan = []
        for level in sorted(set(self.bytecode_optimization_levels)):
            optimization = level if level >= 1 else ""
            final = Path(
                importlib.util.cache_from_source(str(source), optimization=optimization)
            )
            staged = self._work_directory() / "bytecode" / str(self._staged_index)
            self._staged_index += 1
            plan.append((staged, final, level, embedded_name))
        return plan

    def _compile_to_staging(
        self, source: Path, plan: list[tuple[Path, Path, int, str]]
    ) -> list[tuple[str, int, str]]:
        """Compile every required level of ``source`` into temporary files.

        Returns a list of failures instead of raising, so every source file can
        be attempted and all problems reported together. The real cache
        locations are never written while compiling, so bytecode left by an
        earlier install cannot be mistaken for this job's output.
        """
        import py_compile

        failures = []
        for staged, _final, level, embedded_name in plan:
            staged.parent.mkdir(parents=True, exist_ok=True)
            if staged.exists():  # pragma: no cover - defensive
                staged.unlink()
            try:
                py_compile.compile(
                    str(source),
                    cfile=str(staged),
                    dfile=embedded_name,
                    doraise=True,
                    optimize=level,
                )
            except py_compile.PyCompileError as exc:
                failures.append((str(source), level, str(exc.msg)))
            except (SyntaxError, UnicodeError, OSError) as exc:
                failures.append((str(source), level, f"{type(exc).__name__}: {exc}"))
        return failures

    def _prepare_bytecode(
        self, records: Iterable[tuple[Scheme, RecordEntry]]
    ) -> tuple[list[tuple[Path, Path, int, str]], list[tuple[str, int, str]]]:
        """Stage bytecode for all compilable files, without committing anything."""
        plan: list[tuple[Path, Path, int, str]] = []
        failures: list[tuple[str, int, str]] = []
        for scheme, record, source in self._source_targets(records):
            file_plan = self._bytecode_plan(scheme, record, source)
            failures.extend(self._compile_to_staging(source, file_plan))
            plan.extend(file_plan)
        return plan, failures

    def _commit_bytecode(self, plan: list[tuple[Path, Path, int, str]]) -> None:
        """Move freshly compiled bytecode into place, replacing older artifacts."""
        for staged, final, _level, _embedded in plan:
            if not staged.exists():  # pragma: no cover - guarded by staging
                continue
            self._ensure_parent(final.parent)
            self._track_target(final, force_backup=True)
            staged.replace(final)

    def finalize_installation(
        self,
        scheme: Scheme,
        record_file_path: str,
        records: Iterable[tuple[Scheme, RecordEntry]],
    ) -> None:
        """Finalize installation, by writing the ``RECORD`` file & compiling bytecode.

        Bytecode for every required optimization level is prepared and committed
        before ``RECORD`` is written. ``RECORD`` is the admission marker: its
        presence means the installation completed with all required bytecode in
        place. If compilation fails, all files written by this attempt are
        removed, previous bytes are restored and
        :class:`~installer.exceptions.BytecodeCompilationError` is raised.

        :param scheme: scheme to write the ``RECORD`` file in
        :param record_file_path: path of the ``RECORD`` file with that scheme
        :param records: entries to write to the ``RECORD`` file
        """

        def prefix_for_scheme(file_scheme: str) -> str | None:
            if file_scheme == scheme:
                return None
            if _WINDOWS:  # pragma: no cover
                path = os.path.abspath(self.scheme_dict[file_scheme])  # noqa: PTH100
            else:  # pragma: no cover
                path = os.path.relpath(
                    self.scheme_dict[file_scheme],
                    start=self.scheme_dict[scheme],
                )
            return path + "/"

        record_list = list(records)

        plan, failures = self._prepare_bytecode(record_list)
        if failures:
            self._rollback()
            self._cleanup_work_directory()
            raise BytecodeCompilationError(failures)

        try:
            self._commit_bytecode(plan)

            with construct_record_file(record_list, prefix_for_scheme) as record_stream:
                self.write_to_fs(
                    scheme, record_file_path, record_stream, is_executable=False
                )
        except BaseException:
            self._rollback()
            raise
        finally:
            self._cleanup_work_directory()


def _pyc_matches_source(pyc_path: Path, source_path: Path) -> bool:
    """Return whether the bytecode at ``pyc_path`` was produced from ``source_path``.

    Applies the interpreter's own invalidation rules: the magic number must
    match and the header must describe the source currently on disk. Bytecode
    produced for other content is therefore reported as stale rather than being
    mistaken for this install's result.
    """
    try:
        header = pyc_path.read_bytes()[:16]
        source_stat = source_path.stat()
        source_bytes = source_path.read_bytes()
    except OSError:
        return False

    if len(header) < 16 or header[:4] != importlib.util.MAGIC_NUMBER:
        return False

    invalidation = int.from_bytes(header[4:8], "little") & 0b11
    if invalidation == 0:  # timestamp-based
        mtime, size = struct.unpack("<II", header[8:16])
        return bool(
            mtime == (int(source_stat.st_mtime) & 0xFFFFFFFF)
            and size == (source_stat.st_size & 0xFFFFFFFF)
        )
    if invalidation in (1, 3):  # checked / unchecked hash-based
        return bool(header[8:16] == importlib.util.source_hash(source_bytes))

    return False  # pragma: no cover - reserved by CPython


def _read_distribution_metadata(record_path: Path) -> tuple[str | None, str | None]:
    try:
        metadata = parse_metadata_file(
            (record_path.parent / "METADATA").read_text("utf-8")
        )
    except OSError:
        return None, None
    return metadata["Name"], metadata["Version"]


def _scheme_root(directory: str, destdir: str | None) -> Path:
    """Map a scheme directory to its on-disk root, honouring ``destdir``."""
    root = Path(os.path.abspath(directory))  # noqa: PTH100
    if destdir is None:
        return root
    return Path(destdir) / root.relative_to(root.anchor)


def _find_root_scheme(roots: "dict[str, Path]", record_path: Path) -> Scheme:
    for scheme, root in roots.items():
        if record_path == root or root in record_path.parents:
            return cast("Scheme", scheme)
    raise ValueError(f"RECORD path {record_path} is not inside any scheme directory")


def inspect_installation(
    scheme_dict: "dict[str, str] | dict[Scheme, str]",
    record_file_path: str,
    *,
    bytecode_optimization_levels: Collection[int] = (),
    destdir: str | None = None,
    root_scheme: Scheme | None = None,
) -> InstallationReport:
    """Inspect an installation from its on-disk artifacts.

    Reads ``RECORD``, hashes every listed file and checks the headers of the
    required cached bytecode. It does not rely on in-memory state, so the result
    can be reproduced in a later process or on a copied directory.

    ``RECORD`` is the admission marker: it is written only after all required
    bytecode has been prepared, so an intact ``RECORD`` identifies the version
    that a re-installing agent may treat as the last good installation.

    :param scheme_dict: mapping of scheme names to their directories, as actually
        installed. For a ``--destdir`` install, pass the directories under it.
    :param record_file_path: path of ``RECORD`` within its scheme, for example
        ``fancy-1.0.0.dist-info/RECORD``.
    :param bytecode_optimization_levels: optimization levels for which every
        installed ``.py`` file must have current cached bytecode.
    :param destdir: staging root used for the install, if any. Scheme paths are
        mapped under it exactly as :class:`SchemeDictionaryDestination` does.
    :param root_scheme: scheme containing ``RECORD``. Detected when omitted.
    """
    roots = {
        scheme: _scheme_root(directory, destdir)
        for scheme, directory in scheme_dict.items()
    }

    if root_scheme is not None:
        resolved_record = Path(
            os.path.abspath(roots[root_scheme] / record_file_path)  # noqa: PTH100
        )
    else:
        candidates = [directory / record_file_path for directory in roots.values()]
        resolved_record = next(
            (candidate for candidate in candidates if candidate.is_file()),
            candidates[0] if candidates else Path(record_file_path),
        )
        resolved_record = Path(os.path.abspath(resolved_record))  # noqa: PTH100

    if not resolved_record.is_file():
        return InstallationReport(
            status=NOT_INSTALLED,
            record_path=None,
            distribution=None,
            version=None,
            official_files={},
            bytecode=(),
            unexpected_bytecode=(),
            issues=(f"No RECORD found at {resolved_record}",),
        )

    if root_scheme is None:
        root_scheme = _find_root_scheme(roots, resolved_record)

    official: dict[str, RecordEntry] = {}
    issues: list[str] = []
    record_name: str | None = None

    for elements in parse_record_file(resolved_record.read_text("utf-8").splitlines()):
        entry = RecordEntry.from_elements(*elements)

        target = None
        for directory in roots.values():
            candidate = Path(os.path.abspath(directory / entry.path))  # noqa: PTH100
            if candidate.is_relative_to(directory) and candidate.is_file():
                target = candidate
                break

        if target is None:
            issues.append(f"Missing file listed in RECORD: {entry.path}")
            continue

        if entry.path == record_file_path:
            record_name = entry.path
            official[entry.path] = entry
            continue

        try:
            with target.open("rb") as stream:
                matches = entry.validate_stream(stream)
        except OSError:
            matches = False

        if matches:
            official[entry.path] = entry
        else:
            issues.append(f"File does not match RECORD: {entry.path}")

    if record_name is None:
        issues.append(f"RECORD does not list itself at {record_file_path}")

    # Locate the source of every installed module, relative to the scheme
    # directories, so that the same pass works with or without ``destdir``.
    def source_for(path: str) -> Path | None:
        for directory in roots.values():
            candidate = Path(os.path.abspath(directory / path))  # noqa: PTH100
            if candidate.is_relative_to(directory) and candidate.is_file():
                return candidate
        return None

    bytecode: list[BytecodeArtifact] = []
    expected_pyc: set[Path] = set()
    scan_dirs: set[Path] = set()

    for path in official:
        if not path.endswith(".py"):
            continue
        source = source_for(path)
        if source is None:  # pragma: no cover - already reported as missing
            continue
        scan_dirs.add(source.parent / "__pycache__")

        for level in sorted(set(bytecode_optimization_levels)):
            optimization = level if level >= 1 else ""
            pyc_path = Path(
                importlib.util.cache_from_source(str(source), optimization=optimization)
            )
            expected_pyc.add(pyc_path)

            if not pyc_path.is_file():
                state = BYTECODE_MISSING
                issues.append(
                    f"Missing bytecode for {path} (optimization level {level})"
                )
            elif not _pyc_matches_source(pyc_path, source):
                state = BYTECODE_STALE
                issues.append(f"Stale bytecode for {path} (optimization level {level})")
            else:
                state = BYTECODE_CURRENT

            bytecode.append(
                BytecodeArtifact(
                    source=path,
                    optimization_level=level,
                    path=pyc_path,
                    state=state,
                )
            )

    unexpected: list[Path] = []
    for cache_dir in sorted(scan_dirs):
        if not cache_dir.is_dir():
            continue
        unexpected.extend(
            candidate
            for candidate in sorted(cache_dir.glob("*.pyc"))
            if candidate not in expected_pyc
        )

    distribution, version = _read_distribution_metadata(resolved_record)
    return InstallationReport(
        status=ADMITTED if not issues else INCOMPLETE,
        record_path=resolved_record,
        distribution=distribution,
        version=version,
        official_files=official,
        bytecode=tuple(bytecode),
        unexpected_bytecode=tuple(unexpected),
        issues=tuple(issues),
    )
