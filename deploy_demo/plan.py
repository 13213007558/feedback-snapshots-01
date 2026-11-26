"""Pre-touch review plan: exactly what an install would write, before writes.

The builder mirrors :func:`installer._core.install` step for step (it even
reuses the private-but-stable scheme mapping helpers from ``installer._core``
so the review cannot drift from real placement):

1. read ``WHEEL`` to determine ``root_scheme``;
2. enumerate entry points and generate the exact launcher bytes;
3. walk ``WheelSource.get_contents()`` and apply ``_determine_scheme``;
4. add ``additional_metadata`` and the final ``RECORD`` row.

Walking ``get_contents()`` opens archive members but does **not** read their
byte streams, so producing the plan is cheap even for multi-hundred-MB wheels.
Declared hashes/sizes come from the wheel's ``RECORD``; generated scripts and
extra metadata are hashed locally because their exact bytes are known.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
from dataclasses import asdict, dataclass, field
from typing import Mapping

from installer._core import _determine_scheme, _process_WHEEL_file
from installer.records import RecordEntry
from installer.scripts import Script
from installer.sources import WheelSource
from installer.utils import Scheme, parse_entrypoints

from deploy_demo.paths import record_prefix_for_scheme, safe_resolve

DEFAULT_INTERPRETER = "/usr/bin/python3"
DEFAULT_SCRIPT_KIND = "posix"


@dataclass
class PlanEntry:
    """One thing that :func:`installer.install` would land."""

    kind: str
    scheme: str
    path: str
    source_member: str | None = None
    final_landing: str | None = None
    staging_landing: str | None = None
    record_hash: str | None = None
    size: int | None = None
    hash_basis: str = "unknown"
    transforms: str | None = None
    executable: bool = False
    record_prefix: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class SkippedEntry:
    """A wheel member intentionally not installed (e.g. ``__pycache__``)."""

    path: str
    reason: str


@dataclass
class InstallPlan:
    """Reviewable, serializable answer to "what will be written and where?"."""

    distribution: str
    version: str
    root_scheme: str
    record_file_path: str
    entries: list[PlanEntry] = field(default_factory=list)
    skipped: list[SkippedEntry] = field(default_factory=list)
    scheme_dict: dict[str, str] = field(default_factory=dict)
    generation: str | None = None

    @property
    def declared_total_size(self) -> int:
        return sum(entry.size or 0 for entry in self.entries)

    def paths_by_scheme(self) -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = {}
        for entry in self.entries:
            grouped.setdefault(entry.scheme, []).append(entry.path)
        return grouped

    def to_dict(self) -> dict[str, object]:
        return {
            "distribution": self.distribution,
            "version": self.version,
            "root_scheme": self.root_scheme,
            "record_file_path": self.record_file_path,
            "generation": self.generation,
            "declared_total_size": self.declared_total_size,
            "scheme_dict": self.scheme_dict,
            "entries": [entry.to_dict() for entry in self.entries],
            "skipped": [asdict(item) for item in self.skipped],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def expected_path_set(self) -> set[tuple[str, str]]:
        """All ``(scheme, in-scheme path)`` pairs, including RECORD."""
        return {(entry.scheme, entry.path) for entry in self.entries}


def _digest(data: bytes) -> tuple[str, int]:
    return hashlib.sha256(data).hexdigest(), len(data)


def build_plan(
    source: WheelSource,
    *,
    scheme_dict: Mapping[str, str],
    interpreter: str = DEFAULT_INTERPRETER,
    script_kind: str = DEFAULT_SCRIPT_KIND,
    additional_metadata: Mapping[str, bytes] | None = None,
    stage_dir: str | None = None,
    generation: str | None = None,
) -> InstallPlan:
    """Compute the review plan without writing to any destination."""
    additional_metadata = dict(additional_metadata or {})

    root_scheme: Scheme = _process_WHEEL_file(source)
    record_file_path = posixpath.join(source.dist_info_dir, "RECORD")

    plan = InstallPlan(
        distribution=source.distribution,
        version=source.version,
        root_scheme=str(root_scheme),
        record_file_path=record_file_path,
        scheme_dict={str(k): str(v) for k, v in scheme_dict.items()},
        generation=generation,
    )

    def landings(scheme: str, path: str) -> tuple[str | None, str | None]:
        final: str | None = None
        staging: str | None = None
        if scheme in scheme_dict:
            final = str(safe_resolve(scheme_dict[scheme], path))
        if stage_dir is not None:
            staging = str(safe_resolve(f"{stage_dir}/{scheme}", path))
        return final, staging

    # Entry-point generated scripts.
    if "entry_points.txt" in source.dist_info_filenames:
        entrypoints_text = source.read_dist_info("entry_points.txt")
        for name, module, attr, section in parse_entrypoints(entrypoints_text):
            script_name, data = Script(
                name=name,
                module=module,
                attr=attr,
                section=section,  # type: ignore[arg-type]
            ).generate(interpreter, script_kind)  # type: ignore[arg-type]
            digest, size = _digest(data)
            final, staging = landings("scripts", script_name)
            plan.entries.append(
                PlanEntry(
                    kind=f"{section}-script",
                    scheme="scripts",
                    path=script_name,
                    final_landing=final,
                    staging_landing=staging,
                    record_hash=f"sha256={digest}",
                    size=size,
                    hash_basis="generated-deterministic",
                    executable=True,
                    record_prefix=record_prefix_for_scheme(
                        "scripts",
                        root_scheme=str(root_scheme),
                        scheme_dict=scheme_dict,
                    ),
                )
            )

    # Wheel members: path/scheme mapping only; streams are not read.
    for record_elements, _stream, is_executable in source.get_contents():
        source_record: RecordEntry = RecordEntry.from_elements(*record_elements)
        path = source_record.path
        if path == record_file_path:
            continue
        if "__pycache__" in path.split("/")[:-1]:
            plan.skipped.append(
                SkippedEntry(path=path, reason="__pycache__ security skip")
            )
            continue

        scheme, destination_path = _determine_scheme(
            path=path,
            source=source,
            root_scheme=root_scheme,
        )
        scheme = str(scheme)
        final, staging = landings(scheme, destination_path)
        plan.entries.append(
            PlanEntry(
                kind="wheel-file",
                scheme=scheme,
                path=destination_path,
                source_member=path,
                final_landing=final,
                staging_landing=staging,
                record_hash=str(source_record.hash_) if source_record.hash_ else None,
                size=source_record.size,
                hash_basis="declared-in-RECORD",
                transforms="shebang-may-rewrite" if scheme == "scripts" else None,
                executable=bool(is_executable),
                record_prefix=record_prefix_for_scheme(
                    scheme,
                    root_scheme=str(root_scheme),
                    scheme_dict=scheme_dict,
                ),
            )
        )

    # Platform-provided extra metadata (e.g. INSTALLER).
    for filename, contents in additional_metadata.items():
        path = posixpath.join(source.dist_info_dir, filename)
        digest, size = _digest(contents)
        final, staging = landings(str(root_scheme), path)
        plan.entries.append(
            PlanEntry(
                kind="additional-metadata",
                scheme=str(root_scheme),
                path=path,
                final_landing=final,
                staging_landing=staging,
                record_hash=f"sha256={digest}",
                size=size,
                hash_basis="metadata-bytes-supplied",
            )
        )

    # RECORD itself is generated at finalize time and intentionally has no hash.
    final, staging = landings(str(root_scheme), record_file_path)
    plan.entries.append(
        PlanEntry(
            kind="record",
            scheme=str(root_scheme),
            path=record_file_path,
            final_landing=final,
            staging_landing=staging,
            record_hash=None,
            size=None,
            hash_basis="record-finalized-last-with-empty-hash-by-spec",
            record_prefix=None,
        )
    )

    return plan
