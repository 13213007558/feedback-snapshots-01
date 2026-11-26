"""Shared install driver for provenance auditing.

Uses the real pypa/installer machinery (WheelFile + SchemeDictionaryDestination)
but adds a phase trace and an optional abort immediately before the target
RECORD is written (i.e. before finalize_installation).
"""
import json
import sys
import time
from pathlib import Path

WS = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd()
sys.path.insert(0, str(WS / "src"))

from installer.destinations import SchemeDictionaryDestination  # noqa: E402
from installer.records import RecordEntry  # noqa: E402
from installer.sources import WheelFile  # noqa: E402
from installer.utils import Scheme  # noqa: E402


def now() -> float:
    return time.time()


class TracingDestination(SchemeDictionaryDestination):
    """Destination that logs every write and can abort before RECORD finalize."""

    def __init__(self, *args, trace_path, abort_before_record=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.trace_path = Path(trace_path)
        self.abort_before_record = abort_before_record
        self.t0 = now()
        self._log(
            "destination-created",
            abort_before_record=abort_before_record,
            interpreter=self.interpreter,
            script_kind=self.script_kind,
        )

    def _log(self, event, **fields):
        rec = {"t_ms": round((now() - self.t0) * 1000, 3), "event": event, **fields}
        with self.trace_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def write_script(self, name, module, attr, section):
        self._log(
            "write_script:begin",
            name=name,
            module=module,
            attr=attr,
            section=section,
            origin="GENERATED_FROM_ENTRY_POINT",
        )
        entry = super().write_script(name, module, attr, section)
        self._log(
            "write_script:done",
            name=name,
            record_path=entry.path,
            hash=str(entry.hash_),
            size=entry.size,
            origin="GENERATED_FROM_ENTRY_POINT",
        )
        return entry

    def write_file(self, scheme, path, stream, is_executable):
        self._log(
            "write_file:begin",
            scheme=scheme,
            path=str(path),
            is_executable=is_executable,
            origin="WHEEL_ARCHIVE_MEMBER",
        )
        entry = super().write_file(scheme, path, stream, is_executable)
        self._log(
            "write_file:done",
            scheme=scheme,
            record_path=entry.path,
            hash=str(entry.hash_),
            size=entry.size,
            origin="WHEEL_ARCHIVE_MEMBER",
        )
        return entry

    def finalize_installation(self, scheme, record_file_path, records):
        # Materialise once: finalize_installation consumes the iterable.
        record_list = list(records)
        record_count = len(record_list)
        if self.abort_before_record:
            self._log(
                "ABORT_BEFORE_RECORD",
                record_file_path=record_file_path,
                pending_record_count=record_count,
                reason=(
                    "simulated interruption: all payload files and the generated "
                    "launcher are on disk, but the target RECORD is not written"
                ),
            )
            raise RuntimeError(
                "Interrupted before finalize_installation: target RECORD not written"
            )
        self._log(
            "finalize_installation:begin",
            record_file_path=record_file_path,
            record_count=record_count,
        )
        super().finalize_installation(scheme, record_file_path, record_list)
        self._log("finalize_installation:done", record_file_path=record_file_path)


def build_scheme_dict(target_root: Path) -> dict:
    root = target_root.resolve()
    return {
        "purelib": str(root / "purelib"),
        "platlib": str(root / "purelib"),
        "scripts": str(root / "scripts"),
        "headers": str(root / "headers"),
        "data": str(root / "data"),
    }


def run(wheel: Path, target_root: Path, trace_path: Path, abort: bool, interpreter: str):
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    trace_path.write_text("", encoding="utf-8")
    with WheelFile.open(wheel) as source:
        # Establish the "source verified" baseline before writing anything.
        source.validate_record(validate_contents=True)
        dest = TracingDestination(
            scheme_dict=build_scheme_dict(target_root),
            interpreter=interpreter,
            script_kind="posix",
            bytecode_optimization_levels=(),
            trace_path=trace_path,
            abort_before_record=abort,
        )
        import installer

        installer.install(source, dest, {})
