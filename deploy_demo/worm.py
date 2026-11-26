"""Write-once / sequential-only destination test double.

The double has two layers:

:class:`WormStore`
    An on-disk object store that enforces the contract shared by WORM/object
    targets: **a key can be opened for writing exactly once**.  Every state
    change is appended to ``ledger.jsonl`` so the set of used keys survives a
    process restart.  With ``brick_on_failure=True`` it additionally models the
    strictest target class -- one raw sequential channel / one PUT stream /
    tape -- where any mid-stream failure kills the whole target and recovery
    means provisioning a *replacement* target, not merely a new prefix.

:class:`WriteOnceDestination`
    A real :class:`installer.destinations.WheelDestination` that streams each
    member straight into a unique generation-scoped key
    (``generations/<generation>/<scheme>/<path>``) using the same chunked
    hashing copy as the stock filesystem destination.  If the source fails
    halfway through a member, bytes have already reached the key: that key is
    recorded as ``failed`` and the sequential session is poisoned.  Reusing the
    key (or the poisoned destination) is refused.  Recovery is a **new
    generation** of never-written keys; a generation is committed by writing a
    write-once ``_manifest.json`` after ``finalize_installation`` succeeds.

Nothing here buffers whole wheels: only fixed-size copy buffers are live.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from installer.destinations import WheelDestination
from installer.records import Hash, RecordEntry
from installer.scripts import Script
from installer.utils import construct_record_file, copyfileobj_with_hashing, fix_shebang

from deploy_demo.errors import WriteOnceViolation
from deploy_demo.paths import record_prefix_for_scheme, safe_resolve

_MANIFEST_NAME = "_manifest.json"


def manifest_key_for(generation: str) -> str:
    """Return the write-once commit-manifest key for a generation."""
    return f"generations/{generation}/{_MANIFEST_NAME}"


def _validate_key(key: str) -> None:
    if not key or key.startswith(("/", "\\")):
        raise WriteOnceViolation(f"invalid write-once key {key!r}")
    parts = Path(key.replace("\\", "/")).parts
    if ".." in parts:
        raise WriteOnceViolation(f"path traversal in write-once key {key!r}")


@dataclass
class LandedBlob:
    """Bookkeeping for one successfully sealed key."""

    scheme: str
    path: str
    key: str
    hash_algorithm: str
    hash_value: str
    size: int
    executable: bool


class WormStore:
    """Filesystem-backed test double of a write-once object/block target."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        brick_on_failure: bool = False,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.root = self.root.resolve()
        self.objects_root = self.root / "objects"
        self.objects_root.mkdir(exist_ok=True)
        self.ledger_path = self.root / "ledger.jsonl"
        self.brick_on_failure = brick_on_failure
        self._lock = threading.RLock()
        self._states: dict[str, str] = {}
        self.bricked = False
        self._replay_ledger()

    def _replay_ledger(self) -> None:
        if not self.ledger_path.exists():
            return
        for line in self.ledger_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            event = json.loads(line)
            kind = event.get("event")
            if kind in {"open", "seal", "fail"}:
                self._states[event["key"]] = (
                    "sealed"
                    if kind == "seal"
                    else "failed"
                    if kind == "fail"
                    else "open"
                )
            elif kind == "brick":
                self.bricked = True
        if self.brick_on_failure and "failed" in self._states.values():
            self.bricked = True

    def _emit(self, payload: dict[str, object]) -> None:
        with self.ledger_path.open("a", encoding="utf-8") as ledger:
            ledger.write(json.dumps(payload, sort_keys=True) + "\n")
            ledger.flush()
            os.fsync(ledger.fileno())

    def actual_path(self, key: str) -> Path:
        """Return the real on-disk path backing ``key`` (for external audit)."""
        _validate_key(key)
        return safe_resolve(self.objects_root, key)

    def state_of(self, key: str) -> str | None:
        return self._states.get(key)

    def keys(self, state: str | None = None) -> list[str]:
        with self._lock:
            if state is None:
                return sorted(self._states)
            return sorted(key for key, value in self._states.items() if value == state)

    def open_write(self, key: str) -> BinaryIO:
        """Open ``key`` for its one and only sequential write."""
        _validate_key(key)
        with self._lock:
            if self.bricked:
                raise WriteOnceViolation(
                    "write-once target is bricked after an earlier mid-stream "
                    "failure; provision a replacement target"
                )
            previous = self._states.get(key)
            if previous is not None:
                raise WriteOnceViolation(
                    f"key {key!r} was already used (state={previous}); writes "
                    "cannot be retried at the same key, use a new generation"
                )
            path = self.actual_path(key)
            path.parent.mkdir(parents=True, exist_ok=True)
            sink = path.open("xb")  # exclusive create: second writer cannot win
            self._states[key] = "open"
            self._emit({"event": "open", "key": key})
            return sink  # type: ignore[return-value]

    def mark_sealed(self, key: str, **metadata: object) -> None:
        with self._lock:
            self._states[key] = "sealed"
            self._emit({"event": "seal", "key": key, **metadata})

    def mark_failed(self, key: str, error: str) -> None:
        with self._lock:
            self._states[key] = "failed"
            self._emit({"event": "fail", "key": key, "error": error})
            if self.brick_on_failure and not self.bricked:
                self.bricked = True
                self._emit({"event": "brick", "reason": error})

    def open_read(self, key: str) -> BinaryIO:
        """Independent read-back path used by verification."""
        return self.actual_path(key).open("rb")

    def put_once(self, key: str, data: bytes) -> None:
        """Write a small auxiliary object (manifest) exactly once."""
        sink = self.open_write(key)
        try:
            sink.write(data)
            sink.flush()
            os.fsync(sink.fileno())
        except BaseException:
            sink.close()
            raise
        else:
            sink.close()
        self.mark_sealed(key, size=len(data))


class WriteOnceDestination(WheelDestination):
    """``WheelDestination`` that streams into a :class:`WormStore`.

    Implements the three-method extension contract (``write_file``,
    ``write_script``, ``finalize_installation``) with compatible signatures
    and return types.
    """

    def __init__(
        self,
        store: WormStore,
        generation: str,
        *,
        scheme_dict: dict[str, str] | None = None,
        interpreter: str = "/usr/bin/python3",
        script_kind: str = "posix",
        hash_algorithm: str = "sha256",
    ) -> None:
        self.store = store
        self.generation = generation
        self.scheme_dict = scheme_dict or {}
        self.interpreter = interpreter
        self.script_kind = script_kind
        self.hash_algorithm = hash_algorithm
        self.landed: list[LandedBlob] = []
        self.dead = False
        self.finalized = False
        self.committed = False
        self._record_scheme: str | None = None

    def key_for(self, scheme: str, path: str) -> str:
        return f"generations/{self.generation}/{scheme}/{path}"

    def _require_live(self) -> None:
        if self.dead:
            raise WriteOnceViolation(
                "write-once session is poisoned after a failed stream; "
                "create a new generation on a fresh destination"
            )

    def _stream_to_key(
        self,
        scheme: str,
        path: str,
        stream: BinaryIO,
        is_executable: bool,
    ) -> RecordEntry:
        self._require_live()
        key = self.key_for(scheme, path)
        try:
            sink = self.store.open_write(key)
        except WriteOnceViolation:
            self.dead = True
            raise

        try:
            hash_value, size = copyfileobj_with_hashing(
                stream, sink, self.hash_algorithm
            )
            sink.flush()
            os.fsync(sink.fileno())
        except Exception as exc:
            try:
                sink.close()
            except OSError:
                pass
            self.store.mark_failed(key, f"{type(exc).__name__}: {exc}")
            self.dead = True
            raise

        sink.close()
        self.store.mark_sealed(
            key,
            scheme=scheme,
            path=path,
            size=size,
            hash=self.hash_algorithm + "=" + hash_value,
            executable=is_executable,
        )
        self.landed.append(
            LandedBlob(
                scheme=scheme,
                path=path,
                key=key,
                hash_algorithm=self.hash_algorithm,
                hash_value=hash_value,
                size=size,
                executable=is_executable,
            )
        )
        return RecordEntry(path, Hash(self.hash_algorithm, hash_value), size)

    def write_file(
        self,
        scheme: str,
        path: "str | os.PathLike[str]",
        stream: BinaryIO,
        is_executable: bool,
    ) -> RecordEntry:
        """Write one wheel/metadata file once, streaming to its key."""
        path_text = os.fspath(path)
        if scheme == "scripts":
            with fix_shebang(stream, self.interpreter) as rewritten:
                return self._stream_to_key(scheme, path_text, rewritten, is_executable)
        return self._stream_to_key(scheme, path_text, stream, is_executable)

    def write_script(
        self,
        name: str,
        module: str,
        attr: str,
        section: str,
    ) -> RecordEntry:
        """Generate an entry-point launcher and write its bytes once."""
        script = Script(name, module, attr, section)  # type: ignore[arg-type]
        script_name, data = script.generate(
            self.interpreter,
            self.script_kind,  # type: ignore[arg-type]
        )
        from io import BytesIO

        with BytesIO(data) as buffer:
            return self._stream_to_key("scripts", script_name, buffer, True)

    def _prefix_for_scheme(self, file_scheme: str) -> str | None:
        if not self.scheme_dict or self._record_scheme is None:
            return None
        return record_prefix_for_scheme(
            file_scheme,
            root_scheme=self._record_scheme,
            scheme_dict=self.scheme_dict,
        )

    def finalize_installation(
        self,
        scheme: str,
        record_file_path: str,
        records: object,
    ) -> None:
        """Write the canonical RECORD object exactly once."""
        self._require_live()
        self._record_scheme = scheme
        record_list = list(records)  # type: ignore[arg-type]
        with construct_record_file(
            record_list,  # type: ignore[arg-type]
            self._prefix_for_scheme,
        ) as record_stream:
            self._stream_to_key(scheme, record_file_path, record_stream, False)
        self.finalized = True

    def commit_manifest(self) -> str:
        """Linearize the generation by writing its write-once manifest.

        Returns the manifest key.  Call only after ``installer.install``
        returned successfully.
        """
        self._require_live()
        if not self.finalized:
            raise WriteOnceViolation("cannot commit before RECORD is finalized")
        key = manifest_key_for(self.generation)
        manifest = {
            "generation": self.generation,
            "hash_algorithm": self.hash_algorithm,
            "blobs": [
                {
                    "scheme": blob.scheme,
                    "path": blob.path,
                    "key": blob.key,
                    "sha256": blob.hash_value,
                    "size": blob.size,
                    "executable": blob.executable,
                }
                for blob in self.landed
            ],
        }
        self.store.put_once(key, (json.dumps(manifest, indent=2) + "\n").encode())
        self.committed = True
        return key
