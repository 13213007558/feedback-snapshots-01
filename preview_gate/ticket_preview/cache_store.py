"""Local JSON file cache for finished Bleach preview artifacts."""

from __future__ import annotations

import json
from pathlib import Path


class CacheStore:
    def __init__(self, live_dir):
        self.live_dir = Path(live_dir)
        self.live_dir.mkdir(parents=True, exist_ok=True)

    def path_for(self, ticket_id) -> Path:
        # Ticket ids are generated identifiers; guard against path traversal.
        safe = "".join(ch for ch in ticket_id if ch.isalnum() or ch in "-_")
        if not safe or safe != ticket_id:
            raise ValueError(f"unsafe ticket id for cache path: {ticket_id!r}")
        return self.live_dir / f"{safe}.json"

    def load(self, ticket_id):
        """Return ``(envelope, error)``.

        A missing file is ``(None, None)`` (a clean cache miss).  A present
        but unreadable/invalid file is ``(None, "cache-unreadable")`` so the
        gate can fail closed instead of trusting unknown bytes.
        """
        path = self.path_for(ticket_id)
        if not path.exists():
            return None, None
        try:
            with path.open("r", encoding="utf-8") as handle:
                envelope = json.load(handle)
            if not isinstance(envelope, dict):
                return None, "cache-unreadable"
            return envelope, None
        except (json.JSONDecodeError, OSError):
            return None, "cache-unreadable"

    def save(self, ticket_id, envelope) -> Path:
        path = self.path_for(ticket_id)
        tmp = path.with_suffix(".json.tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(envelope, handle, ensure_ascii=False, indent=2, sort_keys=False)
            handle.write("\n")
        tmp.replace(path)
        return path

    def activate_fixture(self, fixture_path, ticket_id) -> Path:
        """Copy a prepared cache fixture into the live cache path."""
        import shutil

        fixture_path = Path(fixture_path)
        target = self.path_for(ticket_id)
        shutil.copyfile(fixture_path, target)
        return target

    def read_raw_text(self, ticket_id) -> str:
        return self.path_for(ticket_id).read_text(encoding="utf-8")

    def exists(self, ticket_id) -> bool:
        return self.path_for(ticket_id).exists()
