# -*- coding: utf-8 -*-
"""Hot-swap one mount of a virtual filesystem without disturbing the others.

Scenario
--------

Several organisation directories are mounted under one virtual
:class:`~fs.mountfs.MountFS`. Ops wants to replace the backing store of
one organisation (``/orgs/alpha``) while a copy is still in flight.

The switch must keep three security invariants:

1. A read handle handed out *before* the switch keeps reading from the
   old space, under its original authorization, until it is closed.
2. A write that was already in progress (the copy's destination handle)
   keeps landing in the old space; bytes that were never approved for
   the new mount must not suddenly flow into it.
3. Every request opened *after* the switch resolves to the new space,
   while the other mounts keep serving their own spaces unchanged.

Run it from the repository root::

    python examples/mount_swap_mid_copy.py

The script prints an audit table that traces, for every operation,
which backing space it actually touched, and then asserts the three
invariants above.
"""

from __future__ import print_function, unicode_literals

import unicodedata

from fs.memoryfs import MemoryFS
from fs.mountfs import MountFS
from fs.wrapfs import WrapFS

CHUNK_SIZE = 32


class TrackedHandle(object):
    """Binary file wrapper that unregisters itself from the journal on close."""

    def __init__(self, binary, registry, entry):
        self._binary = binary
        self._registry = registry
        self._entry = entry

    def read(self, size=-1):
        return self._binary.read(size)

    def write(self, data):
        return self._binary.write(data)

    def flush(self):
        return self._binary.flush()

    def seek(self, offset, whence=0):
        return self._binary.seek(offset, whence)

    def tell(self):
        return self._binary.tell()

    def close(self):
        if not self._binary.closed:
            self._binary.close()
            self._registry.remove(self._entry)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


class SpaceFS(WrapFS):
    """Wrap a backing FS so every open is labelled with its backing space."""

    def __init__(self, wrap_fs, space_id, journal, registry):
        super(SpaceFS, self).__init__(wrap_fs)
        self.space_id = space_id
        self._journal = journal
        self._registry = registry

    def openbin(self, path, mode="r", buffering=-1, **options):
        binary = self._wrap_fs.openbin(
            path, mode=mode, buffering=buffering, **options
        )
        role = "read" if "r" in mode else "write"
        entry = {
            "space": self.space_id,
            "path": path,
            "mode": mode,
            "role": role,
        }
        self._registry.append(entry)
        self._journal.record(
            "open({})".format(mode), path, self.space_id,
            "{} handle pinned to this space".format(role),
        )
        return TrackedHandle(binary, self._registry, entry)


class AuditJournal(object):
    """Append-only record of which space each operation resolved to."""

    def __init__(self):
        self.events = []
        self.checks = []

    def record(self, action, path, space_id, note):
        self.events.append(
            {
                "step": len(self.events) + 1,
                "action": action,
                "path": path,
                "space": space_id,
                "note": note,
            }
        )

    def expect(self, description, condition):
        self.checks.append((description, bool(condition)))

    def render(self):
        headers = ("step", "action", "virtual path", "backing space", "note")
        rows = [
            (
                text(event["step"]),
                event["action"],
                event["path"],
                event["space"],
                event["note"],
            )
            for event in self.events
        ]
        widths = [
            display_width(header)
            for header in headers
        ]
        for row in rows:
            for index, cell in enumerate(row):
                widths[index] = max(widths[index], display_width(cell))

        def format_row(row):
            cells = []
            for index, cell in enumerate(row):
                pad = widths[index] - display_width(cell)
                cells.append(cell + " " * pad)
            return "  ".join(cells)

        lines = [format_row(headers), format_row(("-" * width for width in widths))]
        lines.extend(format_row(row) for row in rows)
        return "\n".join(lines)


def display_width(text):
    return sum(2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
               for char in text)


def text(value):
    return "{}".format(value)


def copy_in_chunks(src_handle, dst_handle, total_size, journal, on_progress=None):
    """Copy fixed-size chunks, invoking ``on_progress`` between chunks."""
    copied = 0
    chunk_index = 0
    while copied < total_size:
        chunk = src_handle.read(CHUNK_SIZE)
        if not chunk:
            break
        dst_handle.write(chunk)
        dst_handle.flush()
        copied += len(chunk)
        chunk_index += 1
        journal.record(
            "copy chunk #{}".format(chunk_index),
            "/orgs/alpha/staging/output.bin",
            "via destination handle",
            "{} bytes committed".format(copied),
        )
        if on_progress is not None:
            on_progress(copied)
    return copied


def main():
    journal = AuditJournal()
    open_handles = []

    # One virtual namespace, three organisation directories mounted in it.
    virtual = MountFS(auto_close=True)
    alpha_old = SpaceFS(MemoryFS(), "alpha-old", journal, open_handles)
    bravo = SpaceFS(MemoryFS(), "bravo", journal, open_handles)
    charlie = SpaceFS(MemoryFS(), "charlie", journal, open_handles)
    virtual.mount("/orgs/alpha", alpha_old)
    virtual.mount("/orgs/bravo", bravo)
    virtual.mount("/orgs/charlie", charlie)

    payload = bytes(bytearray(range(100)))  # 100 bytes -> 4 chunks
    alpha_old.makedirs("staging")
    alpha_old.writebytes("staging/input.bin", payload)
    bravo.writetext("notes.txt", "bravo notes")
    charlie.writetext("roster.csv", "id,name\n1,ada\n")

    # --- Handles granted before the switch -----------------------------
    read_handle = virtual.openbin("/orgs/alpha/staging/input.bin", "r")
    read_space = open_handles[-1]["space"]

    dst_handle = virtual.openbin("/orgs/alpha/staging/output.bin", "w")
    dst_space = open_handles[-1]["space"]
    journal.record(
        "copy job opened", "/orgs/alpha/staging/output.bin", dst_space,
        "uncommitted copy destination",
    )

    # --- Run the first half of the copy, then swap the mount -----------
    swap_state = {"done": False, "new_fs": None}

    def swap_halfway(copied):
        if swap_state["done"] or copied < 2 * CHUNK_SIZE:
            return
        swap_state["done"] = True

        alpha_new = SpaceFS(MemoryFS(), "alpha-new", journal, open_handles)
        alpha_new.writetext("NEW_SPACE_MARKER.txt", "written only in alpha-new")

        detached = virtual.remount("/orgs/alpha", alpha_new)
        swap_state["new_fs"] = alpha_new
        journal.record(
            "remount", "/orgs/alpha", "alpha-old -> alpha-new",
            "old space kept open, {} handle(s) still pinned".format(
                len(open_handles)
            ),
        )
        journal.expect("remount returns the previous backing FS", detached is alpha_old)
        journal.expect(
            "old backing FS stays open for draining", not detached.isclosed()
        )

    copied = copy_in_chunks(
        read_handle, dst_handle, len(payload), journal, on_progress=swap_halfway
    )
    alpha_new = swap_state["new_fs"]

    # --- Old read handle finishes under its original authorization -----
    read_handle.seek(0)
    drained = read_handle.read()
    journal.expect("old read handle still sees the old payload", drained == payload)
    journal.expect("old read handle is pinned to alpha-old", read_space == "alpha-old")
    read_handle.close()
    journal.record("close read handle", "/orgs/alpha/staging/input.bin",
                   read_space, "old-space authorization finished")

    dst_handle.close()
    journal.record("close copy destination", "/orgs/alpha/staging/output.bin",
                   dst_space, "all {} bytes settled in old space".format(copied))

    # --- Requests after the switch resolve to the new space -------------
    new_marker = virtual.readtext("/orgs/alpha/NEW_SPACE_MARKER.txt")
    journal.record("read after switch", "/orgs/alpha/NEW_SPACE_MARKER.txt",
                   "alpha-new", "new request routed to new space")

    virtual.writetext("/orgs/alpha/after_switch.txt", "fresh write")
    journal.record("write after switch", "/orgs/alpha/after_switch.txt",
                   "alpha-new", "new write lands in new space only")

    # --- The in-flight copy never leaked into the new mount -------------
    leaked = alpha_new.exists("staging/output.bin")
    settled = alpha_old.exists("staging/output.bin")
    journal.expect("uncommitted copy never reached the new space", not leaked)
    journal.expect("copy finished entirely in the old space",
                   settled and alpha_old.readbytes("staging/output.bin") == payload)
    journal.expect("new writes land in the new space",
                   alpha_new.exists("after_switch.txt")
                   and not alpha_old.exists("after_switch.txt"))
    journal.expect("new marker is readable through the virtual path",
                   new_marker == "written only in alpha-new")

    # --- The other mounts keep working against their own spaces ---------
    journal.expect("bravo mount is untouched",
                   virtual.readtext("/orgs/bravo/notes.txt") == "bravo notes")
    journal.expect("charlie mount is untouched",
                   virtual.readtext("/orgs/charlie/roster.csv").startswith("id,name"))
    virtual.writetext("/orgs/bravo/after_switch.txt", "still bravo")
    journal.record("write after switch", "/orgs/bravo/after_switch.txt",
                   "bravo", "other mount serves its own space")
    journal.expect("bravo write stayed in bravo",
                   bravo.exists("after_switch.txt")
                   and not alpha_new.exists("notes.txt"))

    virtual.close()
    alpha_old.close()
    journal.expect("all handles were closed, nothing left pinned",
                   not open_handles)

    print("Mount hot-swap audit trail")
    print("=" * 72)
    print(journal.render())
    print()
    print("Invariant checks")
    print("=" * 72)
    failed = 0
    for description, ok in journal.checks:
        status = "PASS" if ok else "FAIL"
        if not ok:
            failed += 1
        print("[{}] {}".format(status, description))
    print()
    print("{} check(s), {} failed".format(len(journal.checks), failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
