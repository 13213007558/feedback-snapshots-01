"""Demonstrate approval-scoped delegation over a mounted virtual filesystem.

The reporting service builds one `~fs.mountfs.MountFS` that joins two
different backends:

* a temporary on-disk filesystem (`~fs.tempfs.TempFS`) mounted at
  ``/disk`` -- it has real system paths and ``file://`` URLs;
* an in-memory filesystem (`~fs.memoryfs.MemoryFS`) mounted at
  ``/memory`` -- it has neither system paths nor URLs.

Two sub-trees are then handed to a plugin through `fs.delegation`:

* ``/disk/restricted`` -- a *restricted* subtree.  The plugin may read
  and copy files virtually, and may open sub-directories recursively,
  but it is never given a real system path or a download URL.
* ``/disk/export`` -- an *explicitly approved export* subtree.  In
  addition to virtual read/write it is granted ``SYSPATH`` and ``URL``
  capabilities, so the plugin may obtain the real path and download
  address.

Running this module prints the audit trail showing which delegations
were allowed and which were refused.
"""

from __future__ import print_function, unicode_literals

import fs.copy
from fs.delegation import (
    DelegationScope,
    PermissionDenied,
    delegate,
)
from fs.memoryfs import MemoryFS
from fs.mountfs import MountFS
from fs.tempfs import TempFS


def build_mount():
    # type: () -> MountFS
    """One mount joining a temporary disk backend and a memory backend."""
    disk_fs = TempFS(identifier="delegation-demo")
    memory_fs = MemoryFS()

    disk_fs.makedirs("restricted/secret")
    disk_fs.writetext("restricted/secret/credentials.txt", "top secret payload")
    disk_fs.writetext("restricted/readme.txt", "read-only report data")
    disk_fs.makedirs("export")
    disk_fs.writetext("export/approved.txt", "safe to export")

    memory_fs.makedirs("scratch")
    memory_fs.writetext("scratch/note.txt", "in-memory working file")

    mount_fs = MountFS()
    mount_fs.mount("/disk", disk_fs)
    mount_fs.mount("/memory", memory_fs)
    return mount_fs


def heading(title):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def main():
    mount_fs = build_mount()

    # The approval granted to the plugin.  The most specific matching
    # scope wins for any path.
    scopes = [
        DelegationScope.read_only("/disk/restricted", label="restricted-subtree"),
        DelegationScope(
            "/disk/export",
            read=True,
            write=True,
            syspath=True,
            url=True,
            label="approved-export",
        ),
        DelegationScope.read_write("/memory/scratch", label="memory-scratch"),
    ]
    plugin_fs = delegate(mount_fs, scopes, name="report-plugin")
    policy = plugin_fs.policy

    heading("1. Recursive virtual open of the restricted subtree")
    secret_dir = plugin_fs.opendir("/disk/restricted").opendir("/secret")
    print("recursively opened:", secret_dir)
    print("virtual read  :", secret_dir.readtext("/credentials.txt"))
    print("listdir       :", plugin_fs.listdir("/disk/restricted/secret"))

    heading("2. Cross-backend copy through the normal virtual interface")
    # Copy from the on-disk restricted subtree into the memory backend.
    # This never needs a syspath/URL: it flows through openbin/download.
    fs.copy.copy_file(
        plugin_fs,
        "/disk/restricted/readme.txt",
        plugin_fs,
        "/memory/scratch/readme-copy.txt",
    )
    copied = plugin_fs.readtext("/memory/scratch/readme-copy.txt")
    print("cross-backend copy succeeded, content:", copied)

    heading("3. Direct system path delegation")
    try:
        secret_path = plugin_fs.getsyspath("/disk/restricted/secret/credentials.txt")
        print("UNEXPECTED syspath:", secret_path)
    except PermissionDenied as error:
        print("DENIED syspath (restricted):", error)

    export_path = plugin_fs.getsyspath("/disk/export/approved.txt")
    print("ALLOWED syspath (export)   :", export_path)

    # The memory backend has no system path at all, even where the
    # virtual subtree is fully read/write approved.
    print("hassyspath memory scratch  :", plugin_fs.hassyspath("/memory/scratch/note.txt"))

    heading("4. Download URL delegation")
    try:
        plugin_fs.geturl("/disk/restricted/readme.txt")
    except PermissionDenied as error:
        print("DENIED url (restricted)    :", error)

    export_url = plugin_fs.geturl("/disk/export/approved.txt")
    print("ALLOWED url (export)       :", export_url)

    heading("5. Read / write enforcement by approval")
    try:
        plugin_fs.writetext("/disk/restricted/new.txt", "nope")
    except PermissionDenied as error:
        print("DENIED write (restricted)  :", error)

    plugin_fs.writetext("/disk/export/written.txt", "approved write")
    print("ALLOWED write (export)     :", plugin_fs.readtext("/disk/export/written.txt"))

    try:
        plugin_fs.readtext("/disk/unsupported/file.txt")
    except PermissionDenied as error:
        print("DENIED read (no scope)     :", error)

    heading("6. Audit trail")
    for record in policy.audit_log:
        print(record)

    heading("Summary")
    denied = [r for r in policy.denied()]
    print("granted delegations :", len(policy.granted()))
    print("refused delegations :", len(denied))
    for record in denied:
        print("  -", record)

    mount_fs.close()


if __name__ == "__main__":
    main()
