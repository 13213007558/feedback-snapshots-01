from __future__ import unicode_literals

import unittest

import fs.copy
from fs.delegation import (
    DelegatedFS,
    DelegatedSubFS,
    DelegationPolicy,
    DelegationScope,
    PermissionDenied,
    delegate,
)
from fs.memoryfs import MemoryFS
from fs.mountfs import MountFS
from fs.tempfs import TempFS


class TestDelegationScope(unittest.TestCase):
    def test_normalizes_path(self):
        scope = DelegationScope("foo//bar/")
        self.assertEqual(scope.path, "/foo/bar")

    def test_capability_flags(self):
        self.assertEqual(DelegationScope("/", read=True).capabilities(), "r---")
        full = DelegationScope("/", read=True, write=True, syspath=True, url=True)
        self.assertEqual(full.capabilities(), "rwsu")

    def test_convenience_constructors(self):
        ro = DelegationScope.read_only("/a")
        self.assertTrue(ro.read)
        self.assertFalse(ro.write)
        rw = DelegationScope.read_write("/b")
        self.assertTrue(rw.read and rw.write)


class TestDelegationPolicy(unittest.TestCase):
    def setUp(self):
        self.policy = DelegationPolicy(
            [
                DelegationScope.read_only("/restricted", label="restricted"),
                DelegationScope(
                    "/restricted/export",
                    read=True,
                    write=True,
                    syspath=True,
                    url=True,
                    label="export",
                ),
            ]
        )

    def test_most_specific_scope_wins(self):
        scope = self.policy.scope_for("/restricted/export/file.txt")
        self.assertEqual(scope.label, "export")
        parent = self.policy.scope_for("/restricted/other.txt")
        self.assertEqual(parent.label, "restricted")

    def test_no_matching_scope(self):
        self.assertIsNone(self.policy.scope_for("/elsewhere"))

    def test_require_read_audit(self):
        self.policy.require_read("test", "/restricted/x")
        self.assertTrue(self.policy.audit_log[-1].allowed)

    def test_denied_outside_scope(self):
        with self.assertRaises(PermissionDenied):
            self.policy.require_write("test", "/restricted/x")
        self.assertFalse(self.policy.audit_log[-1].allowed)
        self.assertEqual(len(self.policy.denied()), 1)

    def test_denied_missing_capability(self):
        # read is allowed but syspath is not on the restricted scope
        self.policy.require_read("test", "/restricted/x")
        with self.assertRaises(PermissionDenied):
            self.policy.require_syspath("test", "/restricted/x")
        record = self.policy.denied()[0]
        self.assertEqual(record.detail, "not granted")


class TestDelegatedFS(unittest.TestCase):
    def setUp(self):
        self.backing = MemoryFS()
        self.backing.makedirs("/restricted/secret")
        self.backing.writetext("/restricted/secret/a.txt", "secret")
        self.backing.writetext("/restricted/readme.txt", "data")
        self.backing.makedirs("/export")
        self.backing.writetext("/export/b.txt", "export")
        self.backing.makedirs("/scratch")
        self.scopes = [
            DelegationScope.read_only("/restricted", label="restricted"),
            DelegationScope(
                "/export",
                read=True,
                write=True,
                syspath=True,
                url=True,
                label="export",
            ),
            DelegationScope.read_write("/scratch", label="scratch"),
        ]
        self.fs = delegate(self.backing, self.scopes, name="plugin")

    def tearDown(self):
        self.backing.close()

    def test_wrapper_type(self):
        self.assertIsInstance(self.fs, DelegatedFS)
        self.assertIsInstance(self.fs.policy, DelegationPolicy)

    def test_allowed_virtual_read(self):
        self.assertEqual(self.fs.readtext("/restricted/secret/a.txt"), "secret")
        self.assertTrue(self.fs.exists("/restricted/readme.txt"))
        self.assertEqual(
            self.fs.listdir("/restricted/secret"), ["a.txt"]
        )

    def test_denied_read_without_scope(self):
        with self.assertRaises(PermissionDenied):
            self.fs.readtext("/nope/file.txt")
        self.assertFalse(self.fs.hassyspath("/nope"))

    def test_denied_write_on_read_only_scope(self):
        with self.assertRaises(PermissionDenied):
            self.fs.writetext("/restricted/new.txt", "x")
        with self.assertRaises(PermissionDenied):
            self.fs.remove("/restricted/readme.txt")
        self.assertFalse(self.backing.exists("/restricted/new.txt"))

    def test_allowed_write(self):
        self.fs.writetext("/scratch/note.txt", "hi")
        self.assertEqual(self.backing.readtext("/scratch/note.txt"), "hi")

    def test_open_mode_authorization(self):
        with self.fs.openbin("/restricted/readme.txt", "rb") as handle:
            self.assertEqual(handle.read(), b"data")
        with self.assertRaises(PermissionDenied):
            self.fs.openbin("/restricted/readme.txt", "wb")

    def test_syspath_gated(self):
        # MemoryFS has no syspath anyway, but the policy must refuse first.
        with self.assertRaises(PermissionDenied):
            self.fs.getsyspath("/restricted/readme.txt")
        self.assertFalse(self.fs.hassyspath("/restricted/readme.txt"))
        # Export scope asks for syspath; the underlying FS then decides.
        self.assertFalse(self.fs.hassyspath("/export/b.txt"))

    def test_url_gated(self):
        with self.assertRaises(PermissionDenied):
            self.fs.geturl("/restricted/readme.txt")
        self.assertFalse(self.fs.hasurl("/restricted/readme.txt"))
        self.assertFalse(self.fs.hasurl("/export/b.txt"))

    def test_syspath_and_url_on_disk_backend(self):
        disk = TempFS()
        try:
            disk.makedirs("export")
            disk.writetext("export/f.txt", "x")
            disk.makedirs("restricted")
            disk.writetext("restricted/f.txt", "y")
            view = delegate(
                disk,
                [
                    DelegationScope.read_only("/restricted"),
                    DelegationScope(
                        "/export", read=True, syspath=True, url=True
                    ),
                ],
            )
            self.assertTrue(view.hassyspath("/export/f.txt"))
            self.assertIn("export/f.txt", view.getsyspath("/export/f.txt"))
            self.assertTrue(view.geturl("/export/f.txt").startswith("file://"))
            with self.assertRaises(PermissionDenied):
                view.getsyspath("/restricted/f.txt")
            with self.assertRaises(PermissionDenied):
                view.geturl("/restricted/f.txt")
        finally:
            disk.close()

    def test_recursive_opendir_keeps_policy(self):
        sub = self.fs.opendir("/restricted")
        self.assertIsInstance(sub, DelegatedSubFS)
        deeper = sub.opendir("/secret")
        self.assertIs(deeper.policy, self.fs.policy)
        self.assertEqual(deeper.readtext("/a.txt"), "secret")
        with self.assertRaises(PermissionDenied):
            deeper.writetext("/a.txt", "tamper")

    def test_opendir_requires_directory(self):
        with self.assertRaises(Exception):
            self.fs.opendir("/restricted/readme.txt")

    def test_cross_backend_copy_respects_policy(self):
        target = MemoryFS()
        try:
            # Approved source read + destination write.
            fs.copy.copy_file(
                self.fs,
                "/restricted/readme.txt",
                self.fs,
                "/scratch/copy.txt",
            )
            self.assertEqual(
                self.backing.readtext("/scratch/copy.txt"), "data"
            )
            # Copying into a read-only subtree must be refused.
            with self.assertRaises(PermissionDenied):
                fs.copy.copy_file(
                    self.fs,
                    "/restricted/readme.txt",
                    self.fs,
                    "/restricted/copy.txt",
                )
        finally:
            target.close()

    def test_move_requires_src_read_and_dst_write(self):
        with self.assertRaises(PermissionDenied):
            self.fs.move(
                "/restricted/readme.txt", "/restricted/moved.txt"
            )


class TestDelegatedMount(unittest.TestCase):
    def setUp(self):
        self.disk = TempFS(identifier="delegation-test")
        self.memory = MemoryFS()
        self.disk.makedirs("restricted/secret")
        self.disk.writetext("restricted/secret/a.txt", "secret")
        self.disk.makedirs("export")
        self.disk.writetext("export/b.txt", "export")
        self.memory.makedirs("scratch")

        self.mount = MountFS()
        self.mount.mount("/disk", self.disk)
        self.mount.mount("/memory", self.memory)

        self.plugin = delegate(
            self.mount,
            [
                DelegationScope.read_only(
                    "/disk/restricted", label="restricted"
                ),
                DelegationScope(
                    "/disk/export",
                    read=True,
                    write=True,
                    syspath=True,
                    url=True,
                    label="export",
                ),
                DelegationScope.read_write(
                    "/memory/scratch", label="scratch"
                ),
            ],
            name="report-plugin",
        )

    def tearDown(self):
        self.mount.close()

    def test_recursive_open_across_mount(self):
        deep = self.plugin.opendir("/disk/restricted").opendir("/secret")
        self.assertEqual(deep.readtext("/a.txt"), "secret")

    def test_cross_backend_copy_disk_to_memory(self):
        fs.copy.copy_file(
            self.plugin,
            "/disk/restricted/secret/a.txt",
            self.plugin,
            "/memory/scratch/a-copy.txt",
        )
        self.assertEqual(
            self.memory.readtext("/scratch/a-copy.txt"), "secret"
        )

    def test_syspath_only_for_approved_export(self):
        with self.assertRaises(PermissionDenied):
            self.plugin.getsyspath("/disk/restricted/secret/a.txt")
        sys_path = self.plugin.getsyspath("/disk/export/b.txt")
        self.assertIn("export", sys_path)

    def test_url_only_for_approved_export(self):
        with self.assertRaises(PermissionDenied):
            self.plugin.geturl("/disk/restricted/secret/a.txt")
        self.assertTrue(
            self.plugin.geturl("/disk/export/b.txt").startswith("file://")
        )

    def test_memory_backend_has_no_syspath_or_url(self):
        self.memory.writetext("/scratch/n.txt", "x")
        self.assertFalse(
            self.plugin.hassyspath("/memory/scratch/n.txt")
        )
        self.assertFalse(self.plugin.hasurl("/memory/scratch/n.txt"))

    def test_audit_records_decisions(self):
        self.plugin.readtext("/disk/export/b.txt")
        with self.assertRaises(PermissionDenied):
            self.plugin.getsyspath("/disk/restricted/secret/a.txt")
        denied = self.plugin.policy.denied()
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0].capability, "syspath")
        self.assertTrue(self.plugin.policy.granted())


if __name__ == "__main__":
    unittest.main()
