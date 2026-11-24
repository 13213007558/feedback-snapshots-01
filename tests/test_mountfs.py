from __future__ import unicode_literals

import importlib.util
import os
import unittest

from fs.memoryfs import MemoryFS
from fs.mountfs import MountError, MountFS
from fs.tempfs import TempFS
from fs.test import FSTestCases


class TestMountFS(FSTestCases, unittest.TestCase):
    """Test OSFS implementation."""

    def make_fs(self):
        fs = MountFS()
        mem_fs = MemoryFS()
        fs.mount("/", mem_fs)
        return fs


class TestMountFS2(FSTestCases, unittest.TestCase):
    """Test OSFS implementation."""

    def make_fs(self):
        fs = MountFS()
        mem_fs = MemoryFS()
        fs.mount("/foo", mem_fs)
        return fs.opendir("foo")


class TestMountFSBehaviours(unittest.TestCase):
    def test_bad_mount(self):
        mount_fs = MountFS()
        with self.assertRaises(TypeError):
            mount_fs.mount("foo", 5)
        with self.assertRaises(TypeError):
            mount_fs.mount("foo", b"bar")

    def test_listdir(self):
        mount_fs = MountFS()
        self.assertEqual(mount_fs.listdir("/"), [])
        m1 = MemoryFS()
        m3 = MemoryFS()
        m4 = TempFS()
        mount_fs.mount("/m1", m1)
        mount_fs.mount("/m2", "temp://")
        mount_fs.mount("/m3", m3)
        with self.assertRaises(MountError):
            mount_fs.mount("/m3/foo", m4)
        self.assertEqual(sorted(mount_fs.listdir("/")), ["m1", "m2", "m3"])
        m3.makedir("foo")
        self.assertEqual(sorted(mount_fs.listdir("/m3")), ["foo"])

    def test_auto_close(self):
        """Test MountFS auto close is working"""
        mount_fs = MountFS()
        m1 = MemoryFS()
        m2 = MemoryFS()
        mount_fs.mount("/m1", m1)
        mount_fs.mount("/m2", m2)
        self.assertFalse(m1.isclosed())
        self.assertFalse(m2.isclosed())
        mount_fs.close()
        self.assertTrue(m1.isclosed())
        self.assertTrue(m2.isclosed())

    def test_no_auto_close(self):
        """Test MountFS auto close can be disabled"""
        mount_fs = MountFS(auto_close=False)
        m1 = MemoryFS()
        m2 = MemoryFS()
        mount_fs.mount("/m1", m1)
        mount_fs.mount("/m2", m2)
        self.assertFalse(m1.isclosed())
        self.assertFalse(m2.isclosed())
        mount_fs.close()
        self.assertFalse(m1.isclosed())
        self.assertFalse(m2.isclosed())

    def test_empty(self):
        """Test MountFS with nothing mounted."""
        mount_fs = MountFS()
        self.assertEqual(mount_fs.listdir("/"), [])

    def test_mount_self(self):
        mount_fs = MountFS()
        with self.assertRaises(ValueError):
            mount_fs.mount("/", mount_fs)

    def test_desc(self):
        mount_fs = MountFS()
        mount_fs.desc("/")

    def test_unmount(self):
        mount_fs = MountFS()
        m1 = MemoryFS()
        mount_fs.mount("/m1", m1)
        self.assertEqual(sorted(mount_fs.listdir("/")), ["m1"])

        detached = mount_fs.unmount("/m1")
        self.assertIs(detached, m1)
        self.assertTrue(m1.isclosed())
        self.assertEqual(mount_fs.listdir("/"), [])

    def test_unmount_keep_open(self):
        mount_fs = MountFS()
        m1 = MemoryFS()
        mount_fs.mount("/m1", m1)
        detached = mount_fs.unmount("/m1", close=False)
        self.assertIs(detached, m1)
        self.assertFalse(m1.isclosed())
        self.assertFalse(mount_fs.mounts)
        m1.close()

    def test_unmount_missing(self):
        mount_fs = MountFS()
        with self.assertRaises(MountError):
            mount_fs.unmount("/nope")

    def test_remount_switches_new_requests(self):
        mount_fs = MountFS()
        old_fs = MemoryFS()
        old_fs.writetext("file.txt", "old")
        mount_fs.mount("/org", old_fs)

        new_fs = MemoryFS()
        new_fs.writetext("file.txt", "new")
        detached = mount_fs.remount("/org", new_fs)

        self.assertIs(detached, old_fs)
        self.assertFalse(old_fs.isclosed())
        self.assertEqual(mount_fs.readtext("/org/file.txt"), "new")
        self.assertEqual(old_fs.readtext("file.txt"), "old")

    def test_remount_keeps_old_handles_and_other_mounts(self):
        mount_fs = MountFS()
        alpha_old = MemoryFS()
        bravo = MemoryFS()
        alpha_old.writetext("input.txt", "payload")
        bravo.writetext("notes.txt", "bravo")
        mount_fs.mount("/alpha", alpha_old)
        mount_fs.mount("/bravo", bravo)

        old_handle = mount_fs.openbin("/alpha/input.txt", "r")
        copy_handle = mount_fs.openbin("/alpha/output.bin", "w")

        alpha_new = MemoryFS()
        returned = mount_fs.remount("/alpha", alpha_new)
        self.assertIs(returned, alpha_old)

        # Handles opened before the switch stay bound to the old space.
        self.assertEqual(old_handle.read(), b"payload")
        copy_handle.write(b"half written")
        copy_handle.close()
        old_handle.close()
        self.assertEqual(alpha_old.readbytes("output.bin"), b"half written")
        self.assertFalse(alpha_new.exists("output.bin"))

        # New requests go to the new space; other mounts are untouched.
        mount_fs.writetext("/alpha/after.txt", "new space")
        self.assertTrue(alpha_new.exists("after.txt"))
        self.assertFalse(alpha_old.exists("after.txt"))
        self.assertEqual(mount_fs.readtext("/bravo/notes.txt"), "bravo")

        alpha_old.close()

    def test_remount_missing_and_validation(self):
        mount_fs = MountFS()
        with self.assertRaises(MountError):
            mount_fs.remount("/nope", MemoryFS())
        with self.assertRaises(TypeError):
            mount_fs.remount("/nope", 5)

    def test_remount_self_rejected(self):
        mount_fs = MountFS()
        m1 = MemoryFS()
        mount_fs.mount("/m1", m1)
        with self.assertRaises(ValueError):
            mount_fs.remount("/m1", mount_fs)


class TestMountSwapExample(unittest.TestCase):
    def test_demo_invariants(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        script = os.path.join(repo_root, "examples", "mount_swap_mid_copy.py")
        spec = importlib.util.spec_from_file_location("mount_swap_mid_copy", script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.main(), 0)
