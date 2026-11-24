"""Acceptance tests for permission-preserving moves between backends.

The acceptance criteria are observable rather than implementation based:

* where the object is actually visible afterwards (source vs. destination),
* the access level (permissions) the visible object carries, and
* whether the restricted source was lost.

A real on-disk `~fs.tempfs.TempFS` is used alongside the in-memory
`~fs.memoryfs.MemoryFS` because only the former stores an *access* namespace,
which lets us exercise both a capable and an incapable destination.
"""

from __future__ import unicode_literals

import os
import stat
import unittest

try:
    from unittest import mock
except ImportError:  # pragma: no cover - Python 2 fallback
    import mock

from fs import open_fs
from fs.errors import FSError
from fs.inbox import PermissionUnsupported, secure_move_file

RESTRICTED_MODE = 0o600


def _mode(temp_fs, path):
    # type: (object, str) -> int
    return stat.S_IMODE(os.stat(temp_fs.getsyspath(path)).st_mode)


def _make_restricted(temp_fs, path, contents="restricted contents"):
    # type: (object, str, str) -> None
    temp_fs.writetext(path, contents)
    os.chmod(temp_fs.getsyspath(path), RESTRICTED_MODE)


class TestSameSourceRename(unittest.TestCase):
    """A move within one backend is a rename and keeps every attribute."""

    def test_temp_rename_preserves_permissions(self):
        with open_fs("temp://") as tmp:
            _make_restricted(tmp, "secret.txt")
            secure_move_file(tmp, "secret.txt", tmp, "renamed.txt")

            self.assertFalse(tmp.exists("secret.txt"))
            self.assertTrue(tmp.isfile("renamed.txt"))
            self.assertEqual(_mode(tmp, "renamed.txt"), RESTRICTED_MODE)
            self.assertEqual(tmp.readtext("renamed.txt"), "restricted contents")

    def test_memory_rename(self):
        with open_fs("mem://") as mem:
            mem.writetext("file.txt", "data")
            secure_move_file(mem, "file.txt", mem, "moved.txt")
            self.assertFalse(mem.exists("file.txt"))
            self.assertTrue(mem.isfile("moved.txt"))
            self.assertEqual(mem.readtext("moved.txt"), "data")


class TestIncapableDestination(unittest.TestCase):
    """A backend that cannot store the access level must reject the move."""

    def test_restricted_temp_to_memory_aborts(self):
        with open_fs("temp://") as tmp, open_fs("mem://") as mem:
            _make_restricted(tmp, "secret.txt")

            with self.assertRaises(PermissionUnsupported) as ctx:
                secure_move_file(tmp, "secret.txt", mem, "secret.txt")

            # The required access level is reported on the error.
            self.assertEqual(
                set(ctx.exception.required_permissions), {"u_r", "u_w"}
            )

            # Nothing was written to the destination ...
            self.assertFalse(mem.exists("secret.txt"))
            # ... and the restricted source is still present, unchanged.
            self.assertTrue(tmp.isfile("secret.txt"))
            self.assertEqual(_mode(tmp, "secret.txt"), RESTRICTED_MODE)
            self.assertEqual(tmp.readtext("secret.txt"), "restricted contents")

    def test_unrestricted_memory_to_memory_is_allowed(self):
        # A source without an access namespace places no requirement on the
        # destination, so the move still goes through.
        with open_fs("mem://") as src, open_fs("mem://") as dst:
            src.writetext("file.txt", "data")
            secure_move_file(src, "file.txt", dst, "file.txt")
            self.assertFalse(src.exists("file.txt"))
            self.assertEqual(dst.readtext("file.txt"), "data")


class TestCapableDestination(unittest.TestCase):
    """Two backends that both understand permissions carry the level over."""

    def test_temp_to_temp_preserves_permissions(self):
        with open_fs("temp://") as src, open_fs("temp://") as dst:
            _make_restricted(src, "secret.txt")

            secure_move_file(src, "secret.txt", dst, "kept.txt")

            self.assertFalse(src.exists("secret.txt"))
            self.assertTrue(dst.isfile("kept.txt"))
            self.assertEqual(_mode(dst, "kept.txt"), RESTRICTED_MODE)
            self.assertEqual(dst.readtext("kept.txt"), "restricted contents")


class TestDeleteFailureRetry(unittest.TestCase):
    """If the final source deletion fails the move must roll back cleanly."""

    def test_failed_delete_rolls_back_and_retry_succeeds(self):
        with open_fs("temp://") as src, open_fs("temp://") as dst:
            _make_restricted(src, "secret.txt")

            with mock.patch.object(src, "remove") as remove_mock:
                remove_mock.side_effect = FSError("cannot remove source")
                with self.assertRaises(FSError):
                    secure_move_file(src, "secret.txt", dst, "kept.txt")

            # Rollback: object survives in its original, restricted location
            # and no duplicate is left behind.
            self.assertTrue(src.isfile("secret.txt"))
            self.assertEqual(_mode(src, "secret.txt"), RESTRICTED_MODE)
            self.assertFalse(dst.exists("kept.txt"))

            # Once deletion works again the same operation can be retried.
            secure_move_file(src, "secret.txt", dst, "kept.txt")
            self.assertFalse(src.exists("secret.txt"))
            self.assertTrue(dst.isfile("kept.txt"))
            self.assertEqual(_mode(dst, "kept.txt"), RESTRICTED_MODE)

    def test_failed_delete_without_cleanup_keeps_both_copies(self):
        with open_fs("temp://") as src, open_fs("temp://") as dst:
            _make_restricted(src, "secret.txt")

            with mock.patch.object(src, "remove") as remove_mock:
                remove_mock.side_effect = FSError("cannot remove source")
                with self.assertRaises(FSError):
                    secure_move_file(
                        src,
                        "secret.txt",
                        dst,
                        "kept.txt",
                        cleanup_dst_on_error=False,
                    )

            # Source retained and, when cleanup is disabled, the destination
            # copy is left in place with the correct level.
            self.assertTrue(src.isfile("secret.txt"))
            self.assertTrue(dst.isfile("kept.txt"))
            self.assertEqual(_mode(dst, "kept.txt"), RESTRICTED_MODE)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
