from __future__ import unicode_literals

import unittest

from six import text_type

from fs import errors
from fs.memoryfs import MemoryFS
from fs.mode import check_writable
from fs.multifs import MultiFS
from fs.test import FSTestCases


class UnavailableMemoryFS(MemoryFS):
    """A MemoryFS whose *read* operations always fail.

    Simulates an upper backend that cannot be reached while still
    allowing writes so the object can be populated in fixtures.
    """

    def getinfo(self, path, namespaces=None):
        raise errors.RemoteConnectionError(path=path, msg="simulated outage")

    def listdir(self, path):
        raise errors.RemoteConnectionError(path=path, msg="simulated outage")

    def scandir(self, path, namespaces=None, page=None):
        raise errors.RemoteConnectionError(path=path, msg="simulated outage")
        # Make this method a generator for FS subclasses.
        yield  # pragma: no cover

    def openbin(self, path, mode="r", buffering=-1, **options):
        if check_writable(mode):
            return super(UnavailableMemoryFS, self).openbin(
                path, mode=mode, buffering=buffering, **options
            )
        raise errors.RemoteConnectionError(path=path, msg="simulated outage")


class TestMultiFS(FSTestCases, unittest.TestCase):
    """Test OSFS implementation."""

    def setUp(self):
        fs = MultiFS()
        mem_fs = MemoryFS()
        fs.add_fs("mem", mem_fs, write=True)
        self.fs = fs
        self.mem_fs = mem_fs

    def make_fs(self):
        fs = MultiFS()
        mem_fs = MemoryFS()
        fs.add_fs("mem", mem_fs, write=True)
        return fs

    def test_get_fs(self):
        self.assertIs(self.fs.get_fs("mem"), self.mem_fs)

    def test_which(self):
        self.fs.writebytes("foo", b"bar")
        self.assertEqual(self.fs.which("foo"), ("mem", self.mem_fs))
        self.assertEqual(self.fs.which("bar", "w"), ("mem", self.mem_fs))
        self.assertEqual(self.fs.which("baz"), (None, None))

    def test_auto_close(self):
        """Test MultiFS auto close is working"""
        multi_fs = MultiFS()
        m1 = MemoryFS()
        m2 = MemoryFS()
        multi_fs.add_fs("m1", m1)
        multi_fs.add_fs("m2", m2)
        self.assertFalse(m1.isclosed())
        self.assertFalse(m2.isclosed())
        multi_fs.close()
        self.assertTrue(m1.isclosed())
        self.assertTrue(m2.isclosed())

    def test_no_auto_close(self):
        """Test MultiFS auto close can be disabled"""
        multi_fs = MultiFS(auto_close=False)
        self.assertEqual(repr(multi_fs), "MultiFS(auto_close=False)")
        m1 = MemoryFS()
        m2 = MemoryFS()
        multi_fs.add_fs("m1", m1)
        multi_fs.add_fs("m2", m2)
        self.assertFalse(m1.isclosed())
        self.assertFalse(m2.isclosed())
        multi_fs.close()
        self.assertFalse(m1.isclosed())
        self.assertFalse(m2.isclosed())

    def test_opener(self):
        """Test use of FS URLs."""
        multi_fs = MultiFS()
        with self.assertRaises(TypeError):
            multi_fs.add_fs("foo", 5)
        multi_fs.add_fs("f1", "mem://")
        multi_fs.add_fs("f2", "temp://")
        self.assertIsInstance(multi_fs.get_fs("f1"), MemoryFS)

    def test_priority(self):
        """Test priority order is working"""
        m1 = MemoryFS()
        m2 = MemoryFS()
        m3 = MemoryFS()
        m1.writebytes("name", b"m1")
        m2.writebytes("name", b"m2")
        m3.writebytes("name", b"m3")
        multi_fs = MultiFS(auto_close=False)
        multi_fs.add_fs("m1", m1)
        multi_fs.add_fs("m2", m2)
        multi_fs.add_fs("m3", m3)
        self.assertEqual(multi_fs.readbytes("name"), b"m3")

        m1 = MemoryFS()
        m2 = MemoryFS()
        m3 = MemoryFS()
        m1.writebytes("name", b"m1")
        m2.writebytes("name", b"m2")
        m3.writebytes("name", b"m3")
        multi_fs = MultiFS(auto_close=False)
        multi_fs.add_fs("m1", m1)
        multi_fs.add_fs("m2", m2, priority=10)
        multi_fs.add_fs("m3", m3)
        self.assertEqual(multi_fs.readbytes("name"), b"m2")

        m1 = MemoryFS()
        m2 = MemoryFS()
        m3 = MemoryFS()
        m1.writebytes("name", b"m1")
        m2.writebytes("name", b"m2")
        m3.writebytes("name", b"m3")
        multi_fs = MultiFS(auto_close=False)
        multi_fs.add_fs("m1", m1)
        multi_fs.add_fs("m2", m2, priority=10)
        multi_fs.add_fs("m3", m3, priority=10)
        self.assertEqual(multi_fs.readbytes("name"), b"m3")

        m1 = MemoryFS()
        m2 = MemoryFS()
        m3 = MemoryFS()
        m1.writebytes("name", b"m1")
        m2.writebytes("name", b"m2")
        m3.writebytes("name", b"m3")
        multi_fs = MultiFS(auto_close=False)
        multi_fs.add_fs("m1", m1, priority=11)
        multi_fs.add_fs("m2", m2, priority=10)
        multi_fs.add_fs("m3", m3, priority=10)
        self.assertEqual(multi_fs.readbytes("name"), b"m1")

    def test_no_writable(self):
        fs = MultiFS()
        with self.assertRaises(errors.ResourceReadOnly):
            fs.writebytes("foo", b"bar")

    def test_validate_path(self):
        self.fs.write_fs = None
        self.fs.validatepath("foo")

    def test_listdir_duplicates(self):
        m1 = MemoryFS()
        m2 = MemoryFS()
        m1.touch("foo")
        m2.touch("foo")
        multi_fs = MultiFS()
        multi_fs.add_fs("m1", m1)
        multi_fs.add_fs("m2", m2)
        self.assertEqual(multi_fs.listdir("/"), ["foo"])


class TestMultiFSMasks(unittest.TestCase):
    """Masking rules across single-file lookups and directory walks."""

    def setUp(self):
        self.lower = MemoryFS()
        self.lower.makedirs("pub/secret")
        self.lower.writetext("pub/secret/archive.txt", "archive")
        self.lower.writetext("pub/sibling.txt", "sibling")

        self.upper = MemoryFS()
        self.upper.makedirs("pub/secret")
        self.upper.writetext("pub/secret/upper.txt", "upper")
        self.upper.writetext("pub/published.txt", "published")

        self.multi = MultiFS(auto_close=False)
        self.multi.add_fs("lower", self.lower)
        self.multi.add_fs("upper", self.upper)

    def test_masks_property_normalizes_and_snapshots(self):
        self.assertEqual(self.multi.masks, frozenset())
        self.multi.add_mask("pub/secret/")
        self.assertEqual(self.multi.masks, frozenset(["/pub/secret"]))
        snapshot = self.multi.masks
        self.multi.add_mask("pub/other")
        self.assertNotIn("/pub/other", snapshot)
        self.multi.remove_mask("pub/secret")
        self.assertEqual(self.multi.masks, frozenset(["/pub/other"]))

    def test_remove_unknown_mask_raises(self):
        with self.assertRaises(KeyError):
            self.multi.remove_mask("pub/secret")

    def test_masked_directory_hidden_from_single_file_lookups(self):
        self.multi.add_mask("/pub/secret")
        # The data is still physically present in both layers.
        self.assertTrue(self.upper.exists("/pub/secret/upper.txt"))
        self.assertTrue(self.lower.exists("/pub/secret/archive.txt"))
        for hidden in ("/pub/secret", "/pub/secret/upper.txt",
                       "/pub/secret/archive.txt"):
            self.assertFalse(self.multi.exists(hidden))
            with self.assertRaises(errors.ResourceNotFound):
                self.multi.getinfo(hidden)
            with self.assertRaises(errors.ResourceNotFound):
                self.multi.open(hidden, "r")
            self.assertEqual(self.multi.which(hidden), (None, None))

    def test_masked_directory_hidden_from_traversal(self):
        self.multi.add_mask("/pub/secret")
        self.assertEqual(
            sorted(self.multi.listdir("/pub")),
            ["published.txt", "sibling.txt"],
        )
        names = sorted(info.name for info in self.multi.scandir("/pub"))
        self.assertEqual(names, ["published.txt", "sibling.txt"])
        with self.assertRaises(errors.ResourceNotFound):
            self.multi.listdir("/pub/secret")
        with self.assertRaises(errors.ResourceNotFound):
            list(self.multi.scandir("/pub/secret"))

    def test_masked_file_only_hides_that_file(self):
        self.multi.add_mask("/pub/published.txt")
        self.assertFalse(self.multi.exists("/pub/published.txt"))
        self.assertTrue(self.multi.exists("/pub/sibling.txt"))
        self.assertEqual(
            sorted(self.multi.listdir("/pub")),
            ["secret", "sibling.txt"],
        )

    def test_public_siblings_still_resolved_in_priority_order(self):
        # Before masking, the upper layer wins for its own files.
        self.assertEqual(
            self.multi.which("/pub/published.txt")[0], "upper"
        )
        self.multi.add_mask("/pub/secret")
        # Public content with no upper definition falls through to the
        # lower, archival layer.
        self.assertEqual(self.multi.readtext("/pub/sibling.txt"), "sibling")
        name, fs = self.multi.which("/pub/sibling.txt")
        self.assertEqual(name, "lower")
        self.assertIs(fs, self.lower)
        # Upper-defined public content still comes from the upper layer.
        self.assertEqual(
            self.multi.readtext("/pub/published.txt"), "published"
        )
        name, fs = self.multi.which("/pub/published.txt")
        self.assertEqual(name, "upper")
        self.assertIs(fs, self.upper)

    def test_traversal_uses_a_consistent_snapshot(self):
        scan = self.multi.scandir("/pub")
        first = next(scan)
        self.assertEqual(first.name, "secret")
        # Reconfigure halfway through the iteration.
        self.multi.add_mask("/pub/secret")
        self.multi.add_mask("/pub/published.txt")
        # The running traversal keeps the configuration it started with.
        names = [first.name] + [info.name for info in scan]
        self.assertEqual(sorted(names),
                         ["published.txt", "secret", "sibling.txt"])
        # A fresh traversal observes the new configuration.
        self.assertEqual(
            sorted(info.name for info in self.multi.scandir("/pub")),
            ["sibling.txt"],
        )

    def test_listdir_uses_a_consistent_snapshot(self):
        sequence, masks = self.multi._snapshot()
        self.multi.add_mask("/pub/secret")
        # The captured snapshot still reflects the unmasked view.
        self.assertFalse(
            self.multi._is_masked("/pub/secret/upper.txt", masks)
        )
        self.assertEqual(sorted(self.multi.listdir("/pub")),
                         ["published.txt", "sibling.txt"])


class TestMultiFSBackendUnavailable(unittest.TestCase):
    """Callers are told when an unreachable layer made the result partial."""

    def setUp(self):
        self.lower = MemoryFS()
        self.lower.makedirs("pub/secret")
        self.lower.writetext("pub/secret/archive.txt", "archive")
        self.lower.writetext("pub/sibling.txt", "sibling")

        # Populate while it is an ordinary MemoryFS, then take the
        # backend offline for the duration of the test.
        upper = MemoryFS()
        upper.makedirs("pub/ghost")
        upper.writetext("pub/ghost/ghost.txt", "ghost")
        upper.__class__ = UnavailableMemoryFS
        self.upper = upper

        self.multi = MultiFS(auto_close=False)
        self.multi.add_fs("lower", self.lower)
        self.multi.add_fs("upper", self.upper)

    def test_unavailable_upper_does_not_block_lower_reads(self):
        self.assertEqual(self.multi.readtext("/pub/sibling.txt"), "sibling")
        with self.multi.open("/pub/sibling.txt", "r") as f:
            self.assertEqual(f.read(), "sibling")
        info = self.multi.getinfo("/pub/sibling.txt")
        self.assertEqual(info.name, "sibling.txt")
        self.assertTrue(self.multi.isfile("/pub/sibling.txt"))

    def test_unknown_path_signals_backend_unavailable(self):
        for path in ("/pub/ghost", "/pub/ghost/ghost.txt", "/missing"):
            with self.assertRaises(errors.BackendUnavailable) as ctx:
                self.multi.getinfo(path)
            self.assertEqual(ctx.exception.path, path)
            self.assertEqual(
                [name for name, _p, _exc in ctx.exception.failures],
                ["upper"],
            )
            self.assertIsInstance(
                ctx.exception.failures[0][2], errors.RemoteConnectionError
            )
        with self.assertRaises(errors.BackendUnavailable):
            self.multi.open("/missing", "r")
        with self.assertRaises(errors.BackendUnavailable):
            self.multi.which("/missing")

    def test_scandir_reports_partial_result(self):
        with self.assertRaises(errors.BackendUnavailable) as ctx:
            list(self.multi.scandir("/pub"))
        self.assertEqual(sorted(ctx.exception.partial),
                         ["secret", "sibling.txt"])
        failure_names = [name for name, _p, _exc in ctx.exception.failures]
        self.assertEqual(failure_names, ["upper"])

    def test_listdir_reports_partial_result(self):
        with self.assertRaises(errors.BackendUnavailable) as ctx:
            self.multi.listdir("/pub")
        self.assertEqual(sorted(ctx.exception.partial),
                         ["secret", "sibling.txt"])

    def test_scandir_of_missing_directory_raises_when_backend_down(self):
        with self.assertRaises(errors.BackendUnavailable):
            list(self.multi.scandir("/nowhere"))

    def test_mask_short_circuits_before_touching_backends(self):
        self.multi.add_mask("/pub/sibling.txt")
        with self.assertRaises(errors.ResourceNotFound):
            self.multi.getinfo("/pub/sibling.txt")

    def test_all_layers_unavailable(self):
        broken = MultiFS(auto_close=False)
        broken.add_fs("only", UnavailableMemoryFS())
        with self.assertRaises(errors.BackendUnavailable):
            broken.getinfo("/anything")
        with self.assertRaises(errors.BackendUnavailable):
            broken.listdir("/")
        with self.assertRaises(errors.BackendUnavailable):
            list(broken.scandir("/"))

    def test_backend_unavailable_is_picklable(self):
        import pickle

        try:
            self.multi.getinfo("/missing")
        except errors.BackendUnavailable as exc:
            clone = pickle.loads(pickle.dumps(exc))
            self.assertIsInstance(clone, errors.BackendUnavailable)
            self.assertEqual(clone.partial, exc.partial)
            self.assertEqual(clone.path, exc.path)
            self.assertEqual(len(clone.failures), len(exc.failures))
            self.assertEqual(clone.failures[0][0], exc.failures[0][0])
            self.assertEqual(clone.failures[0][1], exc.failures[0][1])
            self.assertEqual(
                type(clone.failures[0][2]),
                type(exc.failures[0][2]),
            )
            self.assertEqual(
                text_type(clone.failures[0][2]),
                text_type(exc.failures[0][2]),
            )
        else:  # pragma: no cover
            self.fail("BackendUnavailable was not raised")
