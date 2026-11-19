"""
Tests for the root-directory contract shared by storage backends.

Each backend is configured with a root (``location``) of ``attachments``
while the underlying storage also holds the adjacent ``attachments-private``
namespace. The local stand-ins emulate backends whose prefix matching
ignores directory boundaries, so the adjacent namespace is always handed
back to the storage. The contract requires that:

* callers using legal relative names are served normally,
* names escaping the root are rejected when opening objects,
* listing results keep the root's own files and subdirectories but never
  return anything from the adjacent namespace.
"""

from django.core.exceptions import SuspiciousOperation
from django.test import TestCase

from storages.backends import azure_storage
from storages.backends import s3
from tests.fakes import FakeAzureContainerClient
from tests.fakes import FakeS3Connection

LOCATION = "attachments"
ADJACENT_LOCATION = "attachments-private"

OBJECTS = {
    "attachments/report.txt": b"report",
    "attachments/2024-11/summary.txt": b"summary",
    "attachments-private/passwords.txt": b"passwords",
    "attachments-private/2024-11/audit.txt": b"audit",
}


class S3RootContractTests(TestCase):
    def setUp(self):
        self.storage = s3.S3Storage(location=LOCATION)
        self.storage._connections.connection = FakeS3Connection(OBJECTS)

    def test_listdir_keeps_own_files_and_subdirectories(self):
        directories, files = self.storage.listdir("")
        self.assertEqual(directories, ["2024-11"])
        self.assertEqual(files, ["report.txt"])

        directories, files = self.storage.listdir("2024-11")
        self.assertEqual(directories, [])
        self.assertEqual(files, ["summary.txt"])

    def test_listdir_excludes_adjacent_namespace(self):
        directories, files = self.storage.listdir("")
        self.assertNotIn(ADJACENT_LOCATION, directories)
        self.assertFalse(any(ADJACENT_LOCATION in name for name in directories))
        self.assertFalse(any(ADJACENT_LOCATION in name for name in files))

    def test_open_valid_relative_name(self):
        with self.storage.open("report.txt") as f:
            self.assertEqual(f.read(), b"report")
        with self.storage.open("2024-11/summary.txt") as f:
            self.assertEqual(f.read(), b"summary")

    def test_open_rejects_names_outside_root(self):
        with self.assertRaises(SuspiciousOperation):
            self.storage.open("../%s/passwords.txt" % ADJACENT_LOCATION)


class AzureRootContractTests(TestCase):
    def setUp(self):
        self.storage = azure_storage.AzureStorage(location=LOCATION)
        self.storage._client = FakeAzureContainerClient(OBJECTS)

    def test_listdir_keeps_own_files_and_subdirectories(self):
        directories, files = self.storage.listdir("")
        self.assertEqual(directories, [])
        self.assertEqual(
            files,
            ["attachments/2024-11/summary.txt", "attachments/report.txt"],
        )

        directories, files = self.storage.listdir("2024-11")
        self.assertEqual(directories, [])
        self.assertEqual(files, ["attachments/2024-11/summary.txt"])

    def test_listdir_excludes_adjacent_namespace(self):
        _, files = self.storage.listdir("")
        self.assertFalse(any(ADJACENT_LOCATION in name for name in files))

    def test_open_valid_relative_name(self):
        with self.storage.open("report.txt") as f:
            self.assertEqual(f.read(), b"report")
        with self.storage.open("2024-11/summary.txt") as f:
            self.assertEqual(f.read(), b"summary")

    def test_open_rejects_names_outside_root(self):
        with self.assertRaises(SuspiciousOperation):
            self.storage.open("../%s/passwords.txt" % ADJACENT_LOCATION)
