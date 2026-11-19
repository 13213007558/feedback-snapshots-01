import io
import os
import socket
import stat
import tempfile
from unittest.mock import MagicMock
from unittest.mock import call
from unittest.mock import patch

import paramiko
from django.core.files.base import File
from django.test import TestCase
from django.test import override_settings

from storages.backends import sftpstorage
from tests.utils import NonSeekableContentFile


class SFTPStorageTest(TestCase):
    def setUp(self):
        self.storage = sftpstorage.SFTPStorage(host="foo", root_path="root")

    def test_init(self):
        pass

    @patch("paramiko.SSHClient")
    def test_no_known_hosts_file(self, mock_ssh):
        self.storage.known_host_file = "not_existed_file"
        self.storage._connect()
        self.assertEqual("foo", mock_ssh.return_value.connect.call_args[0][0])

    @patch.object(os.path, "expanduser", return_value="/path/to/known_hosts")
    @patch.object(os.path, "exists", return_value=True)
    @patch("paramiko.SSHClient")
    def test_error_when_known_hosts_file_not_defined(self, mock_ssh, *a):
        self.storage._connect()
        self.storage._ssh.load_host_keys.assert_called_once_with("/path/to/known_hosts")

    @patch("paramiko.SSHClient")
    def test_connect(self, mock_ssh):
        self.storage._connect()
        self.assertEqual("foo", mock_ssh.return_value.connect.call_args[0][0])

    @patch("paramiko.SSHClient")
    def test_close_unopened(self, mock_ssh):
        with self.storage:
            pass
        mock_ssh.return_value.close.assert_not_called()

    @patch("paramiko.SSHClient")
    def test_close_opened(self, mock_ssh):
        with self.storage as storage:
            storage._connect()
        mock_ssh.return_value.close.assert_called_once_with()

    def test_open(self):
        file_ = self.storage._open("foo")
        self.assertIsInstance(file_, sftpstorage.SFTPStorageFile)

    @patch("storages.backends.sftpstorage.SFTPStorage.sftp")
    def test_read(self, mock_sftp):
        self.storage._read("foo")
        self.assertTrue(mock_sftp.open.called)

    @patch("storages.backends.sftpstorage.SFTPStorage.sftp")
    def test_chown(self, mock_sftp):
        self.storage._chown("foo", 1, 1)
        self.assertEqual(mock_sftp.chown.call_args[0], ("foo", 1, 1))

    @patch("storages.backends.sftpstorage.SFTPStorage.sftp")
    def test_mkdir(self, mock_sftp):
        self.storage._mkdir("foo")
        self.assertEqual(mock_sftp.mkdir.call_args[0], ("foo",))

    @patch(
        "storages.backends.sftpstorage.SFTPStorage.sftp",
        **{"stat.side_effect": (FileNotFoundError(), True)},
    )
    def test_mkdir_parent(self, mock_sftp):
        self.storage._mkdir("bar/foo")
        self.assertEqual(mock_sftp.mkdir.call_args_list[0][0], ("bar",))
        self.assertEqual(mock_sftp.mkdir.call_args_list[1][0], ("bar/foo",))

    @patch("storages.backends.sftpstorage.SFTPStorage.sftp")
    def test_save(self, mock_sftp):
        self.storage._save("foo", File(io.BytesIO(b"foo"), "foo"))
        self.assertTrue(mock_sftp.putfo.called)

    @patch("storages.backends.sftpstorage.SFTPStorage.sftp")
    def test_save_non_seekable(self, mock_sftp):
        self.storage._save("foo", NonSeekableContentFile("foo"))
        self.assertTrue(mock_sftp.putfo.called)

    @patch(
        "storages.backends.sftpstorage.SFTPStorage.sftp",
        **{"stat.side_effect": (FileNotFoundError(), True)},
    )
    def test_save_in_subdir(self, mock_sftp):
        self.storage._save("bar/foo", File(io.BytesIO(b"foo"), "foo"))
        self.assertEqual(mock_sftp.stat.call_args_list[0][0], ("root/bar",))
        self.assertEqual(mock_sftp.mkdir.call_args_list[0][0], ("root/bar",))
        self.assertTrue(mock_sftp.putfo.called)

    @patch("storages.backends.sftpstorage.SFTPStorage.sftp")
    def test_delete(self, mock_sftp):
        self.storage.delete("foo")
        self.assertEqual(mock_sftp.remove.call_args_list[0][0], ("root/foo",))

    @patch("storages.backends.sftpstorage.SFTPStorage.sftp")
    def test_path_exists(self, mock_sftp):
        self.assertTrue(self.storage._path_exists("root/foo"))

    @patch("storages.backends.sftpstorage.SFTPStorage.sftp")
    def test_exists(self, mock_sftp):
        self.assertTrue(self.storage.exists("foo"))

    @patch(
        "storages.backends.sftpstorage.SFTPStorage.sftp",
        **{"stat.side_effect": FileNotFoundError()},
    )
    def test_not_exists(self, mock_sftp):
        self.assertFalse(self.storage.exists("foo"))

    @patch(
        "storages.backends.sftpstorage.SFTPStorage.sftp",
        **{"stat.side_effect": FileNotFoundError()},
    )
    def test_not_path_exists(self, mock_sftp):
        self.assertFalse(self.storage._path_exists("root/foo"))

    @patch(
        "storages.backends.sftpstorage.SFTPStorage.sftp",
        **{"stat.side_effect": socket.timeout()},
    )
    def test_not_exists_timeout(self, mock_sftp):
        with self.assertRaises(socket.timeout):
            self.storage.exists("foo")

    @patch(
        "storages.backends.sftpstorage.SFTPStorage.sftp",
        **{
            "listdir_attr.return_value": [
                MagicMock(filename="foo", st_mode=stat.S_IFDIR),
                MagicMock(filename="bar", st_mode=None),
            ]
        },
    )
    def test_listdir(self, mock_sftp):
        dirs, files = self.storage.listdir("/")
        self.assertTrue(dirs)
        self.assertTrue(files)

    @patch(
        "storages.backends.sftpstorage.SFTPStorage.sftp",
        **{
            "stat.return_value.st_size": 42,
        },
    )
    def test_size(self, mock_sftp):
        self.assertEqual(self.storage.size("foo"), 42)

    def test_url(self):
        self.assertEqual(self.storage.url("foo"), "/media/foo")
        # Test custom
        self.storage.base_url = "http://bar.pt/"
        self.assertEqual(self.storage.url("foo"), "http://bar.pt/foo")
        # Test error
        with self.assertRaises(ValueError):
            self.storage.base_url = None
            self.storage.url("foo")

    @patch(
        "storages.backends.sftpstorage.SFTPStorage.sftp",
        **{
            "stat.return_value.st_mtime": 1720287559,
            "stat.return_value.st_atime": 1720287559,
        },
    )
    def test_times(self, mock_sftp):
        self.storage.get_modified_time("foo")
        self.storage.get_accessed_time("foo")

    @patch("paramiko.transport.Transport", **{"is_active.side_effect": (True, False)})
    @patch("storages.backends.sftpstorage.SFTPStorage._connect")
    def test_sftp(self, connect, transport):
        self.assertIsNone(self.storage.sftp)
        self.assertTrue(connect.called)
        connect.reset_mock()
        self.storage._ssh = paramiko.SSHClient()
        self.storage._ssh._transport = transport

        self.storage._sftp = True
        self.assertTrue(self.storage.sftp)
        self.assertFalse(connect.called)

        self.assertTrue(self.storage.sftp)
        self.assertTrue(connect.called)

    def test_override_settings(self):
        with override_settings(SFTP_STORAGE_ROOT="foo1"):
            storage = sftpstorage.SFTPStorage()
            self.assertEqual(storage.root_path, "foo1")
        with override_settings(SFTP_STORAGE_ROOT="foo2"):
            storage = sftpstorage.SFTPStorage()
            self.assertEqual(storage.root_path, "foo2")

    def test_override_class_variable(self):
        class MyStorage1(sftpstorage.SFTPStorage):
            root_path = "foo1"

        storage = MyStorage1()
        self.assertEqual(storage.root_path, "foo1")

        class MyStorage2(sftpstorage.SFTPStorage):
            root_path = "foo2"

        storage = MyStorage2()
        self.assertEqual(storage.root_path, "foo2")

    def test_override_init_argument(self):
        storage = sftpstorage.SFTPStorage(root_path="foo1")
        self.assertEqual(storage.root_path, "foo1")
        storage = sftpstorage.SFTPStorage(root_path="foo2")
        self.assertEqual(storage.root_path, "foo2")


class SFTPStorageFileTest(TestCase):
    def setUp(self):
        self.storage = sftpstorage.SFTPStorage(host="foo")
        self.file = sftpstorage.SFTPStorageFile("bar", self.storage, "wb")

    @patch(
        "storages.backends.sftpstorage.SFTPStorage.sftp",
        **{
            "stat.return_value.st_size": 42,
        },
    )
    def test_size(self, mock_sftp):
        self.assertEqual(self.file.size, 42)

    @patch(
        "storages.backends.sftpstorage.SFTPStorage.sftp",
        **{
            "open.return_value.read.return_value": b"foo",
        },
    )
    def test_read(self, mock_sftp):
        self.assertEqual(self.file.read(), b"foo")
        self.assertTrue(mock_sftp.open.called)

    def test_write(self):
        self.file.write(b"foo")
        self.assertEqual(self.file.file.read(), b"foo")

    @patch("storages.backends.sftpstorage.SFTPStorage.sftp")
    def test_close(self, mock_sftp):
        self.file.write(b"foo")
        self.file.close()
        self.assertTrue(mock_sftp.putfo.called)


class SFTPStorageHostKeyVerificationTest(TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.production_known_hosts = os.path.join(
            self.temp_dir.name, "production_known_hosts"
        )
        self.partner_known_hosts = os.path.join(
            self.temp_dir.name, "partner_known_hosts"
        )
        open(self.production_known_hosts, "w").close()
        open(self.partner_known_hosts, "w").close()

        self.production = sftpstorage.SFTPStorage(
            host="sftp.production.example",
            known_host_file=self.production_known_hosts,
            host_key_policy="reject",
        )
        self.partner = sftpstorage.SFTPStorage(
            host="sftp.partner.example",
            known_host_file=self.partner_known_hosts,
            host_key_policy="auto-add",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("paramiko.SSHClient")
    def test_each_alias_loads_its_own_trust_file_and_policy(self, mock_ssh):
        self.production._connect()
        client = mock_ssh.return_value
        client.load_host_keys.assert_called_once_with(self.production_known_hosts)
        self.assertIsInstance(
            client.set_missing_host_key_policy.call_args[0][0],
            paramiko.RejectPolicy,
        )
        self.assertEqual("sftp.production.example", client.connect.call_args[0][0])

    @patch("paramiko.SSHClient")
    def test_partner_alias_uses_its_own_trust_file_and_policy(self, mock_ssh):
        self.partner._connect()
        client = mock_ssh.return_value
        client.load_host_keys.assert_called_once_with(self.partner_known_hosts)
        self.assertIsInstance(
            client.set_missing_host_key_policy.call_args[0][0],
            paramiko.AutoAddPolicy,
        )
        with self.assertRaises(AssertionError):
            client.load_host_keys.assert_any_call(self.production_known_hosts)

    @patch("paramiko.SSHClient")
    def test_host_verification_runs_before_the_connection(self, mock_ssh):
        self.production._connect()
        client = mock_ssh.return_value
        calls = client.mock_calls
        connect_index = calls.index(call.connect("sftp.production.example"))
        self.assertIn(call.load_host_keys(self.production_known_hosts), calls)
        self.assertLess(
            calls.index(call.load_host_keys(self.production_known_hosts)),
            connect_index,
        )
        self.assertLess(
            calls.index(
                call.set_missing_host_key_policy(
                    client.set_missing_host_key_policy.call_args[0][0]
                )
            ),
            connect_index,
        )

    @patch("paramiko.SSHClient")
    def test_bad_host_key_blocks_the_sftp_session(self, mock_ssh):
        client = mock_ssh.return_value
        client.connect.side_effect = paramiko.BadHostKeyException(
            "sftp.production.example",
            MagicMock(),
            MagicMock(),
        )
        with self.assertRaises(paramiko.BadHostKeyException):
            self.production._connect()
        # No SFTP session is handed back for an unverified host.
        client.open_sftp.assert_not_called()
        self.assertIsNone(self.production._sftp)
        # The half-open connection is torn down rather than reused.
        client.close.assert_called_once_with()
        self.assertIsNone(self.production._ssh)

    @patch("paramiko.SSHClient")
    def test_unknown_host_key_is_rejected_by_the_strict_alias(self, mock_ssh):
        client = mock_ssh.return_value
        client.connect.side_effect = paramiko.SSHException(
            "Server '[sftp.production.example]' not found in known_hosts"
        )
        with self.assertRaises(paramiko.SSHException):
            self.production._connect()
        client.open_sftp.assert_not_called()
        self.assertIsNone(self.production._sftp)

    @patch("paramiko.SSHClient")
    def test_foreign_trust_file_cannot_authorize_this_connection(self, mock_ssh):
        # The partner's trust store is presented, but this alias only trusts
        # its own file. The presented key therefore fails verification.
        self.production.known_host_file = self.partner_known_hosts
        client = mock_ssh.return_value
        client.connect.side_effect = paramiko.BadHostKeyException(
            "sftp.production.example",
            MagicMock(),
            MagicMock(),
        )
        with self.assertRaises(paramiko.BadHostKeyException):
            self.production._connect()
        client.open_sftp.assert_not_called()
        # Only the foreign file was consulted; this alias' own file was not.
        client.load_host_keys.assert_called_once_with(self.partner_known_hosts)
        with self.assertRaises(AssertionError):
            client.load_host_keys.assert_any_call(self.production_known_hosts)
        # The lazy accessor must not return a usable session either.
        self.assertRaises(
            paramiko.BadHostKeyException, getattr, self.production, "sftp"
        )

    @patch("paramiko.SSHClient")
    def test_write_uses_a_session_that_passed_host_verification(self, mock_ssh):
        self.production._save("foo", File(io.BytesIO(b"foo"), "foo"))
        client = mock_ssh.return_value
        # Host verification precedes any SFTP operation.
        client.set_missing_host_key_policy.assert_called_once()
        client.load_host_keys.assert_called_once_with(self.production_known_hosts)
        calls = client.mock_calls
        connect_index = calls.index(call.connect("sftp.production.example"))
        self.assertLess(
            calls.index(call.load_host_keys(self.production_known_hosts)),
            connect_index,
        )
        # The session used for writing is the one opened after verification.
        self.assertEqual(client.open_sftp.return_value, self.production.sftp)
        client.open_sftp.return_value.putfo.assert_called_once()

    @patch("paramiko.SSHClient")
    def test_read_uses_a_session_that_passed_host_verification(self, mock_ssh):
        self.production._read("foo")
        client = mock_ssh.return_value
        client.load_host_keys.assert_called_once_with(self.production_known_hosts)
        self.assertEqual(client.open_sftp.return_value, self.production.sftp)
        client.open_sftp.return_value.open.assert_called_once_with("foo", "rb")

    @patch("paramiko.SSHClient")
    def test_reconnect_reapplies_this_alias_configuration(self, mock_ssh):
        self.production._connect()
        self.production._connect()
        client = mock_ssh.return_value
        # A fresh client rebuilds trust from this alias' own file every time.
        self.assertEqual(
            client.load_host_keys.call_args_list,
            [
                call(self.production_known_hosts),
                call(self.production_known_hosts),
            ],
        )
        self.assertEqual(2, client.set_missing_host_key_policy.call_count)
        for policy_call in client.set_missing_host_key_policy.call_args_list:
            self.assertIsInstance(policy_call[0][0], paramiko.RejectPolicy)
        with self.assertRaises(AssertionError):
            client.load_host_keys.assert_any_call(self.partner_known_hosts)

    @patch("paramiko.SSHClient")
    def test_failed_verification_on_reconnect_does_not_reuse_old_session(
        self, mock_ssh
    ):
        self.production._connect()
        first_session = self.production._sftp
        self.assertIsNotNone(first_session)

        # Simulate a rebuilt connection whose key no longer matches.
        mock_ssh.reset_mock()
        second_client = mock_ssh.return_value
        second_client.connect.side_effect = paramiko.BadHostKeyException(
            "sftp.production.example",
            MagicMock(),
            MagicMock(),
        )
        with self.assertRaises(paramiko.BadHostKeyException):
            self.production._connect()
        second_client.open_sftp.assert_not_called()
        self.assertIsNone(self.production._sftp)
        self.assertIsNone(self.production._ssh)

    def test_host_key_policy_strings_map_to_paramiko_policies(self):
        for name, policy_class in (
            ("reject", paramiko.RejectPolicy),
            ("auto-add", paramiko.AutoAddPolicy),
            ("warning", paramiko.WarningPolicy),
        ):
            storage = sftpstorage.SFTPStorage(host="foo", host_key_policy=name)
            self.assertIsInstance(storage._get_host_key_policy(), policy_class)

    def test_unknown_host_key_policy_is_rejected(self):
        storage = sftpstorage.SFTPStorage(
            host="foo", host_key_policy="trust-everything"
        )
        with self.assertRaises(ValueError):
            storage._get_host_key_policy()

    def test_host_key_policy_accepts_a_policy_instance(self):
        policy = paramiko.WarningPolicy()
        storage = sftpstorage.SFTPStorage(host="foo", host_key_policy=policy)
        self.assertIs(storage._get_host_key_policy(), policy)

    def test_default_host_key_policy_is_strict(self):
        storage = sftpstorage.SFTPStorage(host="foo")
        self.assertEqual(storage.host_key_policy, "reject")
        self.assertIsInstance(storage._get_host_key_policy(), paramiko.RejectPolicy)

    @patch("paramiko.SSHClient")
    def test_sftp_accessor_reconnects_with_alias_configuration(self, mock_ssh):
        client = mock_ssh.return_value
        client.connect.side_effect = paramiko.BadHostKeyException(
            "sftp.production.example",
            MagicMock(),
            MagicMock(),
        )
        client.get_transport.return_value.is_active.return_value = False
        self.production._ssh = client
        self.production._sftp = None

        self.assertRaises(
            paramiko.BadHostKeyException, getattr, self.production, "sftp"
        )

        client.load_host_keys.assert_called_once_with(self.production_known_hosts)
        client.open_sftp.assert_not_called()
