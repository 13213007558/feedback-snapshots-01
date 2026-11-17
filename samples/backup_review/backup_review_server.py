#!/usr/bin/env python3
"""
Backup review server
====================

A BACpypes3 application that exposes two in-memory BACnet File objects
through a scoped AtomicReadFile/AtomicWriteFile adapter:

* ``file,1`` -- stream (byte) oriented, readable window fixed to octets
  ``[4, 12)``;
* ``file,2`` -- record oriented, readable window fixed to records
  ``[2, 6)``.

The authorization context is built once at startup.  A client cannot reach
data outside the windows or switch the access method to widen the scope.
Writes are denied by :class:`WritePolicy` unless a grant is installed.

Run on a VLAN or IPv4 stack like any other sample, e.g.::

    python backup_review_server.py --address 192.168.1.10/24 --instance 599
"""

from __future__ import annotations

import asyncio

from bacpypes3.app import Application
from bacpypes3.argparse import SimpleArgumentParser
from bacpypes3.debugging import ModuleLogger, bacpypes_debugging
from bacpypes3.object import FileObject
from bacpypes3.primitivedata import ObjectIdentifier, OctetString

from .backup_file_adapter import (
    RECORD_ACCESS,
    STREAM_ACCESS,
    AtomicFileServices,
    ReadGrant,
    RecordBackupFile,
    StreamBackupFile,
    WriteGrant,
)

# some debugging
_debug = 0
_log = ModuleLogger(globals())

#: fixed identifiers for the two review files
STREAM_FILE_ID = ObjectIdentifier("file,1")
RECORD_FILE_ID = ObjectIdentifier("file,2")

#: approved windows (half-open, units follow the access method)
STREAM_WINDOW = (4, 12)
RECORD_WINDOW = (2, 6)


@bacpypes_debugging
class BackupReviewApplication(AtomicFileServices, Application):
    """Application with the scoped Atomic File services mixed in.

    The constructor only prepares the adapter tables; call
    :meth:`load_backup_files` once after the stack is built (and after any
    BACnet File objects from config have been registered) to bind the
    in-memory content and the authorization windows.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.init_atomic_file_services()

    def load_backup_files(self) -> None:
        """Bind in-memory content, read grants and the write policy."""
        # 16 octets: indices 0..15, the grant only exposes octets 4..11
        stream_payload = bytes(range(0x10, 0x20))
        self.backup_files[STREAM_FILE_ID] = StreamBackupFile(
            file_identifier=STREAM_FILE_ID,
            data=stream_payload,
        )
        self.read_grants[STREAM_FILE_ID] = ReadGrant(
            file_identifier=STREAM_FILE_ID,
            access_method=STREAM_ACCESS,
            range_start=STREAM_WINDOW[0],
            range_end=STREAM_WINDOW[1],
        )
        self._register_file_object(
            FileObject(
                objectIdentifier=STREAM_FILE_ID,
                objectName="backup-stream",
                fileType="X-REVIEW/STREAM",
                fileSize=len(stream_payload),
                readOnly=True,
                fileAccessMethod="streamAccess",
            )
        )

        # 10 records; the grant only exposes records 2..5
        records = [OctetString(b"R%02d" % index) for index in range(10)]
        self.backup_files[RECORD_FILE_ID] = RecordBackupFile(
            file_identifier=RECORD_FILE_ID,
            records=records,
        )
        self.read_grants[RECORD_FILE_ID] = ReadGrant(
            file_identifier=RECORD_FILE_ID,
            access_method=RECORD_ACCESS,
            range_start=RECORD_WINDOW[0],
            range_end=RECORD_WINDOW[1],
        )
        self._register_file_object(
            FileObject(
                objectIdentifier=RECORD_FILE_ID,
                objectName="backup-record",
                fileType="X-REVIEW/RECORD",
                recordCount=len(records),
                readOnly=True,
                fileAccessMethod="recordAccess",
            )
        )

        # example of an explicit write grant: only octets [8, 10) of the
        # stream file may be overwritten. Everything else stays denied.
        self.write_policy.allowed[(STREAM_FILE_ID, STREAM_ACCESS)] = WriteGrant(
            range_start=8,
            range_end=10,
        )

    def _register_file_object(self, file_object: FileObject) -> None:
        """Register a FileObject unless config already supplied one."""
        if file_object.objectIdentifier in self.objectIdentifier:
            return
        self.add_object(file_object)


async def main() -> None:
    app = None
    try:
        args = SimpleArgumentParser().parse_args()
        if _debug:
            _log.debug("args: %r", args)

        app = BackupReviewApplication.from_args(args)
        if _debug:
            _log.debug("app: %r", app)

        app.load_backup_files()

        # run until cancelled
        await asyncio.Future()
    finally:
        if app:
            app.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
