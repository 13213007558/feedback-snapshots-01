import pytest

from safe_migration.evidence import MailboxAnchor
from safe_migration.progress import ProgressStore

SOURCE = MailboxAnchor("src.example", "INBOX", 9001)
DESTINATION = MailboxAnchor("dst.example", "Archive/Migrated", 9002)

RFC822 = (
    b"From: approved@src.example\r\n"
    b"To: archive@dst.example\r\n"
    b"Message-ID: <approved-uid-7@src.example>\r\n"
    b"Subject: approved migration message\r\n\r\n"
    b"pre-approved body content\r\n"
)

DEST_LINES = [
    b"OK [UIDVALIDITY 9002] UIDs valid",
    b"OK [UIDNEXT 500] Predicted next UID",
]


def fetch_lines(uid, literal=RFC822):
    return [
        f"* {uid} FETCH (UID {uid} INTERNALDATE \"18-Nov-2026 10:00:00 +0000\" "
        f"RFC822.SIZE {len(literal)} BODY[] {{{len(literal)}}}".encode(),
        literal,
        b")",
    ]


@pytest.fixture()
def store(tmp_path):
    progress = ProgressStore(str(tmp_path / "progress.json"))
    progress.init_job(SOURCE, DESTINATION)
    progress.add_approved_uid(7)
    return progress
