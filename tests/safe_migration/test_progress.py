import json

import pytest

from safe_migration.evidence import MailboxAnchor, MigrationStatus
from safe_migration.progress import MigrationRecord, ProgressStore


def make_store(path):
    store = ProgressStore(path)
    store.init_job(MailboxAnchor("src", "INBOX", 1),
                   MailboxAnchor("dst", "Archive", 2))
    store.add_approved_uid(10)
    return store


def test_round_trip_preserves_record_state(tmp_path):
    path = str(tmp_path / "p.json")
    store = make_store(path)
    record = store.get(10)
    record.status = MigrationStatus.MOVE_SENT_UNKNOWN.value
    record.target_uid = 437
    store.save(record, "answer lost")

    reopened = ProgressStore(path)
    loaded = reopened.get(10)
    assert loaded.status == MigrationStatus.MOVE_SENT_UNKNOWN.value
    assert loaded.target_uid == 437
    assert any("answer lost" in entry for entry in loaded.log)

    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    assert payload["source"]["uidvalidity"] == 1
    assert "10" in payload["records"]


def test_terminal_transition_is_rejected(tmp_path):
    store = make_store(str(tmp_path / "p.json"))
    record = store.get(10)
    record.status = MigrationStatus.CONFIRMED.value
    store.save(record, "done")

    mutated = MigrationRecord(source_uid=10, status=MigrationStatus.PENDING.value)
    with pytest.raises(ValueError):
        store.save(mutated, "must not reopen")


def test_init_twice_is_rejected(tmp_path):
    path = str(tmp_path / "p.json")
    make_store(path)
    with pytest.raises(ValueError):
        make_store(path)
