from safe_migration.evidence import (
    build_fingerprint,
    extract_literal,
    parse_copyuid,
    parse_fetch_uid,
    parse_internal_date,
    parse_search_uids,
    parse_uidvalidity,
)
from tests.safe_migration.conftest import RFC822, fetch_lines


def test_parse_uidvalidity_from_select():
    lines = [b"1 EXISTS", b"OK [UIDVALIDITY 9001] UIDs valid",
             b"OK [UIDNEXT 42] Predicted next UID"]
    assert parse_uidvalidity(lines) == 9001


def test_parse_copyuid_single_and_range():
    single = parse_copyuid([b"OK [COPYUID 9002 7 437]"])
    assert single.uidvalidity == 9002
    assert single.maps_single(7) == 437

    ranged = parse_copyuid([b"OK [COPYUID 9002 7:9 437:439]"])
    assert ranged.source_uids == (7, 8, 9)
    assert ranged.target_uids == (437, 438, 439)
    assert ranged.maps_single(7) is None  # not a single-message mapping


def test_parse_copyuid_returns_none_without_code():
    assert parse_copyuid([b"OK Copy completed"]) is None


def test_parse_fetch_uid_and_search():
    assert parse_fetch_uid([b"* 7 FETCH (UID 7 FLAGS (\\Seen))"]) == 7
    assert parse_fetch_uid([b"* SEARCH 437 438"]) is None
    assert parse_search_uids([b"* SEARCH 437 438"]) == (437, 438)
    assert parse_search_uids([b"* SEARCH"]) == ()


def test_internal_date_and_literal_and_fingerprint():
    lines = fetch_lines(7)
    assert parse_internal_date(lines) == "18-Nov-2026 10:00:00 +0000"
    assert extract_literal(lines) == RFC822
    fingerprint = build_fingerprint(7, lines, extract_literal(lines))
    assert fingerprint.message_id == "<approved-uid-7@src.example>"
    assert fingerprint.rfc822_size == len(RFC822)
    assert fingerprint.body_sha256 and len(fingerprint.body_sha256) == 64
