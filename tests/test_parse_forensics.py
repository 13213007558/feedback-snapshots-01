import hashlib
import io
import os

import pytest

from loguru import logger

RECORD_PATTERN = rb"(?m)^(?P<seq>[0-9]{4})\|(?P<level>[A-Z]+)\|(?P<message>[^\n]*)\n"
TEXT_RECORD_PATTERN = r"(?m)^(?P<seq>[0-9]{4})\|(?P<level>[A-Z]+)\|(?P<message>[^\n]*)\n"

SAME_SOURCE_COMPLETE = "same-source-complete"
NEW_SOURCE_REQUIRES_REQUERY = "new-source-requires-requery"
EVIDENCE_INSUFFICIENT = "evidence-insufficient"

CHUNK_SIZES = [1, 2, 3, 7, 16, 2**16]


def _record(seq, message, level=b"INFO"):
    return b"|".join((seq, level, message)) + b"\n"


def _group(seq, message, level=b"INFO"):
    return {"seq": seq, "level": level, "message": message}


def _encode(groups):
    return b"|".join((groups["seq"], groups["level"], groups["message"])) + b"\n"


def _scan(raw, chunk):
    groups = tuple(logger.parse(io.BytesIO(raw), RECORD_PATTERN, chunk=chunk))
    canonical = b"".join(_encode(group) for group in groups)
    consumed = len(canonical)
    return groups, consumed, raw[:consumed] == canonical


def _source_state(path):
    with open(str(path), "rb") as file:
        stat = os.fstat(file.fileno())
        raw = file.read()
    return (stat.st_dev, stat.st_ino), raw


def _line_at(raw, offset):
    return raw[offset : raw.index(b"\n", offset) + 1]


def _parse_at_offset(path, offset, chunk):
    with open(str(path), "rb") as file:
        file.seek(offset)
        return list(logger.parse(file, RECORD_PATTERN, chunk=chunk))


class SourceEvidence:
    def __init__(self, identity, raw, groups, consumed, contiguous):
        self.identity = identity
        self.size = len(raw)
        self.records = groups
        self.resume_offset = consumed
        self.pending_tail = raw[consumed:]
        self.prefix_digest = hashlib.sha256(raw[:consumed]).hexdigest()
        self.coverage_ok = contiguous


class ResumeOutcome:
    def __init__(
        self,
        verdict,
        *,
        records=(),
        resume_offset=None,
        identity=None,
        pending_tail=b"",
        reason=None
    ):
        self.verdict = verdict
        self.records = records
        self.resume_offset = resume_offset
        self.identity = identity
        self.pending_tail = pending_tail
        self.reason = reason


def capture(path, chunk=2**16):
    identity, raw = _source_state(path)
    groups, consumed, contiguous = _scan(raw, chunk)
    return SourceEvidence(identity, raw, groups, consumed, contiguous)


def resume(evidence, path, chunk=2**16):
    try:
        identity, raw = _source_state(path)
    except FileNotFoundError:
        return ResumeOutcome(EVIDENCE_INSUFFICIENT, reason="source-missing")

    if identity != evidence.identity:
        groups, consumed, _ = _scan(raw, chunk)
        return ResumeOutcome(
            NEW_SOURCE_REQUIRES_REQUERY,
            records=groups,
            resume_offset=consumed,
            identity=identity,
            pending_tail=raw[consumed:],
            reason="identity-changed",
        )

    if not evidence.coverage_ok:
        return ResumeOutcome(
            EVIDENCE_INSUFFICIENT,
            resume_offset=evidence.resume_offset,
            identity=identity,
            reason="evidence-not-contiguous",
        )

    if len(raw) < evidence.resume_offset:
        return ResumeOutcome(
            EVIDENCE_INSUFFICIENT,
            resume_offset=evidence.resume_offset,
            identity=identity,
            reason="source-shrank",
        )

    if hashlib.sha256(raw[: evidence.resume_offset]).hexdigest() != evidence.prefix_digest:
        return ResumeOutcome(
            EVIDENCE_INSUFFICIENT,
            resume_offset=evidence.resume_offset,
            identity=identity,
            reason="prefix-diverged",
        )

    tail = evidence.pending_tail
    if tail and raw[evidence.resume_offset : evidence.resume_offset + len(tail)] != tail:
        return ResumeOutcome(
            EVIDENCE_INSUFFICIENT,
            resume_offset=evidence.resume_offset,
            identity=identity,
            reason="pending-tail-rewritten",
        )

    groups, consumed, contiguous = _scan(raw[evidence.resume_offset :], chunk)
    offset = evidence.resume_offset + consumed

    if not contiguous:
        return ResumeOutcome(
            EVIDENCE_INSUFFICIENT,
            resume_offset=evidence.resume_offset,
            identity=identity,
            reason="unrecognized-data",
        )

    if offset < len(raw):
        return ResumeOutcome(
            EVIDENCE_INSUFFICIENT,
            records=groups,
            resume_offset=offset,
            identity=identity,
            pending_tail=raw[offset:],
            reason="incomplete-trailing-record",
        )

    return ResumeOutcome(
        SAME_SOURCE_COMPLETE,
        records=groups,
        resume_offset=offset,
        identity=identity,
        reason="clean-eof",
    )


@pytest.mark.parametrize("chunk", CHUNK_SIZES)
def test_capture_identifies_physical_source_and_complete_records(tmp_path, chunk):
    path = tmp_path / "app.log"
    first = _record(b"1001", b"alpha")
    second = _record(b"1002", "日本語".encode("utf-8"))
    path.write_bytes(first + second)
    stat = path.stat()

    evidence = capture(path, chunk=chunk)

    assert evidence.identity == (stat.st_dev, stat.st_ino)
    assert evidence.size == len(first) + len(second)
    assert evidence.records == (
        _group(b"1001", b"alpha"),
        _group(b"1002", "日本語".encode("utf-8")),
    )
    assert evidence.resume_offset == len(first) + len(second)
    assert evidence.pending_tail == b""
    assert evidence.coverage_ok is True


@pytest.mark.parametrize("chunk", CHUNK_SIZES)
def test_resume_of_unchanged_source_reuses_conclusions(tmp_path, chunk):
    path = tmp_path / "app.log"
    path.write_bytes(_record(b"1001", b"alpha") + _record(b"1002", b"bravo"))

    evidence = capture(path, chunk=chunk)
    outcome = resume(evidence, path, chunk=chunk)

    assert outcome.verdict == SAME_SOURCE_COMPLETE
    assert outcome.records == ()
    assert outcome.identity == evidence.identity
    assert outcome.resume_offset == evidence.resume_offset
    assert outcome.pending_tail == b""


@pytest.mark.parametrize("chunk", CHUNK_SIZES)
def test_resume_after_append_emits_only_new_complete_records(tmp_path, chunk):
    path = tmp_path / "app.log"
    first = _record(b"1001", b"alpha")
    second = _record(b"1002", b"bravo")
    third = _record(b"1003", "charlie".encode("utf-8"))
    path.write_bytes(first)

    evidence = capture(path, chunk=chunk)
    with open(str(path), "ab") as file:
        file.write(second + third)

    outcome = resume(evidence, path, chunk=chunk)

    assert outcome.verdict == SAME_SOURCE_COMPLETE
    assert outcome.records == (
        _group(b"1002", b"bravo"),
        _group(b"1003", "charlie".encode("utf-8")),
    )
    assert outcome.resume_offset == len(first) + len(second) + len(third)
    assert evidence.records == (_group(b"1001", b"alpha"),)


@pytest.mark.parametrize("chunk", CHUNK_SIZES)
def test_truncated_multibyte_tail_is_insufficient_until_completed(tmp_path, chunk):
    path = tmp_path / "app.log"
    first = _record(b"1001", b"alpha")
    second = _record(b"1002", "日本語".encode("utf-8"))
    partial = second[:-2]
    path.write_bytes(first + partial)

    evidence = capture(path, chunk=chunk)

    assert evidence.records == (_group(b"1001", b"alpha"),)
    assert evidence.resume_offset == len(first)
    assert evidence.pending_tail == partial

    blocked = resume(evidence, path, chunk=chunk)

    assert blocked.verdict == EVIDENCE_INSUFFICIENT
    assert blocked.reason == "incomplete-trailing-record"
    assert blocked.records == ()
    assert blocked.resume_offset == len(first)
    assert blocked.pending_tail == partial

    path.write_bytes(first + second)
    completed = resume(evidence, path, chunk=chunk)

    assert completed.verdict == SAME_SOURCE_COMPLETE
    assert completed.records == (_group(b"1002", "日本語".encode("utf-8")),)
    assert completed.resume_offset == len(first) + len(second)
    assert completed.pending_tail == b""


@pytest.mark.parametrize("chunk", [1, 2, 3, 7, 2**16])
def test_complete_record_after_partial_capture_is_new_but_tail_still_pending(tmp_path, chunk):
    path = tmp_path / "app.log"
    first = _record(b"1001", b"alpha")
    second = _record(b"1002", b"bravo")
    third = _record(b"1003", "日本語".encode("utf-8"))
    path.write_bytes(first + second[:5])

    evidence = capture(path, chunk=chunk)

    assert evidence.records == (_group(b"1001", b"alpha"),)
    assert evidence.pending_tail == second[:5]

    path.write_bytes(first + second + third[:-1])
    outcome = resume(evidence, path, chunk=chunk)

    assert outcome.verdict == EVIDENCE_INSUFFICIENT
    assert outcome.reason == "incomplete-trailing-record"
    assert outcome.records == (_group(b"1002", b"bravo"),)
    assert outcome.resume_offset == len(first) + len(second)
    assert outcome.pending_tail == third[:-1]

    path.write_bytes(first + second + third)
    completed = resume(evidence, path, chunk=chunk)

    assert completed.verdict == SAME_SOURCE_COMPLETE
    assert completed.records == (
        _group(b"1002", b"bravo"),
        _group(b"1003", "日本語".encode("utf-8")),
    )
    assert completed.resume_offset == len(first) + len(second) + len(third)


def test_text_path_parse_cannot_read_truncated_multibyte_tail(tmp_path):
    path = tmp_path / "app.log"
    first = _record(b"1001", b"alpha")
    second = _record(b"1002", "日本語".encode("utf-8"))
    path.write_bytes(first + second[:-2])

    with pytest.raises(UnicodeDecodeError):
        list(logger.parse(str(path), TEXT_RECORD_PATTERN, chunk=4))

    with open(str(path), "rb") as file:
        assert list(logger.parse(file, RECORD_PATTERN, chunk=4)) == [
            _group(b"1001", b"alpha")
        ]

    path.write_bytes(first + second)

    assert list(logger.parse(str(path), TEXT_RECORD_PATTERN, chunk=3)) == [
        {"seq": "1001", "level": "INFO", "message": "alpha"},
        {"seq": "1002", "level": "INFO", "message": "日本語"},
    ]


@pytest.mark.parametrize("chunk", [1, 2, 7, 2**16])
@pytest.mark.parametrize("cut", [1, 3, 5, 9, 13, 15])
def test_half_written_record_only_becomes_visible_when_terminated(tmp_path, chunk, cut):
    path = tmp_path / "app.log"
    first = _record(b"1001", b"alpha")
    second = _record(b"2002", b"bravo")
    assert 0 < cut < len(second)
    path.write_bytes(first + second[:cut])

    evidence = capture(path, chunk=chunk)

    assert evidence.records == (_group(b"1001", b"alpha"),)
    assert evidence.pending_tail == second[:cut]

    blocked = resume(evidence, path, chunk=chunk)

    assert blocked.verdict == EVIDENCE_INSUFFICIENT
    assert blocked.reason == "incomplete-trailing-record"
    assert blocked.resume_offset == len(first)

    path.write_bytes(first + second)
    completed = resume(evidence, path, chunk=chunk)

    assert completed.verdict == SAME_SOURCE_COMPLETE
    assert completed.records == (_group(b"2002", b"bravo"),)
    assert completed.resume_offset == len(first) + len(second)


@pytest.mark.parametrize("chunk", [1, 2, 3, 7, 2**16])
def test_resume_offset_is_a_record_boundary_with_no_false_hit(tmp_path, chunk):
    path = tmp_path / "app.log"
    records = [
        _record(b"1001", b"alpha"),
        _record(b"1002", "日本語".encode("utf-8")),
        _record(b"1003", b"charlie"),
    ]
    groups = [
        _group(b"1001", b"alpha"),
        _group(b"1002", "日本語".encode("utf-8")),
        _group(b"1003", b"charlie"),
    ]
    boundaries = []
    cursor = 0
    for record in records:
        boundaries.append(cursor)
        cursor += len(record)
    boundaries.append(cursor)
    raw = b"".join(records)
    path.write_bytes(raw)

    evidence = capture(path, chunk=chunk)

    assert evidence.resume_offset == boundaries[-1]
    assert _parse_at_offset(path, evidence.resume_offset, chunk) == []

    for index, offset in enumerate(boundaries[:-1]):
        assert offset == sum(len(record) for record in records[:index])
        assert _parse_at_offset(path, offset, chunk) == groups[index:]

    for index, boundary in enumerate(boundaries[1:-1], start=1):
        midpoint = boundary - 1
        assert midpoint not in boundaries
        resumed = _parse_at_offset(path, midpoint, chunk)
        assert groups[index - 1] not in resumed

    partial = _record(b"1004", "日本語".encode("utf-8"))[:-2]
    path.write_bytes(raw + partial)
    evidence = capture(path, chunk=chunk)

    assert evidence.resume_offset == cursor
    assert evidence.pending_tail == partial
    assert _parse_at_offset(path, evidence.resume_offset, chunk) == []


@pytest.mark.parametrize("chunk", [1, 2, 7, 2**16])
def test_same_byte_offset_resolves_to_different_records_after_rotation(tmp_path, chunk):
    path = tmp_path / "app.log"
    legacy_a = _record(b"1001", b"legacy-alpha")
    legacy_b = _record(b"1002", b"legacy-bravo")
    new_a = _record(b"2001", b"newone-alpha")
    new_b = _record(b"2002", b"newtwo-bravo")
    assert len(legacy_a) == len(new_a)
    assert len(legacy_b) == len(new_b)

    calls = {"count": 0}

    def rotate(message, file):
        calls["count"] += 1
        return calls["count"] == 3

    handler = logger.add(str(path), format="{message}", rotation=rotate, catch=False)

    logger.info(legacy_a[:-1].decode("ascii"))
    evidence = capture(path, chunk=chunk)
    logger.info(legacy_b[:-1].decode("ascii"))
    logger.info(new_a[:-1].decode("ascii"))
    logger.info(new_b[:-1].decode("ascii"))
    logger.remove(handler)

    rotated = sorted(set(tmp_path.iterdir()) - {path})
    assert len(rotated) == 1
    backup = rotated[0]

    old_identity = (backup.stat().st_dev, backup.stat().st_ino)
    new_identity = (path.stat().st_dev, path.stat().st_ino)
    assert old_identity == evidence.identity
    assert old_identity != new_identity

    offset = len(legacy_a)
    assert _line_at(backup.read_bytes(), offset) == legacy_b
    assert _line_at(path.read_bytes(), offset) == new_b
    assert legacy_b != new_b

    assert _parse_at_offset(backup, offset, chunk) == [
        _group(b"1002", b"legacy-bravo")
    ]
    assert _parse_at_offset(path, offset, chunk) == [
        _group(b"2002", b"newtwo-bravo")
    ]

    continued = resume(evidence, backup, chunk=chunk)

    assert continued.verdict == SAME_SOURCE_COMPLETE
    assert continued.identity == old_identity
    assert continued.records == (_group(b"1002", b"legacy-bravo"),)
    assert continued.resume_offset == len(legacy_a) + len(legacy_b)

    requery = resume(evidence, path, chunk=chunk)

    assert requery.verdict == NEW_SOURCE_REQUIRES_REQUERY
    assert requery.identity == new_identity
    assert requery.reason == "identity-changed"
    assert requery.records == (
        _group(b"2001", b"newone-alpha"),
        _group(b"2002", b"newtwo-bravo"),
    )
    assert {group["seq"] for group in requery.records} == {b"2001", b"2002"}
    assert {group["seq"] for group in continued.records}.isdisjoint({b"2001", b"2002"})


@pytest.mark.parametrize("chunk", [1, 2**16])
def test_byte_identical_replacement_requires_requery(tmp_path, chunk):
    path = tmp_path / "app.log"
    first = _record(b"1001", b"alpha")
    second = _record(b"1002", b"bravo")
    raw = first + second
    path.write_bytes(raw)

    evidence = capture(path, chunk=chunk)

    replacement = tmp_path / "replacement.log"
    replacement.write_bytes(raw)
    os.replace(str(replacement), str(path))

    assert (path.stat().st_dev, path.stat().st_ino) != evidence.identity

    outcome = resume(evidence, path, chunk=chunk)

    assert outcome.verdict == NEW_SOURCE_REQUIRES_REQUERY
    assert outcome.reason == "identity-changed"
    assert outcome.records == (_group(b"1001", b"alpha"), _group(b"1002", b"bravo"))


@pytest.mark.parametrize("chunk", [1, 2**16])
def test_rewritten_prefix_on_same_inode_is_insufficient(tmp_path, chunk):
    path = tmp_path / "app.log"
    legacy_a = _record(b"1001", b"legacy-alpha")
    legacy_b = _record(b"1002", b"legacy-bravo")
    new_a = _record(b"2001", b"newone-alpha")
    new_b = _record(b"2002", b"newtwo-bravo")
    path.write_bytes(legacy_a + legacy_b)

    evidence = capture(path, chunk=chunk)

    with open(str(path), "r+b") as file:
        file.truncate(0)
        file.write(new_a + new_b)

    identity = (path.stat().st_dev, path.stat().st_ino)
    assert identity == evidence.identity

    outcome = resume(evidence, path, chunk=chunk)

    assert outcome.verdict == EVIDENCE_INSUFFICIENT
    assert outcome.reason == "prefix-diverged"
    assert outcome.records == ()
    assert outcome.identity == identity


@pytest.mark.parametrize("chunk", [1, 2**16])
def test_shrunken_same_inode_is_insufficient(tmp_path, chunk):
    path = tmp_path / "app.log"
    first = _record(b"1001", b"alpha")
    second = _record(b"1002", b"bravo")
    path.write_bytes(first + second)

    evidence = capture(path, chunk=chunk)
    path.write_bytes(first)

    outcome = resume(evidence, path, chunk=chunk)

    assert outcome.verdict == EVIDENCE_INSUFFICIENT
    assert outcome.reason == "source-shrank"
    assert outcome.records == ()


@pytest.mark.parametrize("chunk", [1, 2**16])
def test_rewritten_pending_tail_is_insufficient(tmp_path, chunk):
    path = tmp_path / "app.log"
    first = _record(b"1001", b"alpha")
    second = _record(b"1002", b"bravo")
    path.write_bytes(first + second[:5])

    evidence = capture(path, chunk=chunk)
    assert evidence.pending_tail == second[:5]

    replacement = b"XYZ"
    assert replacement != second[:5]
    assert len(replacement) != len(second[:5])
    with open(str(path), "r+b") as file:
        file.seek(len(first))
        file.truncate(len(first) + len(replacement))
        file.write(replacement)

    identity = (path.stat().st_dev, path.stat().st_ino)
    assert identity == evidence.identity
    assert path.read_bytes()[len(first) :] == replacement

    outcome = resume(evidence, path, chunk=chunk)

    assert outcome.verdict == EVIDENCE_INSUFFICIENT
    assert outcome.reason == "pending-tail-rewritten"
    assert outcome.records == ()


@pytest.mark.parametrize("chunk", [1, 2**16])
def test_unrecognized_bytes_after_resume_point_are_insufficient(tmp_path, chunk):
    path = tmp_path / "app.log"
    first = _record(b"1001", b"alpha")
    second = _record(b"1002", b"bravo")
    path.write_bytes(first)

    evidence = capture(path, chunk=chunk)
    assert evidence.resume_offset == len(first)

    with open(str(path), "ab") as file:
        file.write(b"# unreviewed marker\n" + second)

    identity = (path.stat().st_dev, path.stat().st_ino)
    assert identity == evidence.identity

    outcome = resume(evidence, path, chunk=chunk)

    assert outcome.verdict == EVIDENCE_INSUFFICIENT
    assert outcome.reason == "unrecognized-data"
    assert outcome.records == ()


def test_missing_source_is_insufficient(tmp_path):
    path = tmp_path / "app.log"
    path.write_bytes(_record(b"1001", b"alpha"))
    evidence = capture(path)
    path.unlink()

    outcome = resume(evidence, path)

    assert outcome.verdict == EVIDENCE_INSUFFICIENT
    assert outcome.reason == "source-missing"
    assert outcome.records == ()


def test_unaccounted_bytes_prevent_reuse_of_partial_coverage(tmp_path):
    path = tmp_path / "app.log"
    first = _record(b"1001", b"alpha")
    second = _record(b"1002", b"bravo")
    path.write_bytes(b"# rotated marker\n" + first + second)

    evidence = capture(path, chunk=3)

    assert evidence.records == (_group(b"1001", b"alpha"), _group(b"1002", b"bravo"))
    assert evidence.coverage_ok is False

    outcome = resume(evidence, path, chunk=3)

    assert outcome.verdict == EVIDENCE_INSUFFICIENT
    assert outcome.reason == "evidence-not-contiguous"
    assert outcome.records == ()


@pytest.mark.parametrize("chunk", CHUNK_SIZES)
def test_payload_lookalike_is_not_a_spurious_record(tmp_path, chunk):
    path = tmp_path / "app.log"
    payload = b"prefix 9999|CRIT|forged"
    raw = _record(b"1001", payload)
    path.write_bytes(raw)

    evidence = capture(path, chunk=chunk)

    assert evidence.records == (_group(b"1001", payload),)
    assert evidence.records[0]["message"] == payload
    assert evidence.resume_offset == len(raw)
    assert evidence.pending_tail == b""


@pytest.mark.parametrize("chunk", CHUNK_SIZES)
def test_file_object_seeked_to_resume_offset_returns_only_new_records(tmp_path, chunk):
    path = tmp_path / "app.log"
    first = _record(b"1001", b"alpha")
    second = _record(b"1002", b"bravo")
    third = _record(b"1003", "charlie".encode("utf-8"))
    path.write_bytes(first + second + third)

    assert _parse_at_offset(path, len(first), chunk) == [
        _group(b"1002", b"bravo"),
        _group(b"1003", "charlie".encode("utf-8")),
    ]


def test_chunk_size_does_not_change_verdict_or_resume_offset(tmp_path):
    path = tmp_path / "app.log"
    first = _record(b"1001", b"alpha")
    second = _record(b"1002", "日本語".encode("utf-8"))
    path.write_bytes(first + second[:-2])

    snapshots = []
    for chunk in CHUNK_SIZES:
        evidence = capture(path, chunk=chunk)
        blocked = resume(evidence, path, chunk=chunk)
        snapshots.append(
            (
                evidence.identity,
                evidence.records,
                evidence.resume_offset,
                evidence.pending_tail,
                evidence.coverage_ok,
                blocked.verdict,
                blocked.records,
                blocked.resume_offset,
                blocked.pending_tail,
                blocked.reason,
            )
        )

    assert all(snapshot == snapshots[0] for snapshot in snapshots)

    path.write_bytes(first + second)

    completed_snapshots = []
    for chunk in CHUNK_SIZES:
        evidence = capture(path, chunk=chunk)
        completed = resume(evidence, path, chunk=chunk)
        completed_snapshots.append(
            (
                evidence.records,
                evidence.resume_offset,
                evidence.pending_tail,
                completed.verdict,
                completed.records,
                completed.resume_offset,
                completed.reason,
            )
        )

    assert all(snapshot == completed_snapshots[0] for snapshot in completed_snapshots)
