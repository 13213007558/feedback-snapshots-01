import pytest

from aioimaplib import Response
from example.imap_sequence_view import AlertCache, SequenceView, select_mailbox


def response(*lines: bytes, result: str = 'OK') -> Response:
    return Response(result, list(lines))


def select_response(uidvalidity: int, exists: int) -> Response:
    return response(
        b'FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)',
        b'%d EXISTS' % exists,
        b'0 RECENT',
        b'OK [UIDVALIDITY %d] UIDs valid' % uidvalidity,
        b'OK [UIDNEXT %d] Predicted next UID' % (uidvalidity + exists + 1),
    )


def uid_fetch_response(*uids: int) -> Response:
    lines = [b'%d FETCH (UID %d)' % (sequence, uid) for sequence, uid in enumerate(uids, start=1)]
    lines.append(b'FETCH completed.')
    return response(*lines)


def rendered(cache: AlertCache, view: SequenceView):
    return [(row.uid, row.sequence, row.text) for row in cache.render(view)]


@pytest.fixture()
def three_mail_view_and_cache():
    view = SequenceView()
    cache = AlertCache()
    select_mailbox(view, cache, 'INBOX', select_response(77, 3))
    view.load_full_uid_fetch(uid_fetch_response(101, 102, 103))
    cache.add(101, 'mailbox nearly full')
    cache.add(102, 'certificate expires soon')
    cache.add(103, 'delivery queue lag')
    return view, cache


def test_three_message_transcript_expunges_middle_then_fetches_the_shifted_message(
    three_mail_view_and_cache,
):
    view, cache = three_mail_view_and_cache

    assert rendered(cache, view) == [
        (101, 1, 'mailbox nearly full'),
        (102, 2, 'certificate expires soon'),
        (103, 3, 'delivery queue lag'),
    ]

    view.handle_untagged([b'2 EXPUNGE', b'2 FETCH (UID 103)'])

    assert view.valid
    assert view.uids == (101, 103)
    assert rendered(cache, view) == [
        (101, 1, 'mailbox nearly full'),
        (102, None, 'certificate expires soon'),
        (103, 2, 'delivery queue lag'),
    ]
    assert (102, 2) not in rendered(cache, view)


def test_repeated_fetch_notifications_are_idempotent(three_mail_view_and_cache):
    view, cache = three_mail_view_and_cache

    view.handle_untagged([
        b'2 FETCH (UID 102)',
        b'2 FETCH (UID 102)',
        b'3 FETCH (UID 103)',
    ])

    assert view.valid
    assert view.uids == (101, 102, 103)
    assert rendered(cache, view)[1] == (102, 2, 'certificate expires soon')


def test_interleaved_expunge_and_fetch_are_applied_in_wire_order(three_mail_view_and_cache):
    view, cache = three_mail_view_and_cache

    view.handle_untagged([
        b'1 EXPUNGE',
        b'1 FETCH (UID 102)',
        b'1 FETCH (UID 102)',
        b'1 EXPUNGE',
        b'1 FETCH (UID 103)',
    ])

    assert view.valid
    assert view.uids == (103,)
    assert rendered(cache, view) == [
        (101, None, 'mailbox nearly full'),
        (102, None, 'certificate expires soon'),
        (103, 1, 'delivery queue lag'),
    ]


def test_fetch_without_uid_invalidates_and_no_sequence_is_guessed(three_mail_view_and_cache):
    view, cache = three_mail_view_and_cache

    view.handle_untagged([b'2 FETCH (FLAGS (\\Seen))'])

    assert not view.valid
    assert 'without UID' in view.reason
    assert rendered(cache, view) == [
        (101, None, 'mailbox nearly full'),
        (102, None, 'certificate expires soon'),
        (103, None, 'delivery queue lag'),
    ]


def test_fetch_with_conflicting_uid_invalidates_the_view(three_mail_view_and_cache):
    view, cache = three_mail_view_and_cache

    view.handle_untagged([b'2 FETCH (UID 999)'])

    assert not view.valid
    assert rendered(cache, view)[1] == (102, None, 'certificate expires soon')


def test_expunge_outside_the_view_invalidates_instead_of_guessing(three_mail_view_and_cache):
    view, cache = three_mail_view_and_cache

    view.handle_untagged([b'4 EXPUNGE'])

    assert not view.valid
    assert all(sequence is None for _, sequence, _ in rendered(cache, view))


def test_full_fetch_with_a_sequence_gap_invalidates(three_mail_view_and_cache):
    view, cache = three_mail_view_and_cache

    view.load_full_uid_fetch(response(b'1 FETCH (UID 101)', b'3 FETCH (UID 103)'))

    assert not view.valid
    assert 'sequence gap' in view.reason
    assert all(sequence is None for _, sequence, _ in rendered(cache, view))


def test_full_fetch_without_uid_invalidates(three_mail_view_and_cache):
    view, cache = three_mail_view_and_cache

    view.load_full_uid_fetch(response(b'1 FETCH (FLAGS (\\Seen))', b'2 FETCH (UID 102)'))

    assert not view.valid
    assert 'without UID' in view.reason


def test_selecting_another_mailbox_clears_alerts_and_requires_a_rebuild(three_mail_view_and_cache):
    view, cache = three_mail_view_and_cache

    select_mailbox(view, cache, 'Archive', select_response(88, 1))

    assert view.valid is False
    assert view.scope == ('Archive', 88)
    assert rendered(cache, view) == []
    assert view.sequence_of(103) is None


def test_uidvalidity_change_starts_a_new_scope_and_clears_alerts(three_mail_view_and_cache):
    view, cache = three_mail_view_and_cache

    select_mailbox(view, cache, 'INBOX', select_response(78, 3))

    assert view.valid is False
    assert view.scope == ('INBOX', 78)
    assert rendered(cache, view) == []


def test_reselecting_the_same_scope_is_an_evidence_boundary(three_mail_view_and_cache):
    view, cache = three_mail_view_and_cache

    select_mailbox(view, cache, 'INBOX', select_response(77, 3))
    select_mailbox(view, cache, 'INBOX', select_response(77, 3))

    assert not view.valid
    assert 'evidence boundary' in view.reason
    assert all(sequence is None for _, sequence, _ in rendered(cache, view))

    view.load_full_uid_fetch(uid_fetch_response(101, 102, 103))
    assert view.valid
    assert rendered(cache, view)[1] == (102, 2, 'certificate expires soon')


def test_new_fetch_beyond_an_unannounced_message_invalidates(three_mail_view_and_cache):
    view, cache = three_mail_view_and_cache

    view.handle_untagged([b'4 FETCH (UID 104)'])

    assert not view.valid
    assert all(sequence is None for _, sequence, _ in rendered(cache, view))


def test_alerts_are_deduplicated_by_uid_and_text(three_mail_view_and_cache):
    view, cache = three_mail_view_and_cache

    cache.add(102, 'certificate expires soon')
    cache.add(102, 'certificate expires soon')

    assert rendered(cache, view).count((102, 2, 'certificate expires soon')) == 1


def test_exists_growth_waits_for_fetch_uid_before_extending_the_view(three_mail_view_and_cache):
    view, cache = three_mail_view_and_cache

    view.handle_untagged([b'4 EXISTS', b'4 FETCH (UID 104)'])

    assert view.valid
    assert view.uids == (101, 102, 103, 104)
    assert rendered(cache, view) == [
        (101, 1, 'mailbox nearly full'),
        (102, 2, 'certificate expires soon'),
        (103, 3, 'delivery queue lag'),
    ]


def test_fetch_for_an_unannounced_sequence_invalidates(three_mail_view_and_cache):
    view, cache = three_mail_view_and_cache

    view.handle_untagged([b'4 FETCH (UID 104)'])

    assert not view.valid
    assert 'beyond the tracked message count' in view.reason
    assert all(sequence is None for _, sequence, _ in rendered(cache, view))


def test_exists_shrink_without_expunge_invalidates(three_mail_view_and_cache):
    view, cache = three_mail_view_and_cache

    view.handle_untagged([b'2 EXISTS'])

    assert not view.valid
    assert 'EXPUNGE was lost' in view.reason
    assert all(sequence is None for _, sequence, _ in rendered(cache, view))


def test_duplicate_expunge_notification_invalidates_instead_of_removing_another_message(
    three_mail_view_and_cache,
):
    view, cache = three_mail_view_and_cache

    view.handle_untagged([b'2 EXPUNGE', b'2 EXPUNGE'])

    assert not view.valid
    assert 'duplicate EXPUNGE' in view.reason
    assert all(sequence is None for _, sequence, _ in rendered(cache, view))


def test_fetch_between_expunges_disambiguates_reusing_the_same_sequence(three_mail_view_and_cache):
    view, cache = three_mail_view_and_cache

    view.handle_untagged([
        b'1 EXPUNGE',
        b'1 FETCH (UID 102)',
        b'1 EXPUNGE',
        b'1 FETCH (UID 103)',
    ])

    assert view.valid
    assert view.uids == (103,)
