"""Keep a sequence-number view while alert identities stay UID based.

IMAP message sequence numbers are positions in the currently selected
mailbox.  An ``EXPUNGE`` shifts every following position, so a cached
``(sequence number, alert)`` pair must never be reused after an expunge.  The
persistent key is the UID obtained from ``FETCH``; this module only uses the
sequence view to render those UIDs for a human.

The view is deliberately conservative.  It is invalidated when the server
evidence is missing or contradictory, for example a ``FETCH`` without a UID,
a sequence gap, an out-of-range ``EXPUNGE``, a jammed UID at a sequence, or an
``EXISTS`` count below the tracked messages.  Once invalid, the alert cache
still shows UIDs but no display sequence is guessed until a full
``UID FETCH 1:* (UID)`` rebuilds the view.  A SELECT, even of the same mailbox,
is also an evidence boundary and requires such a rebuild.

Typical aioimaplib wiring::

    select_response = await imap_client.select('INBOX')
    view.select('INBOX', select_response)

    uid_response = await imap_client.uid('fetch', '1:*', '(UID)')
    view.load_full_uid_fetch(uid_response)

    # cache alerts by the UID parsed from the fetched message
    alerts.bind(*view.scope)
    alerts.add(uid, 'disk quota exceeded')

    # IDLE / NOOP unsolicited lines: EXPUNGE and FETCH can be interleaved
    view.handle_untagged(await imap_client.wait_server_push())
    for row in alerts.render(view):
        print(row.uid, row.sequence, row.text)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple, Union

from aioimaplib import Response

FETCH_START_RE = re.compile(rb'^(?P<seq>\d+) FETCH\b')
EXPUNGE_RE = re.compile(rb'^(?P<seq>\d+) EXPUNGE$')
EXISTS_RE = re.compile(rb'^(?P<count>\d+) EXISTS$')
UID_IN_ATTRS_RE = re.compile(rb'(?:^|[ (])UID\s+(?P<uid>\d+)(?:[\s)])')
UIDVALIDITY_RE = re.compile(rb'\[UIDVALIDITY\s+(?P<uidvalidity>\d+)\]')


def response_lines(response: Union[Response, Iterable[bytes]]) -> Iterable[bytes]:
    """Return aioimaplib response lines, accepting a bare iterable as well."""
    if isinstance(response, Response):
        return response.lines
    return response


def _strip_untagged_prefix(line: bytes) -> bytes:
    return line.removeprefix(b'* ')


@dataclass(frozen=True)
class RenderedAlert:
    """An alert with the sequence derived from the *current* view."""

    uid: int
    sequence: Optional[int]
    text: str

    @property
    def attached(self) -> bool:
        return self.sequence is not None


class SequenceView:
    """Explicit ``sequence number -> UID`` map for one selected mailbox."""

    def __init__(self) -> None:
        self.mailbox: Optional[str] = None
        self.uidvalidity: Optional[int] = None
        self.valid = False
        self.reason: Optional[str] = 'no mailbox selected'
        self._uids: List[int] = []
        self._expected_count: Optional[int] = None
        self.expunged_uids: List[int] = []
        self._last_expunge_sequence: Optional[int] = None
        self._generation = 0

    @property
    def scope(self) -> Tuple[Optional[str], Optional[int]]:
        return self.mailbox, self.uidvalidity

    @property
    def generation(self) -> int:
        """Increments whenever the mailbox/UIDVALIDITY scope changes."""
        return self._generation

    @property
    def uids(self) -> Tuple[int, ...]:
        return tuple(self._uids)

    @property
    def count(self) -> int:
        return len(self._uids)

    def sequence_of(self, uid: int) -> Optional[int]:
        if not self.valid:
            return None
        try:
            return self._uids.index(uid) + 1
        except ValueError:
            return None

    def invalidate(self, reason: str) -> None:
        self.valid = False
        self.reason = reason

    def select(self, mailbox: str, response: Response) -> None:
        """Apply a SELECT/EXAMINE response.

        A different mailbox or UIDVALIDITY starts a new scope and therefore a
        new, initially invalid view.  Re-selecting the same scope is also an
        evidence boundary: the server sends a fresh EXISTS without replaying
        EXPUNGEs that happened while the mailbox was not selected, so the view
        always requires a full UID FETCH afterwards.
        """
        if response.result != 'OK':
            self.invalidate('SELECT failed')
            return

        uidvalidity = self._parse_uidvalidity(response.lines)
        exists = self._parse_exists(response.lines)
        scope_changed = mailbox != self.mailbox or uidvalidity != self.uidvalidity

        self.mailbox = mailbox
        self.uidvalidity = uidvalidity
        self._last_expunge_sequence = None
        if scope_changed:
            self._uids = []
            self.expunged_uids = []
            self._generation += 1
        self._expected_count = exists

        if uidvalidity is None:
            self.invalidate('SELECT response has no UIDVALIDITY')
        elif exists is None:
            self.invalidate('SELECT response has no EXISTS')
        else:
            self.invalidate('SELECT is an evidence boundary; load UID FETCH 1:* (UID)')

    def load_full_uid_fetch(self, response: Response) -> None:
        """Rebuild the view from ``UID FETCH 1:* (UID)``.

        Every UID must be present exactly once and sequence numbers must be
        contiguous from 1.  Any hole means evidence was lost, so the view is
        invalidated rather than filled by assumption.
        """
        if response.result != 'OK':
            self.invalidate('UID FETCH failed')
            return
        if self.mailbox is None or self.uidvalidity is None:
            self.invalidate('UID FETCH before a SELECT with UIDVALIDITY')
            return

        by_sequence = {}
        for raw_line in response.lines:
            line = _strip_untagged_prefix(raw_line)
            match = FETCH_START_RE.match(line)
            if match is None:
                continue
            uid = self._uid_from_attrs(line)
            if uid is None:
                self.invalidate('FETCH response without UID')
                return
            sequence = int(match.group('seq'))
            if sequence < 1:
                self.invalidate('FETCH with invalid sequence number')
                return
            if sequence in by_sequence and by_sequence[sequence] != uid:
                self.invalidate('conflicting UIDs for sequence %d' % sequence)
                return
            by_sequence[sequence] = uid

        if not by_sequence:
            if self._expected_count == 0:
                self._uids = []
                self.valid = True
                self.reason = None
                return
            self.invalidate('UID FETCH returned no messages')
            return

        sequences = sorted(by_sequence)
        if sequences != list(range(1, len(sequences) + 1)):
            self.invalidate('UID FETCH sequence gap')
            return
        if len(set(by_sequence.values())) != len(by_sequence):
            self.invalidate('the same UID appears at different sequence numbers')
            return
        if self._expected_count is not None and len(sequences) != self._expected_count:
            self.invalidate(
                'UID FETCH returned %d messages, SELECT announced %d' %
                (len(sequences), self._expected_count)
            )
            return

        self._uids = [by_sequence[sequence] for sequence in sequences]
        self._expected_count = len(self._uids)
        self._last_expunge_sequence = None
        self.valid = True
        self.reason = None

    def handle_untagged(self, response: Union[Response, Iterable[bytes]]) -> None:
        """Apply unsolicited ``EXPUNGE``/``FETCH``/``EXISTS`` lines in order.

        ``EXPUNGE`` renumbers the messages that follow it, so stateful lines
        must be applied in wire order; callers must not group or reorder them.
        """
        for raw_line in response_lines(response):
            line = _strip_untagged_prefix(raw_line)
            expunge = EXPUNGE_RE.match(line)
            if expunge is not None:
                self._apply_expunge(int(expunge.group('seq')))
                continue
            if FETCH_START_RE.match(line):
                self._apply_fetch(line)
                continue
            exists = EXISTS_RE.match(line)
            if exists is not None:
                self._apply_exists(int(exists.group('count')))

    def _apply_fetch(self, line: bytes) -> None:
        match = FETCH_START_RE.match(line)
        uid = self._uid_from_attrs(line)
        if uid is None:
            self.invalidate('FETCH notification without UID')
            return
        self._last_expunge_sequence = None
        if not self.valid:
            return

        sequence = int(match.group('seq'))
        if sequence < 1:
            self.invalidate('FETCH notification with invalid sequence number')
            return
        if sequence <= len(self._uids):
            if self._uids[sequence - 1] != uid:
                self.invalidate(
                    'FETCH UID %d disagrees with tracked UID %d at sequence %d' %
                    (uid, self._uids[sequence - 1], sequence)
                )
            return
        if sequence == len(self._uids) + 1 and (
            self._expected_count is None or len(self._uids) < self._expected_count
        ):
            self._uids.append(uid)
            self._expected_count = max(self._expected_count or 0, len(self._uids))
            return
        self.invalidate('FETCH sequence %d is beyond the tracked message count' % sequence)

    def _apply_expunge(self, sequence: int) -> None:
        if not self.valid:
            return
        if sequence == self._last_expunge_sequence:
            # A standard EXPUNGE carries no UID, so a repeated identical
            # notification cannot be distinguished from expunging the message
            # that has since moved into that position.  Refuse to guess.
            self.invalidate('duplicate EXPUNGE notification for sequence %d' % sequence)
            return
        if sequence < 1 or sequence > len(self._uids):
            self.invalidate('EXPUNGE sequence %d is outside the view' % sequence)
            return
        self.expunged_uids.append(self._uids.pop(sequence - 1))
        self._expected_count = len(self._uids)
        self._last_expunge_sequence = sequence

    def _apply_exists(self, count: int) -> None:
        if not self.valid:
            return
        self._last_expunge_sequence = None
        if count < len(self._uids):
            self.invalidate(
                'EXISTS %d is below %d tracked messages; EXPUNGE was lost' %
                (count, len(self._uids))
            )
        else:
            # New messages at the tail do not shift existing sequence numbers.
            # Their UIDs remain unknown until a following FETCH provides them.
            self._expected_count = count

    @staticmethod
    def _uid_from_attrs(line: bytes) -> Optional[int]:
        match = UID_IN_ATTRS_RE.search(line)
        return int(match.group('uid')) if match is not None else None

    @staticmethod
    def _parse_uidvalidity(lines: Iterable[bytes]) -> Optional[int]:
        for raw_line in lines:
            match = UIDVALIDITY_RE.search(_strip_untagged_prefix(raw_line))
            if match is not None:
                return int(match.group('uidvalidity'))
        return None

    @staticmethod
    def _parse_exists(lines: Iterable[bytes]) -> Optional[int]:
        for raw_line in lines:
            match = EXISTS_RE.match(_strip_untagged_prefix(raw_line))
            if match is not None:
                return int(match.group('count'))
        return None


@dataclass(frozen=True)
class Alert:
    uid: int
    text: str


class AlertCache:
    """Alerts keyed by UID and scoped by ``(mailbox, UIDVALIDITY)``.

    Sequence numbers are derived only when rendering through a valid
    :class:`SequenceView`.  Switching mailbox scope clears the cache so an
    INBOX alert can never be attached to an Archive message that happens to
    reuse the same UID number.
    """

    def __init__(self) -> None:
        self.mailbox: Optional[str] = None
        self.uidvalidity: Optional[int] = None
        self._alerts: List[Alert] = []
        self._seen = set()

    @property
    def scope(self) -> Tuple[Optional[str], Optional[int]]:
        return self.mailbox, self.uidvalidity

    def bind(self, mailbox: Optional[str], uidvalidity: Optional[int]) -> None:
        scope = mailbox, uidvalidity
        if scope != self.scope:
            self.mailbox = mailbox
            self.uidvalidity = uidvalidity
            self._alerts.clear()
            self._seen.clear()

    def add(self, uid: int, text: str) -> None:
        key = uid, text
        if key not in self._seen:
            self._seen.add(key)
            self._alerts.append(Alert(uid, text))

    def render(self, view: SequenceView) -> List[RenderedAlert]:
        same_scope = (
            view.mailbox == self.mailbox and
            view.uidvalidity == self.uidvalidity and
            view.uidvalidity is not None
        )
        return [
            RenderedAlert(alert.uid, view.sequence_of(alert.uid) if same_scope else None, alert.text)
            for alert in self._alerts
        ]


def select_mailbox(
    view: SequenceView, cache: AlertCache, mailbox: str, response: Response
) -> None:
    """Apply SELECT, then bind the cache to the mailbox identity scope."""
    view.select(mailbox, response)
    cache.bind(view.mailbox, view.uidvalidity)


def _demo_response(*lines: bytes) -> Response:
    return Response('OK', list(lines))


def main() -> None:
    """Three-message transcript: remove the middle message, then FETCH again."""
    view = SequenceView()
    cache = AlertCache()

    select_inbox = _demo_response(
        b'FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)',
        b'3 EXISTS',
        b'0 RECENT',
        b'OK [UIDVALIDITY 77] UIDs valid',
        b'OK [UIDNEXT 104] Predicted next UID',
    )
    select_mailbox(view, cache, 'INBOX', select_inbox)

    full_fetch = _demo_response(
        b'1 FETCH (UID 101)',
        b'2 FETCH (UID 102)',
        b'3 FETCH (UID 103)',
        b'FETCH completed.',
    )
    view.load_full_uid_fetch(full_fetch)
    cache.add(101, 'mailbox nearly full')
    cache.add(102, 'certificate expires soon')
    cache.add(103, 'delivery queue lag')

    print('before EXPUNGE')
    for row in cache.render(view):
        print('  uid=%d sequence=%s text=%s' % (row.uid, row.sequence, row.text))

    # The middle message is expunged, then an unsolicited FETCH refers to the
    # message that moved from sequence 3 to sequence 2.  The duplicate FETCH
    # notification must be idempotent.
    view.handle_untagged([
        b'2 EXPUNGE',
        b'2 FETCH (UID 103)',
        b'2 FETCH (UID 103)',
    ])

    print('after EXPUNGE (view valid=%s, uids=%s)' % (view.valid, view.uids))
    for row in cache.render(view):
        print('  uid=%d sequence=%s text=%s' % (row.uid, row.sequence, row.text))


if __name__ == '__main__':
    main()
