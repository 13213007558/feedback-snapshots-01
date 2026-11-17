# -*- coding: utf-8 -*-
"""Receive-path regression for protocol-looking bytes inside response literals.

The wire is a line protocol interrupted by counted literals: after a line
ending in ``{n}`` exactly n bytes belong to the literal, whatever they look
like. Mail bodies can contain ``* BYE``, complete tagged-response lookalikes
and arbitrary binary, so the receive parser must switch to a byte-counting
mode between the first and the n-th byte and must not run line matching on
those bytes.

Every case is built from an explicit layout (line, literal, line, ...). The
expected command response, connection state and consumer bytes are derived
from that layout alone, never from the parser under test. The same wire is
then fed through ``data_received`` at every single cut point, so a state leak
across chunks is visible as a different command result.
"""
import asyncio

import pytest

from aioimaplib import aioimaplib
from aioimaplib.aioimaplib import CRLF, IMAP4ClientProtocol, Command, FetchCommand

aioimaplib.get_running_loop = asyncio.new_event_loop


# ---------------------------------------------------------------------------
# Independent layout oracle
# ---------------------------------------------------------------------------

def _tagged_line(tag: bytes, status: bytes, text: bytes) -> bytes:
    return tag + b' ' + status + b' ' + text


class Layout:
    """An ordered response layout plus the exact bytes it serialises to.

    Items are ``('line', bytes)`` for a CRLF-terminated response line and
    ``('literal', bytes)`` for counted literal content. A line ending in
    ``{n}`` must be immediately followed by a literal whose length is n.
    """

    def __init__(self, tag=b'TAG', untagged_prefix=b'* '):
        self.tag = tag
        self.untagged_prefix = untagged_prefix
        self.items = []

    def line(self, text, untagged=False, literal=None):
        if untagged and not text.startswith(self.untagged_prefix):
            text = self.untagged_prefix + text
        wire = text
        self.items.append(('line', wire))
        if literal is not None:
            self.literal(literal)
        return self

    def literal(self, data):
        self.items.append(('literal', data))
        return self

    def crlf(self):
        """Terminate the current response line right after a literal."""
        self.items.append(('crlf', b''))
        return self

    def wire(self):
        out = bytearray()
        for kind, data in self.items:
            if kind == 'crlf':
                out += CRLF
            elif kind == 'line':
                out += data + CRLF
            else:
                out += data
        return bytes(out)

    def expected_lines(self, tag):
        """What the command should receive, following the protocol rules:
        untagged prefix and the leading tag of the completion are removed;
        literal bytes are kept verbatim as one response line."""
        expected = []
        for kind, data in self.items:
            if kind == 'crlf':
                continue
            if kind == 'literal':
                expected.append(data)
            elif data.startswith(self.untagged_prefix):
                expected.append(data[len(self.untagged_prefix):])
            elif data.startswith(tag + b' '):
                expected.append(data[len(tag) + 1:].split(b' ', 1)[1])
            else:
                expected.append(data)
        return expected


def literal_line(prefix, body):
    return prefix + b' {%d}' % len(body)


# ---------------------------------------------------------------------------
# Harness: drive data_received directly, with a recording transport
# ---------------------------------------------------------------------------

class RecordingTransport:
    def __init__(self):
        self.written = []
        self.closed = False

    def write(self, data):
        self.written.append(data)

    def close(self):
        self.closed = True

    def is_closing(self):
        return self.closed

    def pause_reading(self):
        pass

    def resume_reading(self):
        pass


def observation(protocol, command):
    response = command.response
    return {
        'result': response.result,
        'lines': [bytes(line) for line in response.lines],
        'state': protocol.state,
        'incomplete_line': protocol.incomplete_line,
        'literal_continuation': getattr(protocol, 'literal_continuation', False),
        'current_command': protocol.current_command,
        'pending_sync': protocol.pending_sync_command,
        'pending_async': dict(protocol.pending_async_commands),
        'completed': command._event.is_set(),
        'closed': protocol.transport.is_closing(),
        'written': list(protocol.transport.written),
    }


def receive(wire, cuts=(), *, command=None, async_mode=False, tag=b'TAG'):
    protocol = IMAP4ClientProtocol(None)
    protocol.connection_made(RecordingTransport())
    protocol.state = aioimaplib.SELECTED

    tag_text = tag.decode()
    if command is None:
        command = FetchCommand(tag_text, '1', '(BODY[])')
    if async_mode:
        protocol.pending_async_commands[command.untagged_resp_name] = command
    else:
        protocol.pending_sync_command = command

    bounds = [0] + list(cuts) + [len(wire)]
    for start, end in zip(bounds, bounds[1:]):
        if end > start:
            protocol.data_received(wire[start:end])

    return observation(protocol, command)


def every_split(wire):
    for cut in range(1, len(wire)):
        yield [cut]


# ---------------------------------------------------------------------------
# 1. A literal is byte-counted, not line-matched
# ---------------------------------------------------------------------------

def test_body_with_fake_bye_and_tagged_completion_is_preserved_byte_for_byte():
    body = b'* BYE Logging out\r\nTAG OK LOGOUT completed\r\n\x00\xff'
    layout = Layout().line(b'* 1 FETCH (UID 1 BODY[] {%d}' % len(body), untagged=True)
    layout.literal(body)
    layout.line(b')')
    layout.line(_tagged_line(b'TAG', b'OK', b'FETCH completed'))
    wire = layout.wire()

    observation_ = receive(wire)

    assert observation_['result'] == 'OK'
    assert observation_['lines'] == layout.expected_lines(b'TAG')
    assert observation_['lines'][1] == body
    assert observation_['state'] == aioimaplib.SELECTED
    assert observation_['completed'] is True
    assert observation_['pending_sync'] is None


def test_fake_bye_inside_literal_does_not_touch_connection_state_or_transport():
    body = b'* BYE Logging out\r\n'
    layout = Layout().line(b'* 1 FETCH (BODY[] {%d}' % len(body), untagged=True)
    layout.literal(body)
    layout.line(b')')
    layout.line(_tagged_line(b'TAG', b'OK', b'FETCH completed'))
    received = receive(layout.wire())

    assert received['lines'][1] == body
    assert received['closed'] is False
    assert received['written'] == []
    assert received['state'] == aioimaplib.SELECTED


def test_literal_shorter_than_a_full_fake_status_does_not_end_response_early():
    body = b'TAG OK FETCH completed.\r\n'
    layout = Layout().line(b'* 1 FETCH (BODY[] {%d}' % len(body), untagged=True)
    layout.literal(body)
    layout.line(b')')
    layout.line(_tagged_line(b'TAG', b'OK', b'FETCH completed'))
    received = receive(layout.wire())

    assert received['lines'][1] == body
    assert received['result'] == 'OK'
    assert received['completed'] is True


# ---------------------------------------------------------------------------
# 2. Layout coverage: empty literal, multiple literals, CRLF across splits,
#    completion immediately after the body
# ---------------------------------------------------------------------------

def test_empty_literal_is_an_empty_response_line_not_a_control_line():
    layout = Layout().line(b'* 1 FETCH (UID 1 BODY[] {0}', untagged=True)
    layout.line(b')')
    layout.line(_tagged_line(b'TAG', b'OK', b'FETCH completed'))
    wire = layout.wire()

    received = receive(wire)

    assert received['lines'] == [b'1 FETCH (UID 1 BODY[] {0}', b'', b')', b'FETCH completed']
    assert received['result'] == 'OK'


def test_empty_literal_at_end_forces_parser_to_consume_counted_zero_without_guessing():
    # The response is complete on the literal boundary; a later chunk starts
    # with a line that looks like a new untagged control response.
    layout = Layout().line(b'* 1 FETCH (UID 1 BODY[] {0}', untagged=True)
    layout.line(b')')
    layout.line(_tagged_line(b'TAG', b'OK', b'FETCH completed'))
    wire = layout.wire()
    literal_end = wire.index(b')', wire.index(b'{0}'))

    received = receive(wire, [literal_end])

    assert received['lines'] == [b'1 FETCH (UID 1 BODY[] {0}', b'', b')', b'FETCH completed']


def test_multiple_literals_in_one_response_stay_in_order_and_verbatim():
    first = b'first\r\n* BYE\r\n'
    second = b'second\x00\xff{4}\r\n'
    layout = Layout()
    layout.line(literal_line(b'* 1 FETCH (UID 1 BODY[]', first), untagged=True)
    layout.literal(first)
    layout.line(literal_line(b' BODY[HEADER]', second))
    layout.literal(second)
    layout.line(b')')
    layout.line(_tagged_line(b'TAG', b'OK', b'FETCH completed'))
    wire = layout.wire()

    received = receive(wire)

    assert received['lines'] == [
        b'1 FETCH (UID 1 BODY[] {%d}' % len(first),
        first,
        b' BODY[HEADER] {%d}' % len(second),
        second,
        b')',
        b'FETCH completed',
    ]
    assert received['lines'][1] == first
    assert received['lines'][3] == second


def test_crlf_split_across_chunks_inside_literal_is_not_added_or_lost():
    body = b'before\r\nafter\r'
    layout = Layout().line(b'* 1 FETCH (UID 1 BODY[] {%d}' % len(body), untagged=True)
    layout.literal(body)
    layout.line(b')')
    layout.line(_tagged_line(b'TAG', b'OK', b'FETCH completed'))
    wire = layout.wire()
    body_start = wire.index(b'before')
    crlf_pos = body_start + body.index(b'\r\n')

    for cuts in ([crlf_pos + 1], [crlf_pos], [body_start, crlf_pos + 1]):
        reference = receive(wire)
        received = receive(wire, cuts)
        assert received == reference
        assert received['lines'][1] == body


def test_completion_immediately_after_literal_body_is_attributed_to_command():
    body = b'abc'
    layout = Layout().line(b'* 1 FETCH (UID 1 BODY[] {%d}' % len(body), untagged=True)
    layout.literal(body)
    layout.line(b')')
    layout.line(_tagged_line(b'TAG', b'OK', b'FETCH completed'))
    wire = layout.wire()

    received = receive(wire)

    assert received['lines'] == [b'1 FETCH (UID 1 BODY[] {3}', body, b')', b'FETCH completed']
    assert received['completed'] is True


# ---------------------------------------------------------------------------
# 3. Same body, every cut point: result, connection state and consumer bytes
# ---------------------------------------------------------------------------

def _assert_all_splits_equivalent(wire, command_factory, *, async_mode=False):
    reference = receive(wire, command=command_factory(), async_mode=async_mode)
    for cuts in every_split(wire):
        received = receive(wire, cuts, command=command_factory(), async_mode=async_mode)
        assert received == reference, 'cut %r changed the receive outcome' % (cuts,)
    return reference


@pytest.mark.parametrize('body', [
    b'* BYE Logging out\r\nTAG OK LOGOUT completed\r\n',
    b'\x00\x01\x02\xff\xfe\r\n',
    b'prefix\r\n\r\nsuffix',
    b'',
])
def test_every_split_point_yields_identical_result_state_and_consumer_bytes(body):
    layout = Layout().line(b'* 1 FETCH (UID 1 BODY[] {%d}' % len(body), untagged=True)
    layout.literal(body)
    layout.line(b')')
    layout.line(_tagged_line(b'TAG', b'OK', b'FETCH completed'))
    wire = layout.wire()

    reference = _assert_all_splits_equivalent(wire, lambda: FetchCommand('TAG', '1', '(BODY[])'))

    assert reference['result'] == 'OK'
    assert reference['lines'][1] == body
    assert reference['state'] == aioimaplib.SELECTED
    assert reference['completed'] is True


def test_every_split_point_on_multi_literal_response_is_invariant():
    first = b'aa\r\n* BYE\r\n'
    second = b'bb)'
    layout = Layout()
    layout.line(literal_line(b'* 1 FETCH (UID 1 BODY[]', first), untagged=True)
    layout.literal(first)
    layout.line(literal_line(b' BODY[HEADER]', second))
    layout.literal(second)
    layout.line(b')')
    layout.line(_tagged_line(b'TAG', b'OK', b'FETCH completed'))
    wire = layout.wire()

    reference = _assert_all_splits_equivalent(wire, lambda: FetchCommand('TAG', '1', '(BODY[])'))

    assert reference['lines'][1] == first
    assert reference['lines'][3] == second
    assert reference['completed'] is True


def test_generic_command_with_literal_is_split_invariant():
    body = b'foo\r\n* BYE\r\nbar'
    layout = Layout()
    layout.line(b'* LIST () "/" {%d}' % len(body), untagged=True)
    layout.literal(body)
    layout.crlf()
    layout.line(_tagged_line(b'TAG', b'OK', b'LIST completed'))
    wire = layout.wire()

    reference = _assert_all_splits_equivalent(wire, lambda: Command('LIST', 'TAG', untagged_resp_name='LIST'), async_mode=True)

    assert reference['lines'] == [b'() "/" {%d}' % len(body), body, b'LIST completed']
    assert reference['completed'] is True


@pytest.mark.parametrize('async_mode', [False, True])
def test_sync_and_async_ownership_do_not_change_literal_attribution(async_mode):
    body = b'* BYE\r\nTAG OK NO\r\n'
    layout = Layout().line(b'* 1 FETCH (UID 1 BODY[] {%d}' % len(body), untagged=True)
    layout.literal(body)
    layout.line(b')')
    layout.line(_tagged_line(b'TAG', b'OK', b'FETCH completed'))
    wire = layout.wire()

    reference = _assert_all_splits_equivalent(
        wire, lambda: FetchCommand('TAG', '1', '(BODY[])'), async_mode=async_mode)

    assert reference['lines'][1] == body
    assert reference['pending_sync'] is None
    assert reference['pending_async'] == {}


# ---------------------------------------------------------------------------
# 4. Under-declared literal: the declared count is authoritative
# ---------------------------------------------------------------------------

def test_under_declared_literal_does_not_promote_the_next_line_to_a_control_response():
    """A body line that looks like a tagged completion is only a body line.

    ``{4}`` declares exactly four bytes. The following bytes therefore keep
    the response owner: they are continuation text for the same command, and
    the parser must not read them as a new tagged status for TAG.
    """
    body = b'abcd'
    trailing = b')\r\n'
    layout = Layout().line(b'* 1 FETCH (UID 1 BODY[] {%d}' % len(body), untagged=True)
    layout.literal(body)
    layout.line(b')')
    layout.line(_tagged_line(b'TAG', b'OK', b'FETCH completed'))
    wire = layout.wire()

    received = receive(wire)

    assert received['lines'][1] == body
    assert received['lines'][2] == b')'
    assert received['result'] == 'OK'
    assert received['completed'] is True


def test_declared_count_is_used_even_when_body_looks_like_a_literal_header():
    body = b'{5}\r\n'
    layout = Layout().line(b'* 1 FETCH (UID 1 BODY[] {%d}' % len(body), untagged=True)
    layout.literal(body)
    layout.line(b')')
    layout.line(_tagged_line(b'TAG', b'OK', b'FETCH completed'))
    wire = layout.wire()

    received = receive(wire)

    assert received['lines'][1] == body
    assert received['completed'] is True


def test_literal_end_at_chunk_boundary_keeps_the_command_owner():
    """A balanced header must not release the command at the literal boundary.

    ``* 1 FETCH () UID 1 BODY[] {0}`` already has balanced parentheses, so a
    receiver that decides ownership with a parenthesis count drops the command
    when the empty literal ends exactly at a chunk boundary. The next chunk
    then starts with `` tail`` and is misread as a fresh control line.
    """
    body = b''
    layout = Layout().line(b'* 1 FETCH () UID 1 BODY[] {%d}' % len(body), untagged=True)
    layout.literal(body)
    layout.line(b' tail')
    layout.line(_tagged_line(b'TAG', b'OK', b'FETCH completed'))
    wire = layout.wire()
    literal_end = wire.index(b' tail')

    reference = receive(wire)
    received = receive(wire, [literal_end])

    assert received == reference
    assert received['lines'] == [b'1 FETCH () UID 1 BODY[] {0}', b'', b' tail', b'FETCH completed']
    assert received['completed'] is True


def test_literal_end_at_chunk_boundary_keeps_nonempty_literal_owner():
    body = b'x)'
    layout = Layout().line(b'* 1 FETCH () UID 1 BODY[] {%d}' % len(body), untagged=True)
    layout.literal(body)
    layout.line(b' tail')
    layout.line(_tagged_line(b'TAG', b'OK', b'FETCH completed'))
    wire = layout.wire()
    literal_end = wire.index(b' tail')

    reference = receive(wire)
    received = receive(wire, [literal_end])

    assert received == reference
    assert received['lines'] == [b'1 FETCH () UID 1 BODY[] {2}', body, b' tail', b'FETCH completed']


def test_generic_empty_literal_at_chunk_boundary_does_not_start_a_new_response():
    layout = Layout()
    layout.line(b'* LIST () "/" {0}', untagged=True)
    layout.line(b'foo bar')
    layout.line(_tagged_line(b'TAG', b'OK', b'LIST completed'))
    wire = layout.wire()
    literal_end = len(b'* LIST () "/" {0}\r\n')

    reference = receive(wire, command=Command('LIST', 'TAG', untagged_resp_name='LIST'), async_mode=True)
    received = receive(wire, [literal_end], command=Command('LIST', 'TAG', untagged_resp_name='LIST'), async_mode=True)

    assert received == reference
    assert received['lines'] == [b'() "/" {0}', b'', b'foo bar', b'LIST completed']


def test_under_declared_remainder_cannot_close_the_command_as_a_tagged_status():
    """Only the declared count decides where the literal ends.

    ``{3}`` is followed by three body bytes and then more bytes on the same
    response line. Even when those extra bytes spell a complete tagged
    completion, they are continuation text for the owning command; the parser
    must not guess that the next line is the body end and close early.
    """
    body = b'abc'
    remainder = b'TAG OK FETCH completed'
    layout = Layout().line(b'* 1 FETCH (UID 1 BODY[] {3}', untagged=True)
    layout.literal(body)
    layout.line(remainder)
    layout.line(_tagged_line(b'TAG', b'OK', b'FETCH completed'))
    wire = layout.wire()

    received = receive(wire)

    assert received['lines'] == [
        b'1 FETCH (UID 1 BODY[] {3}', body, remainder, b'FETCH completed']
    assert received['completed'] is True


def test_under_declared_remainder_is_split_invariant():
    body = b'ab'
    remainder = b'* BYE Logging out'
    layout = Layout().line(b'* 1 FETCH (UID 1 BODY[] {2}', untagged=True)
    layout.literal(body)
    layout.line(remainder)
    layout.line(_tagged_line(b'TAG', b'OK', b'FETCH completed'))
    wire = layout.wire()

    reference = _assert_all_splits_equivalent(wire, lambda: FetchCommand('TAG', '1', '(BODY[])'))

    assert reference['lines'] == [b'1 FETCH (UID 1 BODY[] {2}', body, remainder, b'FETCH completed']


# ---------------------------------------------------------------------------
# 5. Anti-pattern oracle: line-first parsing inside literal mode must fail
# ---------------------------------------------------------------------------

class LineFirstProtocol(IMAP4ClientProtocol):
    """Counterexample receiver: it always line-matches before literal mode.

    This is intentionally wrong. Feeding the same frame through it shows the
    failure mode the regression is meant to catch: bytes inside the counted
    literal are promoted to control responses and the body is never delivered
    to the command as one intact blob.
    """

    def _handle_responses(self, data, line_handler, current_cmd=None, after_literal=False):
        for line in data.split(CRLF):
            if not line:
                continue
            try:
                line_handler(line, current_cmd)
            except Exception as exc:  # the wrong owner eventually hits an unexpected tagged line
                self.line_first_error = exc
                break


def receive_with(protocol_class, wire, command):
    protocol = protocol_class(None)
    protocol.connection_made(RecordingTransport())
    protocol.state = aioimaplib.SELECTED
    protocol.pending_sync_command = command
    protocol.data_received(wire)
    return protocol, command


def test_line_first_receiver_promotes_literal_bytes_to_control_message():
    body = b'* BYE Logging out\r\nTAG OK LOGOUT completed\r\n'
    layout = Layout().line(b'* 1 FETCH (UID 1 BODY[] {%d}' % len(body), untagged=True)
    layout.literal(body)
    layout.line(b')')
    layout.line(_tagged_line(b'TAG', b'OK', b'FETCH completed'))
    wire = layout.wire()

    correct = receive(wire)
    assert correct['lines'][1] == body
    assert correct['result'] == 'OK'

    command = FetchCommand('TAG', '1', '(BODY[])')
    bad_protocol, bad_command = receive_with(LineFirstProtocol, wire, command)
    bad_lines = [bytes(line) for line in bad_command.response.lines]

    # the line-first receiver treats the body's fake BYE as an untagged
    # response and the body's fake tagged line as the command completion
    assert body not in bad_lines
    assert b'BYE Logging out' in bad_lines
    assert bad_command.response.result == 'OK'
    assert bad_command._event.is_set()
    assert bad_protocol.pending_sync_command is None
    assert bad_protocol.line_first_error is not None  # the real completion then finds no owner

    # the correct receiver keeps the same bytes as one literal line
    assert correct['lines'] == [b'1 FETCH (UID 1 BODY[] {%d}' % len(body), body, b')', b'FETCH completed']
    assert all(b'BYE Logging out' != line for line in correct['lines'])


def test_receiver_must_not_use_line_matching_while_literal_bytes_are_pending():
    """Direct structural check: mid-literal chunks never invoke the line parser."""
    body = b'* BYE\r\nTAG OK LOGOUT\r\n'
    layout = Layout().line(b'* 1 FETCH (BODY[] {%d}' % len(body), untagged=True)
    layout.literal(body)
    layout.line(b')')
    layout.line(_tagged_line(b'TAG', b'OK', b'FETCH completed'))
    wire = layout.wire()
    body_start = wire.index(body)

    protocol = IMAP4ClientProtocol(None)
    protocol.connection_made(RecordingTransport())
    protocol.state = aioimaplib.SELECTED
    command = FetchCommand('TAG', '1', '(BODY[])')
    protocol.pending_sync_command = command

    seen = []
    original = protocol._handle_line

    def tracking(line, current_cmd):
        seen.append(line)
        return original(line, current_cmd)

    protocol._handle_line = tracking

    protocol.data_received(wire[:body_start + 3])
    protocol.data_received(wire[body_start + 3:body_start + len(body) - 2])
    protocol.data_received(wire[body_start + len(body) - 2:])

    # only the real control lines were line parsed; the literal's own BYE and
    # tagged lookalikes were consumed by byte count and never seen here
    assert [b'* 1 FETCH (BODY[] {%d}' % len(body), b')', b'TAG OK FETCH completed'] == seen
    assert command.response.lines[1] == body
