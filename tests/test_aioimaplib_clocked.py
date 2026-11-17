import asyncio

import pytest

from aioimaplib import Command, CommandTimeout, STOP_WAIT_SERVER_PUSH, AioImapException, Response
from aioimaplib.aioimaplib import (Abort, CommandTotalTimeout, IdleCommand,
                                    IMAP4ClientProtocol)
from aioimaplib.imap_testing_server import ImapProtocol
from tests.server_fixture import EventLoopClockAdvancer, with_server, login_user_async, advance_time


@pytest.mark.asyncio()
async def test_command_timeout(event_loop, advance_time):
    cmd = Command('CMD', 'tag', loop=event_loop, timeout=1)
    await advance_time(2)
    with pytest.raises(AioImapException):
        await cmd.wait()


@pytest.mark.asyncio()
async def test_command_close_cancels_timer(event_loop, advance_time):
    cmd = Command('CMD', 'tag', loop=event_loop, timeout=1)
    cmd.close(b'line', 'OK')
    await advance_time(3)

    await cmd.wait()
    assert Response('OK', [b'line']) == cmd.response


@pytest.mark.asyncio()
async def test_command_begin_literal_data_resets_timer(event_loop, advance_time):
    cmd = Command('CMD', 'tag', loop=event_loop, timeout=2)

    await advance_time(1)
    cmd.begin_literal_data(7, b'literal')

    await advance_time(1.9)
    cmd.close(b'line', 'OK')

    await cmd.wait()
    assert Response('OK', [b'literal', b'line']) == cmd.response


@pytest.mark.asyncio()
async def test_command_append_data_resets_timer(event_loop, advance_time):
    cmd = Command('CMD', 'tag', loop=event_loop, timeout=2)
    cmd.begin_literal_data(4, b'da')

    await advance_time(1.9)
    cmd.append_literal_data(b'ta')

    await advance_time(1.9)
    cmd.close(b'line', 'OK')

    await cmd.wait()
    assert Response('OK', [b'data', b'line']) == cmd.response


@pytest.mark.asyncio()
async def test_command_append_literal_data_resets_timer(event_loop, advance_time):
    cmd = Command('CMD', 'tag', loop=event_loop, timeout=2)
    cmd.begin_literal_data(12, b'literal')

    await advance_time(1.9)
    cmd.append_literal_data(b' data')

    await advance_time(1.9)
    cmd.close(b'line', 'OK')

    await cmd.wait()
    assert Response('OK', [b'literal data', b'line']) == cmd.response


@pytest.mark.asyncio()
async def test_command_append_to_resp_resets_timer(event_loop, advance_time):
    cmd = Command('CMD', 'tag', loop=event_loop, timeout=2)

    await advance_time(1.9)
    cmd.append_to_resp(b'line 1')

    await advance_time(1.9)
    cmd.close(b'line 2', 'OK')

    await cmd.wait()
    assert Response('OK', [b'line 1', b'line 2']) == cmd.response


@pytest.mark.asyncio()
async def test_command_timeout_while_receiving_data(event_loop, advance_time):
    cmd = Command('CMD', 'tag', loop=event_loop, timeout=2)

    await advance_time(1)
    cmd.begin_literal_data(12, b'literal')

    await advance_time(3)
    with pytest.raises(AioImapException):
        await cmd.wait()


@pytest.mark.asyncio()
async def test_when_async_commands_timeout__they_should_be_removed_from_protocol_state(event_loop, with_server, advance_time):
    imap_client = await login_user_async('user', 'pass', select=True, loop=event_loop)
    await (imap_client.protocol.execute(Command(
        'DELAY', imap_client.protocol.new_tag(), '3', loop=event_loop)))

    noop_task = asyncio.ensure_future(imap_client.protocol.execute(
        Command('NOOP', imap_client.protocol.new_tag(), '', loop=event_loop, timeout=2)))
    await advance_time(1)

    assert 1 == len(imap_client.protocol.pending_async_commands)
    await advance_time(1.1)

    finished, pending = await asyncio.wait([noop_task])
    assert noop_task in finished
    assert isinstance(noop_task.exception(), CommandTimeout)
    assert 0 == len(imap_client.protocol.pending_async_commands)


@pytest.mark.asyncio()
async def test_when_sync_commands_timeout__they_should_be_removed_from_protocol_state(event_loop, with_server, advance_time):
    imap_client = await login_user_async('user', 'pass', select=True, loop=event_loop)
    await (imap_client.protocol.execute(Command(
        'DELAY', imap_client.protocol.new_tag(), '3', loop=event_loop)))

    delay_task = asyncio.ensure_future(imap_client.protocol.execute(
        Command('DELAY', imap_client.protocol.new_tag(), '0', loop=event_loop, timeout=2)))
    await advance_time(1)
    assert imap_client.protocol.pending_sync_command is not None
    await advance_time(1.1)

    finished, pending = await asyncio.wait([delay_task])
    assert delay_task in finished
    assert isinstance(delay_task.exception(), CommandTimeout)
    assert imap_client.protocol.pending_sync_command is None


@pytest.mark.asyncio()
async def test_idle_start__exits_queue_get_without_timeout_error(event_loop, with_server, advance_time):
    imap_client = await login_user_async('user', 'pass', select=True, loop=event_loop)

    idle_timeout = 5
    await imap_client.idle_start(idle_timeout)

    push_task = asyncio.ensure_future(imap_client.wait_server_push(idle_timeout + 2))
    await advance_time(idle_timeout + 1)

    r = await push_task
    assert STOP_WAIT_SERVER_PUSH == r


@pytest.mark.asyncio()
async def test_idle_start__exits_queueget_with_keepalive_without_timeout_error(event_loop, with_server, advance_time):
    imap_client = await login_user_async('user', 'pass', select=True, loop=event_loop)

    # Idle long enough for the server to issue a keep-alive
    server_idle_timeout = ImapProtocol.IDLE_STILL_HERE_PERIOD_SECONDS
    idle_timeout = server_idle_timeout + 1
    idle = await imap_client.idle_start(idle_timeout)

    push_task = asyncio.ensure_future(imap_client.wait_server_push(server_idle_timeout - 1))

    # Advance time until we've received a keep-alive from server
    await advance_time(server_idle_timeout)

    # The original push task timed out
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(push_task, 0.1)

    # Read the keepalive from the server
    r = await imap_client.wait_server_push(0.1)
    assert [b'OK Still here'] == r

    # Advance the clock to the client timeout (idle waiter triggers)
    await advance_time(1)
    imap_client.idle_done()

    r = await asyncio.wait_for(idle, 1)
    assert "OK" == r.result

    assert not imap_client.protocol._idle_event.is_set()

    # Start another idle period
    idle = await imap_client.idle_start(idle_timeout)
    await advance_time(1)

    # Read 'stop_wait_server_push'
    push_task = asyncio.ensure_future(imap_client.wait_server_push(0.1))
    await advance_time(1)
    r = await asyncio.wait_for(push_task, None)
    assert STOP_WAIT_SERVER_PUSH == r

    # There shouldn't be anything left in the queue (no '+ idling')
    with pytest.raises(asyncio.TimeoutError):
        push_task = asyncio.ensure_future(imap_client.wait_server_push(0.1))
        await advance_time(1)
        await asyncio.wait_for(push_task, 0.1)

    imap_client.idle_done()
    await asyncio.wait_for(idle, 1)


class FakeTransport:
    """Records writes without opening a socket, so these tests stay deterministic in a sandbox."""

    def __init__(self):
        self.writes = []
        self.closed = False

    def write(self, data):
        self.writes.append(data)

    def close(self):
        self.closed = True


def connected_protocol(loop, state=None, total_timeout=None):
    protocol = IMAP4ClientProtocol(loop)
    protocol.state = state or 'AUTH'
    protocol.transport = FakeTransport()
    protocol.total_timeout = total_timeout
    return protocol


async def tick(loop, seconds=0):
    """Let the loop run and settle, optionally advancing the fake clock.

    The clock advancer only wakes handles once the loop gets another turn, so every
    observation that follows a timeout goes through this helper.
    """
    await asyncio.sleep(0)
    if seconds:
        await EventLoopClockAdvancer(loop)(seconds)
    for _ in range(5):
        await asyncio.sleep(0)


@pytest.mark.asyncio()
async def test_total_timeout_expires_despite_continuous_small_progress(event_loop, advance_time):
    protocol = connected_protocol(event_loop)
    command = Command('SELECT', protocol.new_tag(), 'INBOX', loop=event_loop, timeout=5, total_timeout=3)
    task = asyncio.ensure_future(protocol.execute(command))
    await tick(event_loop)

    # The server makes visible progress below the idle timeout, but never finishes the command.
    for _ in range(4):
        protocol.data_received(b'* 1 EXISTS\r\n')
        await tick(event_loop, 0.5)
    protocol.data_received(b'* 2 EXISTS\r\n')
    await tick(event_loop, 0.6)  # 2.6s total, absolute deadline still not reached

    assert not task.done()
    assert command._exception is None

    await tick(event_loop, 0.5)  # 3.1s total
    assert task.done()
    assert isinstance(task.exception(), CommandTotalTimeout)
    assert task.exception().command is command


@pytest.mark.asyncio()
async def test_total_timeout_fires_even_while_literal_fragments_reset_idle_timer(event_loop, advance_time):
    protocol = connected_protocol(event_loop)
    select = Command('SELECT', protocol.new_tag(), 'INBOX', loop=event_loop, timeout=5, total_timeout=3)
    task = asyncio.ensure_future(protocol.execute(select))
    await tick(event_loop)

    protocol.data_received(b'* 1 FETCH (BODY[] {10}\r\nabc')
    for fragment in (b'de', b'fg'):
        await tick(event_loop, 0.9)  # each fragment resets the 5s idle timer
        protocol.data_received(fragment)

    assert not task.done()
    await tick(event_loop, 0.5)  # 1.8s of fragments + 0.5s here = 2.3s
    protocol.data_received(b'hi')
    await tick(event_loop, 0.9)  # 3.2s total
    assert task.done()
    assert isinstance(task.exception(), CommandTotalTimeout)


@pytest.mark.asyncio()
async def test_total_timeout_does_not_fire_for_a_command_that_completes(event_loop, advance_time):
    protocol = connected_protocol(event_loop)
    command = Command('SELECT', protocol.new_tag(), 'INBOX', loop=event_loop, timeout=5, total_timeout=3)
    task = asyncio.ensure_future(protocol.execute(command))
    await tick(event_loop)

    await tick(event_loop, 1)
    protocol.data_received(b'* 3 EXISTS\r\n')
    await tick(event_loop, 1)
    protocol.data_received(b'%s OK SELECT completed\r\n' % command.tag.encode())

    response = await asyncio.wait_for(task, 0.1)
    assert response.result == 'OK'
    assert b'SELECT completed' in response.lines

    # Timers are cancelled, so advancing past the deadline afterwards changes nothing.
    await tick(event_loop, 10)
    assert task.exception() is None
    assert command._total_timer.cancelled()
    assert command._timer.cancelled()


@pytest.mark.asyncio()
async def test_total_timeout_covers_time_spent_queued_behind_a_sync_command(event_loop, advance_time):
    protocol = connected_protocol(event_loop)
    first = Command('SELECT', protocol.new_tag(), 'INBOX', loop=event_loop, timeout=10)
    first_task = asyncio.ensure_future(protocol.execute(first))
    await tick(event_loop)

    queued = Command('NOOP', protocol.new_tag(), loop=event_loop, timeout=10, total_timeout=2)
    queued_task = asyncio.ensure_future(protocol.execute(queued))
    await tick(event_loop, 2.5)  # never reaches the wire: still waiting for `first`

    assert queued_task.done()
    assert isinstance(queued_task.exception(), CommandTotalTimeout)
    # It must not have been written, and it must not disturb the in-flight command.
    assert [b'%s SELECT INBOX\r\n' % first.tag.encode()] == protocol.transport.writes
    assert protocol.pending_sync_command is first

    protocol.data_received(b'%s OK SELECT completed\r\n' % first.tag.encode())
    assert 'OK' == (await asyncio.wait_for(first_task, 0.1)).result


@pytest.mark.asyncio()
async def test_total_timeout_with_late_completion_releases_the_queued_waiter(event_loop, advance_time):
    protocol = connected_protocol(event_loop, total_timeout=2)
    first = Command('SELECT', protocol.new_tag(), 'INBOX', loop=event_loop, timeout=30)
    first_task = asyncio.ensure_future(protocol.execute(first))
    await tick(event_loop)

    queued = Command('NOOP', protocol.new_tag(), loop=event_loop, timeout=30, total_timeout=10)
    queued_task = asyncio.ensure_future(protocol.execute(queued))
    await tick(event_loop)

    await tick(event_loop, 2.1)
    assert first_task.done() and isinstance(first_task.exception(), CommandTotalTimeout)
    assert protocol.pending_sync_command is None
    assert protocol._resynchronizing

    # The server eventually finishes the abandoned command; the drain ends and the waiter runs.
    protocol.data_received(b'%s OK SELECT completed\r\n' % first.tag.encode())
    await tick(event_loop, 0.1)
    assert not protocol._resynchronizing
    assert protocol.transport.writes[-1] == b'%s NOOP\r\n' % queued.tag.encode()

    protocol.data_received(b'%s OK NOOP completed\r\n' % queued.tag.encode())
    assert 'OK' == (await asyncio.wait_for(queued_task, 0.1)).result
    assert protocol.pending_sync_command is None


@pytest.mark.asyncio()
async def test_after_total_timeout_the_unconsumed_literal_is_not_handed_to_the_next_command(event_loop, advance_time):
    protocol = connected_protocol(event_loop)
    select = Command('SELECT', protocol.new_tag(), 'INBOX', loop=event_loop, timeout=30, total_timeout=2)
    select_task = asyncio.ensure_future(protocol.execute(select))
    await tick(event_loop)

    protocol.data_received(b'* 1 FETCH (BODY[] {20}\r\nabc')
    await tick(event_loop, 2.1)
    assert isinstance(select_task.exception(), CommandTotalTimeout)
    assert protocol._resynchronizing
    assert protocol._resync_skip_literal == 17

    next_command = Command('NOOP', protocol.new_tag(), loop=event_loop, timeout=5)
    next_task = asyncio.ensure_future(protocol.execute(next_command))
    await tick(event_loop, 0.1)
    # The next command is held back while the stale literal is drained.
    assert b'%s NOOP\r\n' % next_command.tag.encode() not in protocol.transport.writes

    # The remaining literal payload contains a fake tagged completion. It must be skipped by
    # size, not parsed, otherwise the stale response would be attributed to the next command.
    protocol.data_received(b'X1 OK\r\n' + b'0123456789')
    protocol.data_received(b')\r\n%s OK SELECT completed\r\n' % select.tag.encode())
    assert protocol._resync_poisoned is False
    await tick(event_loop, 0.1)
    assert b'%s NOOP\r\n' % next_command.tag.encode() in protocol.transport.writes
    assert next_command.response.lines == []

    protocol.data_received(b'%s OK NOOP completed\r\n' % next_command.tag.encode())
    response = await asyncio.wait_for(next_task, 0.1)
    assert response.lines == [b'NOOP completed']


@pytest.mark.asyncio()
async def test_async_command_total_timeout_does_not_swallow_the_next_command(event_loop, advance_time):
    protocol = connected_protocol(event_loop, state='SELECTED')
    fetch = Command('FETCH', protocol.new_tag(), '1', 'BODY[]', loop=event_loop, timeout=30, total_timeout=2)
    fetch_task = asyncio.ensure_future(protocol.execute(fetch))
    await tick(event_loop)

    protocol.data_received(b'* 1 FETCH (BODY[] {8}\r\nabc')
    await tick(event_loop, 2.1)
    assert isinstance(fetch_task.exception(), CommandTotalTimeout)

    # Async commands are tag-multiplexed: a short command can still run while the stale literal
    # is being drained, and the remaining literal bytes never reach it.
    noop = Command('NOOP', protocol.new_tag(), loop=event_loop, timeout=5)
    noop_task = asyncio.ensure_future(protocol.execute(noop))
    await tick(event_loop, 0.1)
    assert b'%s NOOP\r\n' % noop.tag.encode() not in protocol.transport.writes

    protocol.data_received(b'defgh)\r\n%s OK FETCH completed\r\n' % fetch.tag.encode())
    await tick(event_loop, 0.1)
    assert not protocol._resynchronizing
    assert b'%s NOOP\r\n' % noop.tag.encode() in protocol.transport.writes
    protocol.data_received(b'%s OK NOOP completed\r\n' % noop.tag.encode())
    await tick(event_loop, 0.1)

    response = await asyncio.wait_for(noop_task, 0.1)
    assert response.lines == [b'NOOP completed']
    assert protocol._resync_poisoned is False


@pytest.mark.asyncio()
async def test_short_command_with_progress_is_still_usable_after_a_total_timeout(event_loop, advance_time):
    protocol = connected_protocol(event_loop)
    slow = Command('SELECT', protocol.new_tag(), 'INBOX', loop=event_loop, timeout=30, total_timeout=2)
    slow_task = asyncio.ensure_future(protocol.execute(slow))
    await tick(event_loop)
    await tick(event_loop, 2.1)
    assert isinstance(slow_task.exception(), CommandTotalTimeout)

    protocol.data_received(b'%s OK SELECT completed\r\n' % slow.tag.encode())
    await tick(event_loop, 0.1)

    following = Command('NOOP', protocol.new_tag(), loop=event_loop, timeout=5, total_timeout=5)
    following_task = asyncio.ensure_future(protocol.execute(following))
    await tick(event_loop, 0.5)
    protocol.data_received(b'%s OK NOOP completed\r\n' % following.tag.encode())

    assert 'OK' == (await asyncio.wait_for(following_task, 0.1)).result
    assert protocol._resync_poisoned is False


@pytest.mark.asyncio()
async def test_connection_is_poisoned_when_the_abandoned_response_never_completes(event_loop, advance_time):
    protocol = connected_protocol(event_loop, total_timeout=2)
    protocol.resync_timeout = 4
    stuck = Command('SELECT', protocol.new_tag(), 'INBOX', loop=event_loop, timeout=30)
    stuck_task = asyncio.ensure_future(protocol.execute(stuck))
    await tick(event_loop)
    await tick(event_loop, 2.1)
    assert isinstance(stuck_task.exception(), CommandTotalTimeout)
    assert protocol._resynchronizing

    await tick(event_loop, 4.1)
    assert protocol._resynchronizing is False
    assert protocol._resync_poisoned is True

    refused = Command('NOOP', protocol.new_tag(), loop=event_loop, timeout=5)
    with pytest.raises(Abort):
        await protocol.execute(refused)
    assert b'%s NOOP\r\n' % refused.tag.encode() not in protocol.transport.writes


@pytest.mark.asyncio()
async def test_idle_is_not_bounded_by_the_connection_total_timeout(event_loop, advance_time):
    protocol = connected_protocol(event_loop, state='SELECTED', total_timeout=2)
    idle_command = IdleCommand(protocol.new_tag(), protocol.idle_queue, loop=event_loop)
    idle_task = asyncio.ensure_future(protocol.execute(idle_command))
    await tick(event_loop)

    protocol.data_received(b'+ idling\r\n')
    await tick(event_loop, 30)
    assert not idle_task.done()
    assert idle_command._total_timeout is None
    assert protocol.has_pending_idle_command()

    protocol.data_received(b'%s OK IDLE terminated\r\n' % idle_command.tag.encode())
    assert 'OK' == (await asyncio.wait_for(idle_task, 0.1)).result


@pytest.mark.asyncio()
async def test_idle_keepalives_do_not_reset_a_finite_total_timeout(event_loop, advance_time):
    # IDLE itself is exempt, but its *command* level total timeout (if explicitly given) still
    # applies: keepalive-driven progress must not extend an explicit absolute deadline.
    protocol = connected_protocol(event_loop, state='SELECTED')
    idle_command = IdleCommand(protocol.new_tag(), protocol.idle_queue, loop=event_loop)
    idle_command.set_total_timeout(3)
    idle_task = asyncio.ensure_future(protocol.execute(idle_command))
    await tick(event_loop)

    protocol.data_received(b'+ idling\r\n')
    for _ in range(4):
        await tick(event_loop, 0.9)  # server keepalive progress resets the idle timer
        protocol.data_received(b'* OK Still here\r\n')

    assert idle_task.done()
    assert isinstance(idle_task.exception(), CommandTotalTimeout)
    assert not protocol.has_pending_idle_command()


@pytest.mark.asyncio()
async def test_drain_skips_nested_literals_of_a_fetch_bodystructure(event_loop, advance_time):
    protocol = connected_protocol(event_loop, state='SELECTED')
    fetch = Command('FETCH', protocol.new_tag(), '1', 'BODYSTRUCTURE', loop=event_loop,
                    timeout=30, total_timeout=2)
    fetch_task = asyncio.ensure_future(protocol.execute(fetch))
    await tick(event_loop)

    # BODYSTRUCTURE announces two nested literals on the same logical FETCH line.
    protocol.data_received(b'* 1 FETCH (BODYSTRUCTURE (("text" "plain" NIL NIL NIL "7BIT" '
                           b'1 1 NIL NIL NIL NIL)("text" "html" ("name" {4}\r\n')
    await tick(event_loop, 2.1)
    assert isinstance(fetch_task.exception(), CommandTotalTimeout)
    assert protocol._resync_skip_literal == 4
    assert protocol._resync_after_literal is False

    # First literal body, then the remainder of the same line announces the second literal.
    protocol.data_received(b'x.ic) ("<id>" {4}\r\n')
    protocol.data_received(b'y.ic)))\r\n%s OK FETCH completed\r\n' % fetch.tag.encode())
    await tick(event_loop, 0.1)

    assert not protocol._resynchronizing
    assert protocol._resync_poisoned is False
    assert protocol._drained_command_tags == {fetch.tag}

    # The next command only sees its own response; none of the literal bytes leaked into it.
    noop = Command('NOOP', protocol.new_tag(), loop=event_loop, timeout=5)
    noop_task = asyncio.ensure_future(protocol.execute(noop))
    await tick(event_loop, 0.1)
    protocol.data_received(b'%s OK NOOP completed\r\n' % noop.tag.encode())
    assert (await asyncio.wait_for(noop_task, 0.1)).lines == [b'NOOP completed']


@pytest.mark.asyncio()
async def test_command_still_times_out_on_idle_timeout_without_total_timeout(event_loop, advance_time):
    protocol = connected_protocol(event_loop)
    command = Command('SELECT', protocol.new_tag(), 'INBOX', loop=event_loop, timeout=2)
    task = asyncio.ensure_future(protocol.execute(command))
    await tick(event_loop)

    await tick(event_loop, 1.5)
    protocol.data_received(b'* 1 EXISTS\r\n')  # resets the 2s idle timer
    await tick(event_loop, 1.0)
    protocol.data_received(b'* 2 EXISTS\r\n')  # resets it again
    await tick(event_loop, 1.9)
    assert not task.done()
    await tick(event_loop, 0.2)  # idle timer expired 2s after the last line

    assert task.done()
    timeout = task.exception()
    assert isinstance(timeout, CommandTimeout)
    assert not isinstance(timeout, CommandTotalTimeout)
    assert command._total_timeout is None
