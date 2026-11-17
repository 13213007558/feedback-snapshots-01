import asyncio

import pytest

from aioimaplib import Command, CommandTimeout, STOP_WAIT_SERVER_PUSH, RESYNC_REQUIRED, AioImapException, Response, IMAP4
from aioimaplib.imap_testing_server import ImapProtocol, Mail
from tests.server_fixture import with_server, login_user_async, advance_time


async def login_user_with_idle_queue_maxsize(login, password, maxsize, loop=None, timeout=1):
    test_loop = loop if loop is not None else asyncio.get_running_loop()
    imap_client = IMAP4(host='127.0.0.1', port=12345, loop=test_loop, timeout=timeout, idle_queue_maxsize=maxsize)
    await imap_client.wait_hello_from_server()
    await imap_client.login(login, password)
    await imap_client.select()
    return imap_client


@pytest.mark.asyncio()
async def test_command_timeout(event_loop, with_server, advance_time):
    cmd = Command('CMD', 'tag', loop=event_loop, timeout=1)
    await advance_time(2)
    with pytest.raises(AioImapException):
        await cmd.wait()


@pytest.mark.asyncio()
async def test_command_close_cancels_timer(event_loop, with_server, advance_time):
    cmd = Command('CMD', 'tag', loop=event_loop, timeout=1)
    cmd.close(b'line', 'OK')
    await advance_time(3)

    await cmd.wait()
    assert Response('OK', [b'line']) == cmd.response


@pytest.mark.asyncio()
async def test_command_begin_literal_data_resets_timer(event_loop, with_server, advance_time):
    cmd = Command('CMD', 'tag', loop=event_loop, timeout=2)

    await advance_time(1)
    cmd.begin_literal_data(7, b'literal')

    await advance_time(1.9)
    cmd.close(b'line', 'OK')

    await cmd.wait()
    assert Response('OK', [b'literal', b'line']) == cmd.response


@pytest.mark.asyncio()
async def test_command_append_data_resets_timer(event_loop, with_server, advance_time):
    cmd = Command('CMD', 'tag', loop=event_loop, timeout=2)
    cmd.begin_literal_data(4, b'da')

    await advance_time(1.9)
    cmd.append_literal_data(b'ta')

    await advance_time(1.9)
    cmd.close(b'line', 'OK')

    await cmd.wait()
    assert Response('OK', [b'data', b'line']) == cmd.response


@pytest.mark.asyncio()
async def test_command_append_literal_data_resets_timer(event_loop, with_server, advance_time):
    cmd = Command('CMD', 'tag', loop=event_loop, timeout=2)
    cmd.begin_literal_data(12, b'literal')

    await advance_time(1.9)
    cmd.append_literal_data(b' data')

    await advance_time(1.9)
    cmd.close(b'line', 'OK')

    await cmd.wait()
    assert Response('OK', [b'literal data', b'line']) == cmd.response


@pytest.mark.asyncio()
async def test_command_append_to_resp_resets_timer(event_loop, with_server, advance_time):
    cmd = Command('CMD', 'tag', loop=event_loop, timeout=2)

    await advance_time(1.9)
    cmd.append_to_resp(b'line 1')

    await advance_time(1.9)
    cmd.close(b'line 2', 'OK')

    await cmd.wait()
    assert Response('OK', [b'line 1', b'line 2']) == cmd.response


@pytest.mark.asyncio()
async def test_command_timeout_while_receiving_data(event_loop, with_server, advance_time):
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

    # Start another idle period: the subscription generation changes, so the
    # unread 'stop_wait_server_push' from the previous subscription is purged
    # instead of leaking into the new one
    idle = await imap_client.idle_start(idle_timeout)
    await advance_time(1)

    with pytest.raises(asyncio.TimeoutError):
        push_task = asyncio.ensure_future(imap_client.wait_server_push(0.1))
        await advance_time(1)
        await asyncio.wait_for(push_task, 0.1)

    # The new subscription receives its own notifications: the server
    # keepalive, then the client's stop signal after idle_timeout
    push_task = asyncio.ensure_future(imap_client.wait_server_push(idle_timeout))
    await advance_time(server_idle_timeout)
    r = await asyncio.wait_for(push_task, None)
    assert [b'OK Still here'] == r

    push_task = asyncio.ensure_future(imap_client.wait_server_push(2))
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


@pytest.mark.asyncio()
async def test_idle_push_queue_overflow__signals_resync_then_recovers(event_loop, with_server, advance_time):
    imap_client = await login_user_with_idle_queue_maxsize('user', 'pass', maxsize=2, loop=event_loop)
    idle = await imap_client.idle_start(timeout=100)

    # paused consumer: three server keepalives for a capacity-2 queue
    await advance_time(3 * ImapProtocol.IDLE_STILL_HERE_PERIOD_SECONDS)

    queue = imap_client.protocol.idle_queue
    assert queue.overflowed
    assert 3 == queue.qsize()  # 2 kept notifications + RESYNC_REQUIRED marker

    # kept notifications are delivered in order, then the resync marker
    assert [b'OK Still here'] == (await imap_client.wait_server_push(0.1))
    assert [b'OK Still here'] == (await imap_client.wait_server_push(0.1))
    assert RESYNC_REQUIRED == (await imap_client.wait_server_push(0.1))

    # resynchronize, then a fresh subscription receives again
    imap_client.idle_done()
    assert 'OK' == (await asyncio.wait_for(idle, 1)).result
    await imap_client.noop()

    idle = await imap_client.idle_start(timeout=100)
    assert not imap_client.protocol.idle_queue.overflowed

    with_server.receive(Mail.create(to=['user'], mail_from='me', subject='hello'))
    await advance_time(0.1)

    lines = list(await imap_client.wait_server_push(0.1))
    if not any(line.endswith(b'RECENT') for line in lines):
        lines += list(await imap_client.wait_server_push(0.1))
    assert b'1 EXISTS' in lines
    assert b'1 RECENT' in lines

    imap_client.idle_done()
    await asyncio.wait_for(idle, 1)


@pytest.mark.asyncio()
async def test_idle_push_queue__coalesces_state_hints_under_capacity(event_loop, with_server, advance_time):
    imap_client = await login_user_with_idle_queue_maxsize('user', 'pass', maxsize=1, loop=event_loop)
    idle = await imap_client.idle_start(timeout=100)

    with_server.receive(Mail.create(to=['user'], mail_from='me', subject='one'))
    await advance_time(0.1)
    with_server.receive(Mail.create(to=['user'], mail_from='me', subject='two'))
    await advance_time(0.1)

    queue = imap_client.protocol.idle_queue
    assert not queue.overflowed
    assert 1 == queue.qsize()

    push = await imap_client.wait_server_push(0.1)
    assert {b'2 EXISTS', b'2 RECENT'} == set(push)

    imap_client.idle_done()
    await asyncio.wait_for(idle, 1)


@pytest.mark.asyncio()
async def test_idle_push_queue__previous_subscription_content_does_not_leak(event_loop, with_server, advance_time):
    imap_client = await login_user_with_idle_queue_maxsize('user', 'pass', maxsize=4, loop=event_loop)

    idle = await imap_client.idle_start(timeout=5)
    with_server.receive(Mail.create(to=['user'], mail_from='me', subject='stale'))
    # the mail notification and the subscription's own stop signal stay unread
    await advance_time(5)
    assert 2 == imap_client.protocol.idle_queue.qsize()

    imap_client.idle_done()
    await asyncio.wait_for(idle, 1)

    idle = await imap_client.idle_start(timeout=100)

    # notifications and stop signal from the previous subscription were purged
    with pytest.raises(asyncio.TimeoutError):
        push_task = asyncio.ensure_future(imap_client.wait_server_push(0.1))
        await advance_time(1)
        await asyncio.wait_for(push_task, 0.1)

    # the stop signal of the current subscription is delivered normally
    assert await imap_client.stop_wait_server_push()
    assert STOP_WAIT_SERVER_PUSH == (await imap_client.wait_server_push(0.1))

    imap_client.idle_done()
    await asyncio.wait_for(idle, 1)

