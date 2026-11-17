# -*- coding: utf-8 -*-
"""Termination path contract: cancellation, connection loss and late responses.

A command can be in four positions when the termination path runs:
  - queued behind another command (not yet sent)
  - sent: header on the wire, waiting for the tagged completion
  - sent and receiving a literal
  - queued behind a command sharing its untagged response name (e.g. STORE
    and FETCH both use the FETCH untagged responses)

Queued commands can be cancelled safely without touching in-flight commands.
Once a command is sent, a cancellation or a timeout makes the protocol
boundary unknowable: the command is dropped, the connection is closed and
late bytes are ignored instead of being delivered to a later command of the
same type. A connection loss fails every pending command instead of letting
it hang forever, and a new independent connection must work cleanly.
"""
import asyncio
import socket

import pytest

from aioimaplib import aioimaplib
from aioimaplib.aioimaplib import AUTH, Abort, Command, CommandTimeout, FetchCommand, \
    IMAP4ClientProtocol, Response
from aioimaplib.imap_testing_server import ImapProtocol, Mail, MockImapServer
from tests.server_fixture import advance_time


class PausableTransport(asyncio.Transport):
    """Transport whose write side is split in two: bytes go to `buffered`
    while paused and to `sent` (the wire) otherwise, so tests decide exactly
    when a command header is actually emitted."""

    def __init__(self):
        self.paused = False
        self.buffered = []
        self.sent = []
        self.closed = False

    def pause(self):
        self.paused = True

    def resume(self):
        self.paused = False
        self.sent.extend(self.buffered)
        self.buffered.clear()

    def write(self, data):
        (self.buffered if self.paused else self.sent).append(data)

    def close(self):
        self.closed = True

    def is_closing(self):
        return self.closed

    def get_extra_info(self, name, default=None):
        return default


def make_protocol(loop, state=aioimaplib.SELECTED):
    protocol = IMAP4ClientProtocol(loop)
    transport = PausableTransport()
    protocol.connection_made(transport)
    protocol.state = state
    return protocol, transport


async def run_loop_iterations(times=2):
    for _ in range(times):
        await asyncio.sleep(0)


async def open_connection(loop, imapserver):
    """Open a client connection to the mock server over a socketpair: real
    asyncio transports on both ends, without binding any TCP port."""
    client_sock, server_sock = socket.socketpair()
    server_protocol = ImapProtocol(imapserver._server_state, 64, imapserver.capabilities, loop)
    server_transport, _ = await loop.create_connection(lambda: server_protocol, sock=server_sock)
    client_protocol = IMAP4ClientProtocol(loop)
    client_transport, _ = await loop.create_connection(lambda: client_protocol, sock=client_sock)
    await asyncio.wait_for(client_protocol.wait('AUTH|NONAUTH'), 1)
    return client_protocol, client_transport, server_transport


@pytest.mark.asyncio()
async def test_connection_lost_fails_pending_sync_command(event_loop):
    protocol, transport = make_protocol(event_loop, state=AUTH)
    select = Command('SELECT', protocol.new_tag(), 'INBOX', loop=event_loop)
    select_task = asyncio.ensure_future(protocol.execute(select))
    await run_loop_iterations()

    assert protocol.pending_sync_command is select
    assert [b'%s SELECT INBOX\r\n' % select.tag.encode()] == transport.sent

    protocol.connection_lost(ConnectionResetError('reset by peer'))

    with pytest.raises(ConnectionResetError):
        await select_task
    assert protocol.pending_sync_command is None
    assert {} == protocol.pending_async_commands
    assert protocol.transport is None


@pytest.mark.asyncio()
async def test_connection_lost_fails_pending_async_commands_and_cancels_their_timers(event_loop):
    protocol, transport = make_protocol(event_loop)
    fetch = FetchCommand(protocol.new_tag(), '1', '(FLAGS)', loop=event_loop, timeout=10)
    noop = Command('NOOP', protocol.new_tag(), loop=event_loop, timeout=10)
    fetch_task = asyncio.ensure_future(protocol.execute(fetch))
    noop_task = asyncio.ensure_future(protocol.execute(noop))
    await run_loop_iterations()

    assert {'FETCH', 'NOOP'} == set(protocol.pending_async_commands)

    protocol.connection_lost(None)

    with pytest.raises(Abort):
        await fetch_task
    with pytest.raises(Abort):
        await noop_task
    assert {} == protocol.pending_async_commands
    assert fetch._timer._cancelled
    assert noop._timer._cancelled


@pytest.mark.asyncio()
async def test_connection_lost_while_receiving_literal(event_loop):
    protocol, transport = make_protocol(event_loop)
    fetch = FetchCommand(protocol.new_tag(), '1', '(BODY[])', loop=event_loop)
    fetch_task = asyncio.ensure_future(protocol.execute(fetch))
    await run_loop_iterations()

    protocol.data_received(b'* 1 FETCH (BODY[] {10}\r\nabc')
    assert protocol.current_command is fetch
    assert bytearray(b'abc') == fetch._resp_literal_data
    assert fetch.wait_literal_data()

    protocol.connection_lost(None)

    with pytest.raises(Abort):
        await fetch_task
    assert protocol.current_command is None
    assert b'' == protocol.incomplete_line
    assert {} == protocol.pending_async_commands


@pytest.mark.asyncio()
async def test_connection_lost_releases_queued_command_without_sending_it(event_loop):
    protocol, transport = make_protocol(event_loop, state=AUTH)
    select = Command('SELECT', protocol.new_tag(), 'INBOX', loop=event_loop)
    select_task = asyncio.ensure_future(protocol.execute(select))
    await run_loop_iterations()

    noop = Command('NOOP', protocol.new_tag(), loop=event_loop)
    noop_task = asyncio.ensure_future(protocol.execute(noop))
    await run_loop_iterations()

    # the noop is queued behind the sync command: nothing more was written
    assert [b'%s SELECT INBOX\r\n' % select.tag.encode()] == transport.sent

    protocol.connection_lost(None)

    with pytest.raises(Abort):
        await select_task
    with pytest.raises(Abort):
        await noop_task
    assert [b'%s SELECT INBOX\r\n' % select.tag.encode()] == transport.sent
    assert protocol.pending_sync_command is None
    assert {} == protocol.pending_async_commands


@pytest.mark.asyncio()
async def test_cancel_queued_command_does_not_affect_in_flight_command(event_loop):
    protocol, transport = make_protocol(event_loop, state=AUTH)
    select = Command('SELECT', protocol.new_tag(), 'INBOX', loop=event_loop)
    select_task = asyncio.ensure_future(protocol.execute(select))
    await run_loop_iterations()

    noop = Command('NOOP', protocol.new_tag(), loop=event_loop, timeout=30)
    noop_task = asyncio.ensure_future(protocol.execute(noop))
    await run_loop_iterations()

    noop_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await noop_task

    # the queued command was never sent nor registered and its timer is
    # stopped; the in-flight command and the connection are untouched
    assert noop._timer._cancelled
    assert {} == protocol.pending_async_commands
    assert protocol.pending_sync_command is select
    assert not transport.closed

    protocol.data_received(b'%s OK SELECT completed\r\n' % select.tag.encode())
    assert Response('OK', [b'SELECT completed']) == await select_task


@pytest.mark.asyncio()
async def test_cancel_sent_command_closes_connection_and_ignores_late_response(event_loop):
    protocol, transport = make_protocol(event_loop)
    fetch = FetchCommand(protocol.new_tag(), '1', '(FLAGS)', loop=event_loop)
    fetch_task = asyncio.ensure_future(protocol.execute(fetch))
    await run_loop_iterations()

    assert protocol.pending_async_commands.get('FETCH') is fetch

    fetch_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await fetch_task

    # the command was sent: the protocol boundary is unknown, so the command
    # is dropped and the connection is closed
    assert transport.closed
    assert {} == protocol.pending_async_commands

    # a late response must be ignored: not delivered anywhere, not raising
    protocol.data_received(
        b'* 1 FETCH (FLAGS (\\Seen))\r\n%s OK FETCH completed\r\n' % fetch.tag.encode())
    assert {} == protocol.pending_async_commands


@pytest.mark.asyncio()
async def test_cancel_command_whose_header_is_still_buffered_closes_connection(event_loop):
    protocol, transport = make_protocol(event_loop)
    transport.pause()
    noop = Command('NOOP', protocol.new_tag(), loop=event_loop)
    noop_task = asyncio.ensure_future(protocol.execute(noop))
    await run_loop_iterations()

    # header written to the transport but paused before reaching the wire:
    # from the protocol point of view the command is sent
    assert [b'%s NOOP\r\n' % noop.tag.encode()] == transport.buffered
    assert [] == transport.sent

    noop_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await noop_task

    assert transport.closed
    assert {} == protocol.pending_async_commands


@pytest.mark.asyncio()
async def test_command_timeout_closes_connection_and_releases_queued_commands(event_loop, advance_time):
    protocol, transport = make_protocol(event_loop, state=AUTH)
    select = Command('SELECT', protocol.new_tag(), 'INBOX', loop=event_loop, timeout=2)
    select_task = asyncio.ensure_future(protocol.execute(select))
    await advance_time(0.1)

    noop = Command('NOOP', protocol.new_tag(), loop=event_loop, timeout=30)
    noop_task = asyncio.ensure_future(protocol.execute(noop))
    await advance_time(0.1)
    assert protocol.pending_sync_command is select

    await advance_time(2)

    finished, pending = await asyncio.wait([select_task, noop_task])
    assert not pending
    assert isinstance(select_task.exception(), CommandTimeout)
    assert isinstance(noop_task.exception(), CommandTimeout)
    assert protocol.pending_sync_command is None
    assert {} == protocol.pending_async_commands
    assert transport.closed
    assert noop._timer._cancelled


@pytest.mark.asyncio()
async def test_shared_untagged_response_name_commands_are_released_together(event_loop, advance_time):
    protocol, transport = make_protocol(event_loop)
    fetch = FetchCommand(protocol.new_tag(), '1', '(FLAGS)', loop=event_loop, timeout=2)
    fetch_task = asyncio.ensure_future(protocol.execute(fetch))
    await advance_time(0.1)

    store = Command('STORE', protocol.new_tag(), '1', '+FLAGS', '(\\Seen)',
                    untagged_resp_name='FETCH', loop=event_loop, timeout=30)
    store_task = asyncio.ensure_future(protocol.execute(store))
    await advance_time(0.1)

    # STORE shares the FETCH untagged response name: it is queued, not sent
    assert [b'%s FETCH 1 (FLAGS)\r\n' % fetch.tag.encode()] == transport.sent

    await advance_time(2)

    finished, pending = await asyncio.wait([fetch_task, store_task])
    assert not pending
    assert isinstance(fetch_task.exception(), CommandTimeout)
    assert isinstance(store_task.exception(), CommandTimeout)
    assert {} == protocol.pending_async_commands
    assert transport.closed
    assert store._timer._cancelled


@pytest.mark.asyncio()
async def test_timeout_while_receiving_literal_closes_connection(event_loop, advance_time):
    protocol, transport = make_protocol(event_loop)
    fetch = FetchCommand(protocol.new_tag(), '1', '(BODY[])', loop=event_loop, timeout=2)
    fetch_task = asyncio.ensure_future(protocol.execute(fetch))
    await advance_time(0.1)

    protocol.data_received(b'* 1 FETCH (BODY[] {10}\r\nabc')
    assert fetch.wait_literal_data()

    await advance_time(3)

    with pytest.raises(CommandTimeout):
        await fetch_task
    assert {} == protocol.pending_async_commands
    assert transport.closed


@pytest.mark.asyncio()
async def test_sync_command_is_sent_once_async_commands_complete(event_loop):
    protocol, transport = make_protocol(event_loop)
    noop = Command('NOOP', protocol.new_tag(), loop=event_loop)
    noop_task = asyncio.ensure_future(protocol.execute(noop))
    select = Command('SELECT', protocol.new_tag(), 'INBOX', loop=event_loop)
    select_task = asyncio.ensure_future(protocol.execute(select))
    await run_loop_iterations()

    # the sync command waits for the async one: only NOOP is on the wire
    assert [b'%s NOOP\r\n' % noop.tag.encode()] == transport.sent

    protocol.data_received(b'%s OK NOOP completed\r\n' % noop.tag.encode())
    await run_loop_iterations(3)
    assert [b'%s NOOP\r\n' % noop.tag.encode(),
            b'%s SELECT INBOX\r\n' % select.tag.encode()] == transport.sent

    protocol.data_received(b'%s OK SELECT completed\r\n' % select.tag.encode())
    assert Response('OK', [b'NOOP completed']) == await noop_task
    assert Response('OK', [b'SELECT completed']) == await select_task


@pytest.mark.asyncio()
async def test_sync_command_waiting_for_async_commands_fails_with_them(event_loop, advance_time):
    protocol, transport = make_protocol(event_loop)
    noop = Command('NOOP', protocol.new_tag(), loop=event_loop, timeout=2)
    noop_task = asyncio.ensure_future(protocol.execute(noop))
    await advance_time(0.1)

    select = Command('SELECT', protocol.new_tag(), 'INBOX', loop=event_loop, timeout=30)
    select_task = asyncio.ensure_future(protocol.execute(select))
    await advance_time(0.1)
    assert [b'%s NOOP\r\n' % noop.tag.encode()] == transport.sent

    await advance_time(2)

    finished, pending = await asyncio.wait([noop_task, select_task])
    assert not pending
    assert isinstance(noop_task.exception(), CommandTimeout)
    assert isinstance(select_task.exception(), CommandTimeout)
    # the sync command was never sent on the desynchronized connection
    assert [b'%s NOOP\r\n' % noop.tag.encode()] == transport.sent
    assert protocol.pending_sync_command is None
    assert {} == protocol.pending_async_commands
    assert transport.closed


@pytest.mark.asyncio()
async def test_pending_command_fails_when_server_drops_connection(event_loop):
    imapserver = MockImapServer(loop=event_loop)
    protocol, transport, server_transport = await open_connection(event_loop, imapserver)
    await protocol.login('user', 'pass')
    await protocol.select()
    await protocol.execute(Command('DELAY', protocol.new_tag(), '30', loop=event_loop))

    noop_task = asyncio.ensure_future(protocol.execute(
        Command('NOOP', protocol.new_tag(), loop=event_loop)))
    await asyncio.sleep(0.1)
    assert 'NOOP' in protocol.pending_async_commands

    server_transport.close()

    with pytest.raises((Abort, ConnectionError)):
        await asyncio.wait_for(noop_task, 2)
    assert {} == protocol.pending_async_commands
    assert protocol.transport is None


@pytest.mark.asyncio()
async def test_new_connection_after_aborted_one_authenticates_and_reads(event_loop):
    imapserver = MockImapServer(loop=event_loop)
    protocol, transport, server_transport = await open_connection(event_loop, imapserver)
    await protocol.login('user', 'pass')
    await protocol.select()
    await protocol.execute(Command('DELAY', protocol.new_tag(), '30', loop=event_loop))

    fetch_task = asyncio.ensure_future(protocol.fetch('1', '(RFC822)', timeout=60))
    await asyncio.sleep(0.1)
    fetch_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await fetch_task

    # the cancelled command was sent: the old connection is closed
    assert protocol.transport is None or transport.is_closing()

    # a new independent connection authenticates and reads, without any byte
    # or exception left over from the aborted one
    new_protocol, new_transport, new_server_transport = await open_connection(event_loop, imapserver)
    await new_protocol.login('user', 'pass')
    await new_protocol.select()
    mail = Mail.create(['user'], mail_from='me', subject='hello', content='fresh content')
    imapserver.receive(mail)

    response = await new_protocol.fetch('1', '(RFC822)', timeout=5)

    content = mail.as_bytes()
    assert 'OK' == response.result
    assert [b'1 FETCH (RFC822 {%d}' % len(content), content, b')', b'FETCH completed.'] == response.lines
