# -*- coding: utf-8 -*-
#    aioimaplib : an IMAPrev4 lib using python asyncio
#    Copyright (C) 2016  Bruno Thomas
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""In-memory XOAUTH2 tests.

These drive the real ``IMAP4ClientProtocol`` against a scripted peer that feeds
server bytes through the protocol's ``data_received`` callback, while a fake
transport records every byte the client writes. No real socket is opened so the
exact wire bytes (and the fact that the token is never sent twice) can be
asserted deterministically.
"""
import asyncio
from base64 import b64encode

import pytest

from aioimaplib.aioimaplib import (
    IMAP4ClientProtocol, NONAUTH, AUTH, CRLF, Abort,
)
from aioimaplib.imap_testing_server import ImapProtocol, ServerState

USER = 'user@example.com'
TOKEN = 'super-secret-access-token'


class RecordingTransport:
    def __init__(self, protocol):
        self.protocol = protocol
        self.sent = bytearray()
        self.closed = False

    def write(self, data):
        self.sent.extend(data)

    def close(self):
        self.closed = True


class PairedTransport:
    """Forwards writes to the peer protocol while also recording the bytes."""

    def __init__(self, peer):
        self.peer = peer
        self.sent = bytearray()
        self.closed = False

    def write(self, data):
        self.sent.extend(data)
        self.peer.data_received(data)

    def close(self):
        self.closed = True


def build_protocol(loop):
    protocol = IMAP4ClientProtocol(loop)
    transport = RecordingTransport(protocol)
    protocol.connection_made(transport)
    # simulate the greeting / capability exchange: pre-auth state
    protocol.state = NONAUTH
    return protocol, transport


def build_client_server_pair(loop, authenticate_mode='success'):
    server_protocol = ImapProtocol(ServerState(), loop=loop)
    client_protocol = IMAP4ClientProtocol(loop)
    client_transport = PairedTransport(server_protocol)
    server_transport = PairedTransport(client_protocol)
    server_protocol.connection_made(server_transport)
    client_protocol.connection_made(client_transport)
    client_protocol.state = NONAUTH
    server_protocol.authenticate_mode = authenticate_mode
    return client_protocol, client_transport, server_protocol


def expected_initial_command(protocol):
    sasl = b64encode(f"user={USER}\1auth=Bearer {TOKEN}\1\1".encode("ascii")).decode("ascii")
    tag = protocol.pending_sync_command.tag
    return f"{tag} AUTHENTICATE XOAUTH2 {sasl}\r\n".encode("ascii")


@pytest.mark.asyncio()
async def test_xoauth2_success_sends_initial_response_and_enters_auth():
    protocol, transport = build_protocol(asyncio.get_running_loop())

    auth_task = asyncio.ensure_future(protocol.xoauth2(USER, TOKEN))
    await asyncio.sleep(0)
    initial = expected_initial_command(protocol)
    assert bytes(transport.sent) == initial

    tag = protocol.pending_sync_command.tag
    protocol.data_received(f"{tag} OK AUTHENTICATE completed\r\n".encode())
    result = await asyncio.wait_for(auth_task, 2)

    assert result.result == 'OK'
    assert protocol.state == AUTH
    # exactly one write: the AUTHENTICATE command carrying the initial response
    assert bytes(transport.sent) == initial
    # the raw token never appears on the wire (only inside the base64 blob)
    assert TOKEN.encode() not in bytes(transport.sent)


@pytest.mark.asyncio()
async def test_xoauth2_failure_challenge_is_closed_with_empty_response():
    protocol, transport = build_protocol(asyncio.get_running_loop())
    challenge = b'+' + b64encode(b'{"status":"401"}') + CRLF

    auth_task = asyncio.ensure_future(protocol.xoauth2(USER, TOKEN))
    await asyncio.sleep(0)
    initial = expected_initial_command(protocol)
    assert bytes(transport.sent) == initial

    # server rejects the token with a continuation challenge
    protocol.data_received(challenge)
    await asyncio.sleep(0)

    # the client must answer with the empty SASL response and nothing else
    assert bytes(transport.sent) == initial + CRLF
    # the token-bearing initial response is not re-sent
    assert transport.sent.count(initial) == 1

    # server now ends the exchange with the tagged failure
    tag = protocol.pending_sync_command.tag
    protocol.data_received(f"{tag} NO AUTHENTICATE failed\r\n".encode())
    response = await asyncio.wait_for(auth_task, 2)

    assert response.result == 'NO'
    assert protocol.state == NONAUTH
    assert protocol.pending_sync_command is None
    # still exactly the initial command plus the single empty response
    assert bytes(transport.sent) == initial + CRLF


@pytest.mark.asyncio()
async def test_xoauth2_unknown_second_challenge_aborts_without_more_writes():
    protocol, transport = build_protocol(asyncio.get_running_loop())
    challenge = b'+ ' + b64encode(b'{"status":"401"}') + CRLF

    auth_task = asyncio.ensure_future(protocol.xoauth2(USER, TOKEN))
    await asyncio.sleep(0)
    initial = expected_initial_command(protocol)

    protocol.data_received(challenge)
    await asyncio.sleep(0)
    assert bytes(transport.sent) == initial + CRLF

    # a malformed/non-SASL peer sends yet another continuation instead of a tag
    with pytest.raises(Abort):
        protocol.data_received(b'+ unexpected second challenge\r\n')
    await asyncio.sleep(0)

    # no further byte is written and the exchange never reaches AUTH
    assert bytes(transport.sent) == initial + CRLF
    assert protocol.state == NONAUTH
    auth_task.cancel()


@pytest.mark.asyncio()
async def test_xoauth2_connection_lost_never_enters_auth():
    protocol, transport = build_protocol(asyncio.get_running_loop())

    auth_task = asyncio.ensure_future(protocol.xoauth2(USER, TOKEN))
    await asyncio.sleep(0)
    initial = expected_initial_command(protocol)
    pending = protocol.pending_sync_command

    protocol.connection_lost(ConnectionResetError('connection reset by peer'))
    await asyncio.sleep(0)

    assert protocol.state == NONAUTH
    # nothing more is sent once the connection is gone
    assert bytes(transport.sent) == initial

    # the orphaned exchange cannot resolve on its own; its safety timer is what
    # eventually fails it. It never transitions to AUTH.
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(asyncio.shield(auth_task), timeout=0.1)
    assert protocol.state == NONAUTH
    assert protocol.pending_sync_command is pending
    auth_task.cancel()


@pytest.mark.asyncio()
async def test_xoauth2_cancelled_exchange_does_not_reach_auth():
    protocol, transport = build_protocol(asyncio.get_running_loop())

    auth_task = asyncio.ensure_future(protocol.xoauth2(USER, TOKEN))
    await asyncio.sleep(0)
    initial = expected_initial_command(protocol)

    auth_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await auth_task

    assert protocol.state == NONAUTH
    # cancellation must not make the client write anything extra
    assert bytes(transport.sent) == initial


@pytest.mark.asyncio()
async def test_end_to_end_xoauth2_success_against_inmemory_server():
    client, client_transport, server = build_client_server_pair(asyncio.get_running_loop(), 'success')

    auth_task = asyncio.ensure_future(client.xoauth2(USER, TOKEN))
    await asyncio.sleep(0)
    initial = expected_initial_command(client)
    response = await asyncio.wait_for(auth_task, 2)

    assert response.result == 'OK'
    assert client.state == AUTH
    assert server.state == AUTH
    # the client wrote only the single AUTHENTICATE command (no empty response)
    assert bytes(client_transport.sent) == initial
    assert client_transport.sent.count(b'AUTHENTICATE XOAUTH2') == 1


@pytest.mark.asyncio()
async def test_end_to_end_xoauth2_failure_challenge_round_trip():
    client, client_transport, server = build_client_server_pair(asyncio.get_running_loop(), 'failure_challenge')

    auth_task = asyncio.ensure_future(client.xoauth2(USER, TOKEN))
    await asyncio.sleep(0)
    initial = expected_initial_command(client)
    response = await asyncio.wait_for(auth_task, 2)

    # failure leaves the connection in NONAUTH on both ends, never AUTH
    assert response.result == 'NO'
    assert client.state == NONAUTH
    assert server.state == NONAUTH
    assert client.pending_sync_command is None

    # exact bytes: the initial command, then the bare empty SASL response
    assert bytes(client_transport.sent) == initial + CRLF
    assert client_transport.sent.count(initial) == 1
    # the token is only present inside the single base64 initial response
    assert TOKEN.encode() not in bytes(client_transport.sent)

    # the connection is still usable for a fresh, successful authentication
    server.authenticate_mode = 'success'
    retry_task = asyncio.ensure_future(client.xoauth2(USER, TOKEN))
    await asyncio.sleep(0)
    retry_initial = expected_initial_command(client)
    retry = await asyncio.wait_for(retry_task, 2)
    assert retry.result == 'OK'
    assert client.state == AUTH
    assert bytes(client_transport.sent).endswith(retry_initial)
