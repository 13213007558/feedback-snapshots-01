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
import asyncio
from base64 import b64encode
import functools
import logging
import random
import re
import ssl
import sys
import time
from asyncio import BaseTransport, Future, Task
from collections import namedtuple
from copy import copy
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Union, Any, Coroutine, Callable, Optional, List

# to avoid imap servers to kill the connection after 30mn idling
# cf https://www.imapwiki.org/ClientImplementation/Synchronization
TWENTY_NINE_MINUTES = 1740.0

STOP_WAIT_SERVER_PUSH = [b'stop_wait_server_push']
PY37_OR_LATER = sys.version_info[:2] >= (3, 7)

# How long the client trusts the server to finish a response after a command total timeout
# before declaring the connection unusable (see IMAP4ClientProtocol resynchronization).
RESYNC_TIMEOUT_SECONDS = 5.0
# Upper bound on bytes discarded while draining an abandoned response, so a hostile server can
# not turn cleanup into unbounded memory/CPU use.
RESYNC_MAX_DRAINED_BYTES = 1024 * 1024

log = logging.getLogger(__name__)

IMAP4_PORT = 143
IMAP4_SSL_PORT = 993
STARTED, CONNECTED, NONAUTH, AUTH, SELECTED, LOGOUT = 'STARTED', 'CONNECTED', 'NONAUTH', 'AUTH', 'SELECTED', 'LOGOUT'
CRLF = b'\r\n'

ID_MAX_PAIRS_COUNT = 30
ID_MAX_FIELD_LEN = 30
ID_MAX_VALUE_LEN = 1024

AllowedVersions = ('IMAP4REV1', 'IMAP4')
Exec = Enum('Exec', 'is_sync is_async')
Cmd = namedtuple('Cmd', 'name           valid_states                exec')
Commands = {
    'APPEND':       Cmd('APPEND',       (AUTH, SELECTED),           Exec.is_sync),
    'AUTHENTICATE': Cmd('AUTHENTICATE', (NONAUTH,),                 Exec.is_sync),
    'CAPABILITY':   Cmd('CAPABILITY',   (NONAUTH, AUTH, SELECTED),  Exec.is_async),
    'CHECK':        Cmd('CHECK',        (SELECTED,),                Exec.is_async),
    'CLOSE':        Cmd('CLOSE',        (SELECTED,),                Exec.is_sync),
    'COMPRESS':     Cmd('COMPRESS',     (AUTH,),                    Exec.is_sync),
    'COPY':         Cmd('COPY',         (SELECTED,),                Exec.is_async),
    'CREATE':       Cmd('CREATE',       (AUTH, SELECTED),           Exec.is_async),
    'DELETE':       Cmd('DELETE',       (AUTH, SELECTED),           Exec.is_async),
    'DELETEACL':    Cmd('DELETEACL',    (AUTH, SELECTED),           Exec.is_async),
    'ENABLE':       Cmd('ENABLE',       (AUTH,),                    Exec.is_sync),
    'EXAMINE':      Cmd('EXAMINE',      (AUTH, SELECTED),           Exec.is_sync),
    'EXPUNGE':      Cmd('EXPUNGE',      (SELECTED,),                Exec.is_async),
    'FETCH':        Cmd('FETCH',        (SELECTED,),                Exec.is_async),
    'GETACL':       Cmd('GETACL',       (AUTH, SELECTED),           Exec.is_async),
    'GETQUOTA':     Cmd('GETQUOTA',     (AUTH, SELECTED),           Exec.is_async),
    'GETQUOTAROOT': Cmd('GETQUOTAROOT', (AUTH, SELECTED),           Exec.is_async),
    'ID':           Cmd('ID',           (NONAUTH, AUTH, LOGOUT, SELECTED), Exec.is_async),
    'IDLE':         Cmd('IDLE',         (SELECTED,),                Exec.is_sync),
    'LIST':         Cmd('LIST',         (AUTH, SELECTED),           Exec.is_async),
    'LOGIN':        Cmd('LOGIN',        (NONAUTH,),                 Exec.is_sync),
    'LOGOUT':       Cmd('LOGOUT',       (NONAUTH, AUTH, LOGOUT, SELECTED), Exec.is_sync),
    'LSUB':         Cmd('LSUB',         (AUTH, SELECTED),           Exec.is_async),
    'MYRIGHTS':     Cmd('MYRIGHTS',     (AUTH, SELECTED),           Exec.is_async),
    'MOVE':         Cmd('MOVE',         (SELECTED,),                Exec.is_sync),
    'NAMESPACE':    Cmd('NAMESPACE',    (AUTH, SELECTED),           Exec.is_async),
    'NOOP':         Cmd('NOOP',         (NONAUTH, AUTH, SELECTED),  Exec.is_async),
    'RENAME':       Cmd('RENAME',       (AUTH, SELECTED),           Exec.is_async),
    'SEARCH':       Cmd('SEARCH',       (SELECTED,),                Exec.is_async),
    'SELECT':       Cmd('SELECT',       (AUTH, SELECTED),           Exec.is_sync),
    'SETACL':       Cmd('SETACL',       (AUTH, SELECTED),           Exec.is_sync),
    'SETQUOTA':     Cmd('SETQUOTA',     (AUTH, SELECTED),           Exec.is_sync),
    'SORT':         Cmd('SORT',         (SELECTED,),                Exec.is_async),
    'STARTTLS':     Cmd('STARTTLS',     (NONAUTH,),                 Exec.is_sync),
    'STATUS':       Cmd('STATUS',       (AUTH, SELECTED),           Exec.is_async),
    'STORE':        Cmd('STORE',        (SELECTED,),                Exec.is_async),
    'SUBSCRIBE':    Cmd('SUBSCRIBE',    (AUTH, SELECTED),           Exec.is_sync),
    'THREAD':       Cmd('THREAD',       (SELECTED,),                Exec.is_async),
    'UID':          Cmd('UID',          (SELECTED,),                Exec.is_async),
    'UNSUBSCRIBE':  Cmd('UNSUBSCRIBE',  (AUTH, SELECTED),           Exec.is_sync),
    # for testing
    'DELAY':        Cmd('DELAY',        (AUTH, SELECTED),           Exec.is_sync),
}

Response = namedtuple('Response', 'result lines')


def get_running_loop() -> asyncio.AbstractEventLoop:
    if PY37_OR_LATER:
        return asyncio.get_running_loop()

    loop = asyncio.get_event_loop()
    if not loop.is_running():
        raise RuntimeError("no running event loop")

    return loop


def quoted(arg: str) -> str:
    """ Given a string, return a quoted string as per RFC 3501, section 9.

        Implementation copied from https://github.com/mjs/imapclient
        (imapclient/imapclient.py), 3-clause BSD license
    """
    arg = arg.replace('\\', '\\\\')
    arg = arg.replace('"', '\\"')
    return '"' + arg + '"'


def arguments_rfs2971(**kwargs: Union[dict, list, str]) -> Union[dict, list]:
    if kwargs:
        if len(kwargs) > ID_MAX_PAIRS_COUNT:
            raise ValueError('Must not send more than 30 field-value pairs')
        args = ['(']
        for field, value in kwargs.items():
            field = quoted(str(field))
            value = quoted(str(value)) if value is not None else 'NIL'
            if len(field) > ID_MAX_FIELD_LEN:
                raise ValueError('Field: {} must not be longer than 30'.format(field))
            if len(value) > ID_MAX_VALUE_LEN:
                raise ValueError('Field: {} value: {} must not be longer than 1024'.format(field, value))
            args.extend((field, value))
        args.append(')')
    else:
        args = ['NIL']
    return args


# NUL, CR and LF end or split a command line on the wire (RFC 3501 section 9), so an argument
# carrying one of them would be executed by the server as a separate command. Same check as
# CPython's imaplib (gh-143921).
CONTROL_CHARS = re.compile(r'[\x00\r\n]')


class Command:
    def __init__(self, name: str, tag: str, *args, prefix: str = None, untagged_resp_name: str = None,
                 loop: asyncio.AbstractEventLoop = None, timeout: float = None,
                 total_timeout: float = None) -> None:
        for arg in args:
            if arg is not None and CONTROL_CHARS.search(str(arg)):
                raise ValueError('NUL, CR and LF are not allowed in %s command arguments' % name)
        self.name = name
        self.tag = tag
        self.args = args
        self.prefix = prefix + ' ' if prefix else None
        self.untagged_resp_name = untagged_resp_name or name

        self._exception = None
        self._loop = loop if loop is not None else get_running_loop()
        self._event = asyncio.Event()
        self._timeout = timeout
        self._total_timeout = total_timeout
        self._timer = asyncio.Handle(lambda: None, None, self._loop)  # fake timer
        self._total_timer = asyncio.Handle(lambda: None, None, self._loop)  # fake timer
        self._closed = False
        self.sent = False
        self._abandoned = False
        self.accepts_total_timeout = True
        self._abandon_callback: Optional[Callable[['Command'], None]] = None
        self._set_timer()
        self._set_total_timer()
        self._expected_size = 0

        self._resp_literal_data = bytearray()
        self._discarded_literal_bytes = 0
        self._resp_result = 'Init'
        self._resp_lines: List[bytes] = list()

    def __repr__(self) -> str:
        return '{tag} {prefix}{name}{space}{args}'.format(
            tag=self.tag, prefix=self.prefix or '', name=self.name,
            space=' ' if self.args else '', args=' '.join(str(arg) if arg is not None else '' \
                                                          for arg in self.args))

    # for tests
    def __eq__(self, other):
        return other is not None and other.tag == self.tag and other.name == self.name and other.args == self.args

    @property
    def response(self):
        return Response(self._resp_result, self._resp_lines)

    def close(self, line: bytes, result: str) -> None:
        if self._closed:
            return
        self.append_to_resp(line, result=result)
        self._closed = True
        self._timer.cancel()
        self._total_timer.cancel()
        self._event.set()

    def abandon(self, exception: 'CommandTimeout') -> None:
        """Terminate the command without a tagged completion from the server.

        The literal parser state (expected size / bytes already consumed) is kept so the protocol
        can drain the rest of an in-flight literal instead of leaking it to the next command.
        """
        if self._closed:
            return
        self._exception = exception
        self._abandoned = True
        self._closed = True
        self._resp_result = 'KO'
        self._resp_lines.append(str(exception).encode())
        self._timer.cancel()
        self._total_timer.cancel()
        self._event.set()
        if self._abandon_callback is not None:
            self._abandon_callback(self)

    def raise_if_abandoned(self) -> None:
        if self._exception is not None:
            raise self._exception

    def begin_literal_data(self, expected_size: int, literal_data: bytes = b'') -> bytes:
        self._expected_size = expected_size
        return self.append_literal_data(literal_data)

    def _literal_bytes_received(self) -> int:
        return len(self._resp_literal_data) + self._discarded_literal_bytes

    def wait_literal_data(self) -> bool:
        return self._expected_size != 0 and self._literal_bytes_received() != self._expected_size

    def wait_data(self) -> bool:
        return self.wait_literal_data()

    def append_literal_data(self, data: bytes) -> bytes:
        nb_bytes_to_add = self._expected_size - self._literal_bytes_received()
        chunk = data[0:nb_bytes_to_add]
        if self._abandoned:
            # don't retain attacker-controlled volume while draining an abandoned literal
            self._discarded_literal_bytes += len(chunk)
        else:
            self._resp_literal_data.extend(chunk)
        if not self.wait_literal_data():
            if not self._abandoned:
                self.append_to_resp(self._resp_literal_data)
            self._end_literal_data()
        if not self._abandoned:
            self._reset_timer()
        return data[nb_bytes_to_add:]

    def append_to_resp(self, line: bytes, result: str = 'Pending') -> None:
        if self._abandoned:
            return
        self._resp_result = result
        self._resp_lines.append(line)
        if not self._closed:
            self._reset_timer()

    async def wait(self) -> None:
        await self._event.wait()
        if self._exception is not None:
            raise self._exception

    def flush(self) -> None:
        pass

    def _end_literal_data(self) -> None:
        self._expected_size = 0
        self._resp_literal_data = bytearray()
        self._discarded_literal_bytes = 0

    def _set_timer(self) -> None:
        if self._timeout is not None:
            self._timer = self._loop.call_later(self._timeout, self._timeout_callback)

    def _set_total_timer(self) -> None:
        if self._total_timeout is not None:
            self._total_timer = self._loop.call_later(self._total_timeout, self._total_timeout_callback)

    def set_total_timeout(self, total_timeout: float) -> None:
        if self._closed:
            return
        self._total_timer.cancel()
        self._total_timeout = total_timeout
        self._set_total_timer()

    def set_abandon_callback(self, callback: Callable[['Command'], None]) -> None:
        self._abandon_callback = callback

    def _timeout_callback(self) -> None:
        self.abandon(CommandTimeout(self))

    def _total_timeout_callback(self) -> None:
        self.abandon(CommandTotalTimeout(self))

    def _reset_timer(self) -> None:
        self._timer.cancel()
        self._set_timer()


class FetchCommand(Command):
    FETCH_MESSAGE_DATA_RE = re.compile(rb'[0-9]+ FETCH \(')

    def __init__(self, tag: str, *args, prefix: str = None, untagged_resp_name: str = None,
                 loop: asyncio.AbstractEventLoop = None, timeout: float = None,
                 total_timeout: float = None) -> None:
        super().__init__('FETCH', tag, *args, prefix=prefix, untagged_resp_name=untagged_resp_name,
                         loop=loop, timeout=timeout, total_timeout=total_timeout)

    def wait_data(self) -> bool:
        last_fetch_index = 0
        for index, line in enumerate(self._resp_lines):
            if isinstance(line, bytes) and self.FETCH_MESSAGE_DATA_RE.match(line):
                last_fetch_index = index
        return not matched_parenthesis(b''.join(filter(lambda l: isinstance(l, bytes),
                                                      self.response.lines[last_fetch_index:])))


def matched_parenthesis(fetch_response: bytes) -> bool:
    return fetch_response.count(b'(') == fetch_response.count(b')')


class IdleCommand(Command):
    def __init__(self, tag: str, queue: asyncio.Queue, *args, prefix: str = None, untagged_resp_name: str = None,
                 loop: asyncio.AbstractEventLoop = None, timeout: float = None) -> None:
        # IDLE is a long-lived subscription: it deliberately has no total timeout. Its lifetime is
        # bounded by the idle waiter / keepalive contract handled by IMAP4.idle_start.
        super().__init__('IDLE', tag, *args, prefix=prefix, untagged_resp_name=untagged_resp_name,
                         loop=loop, timeout=timeout, total_timeout=None)
        self.accepts_total_timeout = False
        self.queue = queue
        self.buffer: List[bytes] = list()

    def append_to_resp(self, line: bytes, result: str = 'Pending') -> None:
        if result != 'Pending':
            super().append_to_resp(line, result)
        else:
            self.buffer.append(line)

    def flush(self) -> None:
        if self.buffer:
            self.queue.put_nowait(copy(self.buffer))
            self.buffer.clear()


class AioImapException(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)


class Error(AioImapException):
    def __init__(self, reason: str):
        super().__init__(reason)


class Abort(Error):
    def __init__(self, reason: str):
        super().__init__(reason)


class CommandTimeout(AioImapException):
    def __init__(self, command: Command, reason: str = 'command timeout'):
        self.command = command
        super().__init__(reason)


class CommandTotalTimeout(CommandTimeout):
    def __init__(self, command: Command):
        super().__init__(command, 'command %s exceeded its total timeout' % command.name)


class IncompleteRead(AioImapException):
    def __init__(self, cmd: Command, data: bytes = b''):
        self.cmd = cmd
        self.data = data


def change_state(coro: Callable[..., Coroutine[Any, Any, Optional[Response]]]):
    @functools.wraps(coro)
    async def wrapper(self, *args, **kargs) -> Optional[Response]:
        async with self.state_condition:
            res = await coro(self, *args, **kargs)
            log.debug('state -> %s' % self.state)
            self.state_condition.notify_all()
            return res

    return wrapper


# cf https://tools.ietf.org/html/rfc3501#section-9
# untagged responses types
literal_data_re = re.compile(rb'.*\{(?P<size>\d+)\}$')
message_data_re = re.compile(rb'[0-9]+ ((FETCH)|(EXPUNGE))')
tagged_status_response_re = re.compile(rb'[A-Z0-9]+ ((OK)|(NO)|(BAD))')


class IMAP4ClientProtocol(asyncio.Protocol):
    def __init__(self, loop: Optional[asyncio.AbstractEventLoop], conn_lost_cb: Callable[[Optional[Exception]], None] = None):
        self.loop = loop
        self.transport = None
        self.state = STARTED
        self.state_condition = asyncio.Condition()
        self.capabilities = set()
        self.pending_async_commands = dict()
        self.pending_sync_command = None
        self.idle_queue = asyncio.Queue()
        self._idle_event = asyncio.Event()
        self.imap_version = None
        self.literal_data = None
        self.incomplete_line = b''
        self.current_command = None
        self.conn_lost_cb = conn_lost_cb
        self.tasks: set[Future] = set()
        self.total_timeout: Optional[float] = None
        self.resync_timeout: Optional[float] = RESYNC_TIMEOUT_SECONDS
        self._ignored_command_tags: set[str] = set()
        self._drained_command_tags: set[str] = set()
        self._resynchronizing = False
        self._resync_poisoned = False
        self._resync_skip_literal = 0
        self._resync_after_literal = False
        self._resync_partial_line = b''
        self._resync_drained_bytes = 0
        self._resync_event = asyncio.Event()
        self._resync_event.set()
        self._resync_timer = asyncio.Handle(lambda: None, None, self.loop) if self.loop is not None else None

        self.tagnum = 0
        self.tagpre = int2ap(random.randint(4096, 65535))

    def connection_made(self, transport: BaseTransport) -> None:
        self.transport = transport
        self.state = CONNECTED

    def data_received(self, d: bytes) -> None:
        log.debug('Received : %s' % d)
        try:
            if self._resynchronizing:
                self._handle_resync_data(d)
            else:
                self._handle_responses(self.incomplete_line + d, self._handle_line, self.current_command)
                self.incomplete_line = b''
                self.current_command = None
        except IncompleteRead as incomplete_read:
            self.current_command = incomplete_read.cmd
            self.incomplete_line = incomplete_read.data

    def connection_lost(self, exc: Optional[Exception]) -> None:
        log.debug('connection lost: %s', exc)
        if self._resync_timer is not None:
            self._resync_timer.cancel()
        self._resynchronizing = False
        self._resync_poisoned = True
        self._resync_event.set()
        if self.conn_lost_cb is not None:
            self.conn_lost_cb(exc)

    def _handle_responses(self, data: bytes, line_handler: Callable[[bytes, Command], Optional[Command]], current_cmd: Command = None) -> None:
        if not data:
            if self.pending_sync_command is not None:
                self.pending_sync_command.flush()
            if current_cmd is not None and not current_cmd._abandoned and current_cmd.wait_data():
                raise IncompleteRead(current_cmd)
            return

        if current_cmd is not None and current_cmd.wait_literal_data():
            data = current_cmd.append_literal_data(data)
            if current_cmd.wait_literal_data():
                raise IncompleteRead(current_cmd)

        line, separator, tail = data.partition(CRLF)
        if not separator:
            raise IncompleteRead(current_cmd, data)

        cmd = line_handler(line, current_cmd)

        begin_literal = literal_data_re.match(line)
        if begin_literal:
            size = int(begin_literal.group('size'))
            if cmd is None:
                cmd = Command('NIL', 'unused')
            cmd.begin_literal_data(size)
            self._handle_responses(tail, line_handler, current_cmd=cmd)
        elif cmd is not None and cmd.wait_data():
            self._handle_responses(tail, line_handler, current_cmd=cmd)
        else:
            self._handle_responses(tail, line_handler)

    def _handle_resync_data(self, data: bytes) -> None:
        """Drop the bytes of an abandoned response until its tagged completion is seen.

        Literals are skipped by size rather than scanned for CRLF, so a hostile payload can not
        bleed into the next command. A tagged completion for a different command that is still in
        flight is still dispatched, so unrelated short commands stay usable during the drain.
        """
        data = self._resync_partial_line + data
        self._resync_partial_line = b''

        while data:
            if self._resync_skip_literal:
                skipped = data[:self._resync_skip_literal]
                self._resync_skip_literal -= len(skipped)
                self._resync_drain(skipped)
                data = data[len(skipped):]
                if not self._resync_skip_literal:
                    self._resync_after_literal = True
                continue

            line, separator, tail = data.partition(CRLF)
            if not separator:
                self._resync_partial_line = line
                return

            self._resync_drain(line + CRLF)
            data = tail

            if self._resync_after_literal:
                # This line is the remainder of the line that carried the literal (e.g. a closing
                # ')'). It is protocol text, so it may itself announce another literal such as the
                # nested literals of a BODYSTRUCTURE.
                self._resync_after_literal = False
                literal = literal_data_re.match(line)
                if literal:
                    self._resync_skip_literal = int(literal.group('size'))
                    self._resync_after_literal = True
                continue
            elif line.startswith(b'+'):
                # A continuation waiting for client data can never be satisfied here.
                self._abort_resynchronization()
                return
            elif tagged_status_response_re.match(line):
                tag_str = line.partition(b' ')[0].decode()
                if tag_str in self._ignored_command_tags:
                    self._ignored_command_tags.discard(tag_str)
                    self._drained_command_tags.add(tag_str)
                    if not self._ignored_command_tags:
                        self._finish_resynchronization()
                        if data:
                            self._handle_responses(data, self._handle_line)
                        return
                if tag_str in self._drained_command_tags or \
                        self._find_pending_async_cmd_by_tag(tag_str) or \
                        (self.pending_sync_command is not None and self.pending_sync_command.tag == tag_str):
                    # A response for another command that is still in flight.
                    self._response_done(line)
                else:
                    log.debug('dropping late tagged line during resynchronization: %s', line)
            elif line.startswith(b'*'):
                # Untagged data for the abandoned response is dropped so it is not attributed to
                # an unrelated command that may still be in flight.
                log.debug('dropping untagged line during resynchronization: %s', line)
            else:
                self._abort_resynchronization()
                return

            literal = literal_data_re.match(line)
            if literal:
                self._resync_skip_literal = int(literal.group('size'))
                # Whatever follows belongs to the remainder of this response line; never parse it.
                self._resync_after_literal = True

            if self._resync_poisoned:
                self._abort_resynchronization()
                return

    def _resync_drain(self, chunk: bytes) -> None:
        self._resync_drained_bytes += len(chunk)
        if self._resync_drained_bytes > RESYNC_MAX_DRAINED_BYTES:
            self._resync_poisoned = True

    def _finish_resynchronization(self) -> None:
        log.debug('resynchronized after abandoned command')
        self._resynchronizing = False
        self._resync_poisoned = False
        self._resync_skip_literal = 0
        self._resync_after_literal = False
        self._resync_partial_line = b''
        self._ignored_command_tags.clear()
        if self._resync_timer is not None:
            self._resync_timer.cancel()
        self.current_command = None
        self.incomplete_line = b''
        self._resync_event.set()

    def _abort_resynchronization(self) -> None:
        log.warning('could not resynchronize after abandoned command, connection is unusable')
        self._resynchronizing = False
        self._resync_poisoned = True
        self._resync_skip_literal = 0
        self._resync_after_literal = False
        self._resync_partial_line = b''
        self._ignored_command_tags.clear()
        if self._resync_timer is not None:
            self._resync_timer.cancel()
        self.current_command = None
        self.incomplete_line = b''
        self._resync_event.set()

    def _handle_line(self, line: bytes, current_cmd: Command) -> Optional[Command]:
        if not line:
            return

        if self.state == CONNECTED:
            task = asyncio.ensure_future(self.welcome(line))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
        elif tagged_status_response_re.match(line):
            self._response_done(line)
        elif current_cmd is not None:
            current_cmd.append_to_resp(line)
            return current_cmd
        elif line.startswith(b'*'):
            return self._untagged_response(line)
        elif line.startswith(b'+'):
            self._continuation(line)
        else:
            log.info('unknown data received %s' % line)

    def send(self, line: str, scrub: str =None) -> None:
        data = ('%s\r\n' % line).encode()
        if scrub:
            log.debug('Sending : %s' % data.replace(scrub.encode(), len(scrub) * b'*'))
        else:
            log.debug('Sending : %s' % data)
        self.transport.write(data)

    async def execute(self, command: Command, scrub: str =None) -> Response:
        if self.state not in Commands.get(command.name).valid_states:
            raise Abort('command %s illegal in state %s' % (command.name, self.state))

        # The total deadline covers queueing as well as the response read. It starts as soon as
        # the caller asks for the command, not when this command finally reaches the wire.
        # IDLE is a long-lived subscription and is deliberately exempt (see IdleCommand).
        if command.accepts_total_timeout and command._total_timeout is None:
            command.set_total_timeout(self.total_timeout)

        if self.pending_sync_command is not None:
            await self._wait_for_pending_commands([self.pending_sync_command], command)

        if Commands.get(command.name).exec == Exec.is_sync:
            if self.pending_async_commands:
                await self._wait_for_pending_commands(list(self.pending_async_commands.values()), command)
        else:
            pending = self.pending_async_commands.get(command.untagged_resp_name)
            if pending is not None:
                await self._wait_for_pending_commands([pending], command)

        # A previous command may have left an unread response in flight. Never send a new command
        # on top of it; wait for the drain to complete or fail the connection.
        await self._wait_for_resynchronization(command)
        # Queueing may have consumed most of the deadline: never send an already late command.
        command.raise_if_abandoned()
        if self._resync_poisoned:
            raise Abort('connection is out of sync after an abandoned command')

        if Commands.get(command.name).exec == Exec.is_sync:
            self.pending_sync_command = command
        else:
            self.pending_async_commands[command.untagged_resp_name] = command

        command.set_abandon_callback(self._command_abandoned)
        self.send(str(command), scrub=scrub)
        command.sent = True
        try:
            await command.wait()
        finally:
            if command.name == 'IDLE':
                self._idle_event.clear()

        return command.response

    async def _wait_for_pending_commands(self, commands: List[Command], waiting_command: Command) -> None:
        """Wait until one of the queued commands finishes, the connection resynchronizes, or the
        waiting command's own total deadline expires (in which case that command is abandoned)."""
        pending_waiter = asyncio.ensure_future(self._wait_any_commands(commands))
        waiters = {pending_waiter}
        if self._resynchronizing:
            waiters.add(asyncio.ensure_future(self._resync_event.wait()))
        if waiting_command is not None and waiting_command.accepts_total_timeout:
            waiters.add(asyncio.ensure_future(waiting_command._event.wait()))
        try:
            await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for waiter in waiters:
                waiter.cancel()

    async def _wait_any_commands(self, commands: List[Command]) -> None:
        if not commands:
            return
        tasks = {asyncio.ensure_future(cmd.wait()) for cmd in commands}
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                if not task.cancelled():
                    task.exception()  # consume: the owner reports the timeout itself
        finally:
            for task in tasks:
                task.cancel()

    async def _wait_for_resynchronization(self, command: Command) -> None:
        if not self._resynchronizing:
            return
        waiters = {asyncio.ensure_future(self._resync_event.wait())}
        if command.accepts_total_timeout:
            waiters.add(asyncio.ensure_future(command._event.wait()))
        try:
            await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for waiter in waiters:
                waiter.cancel()

    def _forget_command(self, command: Command) -> None:
        """Remove a *sent* command from the protocol's pending state.

        A command abandoned while still queued never reached the wire: it must not remove or
        resynchronize an unrelated command that is the one actually in flight.
        """
        if not command.sent:
            return
        if Commands.get(command.name).exec == Exec.is_sync:
            if self.pending_sync_command is command:
                self.pending_sync_command = None
        elif self.pending_async_commands.get(command.untagged_resp_name) is command:
            self.pending_async_commands.pop(command.untagged_resp_name, None)

    def _command_abandoned(self, command: Command) -> None:
        if not command.sent:
            # Timed out while queued behind another command; nothing was written for it.
            return
        self._forget_command(command)
        if len(self._ignored_command_tags) > 128:
            self._ignored_command_tags.pop()
        self._ignored_command_tags.add(command.tag)
        if len(self._drained_command_tags) > 128:
            self._drained_command_tags.pop()
        # Whatever the command kind, the server may still be writing that response. Drain it
        # (skipping literals by size) before another command is allowed on the wire, otherwise
        # stale untagged data or literal bytes would be attributed to the next command.
        self._start_resynchronization(command)

    def _start_resynchronization(self, command: Command) -> None:
        if not command.sent or self._resynchronizing:
            return
        log.debug('resynchronizing after abandoned command %s', command)
        self._resynchronizing = True
        self._resync_poisoned = False
        self._resync_drained_bytes = 0
        self._resync_partial_line = b''
        self._resync_after_literal = False
        # If the parser is blocked waiting for literal bytes, those bytes must be skipped by size.
        if command is self.current_command and command.wait_literal_data():
            self._resync_skip_literal = command._expected_size - command._literal_bytes_received()
        else:
            self._resync_skip_literal = 0
        self.current_command = None
        self.incomplete_line = b''
        self._resync_event.clear()
        if self._resync_timer is not None:
            self._resync_timer.cancel()
        if self.loop is not None and self.resync_timeout is not None:
            self._resync_timer = self.loop.call_later(self.resync_timeout, self._abort_resynchronization)

    @change_state
    async def welcome(self, command: bytes) -> None:
        if b'PREAUTH' in command:
            self.state = AUTH
        elif b'OK' in command:
            self.state = NONAUTH
        else:
            raise Error(command.decode())
        await self.capability()

    @change_state
    async def login(self, user: str, password: str) -> Response:
        response = await self.execute(
            Command('LOGIN', self.new_tag(), user, '%s' % quoted(password), loop=self.loop),
            scrub=password,
        )

        if 'OK' == response.result:
            self.state = AUTH
            for line in response.lines:
                if b'CAPABILITY' in line:
                    self.capabilities = self.capabilities.union(set(line.decode().replace('CAPABILITY', '').strip().split()))
        return response

    @change_state
    async def xoauth2(self, user: str, token: str) -> Response:
        """Authentication with XOAUTH2.

        Tested with outlook.

        Specification:
        https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth
        https://developers.google.com/gmail/imap/xoauth2-protocol
        """
        sasl_string = b64encode(f"user={user}\1auth=Bearer {token}\1\1".encode("ascii"))

        response = await self.execute(
            Command('AUTHENTICATE', self.new_tag(), 'XOAUTH2', sasl_string.decode("ascii"), loop=self.loop),
            scrub=token,
        )

        if 'OK' == response.result:
            self.state = AUTH
        return response

    @change_state
    async def logout(self) -> Response:
        response = (await self.execute(Command('LOGOUT', self.new_tag(), loop=self.loop)))
        if 'OK' == response.result:
            self.state = LOGOUT
        return response

    @change_state
    async def select(self, mailbox='INBOX') -> Response:
        response = await self.execute(
            Command('SELECT', self.new_tag(), mailbox, loop=self.loop))

        if 'OK' == response.result:
            self.state = SELECTED
        return response

    @change_state
    async def close(self) -> Response:
        response = await self.execute(Command('CLOSE', self.new_tag(), loop=self.loop))
        if response.result == 'OK':
            self.state = AUTH
        return response

    async def idle(self) -> Response:
        if 'IDLE' not in self.capabilities:
            raise Abort('server has not IDLE capability')
        self._idle_event.clear()
        return await self.execute(IdleCommand(self.new_tag(), self.idle_queue, loop=self.loop))

    def has_pending_idle_command(self) -> bool:
        return self.pending_sync_command is not None and self.pending_sync_command.name == 'IDLE'

    def idle_done(self) -> None:
        self.send('DONE')

    async def search(self, *criteria, charset: Optional[str] = 'utf-8', by_uid: bool = False) -> Response:
        args = ('CHARSET', charset) + criteria if charset is not None else criteria
        prefix = 'UID' if by_uid else ''

        return await self.execute(
            Command('SEARCH', self.new_tag(), *args, prefix=prefix, loop=self.loop))

    async def fetch(self, message_set: str, message_parts: str, by_uid: bool = False, timeout: float = None,
                    total_timeout: float = None) -> Response:
        return await self.execute(
            FetchCommand(self.new_tag(), message_set, message_parts,
                         prefix='UID' if by_uid else '', loop=self.loop, timeout=timeout,
                         total_timeout=total_timeout))

    async def store(self, *args: str, by_uid: bool = False) -> Response:
        return await self.execute(
            Command('STORE', self.new_tag(), *args,
                    prefix='UID' if by_uid else '', untagged_resp_name='FETCH', loop=self.loop))

    async def expunge(self, *args: str, by_uid=False) -> Response:
        return await self.execute(
            Command('EXPUNGE', self.new_tag(), *args,
                    prefix='UID' if by_uid else '', loop=self.loop))

    async def uid(self, command: str, *criteria: str, timeout: float = None, total_timeout: float = None) -> Response:
        if self.state not in Commands.get('UID').valid_states:
            raise Abort('command UID illegal in state %s' % self.state)

        if command.upper() == 'FETCH':
            return await self.fetch(criteria[0], criteria[1], by_uid=True, timeout=timeout,
                                    total_timeout=total_timeout)
        if command.upper() == 'STORE':
            return await self.store(*criteria, by_uid=True)
        if command.upper() == 'COPY':
            return await self.copy(*criteria, by_uid=True)
        if command.upper() == 'MOVE':
            return await self.move(*criteria, by_uid=True)
        if command.upper() == 'EXPUNGE':
            if 'UIDPLUS' not in self.capabilities:
                raise Abort('EXPUNGE with uids is only valid with UIDPLUS capability. UIDPLUS not in (%s)' % self.capabilities)
            return await self.expunge(*criteria, by_uid=True)
        raise Abort('command UID only possible with COPY, FETCH, EXPUNGE (w/UIDPLUS) or STORE (was %s)' % command.upper())

    async def copy(self, *args: str, by_uid: bool = False) -> Response:
        return (await self.execute(
            Command('COPY', self.new_tag(), *args, prefix='UID' if by_uid else '', loop=self.loop)))

    async def move(self, uid_set: str, mailbox: str, by_uid: bool = False) -> Response:
        if 'MOVE' not in self.capabilities:
            raise Abort('server has not MOVE capability')

        return (await self.execute(
            Command('MOVE', self.new_tag(), uid_set, mailbox, prefix='UID' if by_uid else '', loop=self.loop)))

    async def capability(self) -> None: # that should be a Response (would avoid the Optional)
        response = await self.execute(Command('CAPABILITY', self.new_tag(), loop=self.loop))

        capability_list = response.lines[0].decode().split()
        self.capabilities = set(capability_list)
        try:
            self.imap_version = list(
                filter(lambda x: x.upper() in AllowedVersions, capability_list)).pop().upper()
        except IndexError:
            raise Error('server not IMAP4 compliant')

    async def append(self, message_bytes: bytes, mailbox: str = 'INBOX', flags: str = None, date: Any = None,
                     timeout: float = None, total_timeout: float = None) -> Response:
        args = [mailbox]
        if flags is not None:
            if (flags[0], flags[-1]) != ('(', ')'):
                args.append('(%s)' % flags)
            else:
                args.append(flags)
        if date is not None:
            args.append(time2internaldate(date))
        args.append('{%s}' % len(message_bytes))
        self.literal_data = message_bytes
        return await self.execute(Command('APPEND', self.new_tag(), *args, loop=self.loop, timeout=timeout,
                                          total_timeout=total_timeout))

    async def id(self, **kwargs: Union[dict, list, str]) -> Response:
        args = arguments_rfs2971(**kwargs)
        return await self.execute(Command('ID', self.new_tag(), *args, loop=self.loop))

    simple_commands = {'NOOP', 'CHECK', 'STATUS', 'CREATE', 'DELETE', 'RENAME',
                       'SUBSCRIBE', 'UNSUBSCRIBE', 'LSUB', 'LIST', 'EXAMINE', 'ENABLE'}

    async def namespace(self) -> Response:
        if 'NAMESPACE' not in self.capabilities:
            raise Abort('server has not NAMESPACE capability')
        return await self.execute(Command('NAMESPACE', self.new_tag(), loop=self.loop))

    async def simple_command(self, name, *args: str) -> Response:
        if name not in self.simple_commands:
            raise NotImplementedError('simple command only available for %s' % self.simple_commands)
        return await self.execute(Command(name, self.new_tag(), *args, loop=self.loop))

    async def wait(self, state_regexp: str) -> None:
        state_re = re.compile(state_regexp)
        async with self.state_condition:
            await self.state_condition.wait_for(lambda: state_re.match(self.state))

    async def wait_for_idle_response(self):
        await self._idle_event.wait()

    def _untagged_response(self, line: bytes) -> Command:
        line = line.replace(b'* ', b'')
        if self.pending_sync_command is not None:
            self.pending_sync_command.append_to_resp(line)
            command = self.pending_sync_command
        else:
            match = message_data_re.match(line)
            if match:
                cmd_name, text = match.group(1), match.string
            else:
                cmd_name, _, text = line.partition(b' ')
            command = self.pending_async_commands.get(cmd_name.decode().upper())
            if command is not None:
                command.append_to_resp(text)
            else:
                # noop is async and servers can send untagged responses
                command = self.pending_async_commands.get('NOOP')
                if command is not None:
                    command.append_to_resp(line)
                else:
                    log.info('ignored untagged response : %s' % line)
        return command

    def _response_done(self, line: bytes) -> None:
        log.debug('tagged status %s' % line)
        tag, _, response = line.partition(b' ')
        tag_str = tag.decode()
        if tag_str in self._drained_command_tags or tag_str in self._ignored_command_tags:
            # A late tagged completion for a response already drained (sync) or abandoned (async).
            self._drained_command_tags.discard(tag_str)
            self._ignored_command_tags.discard(tag_str)
            log.debug('ignored late tagged response %s', line)
            return

        if self.pending_sync_command is not None:
            if self.pending_sync_command.tag != tag_str:
                raise Abort('unexpected tagged response with pending sync command (%s) response: %s' %
                            (self.pending_sync_command, response))
            command = self.pending_sync_command
            self.pending_sync_command = None
        else:
            cmds = self._find_pending_async_cmd_by_tag(tag_str)
            if len(cmds) == 0:
                raise Abort('unexpected tagged (%s) response: %s' % (tag, response))
            elif len(cmds) > 1:
                raise Error('inconsistent state : two commands have the same tag (%s)' % cmds)
            command = cmds.pop()
            self.pending_async_commands.pop(command.untagged_resp_name)

        response_result, _, response_text = response.partition(b' ')
        command.close(response_text, result=response_result.decode())

    def _continuation(self, line: bytes) -> None:
        if self.pending_sync_command is None:
            log.info('server says %s (ignored)' % line)
        elif self.pending_sync_command.name == 'APPEND':
            if self.literal_data is None:
                Abort('asked for literal data but have no literal data to send')
            self.transport.write(self.literal_data)
            self.transport.write(CRLF)
            self.literal_data = None
        elif self.pending_sync_command.name == 'IDLE':
            log.debug('continuation line -- assuming IDLE is active : %s', line)
            self._idle_event.set()
        else:
            log.debug('continuation line appended to pending sync command %s : %s' % (self.pending_sync_command, line))
            self.pending_sync_command.append_to_resp(line)
            self.pending_sync_command.flush()

    def new_tag(self) -> str:
        tag = self.tagpre + str(self.tagnum)
        self.tagnum += 1
        return tag

    def _find_pending_async_cmd_by_tag(self, tag: str) -> list:
        return [c for c in self.pending_async_commands.values() if c is not None and c.tag == tag]


class IMAP4:
    TIMEOUT_SECONDS = 10.0
    _client_task: Task

    def __init__(self, host: str = '127.0.0.1', port: int = IMAP4_PORT, loop: asyncio.AbstractEventLoop = None,
                 timeout: float = TIMEOUT_SECONDS, conn_lost_cb: Callable[[Optional[Exception]], None] = None,
                 ssl_context: ssl.SSLContext = None, total_timeout: float = None):
        self.timeout = timeout
        self.total_timeout = total_timeout
        self.port = port
        self.host = host
        self.protocol = None
        self._idle_waiter = None
        self.tasks: set[Future] = set()
        self.create_client(host, port, loop, conn_lost_cb, ssl_context)

    def create_client(self, host: str, port: int, loop: asyncio.AbstractEventLoop,
                      conn_lost_cb: Callable[[Optional[Exception]], None] = None, ssl_context: ssl.SSLContext = None) -> None:
        local_loop = loop if loop is not None else get_running_loop()
        self.protocol = IMAP4ClientProtocol(local_loop, conn_lost_cb)
        self.protocol.total_timeout = self.total_timeout
        self._client_task = local_loop.create_task(local_loop.create_connection(lambda: self.protocol, host, port, ssl=ssl_context))

    def get_state(self) -> str:
        return self.protocol.state

    async def wait_hello_from_server(self) -> None:
        await asyncio.wait_for(self._wait_connection_and_hello(), self.timeout)

    async def _wait_connection_and_hello(self) -> None:
        # a refused connection, a failed DNS lookup or a TLS handshake error is raised here
        await self._client_task
        await self.protocol.wait('AUTH|NONAUTH')

    async def login(self, user: str, password: str) -> Response:
        return await asyncio.wait_for(self.protocol.login(user, password), self.timeout)

    async def xoauth2(self, user: str, token: bytes) -> Response:
        return await asyncio.wait_for(self.protocol.xoauth2(user, token), self.timeout)

    async def logout(self) -> Response:
        return await asyncio.wait_for(self.protocol.logout(), self.timeout)

    async def select(self, mailbox: str = 'INBOX') -> Response:
        return await asyncio.wait_for(self.protocol.select(mailbox), self.timeout)

    async def search(self, *criteria: str, charset: Optional[str] = 'utf-8') -> Response:
        return await asyncio.wait_for(self.protocol.search(*criteria, charset=charset), self.timeout)

    async def uid_search(self, *criteria: str, charset: Optional[str] = 'utf-8') -> Response:
        return await asyncio.wait_for(self.protocol.search(*criteria, by_uid=True, charset=charset), self.timeout)

    async def uid(self, command: str, *criteria: str, total_timeout: float = None) -> Response:
        return await self.protocol.uid(command, *criteria, timeout=self.timeout,
                                       total_timeout=total_timeout)

    async def store(self, *criteria: str) -> Response:
        return await asyncio.wait_for(self.protocol.store(*criteria), self.timeout)

    async def copy(self, *criteria: str) -> Response:
        return await asyncio.wait_for(self.protocol.copy(*criteria), self.timeout)

    async def expunge(self) -> Response:
        return await asyncio.wait_for(self.protocol.expunge(), self.timeout)

    async def fetch(self, message_set: str, message_parts: str) -> Response:
        return await self.protocol.fetch(message_set, message_parts, timeout=self.timeout)

    async def idle(self) -> Response:
        return await self.protocol.idle()

    def idle_done(self) -> None:
        if self._idle_waiter is not None:
            self._idle_waiter.cancel()
        self.protocol.idle_done()

    async def stop_wait_server_push(self) -> bool:
        if self.protocol.has_pending_idle_command():
            await self.protocol.idle_queue.put(STOP_WAIT_SERVER_PUSH)
            return True
        return False

    async def wait_server_push(self, timeout: float = TWENTY_NINE_MINUTES) -> Response:
        return await asyncio.wait_for(self.protocol.idle_queue.get(), timeout=timeout)

    async def idle_start(self, timeout: float = TWENTY_NINE_MINUTES) -> Future:
        if self._idle_waiter is not None:
            self._idle_waiter.cancel()
        idle = asyncio.ensure_future(self.idle())
        self.tasks.add(idle)
        idle.add_done_callback(self.tasks.discard)
        wait_for_ack = asyncio.ensure_future(self.protocol.wait_for_idle_response())
        self.tasks.add(wait_for_ack)
        wait_for_ack.add_done_callback(self.tasks.discard)
        await asyncio.wait({idle, wait_for_ack}, return_when=asyncio.FIRST_COMPLETED)
        if not self.has_pending_idle():
            wait_for_ack.cancel()
            raise Abort('server returned error to IDLE command')

        def start_stop_wait_server_push():
            task = asyncio.ensure_future(self.stop_wait_server_push())
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)

        self._idle_waiter = self.protocol.loop.call_later(timeout, start_stop_wait_server_push)
        return idle

    def has_pending_idle(self) -> bool:
        return self.protocol.has_pending_idle_command()

    async def id(self, **kwargs) -> Response:
        return await asyncio.wait_for(self.protocol.id(**kwargs), self.timeout)

    async def namespace(self) -> Response:
        return await asyncio.wait_for(self.protocol.namespace(), self.timeout)

    async def noop(self) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('NOOP'), self.timeout)

    async def check(self) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('CHECK'), self.timeout)

    async def examine(self, mailbox: str = 'INBOX') -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('EXAMINE', mailbox), self.timeout)

    async def status(self, mailbox: str, names: str) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('STATUS', mailbox, names), self.timeout)

    async def subscribe(self, mailbox: str) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('SUBSCRIBE', mailbox), self.timeout)

    async def unsubscribe(self, mailbox: str) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('UNSUBSCRIBE', mailbox), self.timeout)

    async def lsub(self, reference_name: str, mailbox_name: str) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('LSUB', reference_name, mailbox_name), self.timeout)

    async def create(self, mailbox_name: str) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('CREATE', mailbox_name), self.timeout)

    async def delete(self, mailbox_name: str) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('DELETE', mailbox_name), self.timeout)

    async def rename(self, old_mailbox_name: str, new_mailbox_name: str) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('RENAME', old_mailbox_name, new_mailbox_name), self.timeout)

    async def getquotaroot(self, mailbox_name: str) -> Response:
        return await asyncio.wait_for(self.protocol.execute(Command('GETQUOTAROOT', self.protocol.new_tag(), 'INBOX', untagged_resp_name='QUOTA')), self.timeout)

    async def list(self, reference_name: str, mailbox_pattern: str) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('LIST', reference_name, mailbox_pattern), self.timeout)

    async def append(self, message_bytes, mailbox: str = 'INBOX', flags: str = None, date: Any = None) -> Response:
        return await self.protocol.append(message_bytes, mailbox, flags, date, timeout=self.timeout)

    async def close(self) -> Response:
        return await asyncio.wait_for(self.protocol.close(), self.timeout)

    async def move(self, uid_set: str, mailbox: str) -> Response:
        return await asyncio.wait_for(self.protocol.move(uid_set, mailbox), self.timeout)

    async def enable(self, capability: str) -> Response:
        if 'ENABLE' not in self.protocol.capabilities:
            raise Abort('server has not ENABLE capability')

        return await asyncio.wait_for(self.protocol.simple_command('ENABLE', capability), self.timeout)

    def has_capability(self, capability: str) -> bool:
        return capability in self.protocol.capabilities


def extract_exists(response: Response) -> Optional[int]:
    for line in response.lines:
        if b'EXISTS' in line:
            return int(line.replace(b' EXISTS', b'').decode())


class IMAP4_SSL(IMAP4):
    def __init__(self, host: str = '127.0.0.1', port: int = IMAP4_SSL_PORT, loop: asyncio.AbstractEventLoop = None,
                 timeout: float = IMAP4.TIMEOUT_SECONDS, ssl_context: ssl.SSLContext = None,
                 total_timeout: float = None):
        super().__init__(host, port, loop, timeout, None, ssl_context, total_timeout)

    def create_client(self, host: str, port: int, loop: asyncio.AbstractEventLoop,
                      conn_lost_cb: Callable[[Optional[Exception]], None] = None, ssl_context: ssl.SSLContext = None) -> None:
        if ssl_context is None:
            ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        super().create_client(host, port, loop, conn_lost_cb, ssl_context)


# functions from imaplib
def int2ap(num) -> str:
    """Convert integer to A-P string representation."""
    val = ''
    ap = 'ABCDEFGHIJKLMNOP'
    num = int(abs(num))
    while num:
        num, mod = divmod(num, 16)
        val += ap[mod:mod + 1]
    return val


Months = ' Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(' ')
Mon2num = {s.encode():n+1 for n, s in enumerate(Months[1:])}


def time2internaldate(date_time: Any) -> str:
    """Convert date_time to IMAP4 INTERNALDATE representation.

    Return string in form: '"DD-Mmm-YYYY HH:MM:SS +HHMM"'.  The
    date_time argument can be a number (int or float) representing
    seconds since epoch (as returned by time.time()), a 9-tuple
    representing local time, an instance of time.struct_time (as
    returned by time.localtime()), an aware datetime instance or a
    double-quoted string.  In the last case, it is assumed to already
    be in the correct format.
    """
    if isinstance(date_time, (int, float)):
        dt = datetime.fromtimestamp(date_time, timezone.utc).astimezone()
    elif isinstance(date_time, tuple):
        try:
            gmtoff = date_time.tm_gmtoff
        except AttributeError:
            if time.daylight:
                dst = date_time[8]
                if dst == -1:
                    dst = time.localtime(time.mktime(date_time))[8]
                gmtoff = -(time.timezone, time.altzone)[dst]
            else:
                gmtoff = -time.timezone
        delta = timedelta(seconds=gmtoff)
        dt = datetime(*date_time[:6], tzinfo=timezone(delta))
    elif isinstance(date_time, datetime):
        if date_time.tzinfo is None:
            raise ValueError("date_time must be aware")
        dt = date_time
    elif isinstance(date_time, str) and (date_time[0],date_time[-1]) == ('"','"'):
        return date_time        # Assume in correct format
    else:
        raise ValueError("date_time not of a known type")
    fmt = '"%d-{}-%Y %H:%M:%S %z"'.format(Months[dt.month])
    return dt.strftime(fmt)
