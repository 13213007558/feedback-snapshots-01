#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

"""
Control Socket Server

Runs in the arbiter process and accepts commands via Unix socket.
Uses asyncio in a background thread to handle client connections.

Fork Safety:
    This server uses os.register_at_fork() to properly handle fork() calls.
    Before fork: the asyncio thread is stopped to prevent lock issues.
    After fork in parent: the server is restarted.
    After fork in child: references are cleared (workers don't need the control server).
"""

import asyncio
import os
import shlex
import threading
from dataclasses import dataclass

from gunicorn.ctl.handlers import CommandHandlers
from gunicorn.ctl.policy import (
    AccessDenied,
    UnknownCommand,
    peer_credentials,
)
from gunicorn.ctl.protocol import (
    ControlProtocol,
    make_response,
    make_error_response,
)


@dataclass
class _ParsedCommand:
    """A command identified before the access check.

    ``canonical`` is the command identity the policy matches against: the
    command and its fixed word (show target, worker action, dirty action,
    known shutdown mode). Numeric or PID values and any trailing words are
    not part of it, and are only read by the handler after the check.
    """

    name: str
    action: object
    args: list
    canonical: str


# Module-level tracking of active control server instances for fork handling.
# This is necessary because os.register_at_fork() callbacks are process-level.
_active_servers = set()
_module_state = {"fork_handlers_registered": False}


def _register_fork_handlers():
    """Register fork handlers once at module level."""
    if _module_state["fork_handlers_registered"]:
        return
    _module_state["fork_handlers_registered"] = True

    os.register_at_fork(
        before=_before_fork,
        after_in_parent=_after_fork_parent,
        after_in_child=_after_fork_child,
    )


def _before_fork():
    """Called before fork() - stop all active control servers."""
    for server in list(_active_servers):
        server._stop_for_fork()


def _after_fork_parent():
    """Called in parent after fork() - restart all control servers."""
    for server in list(_active_servers):
        server._restart_after_fork()


def _after_fork_child():
    """Called in child after fork() - cleanup references."""
    # In the child process (worker), we don't need the control server.
    # Just clear the references without trying to stop anything.
    _active_servers.clear()


class ControlSocketServer:
    """
    Control socket server running in arbiter process.

    The server runs an asyncio event loop in a background thread,
    accepting connections and dispatching commands to handlers.

    Fork safety is handled via os.register_at_fork() - the server
    automatically stops before fork and restarts after in the parent.
    """

    def __init__(self, arbiter, socket_path, socket_mode=0o600,
                 policy=None):
        """
        Initialize control socket server.

        Args:
            arbiter: The Gunicorn arbiter instance
            socket_path: Path for the Unix socket
            socket_mode: Permission mode for socket (default 0o600)
            policy: Optional ControlPolicy. When set, every command is checked
                against the role of the connecting peer before it runs.
        """
        self.arbiter = arbiter
        self.socket_path = socket_path
        self.socket_mode = socket_mode
        self.policy = policy

        self.handlers = CommandHandlers(arbiter)
        self._server = None
        self._loop = None
        self._thread = None
        self._running = False
        self._was_running_before_fork = False
        # Set by the loop thread once self._loop and self._server are live.
        # The stop paths wait on it so a shutdown is never scheduled against a
        # not-yet-initialized loop (which would leak the thread + its fds).
        self._ready = threading.Event()

        # Ensure fork handlers are registered
        _register_fork_handlers()

    def start(self):
        """Start server in background thread with asyncio event loop."""
        if self._running:
            return

        self._running = True
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

        # Track this server for fork handling
        _active_servers.add(self)

    def stop(self):
        """Stop server and cleanup socket."""
        # Remove from active servers tracking
        _active_servers.discard(self)

        if not self._running:
            return

        self._running = False

        # Wait until the loop is live so the shutdown is actually delivered.
        self._ready.wait(timeout=2.0)
        if self._loop is not None:
            # Schedule server close in the loop
            self._loop.call_soon_threadsafe(self._shutdown)

        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

        # Clean up socket file
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass

    def _stop_for_fork(self):
        """Stop server before fork (called by fork handler)."""
        if not self._running:
            self._was_running_before_fork = False
            return

        self._was_running_before_fork = True
        self._running = False

        # Wait until the loop is live before scheduling shutdown. Without this,
        # a fork that lands while the thread is still starting up skips the
        # shutdown, join() times out, and the thread is dropped while still
        # holding its selector fd and the unix socket (the #3648 leak).
        self._ready.wait(timeout=2.0)
        if self._loop is not None:
            try:
                self._loop.call_soon_threadsafe(self._shutdown)
            except RuntimeError:
                # Loop may already be closed
                pass

        if self._thread:
            self._thread.join(timeout=2.0)
            if self._thread.is_alive() and self.arbiter.log:
                self.arbiter.log.warning(
                    "control socket thread did not stop before fork")
            self._thread = None

        self._loop = None
        self._server = None

    def _restart_after_fork(self):
        """Restart server in parent after fork (called by fork handler)."""
        if not self._was_running_before_fork:
            return

        self._was_running_before_fork = False
        self._running = True
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def _shutdown(self):
        """Shutdown server (called from event loop thread)."""
        if self._server:
            self._server.close()

    def _run_loop(self):
        """Run the asyncio event loop in background thread."""
        try:
            asyncio.run(self._serve())
        except Exception as e:
            if self._running and self.arbiter.log:
                self.arbiter.log.error("Control server error: %s", e)
        finally:
            # Release any stop path waiting on readiness, even if the thread
            # never became ready (eg the server failed to bind).
            self._ready.set()

    async def _serve(self):
        """Main async server loop."""
        self._loop = asyncio.get_running_loop()

        # Create parent directory if needed (for ~/.gunicorn/)
        socket_dir = os.path.dirname(self.socket_path)
        if socket_dir and not os.path.exists(socket_dir):
            os.makedirs(socket_dir, mode=0o700)

        # Remove socket if it exists
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)

        # Create Unix socket server
        self._server = await asyncio.start_unix_server(
            self._handle_client,
            path=self.socket_path
        )

        # Set socket permissions
        os.chmod(self.socket_path, self.socket_mode)

        if self.arbiter.log:
            self.arbiter.log.info("Control socket listening at %s",
                                  self.socket_path)

        # Loop and server are live; let the stop paths schedule shutdown.
        self._ready.set()

        try:
            async with self._server:
                await self._server.serve_forever()
        except asyncio.CancelledError:
            pass
        finally:
            if os.path.exists(self.socket_path):
                try:
                    os.unlink(self.socket_path)
                except OSError:
                    pass

    async def _handle_client(self, reader, writer):
        """
        Handle client connection.

        Args:
            reader: asyncio StreamReader
            writer: asyncio StreamWriter
        """
        credentials = None
        if self.policy is not None:
            credentials = self._peer_credentials(
                writer.get_extra_info('socket'))
        try:
            while self._running:
                try:
                    message = await asyncio.wait_for(
                        ControlProtocol.read_message_async(reader),
                        timeout=300.0  # 5 minute idle timeout
                    )
                except asyncio.TimeoutError:
                    # Client idle too long, close connection
                    break
                except asyncio.IncompleteReadError:
                    # Client disconnected
                    break
                except Exception:
                    # Protocol error
                    break

                # Process command. The peer credentials are read once per
                # connection, before the first command.
                response = await self._dispatch(message, credentials)

                # Send response
                await ControlProtocol.write_message_async(writer, response)

        except Exception as e:
            if self.arbiter.log:
                self.arbiter.log.debug("Control client error: %s", e)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    def _peer_credentials(self, sock):
        """Return the peer credentials for a connected socket.

        Split out so a test can supply a peer without switching to its uid.
        """
        return peer_credentials(sock)

    async def _dispatch(self, message: dict, credentials=None) -> dict:  # pylint: disable=too-many-return-statements
        """
        Dispatch command to appropriate handler.

        The command is parsed far enough to know whether it exists, then
        checked against the policy, and only then executed. A denied command
        never reaches a handler, so a monitor cannot cause a reload, a worker
        kill or any other side effect by guessing.

        Args:
            message: Request message dict
            credentials: PeerCredentials of the connection, or None when the
                transport has no peer credentials

        Returns:
            Response dictionary
        """
        request_id = message.get("id", 0)
        command = message.get("command", "").strip()
        args = message.get("args", [])

        if not command:
            return make_error_response(request_id, "Empty command")

        role = None
        try:
            # Parse only far enough to identify the command (e.g.
            # "show workers" or "worker add 2"). Argument values are checked
            # in the handler, after the access check.
            parts = shlex.split(command)
            if args:
                parts.extend(str(a) for a in args)

            if not parts:
                return make_error_response(request_id, "Empty command")

            parsed = self._parse_command(parts)

            if self.policy is not None:
                role = self.policy.role_for(credentials)
                self.policy.check(role, parsed.canonical)

            # Route to handler
            result = self._execute_command(parsed)

            if self.policy is not None:
                result = self.policy.filter_result(role, parsed.canonical, result)

            return make_response(request_id, result)

        except AccessDenied as e:
            return make_error_response(request_id, str(e), code=e.code)
        except UnknownCommand as e:
            return make_error_response(request_id, str(e), code=e.code)
        except ValueError as e:
            return make_error_response(request_id, f"Invalid argument: {e}")
        except Exception as e:
            if self.arbiter.log:
                self.arbiter.log.exception("Command error")
            return make_error_response(request_id, f"Command failed: {e}")

    def _parse_command(self, parts: list) -> "_ParsedCommand":  # pylint: disable=too-many-return-statements
        """
        Identify a command without side effects.

        Raises:
            UnknownCommand: the command or one of its words does not exist
        """
        if not parts:
            raise UnknownCommand("Empty command")

        cmd = parts[0].lower()
        rest = parts[1:]

        if cmd == "show":
            if not rest:
                raise UnknownCommand(
                    "Missing show target "
                    "(all|workers|dirty|config|stats|listeners)")
            target = rest[0].lower()
            if target not in ("all", "workers", "dirty", "config", "stats",
                              "listeners"):
                raise UnknownCommand(f"Unknown show target: {target}")
            return _ParsedCommand(cmd, target, rest[1:], f"show {target}")
        if cmd == "worker":
            if not rest:
                raise UnknownCommand("Missing worker action (add|remove|kill)")
            action = rest[0].lower()
            if action not in ("add", "remove", "kill"):
                raise UnknownCommand(f"Unknown worker action: {action}")
            return _ParsedCommand(cmd, action, rest[1:], f"{cmd} {action}")
        if cmd == "dirty":
            if not rest:
                raise UnknownCommand("Missing dirty action (add|remove)")
            action = rest[0].lower()
            if action not in ("add", "remove"):
                raise UnknownCommand(f"Unknown dirty action: {action}")
            return _ParsedCommand(cmd, action, rest[1:], f"{cmd} {action}")
        if cmd in ("reload", "reopen", "help"):
            return _ParsedCommand(cmd, None, rest, cmd)
        if cmd == "shutdown":
            # An unknown mode was always treated as graceful; keep that, but
            # let the policy match the bare command in that case.
            mode = rest[0] if rest else "graceful"
            canonical = ("shutdown %s" % mode
                         if mode in ("graceful", "quick") else "shutdown")
            return _ParsedCommand(cmd, mode, rest[1:], canonical)
        raise UnknownCommand(f"Unknown command: {cmd}")

    def _execute_command(self, parsed: "_ParsedCommand") -> dict:  # pylint: disable=too-many-return-statements
        """Run a parsed command. Called only after the access check."""
        cmd, action, args = parsed.name, parsed.action, parsed.args

        if cmd == "show":
            return {
                "all": self.handlers.show_all,
                "workers": self.handlers.show_workers,
                "dirty": self.handlers.show_dirty,
                "config": self.handlers.show_config,
                "stats": self.handlers.show_stats,
                "listeners": self.handlers.show_listeners,
            }[action]()
        if cmd == "worker":
            if action == "add":
                count = int(args[0]) if args else 1
                return self.handlers.worker_add(count)
            if action == "kill" and not args:
                raise ValueError("Missing PID for worker kill")
            if action == "remove":
                count = int(args[0]) if args else 1
                return self.handlers.worker_remove(count)
            return self.handlers.worker_kill(int(args[0]))
        if cmd == "dirty":
            count = int(args[0]) if args else 1
            if action == "add":
                return self.handlers.dirty_add(count)
            return self.handlers.dirty_remove(count)
        if cmd == "reload":
            return self.handlers.reload()
        if cmd == "reopen":
            return self.handlers.reopen()
        if cmd == "shutdown":
            return self.handlers.shutdown(action)
        return self.handlers.help()
