---
title: Control Interface (gunicornc)
menu:
    guides:
        weight: 15
---

# Control Interface (gunicornc)

Gunicorn provides a control interface similar to [birdc](https://bird.network.cz/?get_doc&v=20&f=bird-3.html) for the BIRD routing daemon. This allows you to inspect and manage a running Gunicorn instance via a Unix socket.

## Overview

The control interface consists of two parts:

1. **Control Socket Server** - Runs in the arbiter process, accepts commands via Unix socket
2. **gunicornc CLI** - Interactive client that connects to the control socket

## Quick Start

### Start Gunicorn with Control Socket

By default, Gunicorn creates the control socket at `$XDG_RUNTIME_DIR/gunicorn.ctl`. If `XDG_RUNTIME_DIR` is unset or does not point to an existing directory, it falls back to `$HOME/.gunicorn/gunicorn.ctl`:

```bash
gunicorn -w 4 myapp:app
```

Or specify a custom path:

```bash
gunicorn --control-socket /tmp/myapp.ctl -w 4 myapp:app
```

### Connect with gunicornc

```bash
# Connect to default socket (./gunicorn.ctl)
gunicornc

# Connect to custom socket
gunicornc -s /tmp/myapp.ctl

# Run a single command
gunicornc -c "show workers"

# Output as JSON (for scripting)
gunicornc -c "show stats" -j
```

## Interactive Mode

When run without the `-c` flag, gunicornc enters interactive mode with readline support:

```
$ gunicornc
Connected to gunicorn.ctl
Type 'help' for available commands, 'quit' to exit.

gunicorn> show workers
PID        AGE    BOOTED   LAST_BEAT
----------------------------------------
12345      1      yes      0.2s ago
12346      2      yes      0.1s ago
12347      3      yes      0.3s ago

Total: 3 workers

gunicorn> worker add 2
{
  "added": 2,
  "previous": 3,
  "total": 5
}

gunicorn> quit
```

## Commands

### Show Commands

| Command | Description |
|---------|-------------|
| `show all` | Overview of all processes (arbiter, web workers, dirty workers) |
| `show workers` | List HTTP workers with status |
| `show dirty` | List dirty workers and apps |
| `show config` | Show current effective configuration |
| `show stats` | Show server statistics |
| `show listeners` | Show bound sockets |
| `help` | Show available commands |

### Worker Management

| Command | Description |
|---------|-------------|
| `worker add [N]` | Spawn N workers (default 1) |
| `worker remove [N]` | Remove N workers (default 1) |
| `worker kill <PID>` | Gracefully terminate specific worker |

### Dirty Worker Management

| Command | Description |
|---------|-------------|
| `dirty add [N]` | Spawn N dirty workers (default 1) |
| `dirty remove [N]` | Remove N dirty workers (default 1) |

!!! note "Per-App Worker Limits"
    When using `dirty add`, workers only load apps that haven't reached their
    worker limits. If all apps are at their limits, no new workers will be spawned.
    The response will include a `reason` field explaining this.

### Server Control

| Command | Description |
|---------|-------------|
| `reload` | Graceful reload (equivalent to SIGHUP) |
| `reopen` | Reopen log files (equivalent to SIGUSR1) |
| `shutdown [graceful\|quick]` | Shutdown server (SIGTERM or SIGINT) |

## Example Session

```
$ gunicornc
Connected to gunicorn.ctl
Type 'help' for available commands, 'quit' to exit.

gunicorn> show all
ARBITER (master)
  PID: 12345

WEB WORKERS (4)
  PID        AGE    BOOTED   LAST_BEAT
  --------------------------------------
  12346      1      yes      0.05s ago
  12347      2      yes      0.04s ago
  12348      3      yes      0.03s ago
  12349      4      yes      0.02s ago

DIRTY ARBITER
  PID: 12350

DIRTY WORKERS (2)
  PID        AGE    APPS
  --------------------------------------------------
  12351      1      MLModel
                    ImageProcessor
  12352      2      MLModel

gunicorn> show stats
Uptime:           2h 15m 30s
PID:              12345
Workers current:  4
Workers target:   4
Workers spawned:  6
Workers killed:   2
Reloads:          1

gunicorn> worker add
{
  "added": 1,
  "previous": 4,
  "total": 5
}

gunicorn> dirty add 1
{
  "success": true,
  "operation": "add",
  "requested": 1,
  "spawned": 1,
  "total_workers": 3,
  "target_workers": 3
}

gunicorn> quit
```

## Configuration

### Settings

| Setting | CLI Flag | Default | Description |
|---------|----------|---------|-------------|
| `control_socket` | `--control-socket` | `gunicorn.ctl` | Unix socket path |
| `control_socket_mode` | `--control-socket-mode` | `0o600` | Socket file permissions |
| `control_socket_policy` | none | `None` | Per-command access policy (opt-in) |
| `control_socket_disable` | `--no-control-socket` | `False` | Disable control socket |

### Example Configuration

```python
# gunicorn.conf.py
bind = "0.0.0.0:8000"
workers = 4

# Control socket settings
control_socket = "/var/run/gunicorn/myapp.ctl"
control_socket_mode = 0o660  # Allow group access
```

## Scripting

Use the `-j` flag for JSON output when scripting:

```bash
#!/bin/bash

# Get current worker count
workers=$(gunicornc -c "show stats" -j | jq -r '.workers_current')
echo "Current workers: $workers"

# Scale up if needed
if [ "$workers" -lt 8 ]; then
    gunicornc -c "worker add $((8 - workers))"
fi
```

## Security

### Socket permissions

By default the socket uses filesystem permissions:

- **Default mode**: `0o600` (owner only)
- **Unix socket only**: No TCP/remote access

To allow group access:

```python
control_socket_mode = 0o660
```

To disable the control socket entirely:

```bash
gunicorn --no-control-socket myapp:app
```

File permissions say who may connect, not what they may do. Once a
process can connect, the mode does not stop it from reloading or shutting
down the server. For that, enable the command policy.

### Command policy

`control_socket_policy` maps a role to the users or groups that get it.
The arbiter reads the Unix peer credentials of each connection and checks
every command before it runs.

```python
# gunicorn.conf.py
control_socket = "/var/run/gunicorn/myapp.ctl"
control_socket_mode = 0o660

control_socket_policy = {
    # A monitoring process: liveness only.
    "monitor": ["@monitor"],
    # Operations staff: may reload and stop the server.
    "operator": ["deploy", "@wheel"],
}
```

The two built-in roles:

| Role | May run | Reads |
|------|---------|-------|
| `monitor` | `show workers`, `show all`, `show dirty`, `show stats`, `show listeners`, `help` | Liveness fields only |
| `operator` | every command | Every field |

A monitor sees worker pids, ages, boot state and heartbeat age, listener
addresses and counts, and the arbiter pid. It does not see `show config`,
the import paths of dirty apps, `worker_pids`, socket file descriptors, or
the `aborted` flag. Replies are trimmed on the server, so a field added to
a handler later is not exposed to monitors until it is listed in the
policy.

A selector is a user name, a group name prefixed with `@`, a numeric uid,
or `*` for any local user. When a process matches more than one role, the
more privileged role applies.

The policy matches the command, not its values: `worker kill 1234` is the
`worker kill` command, so a role that may run it may pick any pid. A value
cannot turn one command into another.

A denied command returns `permission_denied` and is not executed, so a
monitor cannot start a reload or signal a worker by guessing. A command
that does not exist returns `unknown_command` for every role, so a client
can tell the two apart:

```console
$ gunicornc -c "reload"
Permission denied: Role 'monitor' may not run 'reload'
$ echo $?
2

$ gunicornc -c "frobnicate"
Error: Unknown command: frobnicate
$ echo $?
1
```

Scripts using the client library can read `ControlClientError.code`
(`"permission_denied"` or `"unknown_command"`).

The policy is checked after the command is identified and before the
handler runs, and the socket mode still has to let the client connect. If
the policy lists a role or a user that does not exist, the configuration
is rejected at startup. A control socket with a policy has no anonymous
access: a peer that matches no role can connect but can run nothing.

## Protocol

The control interface uses a JSON-based protocol with length-prefixed framing:

```
+----------------+------------------+
| Length (4B BE) |  JSON Payload    |
+----------------+------------------+
```

### Request Format

```json
{
  "id": 1,
  "command": "show workers"
}
```

### Response Format

```json
{
  "id": 1,
  "status": "ok",
  "data": { ... }
}
```

### Error Response

```json
{
  "id": 1,
  "status": "error",
  "error": "Unknown command: foo",
  "code": "unknown_command"
}
```

`code` is present when the server knows a stable reason. The two a
policy-checked server sends are `permission_denied` and `unknown_command`;
a client should branch on the code, not on the message text.

## Troubleshooting

### Cannot connect to socket

```
Error: Connection refused
```

- Check that Gunicorn is running
- Verify the socket path is correct
- Check socket file permissions

### Permission denied

```
Error: Permission denied
```

Either the socket file is not reachable, or the command policy refused the
command. When the policy refuses, `gunicornc` prints
`Permission denied: Role '...' may not run '...'` and exits with status 2.

- Check that you have read/write access to the socket file
- The socket is created with mode `0o600` by default (owner only)
- Check `control_socket_policy`: the connecting user must match a role, and
  the role must list the command

### Socket not found

```
Error: No such file or directory
```

- By default, Gunicorn creates the socket at `$XDG_RUNTIME_DIR/gunicorn.ctl` or falls back to `$HOME/.gunicorn/gunicorn.ctl`.
- Use an absolute path with `--control-socket /path/to/socket.ctl`
- Check if `--no-control-socket` was specified
