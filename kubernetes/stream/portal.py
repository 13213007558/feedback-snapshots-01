# Copyright 2026 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Disclosure policies and restricted portals for exec WebSocket streams."""

import time
from copy import deepcopy
from io import BytesIO, StringIO

from .ws_client import (
    DIAGNOSTIC_CHANNEL,
    ERROR_CHANNEL,
    STDERR_CHANNEL,
    STDOUT_CHANNEL,
    ProtocolReportedFailure,
    StreamDisconnected,
    Termination,
)


PUBLIC_CHANNELS = (STDOUT_CHANNEL,)
DIAGNOSTIC_CHANNELS = (DIAGNOSTIC_CHANNEL,)
SUPPORT_DIAGNOSTIC_CHANNELS = (STDERR_CHANNEL, DIAGNOSTIC_CHANNEL)
STATUS_CHANNELS = (ERROR_CHANNEL,)
REDACTED = "[REDACTED]"


def _channel_set(value, default=()):
    if value is None:
        return set(default)
    if isinstance(value, int):
        return {value}
    return set(value)


def _empty_like(data, binary=None):
    if binary is None:
        binary = isinstance(data, bytes)
    return b"" if binary else ""


class DisclosurePolicy:
    """One allow/deny and redaction rule used by every portal read path."""

    def __init__(
        self,
        allowed_channels=None,
        *,
        public_channels=None,
        channels=None,
        hidden_channels=None,
        private_channels=None,
        denied_channels=None,
        diagnostic_channels=None,
        status_channels=None,
        aggregate_channels=None,
        reveal_diagnostics=False,
        allow_diagnostics=False,
        authorized=False,
        allow_all_channels=False,
        redactor=None,
        redact=None,
        rule=None,
        disclosure_rule=None,
        replacement=None,
        redaction_token=None,
        secret_values=None,
        expose_status=True,
        expose_status_frame=False,
        expose_status_messages=True,
        expose_status_details=True,
    ):
        explicit_allow = any(value is not None for value in (
            allowed_channels, public_channels, channels))
        explicit_deny = any(value is not None for value in (
            hidden_channels, private_channels, denied_channels,
            diagnostic_channels))
        if explicit_deny and not explicit_allow:
            allow_all_channels = True

        self.allow_all_channels = allow_all_channels
        self.diagnostic_channels = _channel_set(
            diagnostic_channels, DIAGNOSTIC_CHANNELS)
        self.status_channels = _channel_set(status_channels, STATUS_CHANNELS)
        self.expose_status = expose_status
        self.expose_status_frame = expose_status_frame
        self.expose_status_messages = expose_status_messages
        self.expose_status_details = expose_status_details
        self.rule = rule or disclosure_rule
        if self.rule is not None and not callable(self.rule):
            raise TypeError("disclosure rule must be callable")

        allowed = _channel_set(allowed_channels)
        allowed |= _channel_set(public_channels)
        allowed |= _channel_set(channels)
        if not allowed and not allow_all_channels:
            allowed = set(PUBLIC_CHANNELS)
        if reveal_diagnostics or allow_diagnostics or authorized:
            allowed |= self.diagnostic_channels
        self.allowed_channels = allowed

        self.denied_channels = _channel_set(hidden_channels)
        self.denied_channels |= _channel_set(private_channels)
        self.denied_channels |= _channel_set(denied_channels)
        self.denied_channels |= self.diagnostic_channels - self.allowed_channels

        if aggregate_channels is None:
            self.aggregate_channels = {
                channel for channel in self.allowed_channels
                if channel not in self.status_channels
            }
            self.aggregate_all = allow_all_channels or self.rule is not None
        else:
            self.aggregate_channels = _channel_set(aggregate_channels)
            self.aggregate_all = False

        if redactor is not None and not callable(redactor):
            raise TypeError("redactor must be callable")
        if callable(redact):
            redactor = redact
            redact = False
        if replacement is None:
            replacement = redaction_token
        if replacement is None and redact is True:
            replacement = REDACTED
        self.replacement = replacement
        self.secret_values = tuple(secret_values or ())
        if redactor is None and self.secret_values:
            def replace_secrets(value):
                result = value
                token = self.replacement if self.replacement is not None else REDACTED
                for secret in self.secret_values:
                    if isinstance(value, bytes):
                        secret_bytes = (
                            secret.encode("utf-8")
                            if isinstance(secret, str) else bytes(secret)
                        )
                        token_bytes = (
                            token.encode("utf-8")
                            if isinstance(token, str) else bytes(token)
                        )
                        result = result.replace(secret_bytes, token_bytes)
                    else:
                        result = result.replace(str(secret), str(token))
                return result
            redactor = replace_secrets
        self.redactor = redactor

    @classmethod
    def unrestricted(cls):
        return cls(allow_all_channels=True)

    @classmethod
    def internal(cls):
        return cls.unrestricted()

    @classmethod
    def portal(cls, **kwargs):
        kwargs.setdefault("allowed_channels", set(PUBLIC_CHANNELS))
        return cls(**kwargs)

    @classmethod
    def public_summary(cls, **kwargs):
        return cls.portal(**kwargs)

    @classmethod
    def support(cls, diagnostic_channels=None, **kwargs):
        channels = _channel_set(
            diagnostic_channels, SUPPORT_DIAGNOSTIC_CHANNELS)
        kwargs.setdefault("reveal_diagnostics", True)
        kwargs.setdefault("aggregate_channels", set(channels))
        return cls(
            allowed_channels=set(channels),
            diagnostic_channels=set(channels),
            **kwargs,
        )

    def allows_channel(self, channel):
        if channel in self.denied_channels:
            return False
        if channel in self.status_channels:
            return self.expose_status_frame
        if self.allow_all_channels:
            return True
        return channel in self.allowed_channels

    def include_in_aggregate(self, channel):
        if channel in self.status_channels:
            return False
        if self.aggregate_all:
            return True
        return channel in self.aggregate_channels

    def _replacement_for(self, data):
        if self.replacement is None or self.replacement == "":
            return _empty_like(data)
        if isinstance(data, bytes):
            if isinstance(self.replacement, bytes):
                return self.replacement
            return str(self.replacement).encode("utf-8")
        if isinstance(self.replacement, bytes):
            return self.replacement.decode("utf-8", "replace")
        return str(self.replacement)

    def apply_redactor(self, data):
        if data in (None, "", b"") or self.redactor is None:
            return data
        result = self.redactor(data)
        if isinstance(data, bytes) and isinstance(result, str):
            return result.encode("utf-8")
        if isinstance(data, str) and isinstance(result, bytes):
            return result.decode("utf-8", "replace")
        return result

    def reveal_channel(self, channel, data):
        if data in (None, "", b""):
            return _empty_like(data, binary=isinstance(data, bytes))
        if self.rule is not None:
            revealed = self.rule(channel, data)
            if revealed is False or revealed is None:
                return self._replacement_for(data)
            if revealed is not True:
                return revealed
        if not self.allows_channel(channel):
            return self._replacement_for(data)
        return self.apply_redactor(data)

    disclose_channel = reveal_channel

    def _filter_strings(self, value):
        if isinstance(value, dict):
            return {key: self._filter_strings(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._filter_strings(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self._filter_strings(item) for item in value)
        if isinstance(value, str):
            filtered = self.apply_redactor(value)
            if isinstance(filtered, bytes):
                filtered = filtered.decode("utf-8", "replace")
            if self.rule is not None:
                revealed = self.rule(ERROR_CHANNEL, filtered)
                if revealed is None or revealed is False:
                    return None
                if revealed is not True:
                    filtered = revealed
            return filtered
        return value

    def filter_status(self, status):
        if not isinstance(status, dict):
            return None if not self.expose_status else status
        if not self.expose_status:
            return None
        filtered = self._filter_strings(deepcopy(status))
        if not self.expose_status_messages:
            filtered.pop("message", None)
        if not self.expose_status_details:
            filtered.pop("details", None)
        return filtered

    def filter_termination(self, termination):
        if not isinstance(termination, Termination):
            if isinstance(termination, dict):
                termination = Termination(**termination)
            else:
                return termination
        status = self.filter_status(termination.status)
        error = termination.error
        if isinstance(error, str):
            error = self.apply_redactor(error)
            if isinstance(error, bytes):
                error = error.decode("utf-8", "replace")
            if self.rule is not None:
                revealed = self.rule(ERROR_CHANNEL, error)
                if revealed is None or revealed is False:
                    error = None
                elif revealed is not True:
                    error = revealed
        if not self.expose_status:
            error = None
        return Termination(
            termination.kind,
            exit_code=termination.exit_code,
            status=status,
            error=error,
            formal_status_received=termination.formal_status_received,
        )


class RestrictedPortal:
    """Disclosure-filtered, WSClient-compatible read facade."""

    def __init__(self, stream=None, policy=None, **kwargs):
        if isinstance(stream, DisclosurePolicy) and policy is None:
            policy = stream
            stream = kwargs.pop("client", None)
        if policy is not None and not isinstance(policy, DisclosurePolicy):
            kwargs.setdefault("rule", policy)
            policy = None
        for key in ("disclosure_policy", "disclosure", "rule", "disclosure_rule"):
            value = kwargs.pop(key, None)
            if value is None:
                continue
            if isinstance(value, DisclosurePolicy) and policy is None:
                policy = value
            elif callable(value):
                kwargs.setdefault("rule", value)
        if stream is None:
            stream = kwargs.pop("client", None)
            stream = stream or kwargs.pop("source", None)
            stream = stream or kwargs.pop("ws", None)
            stream = stream or kwargs.pop("stream_client", None)
        self._stream = stream
        self.binary = kwargs.pop("binary", getattr(stream, "binary", False))
        if policy is None:
            policy = DisclosurePolicy.portal(**kwargs)
        self.policy = policy
        self._channels = {}
        self._raw_seen = {}
        self._listener_installed = False
        self._all = BytesIO() if self.binary else StringIO()

        add_listener = getattr(stream, "add_frame_listener", None)
        if callable(add_listener):
            add_listener(self._ingest_frame)
            self._listener_installed = True
        self._prime_existing_frames()

    def _empty(self):
        return b"" if self.binary else ""

    def _new_buffer(self):
        return BytesIO() if self.binary else StringIO()

    def _prime_existing_frames(self):
        raw_channels = getattr(self._stream, "_channels", None)
        if not isinstance(raw_channels, dict):
            return
        for channel, data in list(raw_channels.items()):
            if not self._listener_installed:
                self._raw_seen[channel] = len(data)
            self._ingest_frame(channel, data)

    def _sync_from_source(self):
        if self._stream is None:
            return
        raw_channels = getattr(self._stream, "_channels", None)
        if not isinstance(raw_channels, dict):
            return
        for channel in list(self._raw_seen):
            if channel not in raw_channels:
                self._raw_seen.pop(channel, None)
        for channel, data in list(raw_channels.items()):
            seen = self._raw_seen.get(channel, 0)
            if len(data) < seen:
                seen = 0
            suffix = data[seen:]
            if suffix:
                self._ingest_frame(channel, suffix)
            self._raw_seen[channel] = len(data)

    def _ingest_frame(self, channel, data):
        shown = self.policy.reveal_channel(channel, data)
        if not shown:
            return
        if channel in self._channels:
            self._channels[channel] += shown
        else:
            self._channels[channel] = shown
        if self.policy.include_in_aggregate(channel):
            self._all.write(shown)
        raw_channels = getattr(self._stream, "_channels", None)
        if isinstance(raw_channels, dict) and channel in raw_channels:
            self._raw_seen[channel] = len(raw_channels[channel])

    def update(self, timeout=0):
        if self._stream is not None:
            self._stream.update(timeout=timeout)
        self._sync_from_source()

    def run_forever(self, timeout=None):
        if self._stream is not None:
            self._stream.run_forever(timeout=timeout)
        self._sync_from_source()

    def is_open(self):
        if self._stream is None:
            return False
        return self._stream.is_open()

    def _delegate_channel_call(self, method_name, channel):
        if isinstance(getattr(self._stream, "_channels", None), dict):
            return None
        method = getattr(self._stream, method_name, None)
        if not callable(method):
            return None
        raw = method(channel)
        if method_name == "peek_channel":
            return self.policy.reveal_channel(channel, raw)
        self._ingest_frame(channel, raw)
        return self._channels.pop(channel, self._empty())

    @property
    def connected(self):
        return self.is_open()

    def peek_channel(self, channel, timeout=0):
        self.update(timeout=timeout)
        if channel in self._channels:
            return self._channels[channel]
        delegated = self._delegate_channel_call("peek_channel", channel)
        return delegated if delegated is not None else self._empty()

    def read_channel(self, channel, timeout=0):
        self.update(timeout=timeout)
        data = self._channels.pop(channel, None)
        if data is not None:
            return data
        delegated = self._delegate_channel_call("read_channel", channel)
        return delegated if delegated is not None else self._empty()

    def readline_channel(self, channel, timeout=None):
        if timeout is None:
            timeout = float("inf")
        newline = b"\n" if self.binary else "\n"
        start = time.time()
        while True:
            self.update(timeout=0)
            data = self._channels.get(channel)
            if data and newline in data:
                index = data.find(newline)
                line = data[:index]
                remaining = data[index + 1:]
                if remaining:
                    self._channels[channel] = remaining
                else:
                    self._channels.pop(channel, None)
                return line

            if not self.is_open():
                return self._channels.pop(channel, self._empty())

            elapsed = time.time() - start
            if elapsed >= timeout:
                return self._empty()
            wait_timeout = None if timeout == float("inf") else timeout - elapsed
            self.update(timeout=wait_timeout)

    def read_all(self):
        self.update(timeout=0)
        result = self._all.getvalue()
        self._all = self._new_buffer()
        self._channels = {}
        return result

    def read_aggregate(self):
        return self.read_all()

    aggregate = read_all
    read_aggregated = read_all

    def peek_stdout(self, timeout=0):
        return self.peek_channel(STDOUT_CHANNEL, timeout=timeout)

    def read_stdout(self, timeout=None):
        return self.read_channel(STDOUT_CHANNEL, timeout=timeout)

    def readline_stdout(self, timeout=None):
        return self.readline_channel(STDOUT_CHANNEL, timeout=timeout)

    def peek_stderr(self, timeout=0):
        return self.peek_channel(STDERR_CHANNEL, timeout=timeout)

    def read_stderr(self, timeout=None):
        return self.read_channel(STDERR_CHANNEL, timeout=timeout)

    def readline_stderr(self, timeout=None):
        return self.readline_channel(STDERR_CHANNEL, timeout=timeout)

    def read_diagnostics(self, timeout=0):
        self.update(timeout=timeout)
        values = []
        for channel in sorted(self.policy.diagnostic_channels):
            value = self._channels.pop(channel, self._empty())
            if value:
                values.append(value)
        if self.binary:
            return b"".join(values)
        return "".join(values)

    def diagnostics(self, timeout=0):
        return self.read_diagnostics(timeout=timeout)

    def termination(self, timeout=0):
        termination = self._stream.termination(timeout=timeout)
        return self.policy.filter_termination(termination)

    def wait_termination(self, timeout=None):
        termination = self._stream.wait_termination(timeout=timeout)
        return self.policy.filter_termination(termination)

    wait_for_termination = wait_termination
    wait_for_exit = wait_termination

    def exit_result(self, timeout=0):
        return self.termination(timeout=timeout)

    def exit_status(self, timeout=0):
        return self.termination(timeout=timeout)

    def final_exit_result(self, timeout=0):
        return self.termination(timeout=timeout)

    @property
    def returncode(self):
        return self.termination().exit_code

    @property
    def exit_code(self):
        return self.returncode

    def raise_for_termination(self):
        termination = self.termination()
        if termination.protocol_failure:
            raise ProtocolReportedFailure(termination)
        if termination.disconnected:
            raise StreamDisconnected("websocket closed without a formal status")
        return termination

    def write_channel(self, channel, data):
        return self._stream.write_channel(channel, data)

    def write_stdin(self, data):
        return self._stream.write_stdin(data)

    def close_channel(self, channel):
        return self._stream.close_channel(channel)

    def close(self, **kwargs):
        if self._stream is not None:
            return self._stream.close(**kwargs)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


RestrictedView = RestrictedStreamView = PortalView = PublicPortal = RestrictedPortal
RestrictedWSClient = RestrictedStreamClient = RestrictedStream = RestrictedPortal
PortalClient = DisclosurePortal = RestrictedPortal


class InternalStreamReader(RestrictedPortal):
    def __init__(self, stream=None, policy=None, **kwargs):
        super().__init__(
            stream,
            policy=policy or DisclosurePolicy.internal(),
            **kwargs,
        )


InternalPortal = InternalReader = InternalStreamReader


class DiagnosticsAccessDenied(PermissionError):
    """Raised when a support entry is created without approval."""


def _approval_is_granted(approval, approved, authorized, grant, access):
    candidate = approval
    if candidate is None:
        candidate = approved
    if candidate is None:
        candidate = authorized
    if candidate is None:
        candidate = grant
    if candidate is None:
        candidate = access
    if candidate is True:
        return True
    if candidate in (None, False):
        return False
    if callable(candidate):
        candidate = candidate()
        if candidate is True:
            return True
    if isinstance(candidate, dict):
        for key in ("approved", "granted", "allowed", "authorized", "is_authorized"):
            if candidate.get(key):
                return True
        return False
    for name in ("approved", "granted", "allowed", "authorized", "is_authorized"):
        value = getattr(candidate, name, None)
        if callable(value):
            value = value()
        if value:
            return True
    return False


class SupportPortal(RestrictedPortal):
    """Approved-only entry point for private diagnostics."""

    def __init__(
        self,
        stream=None,
        approval=None,
        *,
        approved=None,
        authorized=None,
        grant=None,
        access=None,
        diagnostic_channels=None,
        channels=None,
        policy=None,
        **kwargs,
    ):
        if isinstance(stream, DisclosurePolicy):
            policy = stream
            stream = None
        if not _approval_is_granted(approval, approved, authorized, grant, access):
            raise DiagnosticsAccessDenied(
                "support diagnostics require explicit approval")
        explicit_channels = diagnostic_channels is not None or channels is not None
        diagnostic_channels = _channel_set(
            diagnostic_channels or channels, SUPPORT_DIAGNOSTIC_CHANNELS)
        if policy is None:
            policy = DisclosurePolicy.support(
                diagnostic_channels=diagnostic_channels, **kwargs)
        super().__init__(stream, policy=policy)
        if explicit_channels:
            self.policy.diagnostic_channels = diagnostic_channels
        self.diagnostic_channels = self.policy.diagnostic_channels

    def read(self, timeout=0):
        return self.read_diagnostics(timeout=timeout)

    def read_all(self):
        return self.read_diagnostics()

    def entries(self, timeout=0):
        self.update(timeout=timeout)
        return {
            channel: self._channels.get(channel, self._empty())
            for channel in sorted(self.diagnostic_channels)
        }


SupportView = SupportDiagnostics = SupportEntry = DiagnosticsPortal = SupportPortal
DiagnosticsReader = SupportConsole = ApprovedDiagnosticsEntry = SupportPortal

DisclosureRule = DisclosurePolicy
ExitResult = ExitStatus = TerminalState = Termination


def restricted_view(stream=None, policy=None, **kwargs):
    return RestrictedPortal(stream, policy=policy, **kwargs)


def create_restricted_view(stream=None, policy=None, **kwargs):
    return restricted_view(stream, policy=policy, **kwargs)


def open_portal(stream=None, policy=None, **kwargs):
    return restricted_view(stream, policy=policy, **kwargs)


def support_entry(stream=None, approval=None, **kwargs):
    return SupportPortal(stream, approval=approval, **kwargs)
