import asyncio
import fnmatch
import random
import re
import string
import time
import warnings
from copy import deepcopy
from typing import NamedTuple

from django.conf import settings
from django.core.signals import setting_changed
from django.utils.module_loading import import_string

from channels import DEFAULT_CHANNEL_LAYER

from .exceptions import ChannelFull, InvalidChannelLayerError


class ChannelLayerManager:
    """
    Takes a settings dictionary of backends and initialises them on request.
    """

    def __init__(self):
        self.backends = {}
        setting_changed.connect(self._reset_backends)

    def _reset_backends(self, setting, **kwargs):
        """
        Removes cached channel layers when the CHANNEL_LAYERS setting changes.
        """
        if setting == "CHANNEL_LAYERS":
            self.backends = {}

    @property
    def configs(self):
        # Lazy load settings so we can be imported
        return getattr(settings, "CHANNEL_LAYERS", {})

    def make_backend(self, name):
        """
        Instantiate channel layer.
        """
        config = self.configs[name].get("CONFIG", {})
        return self._make_backend(name, config)

    def make_test_backend(self, name):
        """
        Instantiate channel layer using its test config.
        """
        try:
            config = self.configs[name]["TEST_CONFIG"]
        except KeyError:
            raise InvalidChannelLayerError("No TEST_CONFIG specified for %s" % name)
        return self._make_backend(name, config)

    def _make_backend(self, name, config):
        # Check for old format config
        if "ROUTING" in self.configs[name]:
            raise InvalidChannelLayerError(
                "ROUTING key found for %s - this is no longer needed in Channels 2."
                % name
            )
        # Load the backend class
        try:
            backend_module = self.configs[name]["BACKEND"]
        except KeyError:
            raise InvalidChannelLayerError("No BACKEND specified for %s" % name)
        else:
            try:
                backend_class = import_string(backend_module)
            except ImportError:
                raise InvalidChannelLayerError(
                    "Cannot import BACKEND %r specified for %s"
                    % (self.configs[name]["BACKEND"], name)
                )

        # Initialise and pass config
        return backend_class(**config)

    def __getitem__(self, key):
        if key not in self.backends:
            self.backends[key] = self.make_backend(key)
        return self.backends[key]

    def __contains__(self, key):
        return key in self.configs

    def set(self, key, layer):
        """
        Sets an alias to point to a new ChannelLayerWrapper instance, and
        returns the old one that it replaced. Useful for swapping out the
        backend during tests.
        """
        old = self.backends.get(key, None)
        self.backends[key] = layer
        return old


class BaseChannelLayer:
    """
    Base channel layer class that others can inherit from, with useful
    common functionality.
    """

    MAX_NAME_LENGTH = 100

    def __init__(self, expiry=60, capacity=100, channel_capacity=None):
        self.expiry = expiry
        self.capacity = capacity
        self.channel_capacity = channel_capacity or {}

    def compile_capacities(self, channel_capacity):
        """
        Takes an input channel_capacity dict and returns the compiled list
        of regexes that get_capacity will look for as self.channel_capacity
        """
        result = []
        for pattern, value in channel_capacity.items():
            # If they passed in a precompiled regex, leave it, else interpret
            # it as a glob.
            if hasattr(pattern, "match"):
                result.append((pattern, value))
            else:
                result.append((re.compile(fnmatch.translate(pattern)), value))
        return result

    def get_capacity(self, channel):
        """
        Gets the correct capacity for the given channel; either the default,
        or a matching result from channel_capacity. Returns the first matching
        result; if you want to control the order of matches, use an ordered dict
        as input.
        """
        for pattern, capacity in self.channel_capacity:
            if pattern.match(channel):
                return capacity
        return self.capacity

    def match_type_and_length(self, name):
        if isinstance(name, str) and (len(name) < self.MAX_NAME_LENGTH):
            return True
        return False

    # Name validation functions

    channel_name_regex = re.compile(r"^[a-zA-Z\d\-_.]+(\![\d\w\-_.]*)?$")
    group_name_regex = re.compile(r"^[a-zA-Z\d\-_.]+$")
    invalid_name_error = (
        "{} name must be a valid unicode string "
        + "with length < {} ".format(MAX_NAME_LENGTH)
        + "containing only ASCII alphanumerics, hyphens, underscores, or periods."
    )

    def require_valid_channel_name(self, name, receive=False):
        if not self.match_type_and_length(name):
            raise TypeError(self.invalid_name_error.format("Channel"))
        if not bool(self.channel_name_regex.match(name)):
            raise TypeError(self.invalid_name_error.format("Channel"))
        if "!" in name and not name.endswith("!") and receive:
            raise TypeError("Specific channel names in receive() must end at the !")
        return True

    def require_valid_group_name(self, name):
        if not self.match_type_and_length(name):
            raise TypeError(self.invalid_name_error.format("Group"))
        if not bool(self.group_name_regex.match(name)):
            raise TypeError(self.invalid_name_error.format("Group"))
        return True

    def valid_channel_names(self, names, receive=False):
        _non_empty_list = True if names else False
        _names_type = isinstance(names, list)
        assert _non_empty_list and _names_type, "names must be a non-empty list"
        for channel in names:
            self.require_valid_channel_name(channel, receive=receive)
        return True

    def non_local_name(self, name):
        """
        Given a channel name, returns the "non-local" part. If the channel name
        is a process-specific channel (contains !) this means the part up to
        and including the !; if it is anything else, this means the full name.
        """
        if "!" in name:
            return name[: name.find("!") + 1]
        else:
            return name

    async def send(self, channel, message):
        raise NotImplementedError("send() should be implemented in a channel layer")

    async def receive(self, channel):
        raise NotImplementedError("receive() should be implemented in a channel layer")

    async def new_channel(self):
        raise NotImplementedError(
            "new_channel() should be implemented in a channel layer"
        )

    async def flush(self):
        raise NotImplementedError("flush() not implemented (flush extension)")

    async def group_add(self, group, channel):
        raise NotImplementedError("group_add() not implemented (groups extension)")

    async def group_discard(self, group, channel):
        raise NotImplementedError("group_discard() not implemented (groups extension)")

    async def group_send(self, group, message):
        raise NotImplementedError("group_send() not implemented (groups extension)")

    # Deprecated methods.
    def valid_channel_name(self, channel_name, receive=False):
        """
        Deprecated: Use require_valid_channel_name instead.
        """
        warnings.warn(
            "valid_channel_name is deprecated, use require_valid_channel_name instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.require_valid_channel_name(channel_name)

    def valid_group_name(self, group_name):
        """
        Deprecated: Use require_valid_group_name instead..
        """
        warnings.warn(
            "valid_group_name is deprecated, use require_valid_group_name instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.require_valid_group_name(group_name)


class GroupSendResult(NamedTuple):
    """
    Outcome of an ``InMemoryChannelLayer.group_send()`` call.

    ``delivered`` counts members whose queue accepted the message.
    ``dropped`` counts members whose queue was full (the existing per-channel
    capacity behaviour). ``rejected`` counts members that were not attempted
    because the room did not have enough broadcast budget. ``reason`` is
    ``"capacity"`` when messages were dropped, ``"budget"`` when the whole
    broadcast was rejected, and ``None`` otherwise.
    """

    group: str
    members: int
    delivered: int
    dropped: int
    rejected: int
    reason: str | None = None
    budget_used: int = 0
    budget_remaining: int | None = None
    dropped_channels: tuple[str, ...] = ()
    rejected_channels: tuple[str, ...] = ()

    @property
    def ok(self):
        return self.dropped == 0 and self.rejected == 0


class _QueuedMessage(NamedTuple):
    """
    A message in a channel queue, along with the group broadcast that put it
    there (if any) so its room budget can be released on receive or expiry.
    ``generation`` identifies the member's join generation, so messages left
    behind by a member that already left cannot release a later member's
    budget.
    """

    expires_at: float
    message: dict
    group: str | None = None
    generation: int = 0


class InMemoryChannelLayer(BaseChannelLayer):
    """
    In-memory channel layer implementation
    """

    def __init__(
        self,
        expiry=60,
        group_expiry=86400,
        capacity=100,
        channel_capacity=None,
        group_budget=None,
        group_budgets=None,
        clock=None,
        **kwargs,
    ):
        super().__init__(
            expiry=expiry,
            capacity=capacity,
            channel_capacity=channel_capacity,
            **kwargs,
        )
        if group_budget is not None and group_budget < 0:
            raise ValueError("group_budget must be zero or greater, or None")
        for budget in (group_budgets or {}).values():
            if budget is not None and budget < 0:
                raise ValueError("group budgets must be zero or greater, or None")
        self.channels = {}
        self.groups = {}
        self.group_expiry = group_expiry
        # ``get_capacity()`` iterates compiled patterns, so compile the
        # per-channel overrides here as the in-memory queue relies on it.
        self.channel_capacity = self.compile_capacities(channel_capacity or {})
        # Maximum number of undelivered broadcast deliveries a group may have
        # outstanding. ``None`` preserves the historical unlimited behaviour.
        self.group_budget = group_budget
        # Per-group overrides, matched like channel_capacity.
        self.group_budgets = self.compile_capacities(group_budgets or {})
        # Outstanding budget per group, split by the receiving channel:
        # {group: {channel: undelivered_count}}.
        self._group_budget_used = {}
        # Join generation per (group, channel), used to ensure messages left
        # behind by a member that already left cannot release the budget of a
        # later membership reusing the same channel name.
        self._group_member_generation = {}
        self._group_generation_seq = 0
        # Injectable clock so expiry and budget recovery can be tested without
        # sleeping. Defaults to wall-clock time, as before.
        self.clock = clock or time.time

    # Channel layer API

    extensions = ["groups", "flush"]

    async def send(self, channel, message):
        """
        Send a message onto a (general or specific) channel.
        """
        # Typecheck
        assert isinstance(message, dict), "message is not a dict"
        self.require_valid_channel_name(channel)
        # If it's a process-local channel, strip off local part and stick full
        # name in message
        assert "__asgi_channel__" not in message

        self._put(channel, message)

    async def receive(self, channel):
        """
        Receive the first message that arrives on the channel.
        If more than one coroutine waits on the same channel, a random one
        of the waiting coroutines will get the result.
        """
        self.require_valid_channel_name(channel)
        self._clean_expired()

        queue = self.channels.setdefault(
            channel, asyncio.Queue(maxsize=self.get_capacity(channel))
        )

        # Do a plain direct receive
        try:
            queued = await queue.get()
        finally:
            if queue.empty():
                self.channels.pop(channel, None)

        # A group broadcast that has now been consumed no longer occupies the
        # room's budget.
        self._release_queued_budget(queued, channel)

        return queued.message

    def _put(self, channel, message, group=None, generation=0):
        """
        Put a message into a channel queue, preserving the existing capacity
        semantics (QueueFull becomes ChannelFull).
        """
        queue = self.channels.setdefault(
            channel, asyncio.Queue(maxsize=self.get_capacity(channel))
        )
        try:
            queue.put_nowait(
                _QueuedMessage(
                    self.clock() + self.expiry, deepcopy(message), group, generation
                )
            )
        except asyncio.queues.QueueFull:
            raise ChannelFull(channel)

    def _release_queued_budget(self, queued, channel):
        """
        Releases the budget held by a queued broadcast copy, unless it belongs
        to a membership generation that has already been cleaned up.
        """
        if queued.group is None:
            return
        current = self._group_member_generation.get((queued.group, channel))
        if current != queued.generation:
            return
        self._release_group_budget(queued.group, channel)

    async def new_channel(self, prefix="specific."):
        """
        Returns a new channel name that can be used by something in our
        process as a specific channel.
        """
        return "%s.inmemory!%s" % (
            prefix,
            "".join(random.choice(string.ascii_letters) for i in range(12)),
        )

    # Expire cleanup

    def _clean_expired(self):
        """
        Goes through all messages and groups and removes those that are expired.
        Any channel with an expired message is removed from all groups.
        """
        now = self.clock()
        # Channel cleanup
        for channel, queue in list(self.channels.items()):
            # See if it's expired
            while not queue.empty() and queue._queue[0].expires_at < now:
                queued = queue.get_nowait()
                # Expired broadcasts give their room budget back.
                self._release_queued_budget(queued, channel)
                # Any removal prompts group discard
                self._remove_from_groups(channel)
                # Is the channel now empty and needs deleting?
                if queue.empty():
                    self.channels.pop(channel, None)

        # Group Expiration
        timeout = int(now) - self.group_expiry
        for group, channels in list(self.groups.items()):
            for name, timestamp in list(channels.items()):
                # If join time is older than group_expiry
                # end the group membership
                if timestamp and timestamp < timeout:
                    # Delete from group
                    channels.pop(name, None)
                    # The expired member no longer occupies room budget.
                    self._release_member_budget(group, name)
            if not channels:
                self.groups.pop(group, None)

    # Flush extension

    async def flush(self):
        self.channels = {}
        self.groups = {}
        self._group_budget_used = {}
        self._group_member_generation = {}

    async def close(self):
        # Nothing to go
        pass

    def _remove_from_groups(self, channel):
        """
        Removes a channel from all groups. Used when a message on it expires.
        """
        for group, channels in list(self.groups.items()):
            if channel in channels:
                channels.pop(channel, None)
                self._release_member_budget(group, channel)
            if not channels:
                self.groups.pop(group, None)

    # Room broadcast budget

    def get_group_budget(self, group):
        """
        Returns the configured broadcast budget for a group, or None when the
        group has no budget (the historical unlimited behaviour).
        """
        for pattern, budget in self.group_budgets:
            if pattern.match(group):
                return budget
        return self.group_budget

    def get_group_budget_used(self, group):
        """
        Returns the number of outstanding broadcast deliveries currently
        occupying the group's budget.
        """
        return sum(self._group_budget_used.get(group, {}).values())

    def get_group_budget_remaining(self, group):
        """
        Returns the group's remaining broadcast budget, or None when unlimited.
        """
        budget = self.get_group_budget(group)
        if budget is None:
            return None
        return max(0, budget - self.get_group_budget_used(group))

    def _reserve_group_budget(self, group, channel):
        """
        Records one outstanding broadcast delivery for ``channel`` in ``group``.
        """
        self._group_budget_used.setdefault(group, {})
        self._group_budget_used[group][channel] = (
            self._group_budget_used[group].get(channel, 0) + 1
        )

    def _release_group_budget(self, group, channel, count=1):
        """
        Releases up to ``count`` outstanding broadcast deliveries held by
        ``channel`` in ``group``.
        """
        members = self._group_budget_used.get(group)
        if not members or channel not in members:
            return
        remaining = members[channel] - count
        if remaining > 0:
            members[channel] = remaining
        else:
            members.pop(channel, None)
        if not members:
            self._group_budget_used.pop(group, None)

    def _release_member_budget(self, group, channel):
        """
        Releases all budget held by a departing group member and forgets its
        join generation.
        """
        members = self._group_budget_used.get(group)
        if members:
            members.pop(channel, None)
            if not members:
                self._group_budget_used.pop(group, None)
        self._group_member_generation.pop((group, channel), None)

    def _member_generation(self, group, channel):
        """
        Returns the current join generation for a group member, creating one
        on first use.
        """
        key = (group, channel)
        if key not in self._group_member_generation:
            self._group_generation_seq += 1
            self._group_member_generation[key] = self._group_generation_seq
        return self._group_member_generation[key]

    # Groups extension

    async def group_add(self, group, channel):
        """
        Adds the channel name to a group.
        """
        # Check the inputs
        self.require_valid_group_name(group)
        self.require_valid_channel_name(channel)
        # Add to group dict
        self.groups.setdefault(group, {})
        self.groups[group][channel] = self.clock()
        self._member_generation(group, channel)

    async def group_discard(self, group, channel):
        # Both should be text and valid
        self.require_valid_channel_name(channel)
        self.require_valid_group_name(group)
        # Remove from group set
        group_channels = self.groups.get(group, None)
        if group_channels:
            # remove channel if in group
            group_channels.pop(channel, None)
            # A departing member releases the budget its queued broadcasts hold.
            self._release_member_budget(group, channel)
            # is group now empty? If yes remove it
            if not group_channels:
                self.groups.pop(group, None)

    async def group_send(self, group, message):
        """
        Broadcast a message to a group, respecting the group's broadcast
        budget (if any) and the existing per-channel queue capacity.

        A broadcast is admitted into the room's budget as a whole: if there is
        not enough budget left for every current member, the whole broadcast is
        rejected and no queue is touched. Once admitted, members whose queue is
        full are dropped exactly as before.

        Returns a :class:`GroupSendResult` with ``delivered``, ``dropped``
        and ``rejected`` counts. Per the channel layer spec, this method never
        raises ``ChannelFull``.
        """
        # Check types
        assert isinstance(message, dict), "Message is not a dict"
        assert "__asgi_channel__" not in message
        self.require_valid_group_name(group)
        # Run clean
        self._clean_expired()

        members = list(self.groups.get(group, {}).keys())
        budget = self.get_group_budget(group)
        used = self.get_group_budget_used(group)
        if budget is not None and used + len(members) > budget:
            # Not enough room budget for the whole broadcast: reject it
            # atomically so callers get an unambiguous result.
            return GroupSendResult(
                group=group,
                members=len(members),
                delivered=0,
                dropped=0,
                rejected=len(members),
                reason="budget",
                budget_used=used,
                budget_remaining=self.get_group_budget_remaining(group),
                rejected_channels=tuple(members),
            )

        delivered = 0
        dropped_channels = []
        for channel in members:
            generation = self._member_generation(group, channel)
            try:
                self._put(channel, message, group=group, generation=generation)
            except ChannelFull:
                dropped_channels.append(channel)
            else:
                delivered += 1
                if budget is not None:
                    self._reserve_group_budget(group, channel)

        return GroupSendResult(
            group=group,
            members=len(members),
            delivered=delivered,
            dropped=len(dropped_channels),
            rejected=0,
            reason="capacity" if dropped_channels else None,
            budget_used=self.get_group_budget_used(group),
            budget_remaining=self.get_group_budget_remaining(group),
            dropped_channels=tuple(dropped_channels),
        )


def get_channel_layer(alias=DEFAULT_CHANNEL_LAYER):
    """
    Returns a channel layer by alias, or None if it is not configured.
    """
    try:
        return channel_layers[alias]
    except KeyError:
        return None


# Default global instance of the channel layer manager
channel_layers = ChannelLayerManager()
