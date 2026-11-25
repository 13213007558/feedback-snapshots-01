"""Channel-bound message format selection for the receiver side."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from taskiq.abc.formatter import TaskiqFormatter


@dataclass(frozen=True, slots=True)
class ChannelFormat:
    """
    One message format approved for a channel.

    A channel may approve several formats during a migration window.
    ``legacy`` is a diagnostic marker: it does not change selection,
    it only records that the format is kept for older producers.

    :param formatter: formatter approved for the channel.
    :param version: name of the wire version. Defaults to
        ``formatter.version``.
    :param legacy: whether this format is kept for a legacy producer.
    """

    formatter: TaskiqFormatter
    version: str = ""
    legacy: bool = False

    def __post_init__(self) -> None:
        """Validate the entry and fill in a default version name."""
        if not isinstance(self.formatter, TaskiqFormatter):
            raise ValueError(
                "ChannelFormat formatter must be a TaskiqFormatter instance, "
                f"got {type(self.formatter).__name__}.",
            )
        if not self.version:
            fallback = getattr(self.formatter, "version", "") or "default"
            object.__setattr__(self, "version", fallback)


@dataclass(frozen=True, slots=True)
class ChannelFormatPolicy:
    """
    Immutable set of formats approved for each managed channel.

    The policy is intentionally immutable: the receiver swaps the whole
    object on reload, so a message that already captured a policy keeps
    using it from selection through execution and acknowledgement.

    :param channels: mapping of channel names to approved formats.
        The declaration order of formats is the tie-break order when
        more than one formatter reports a match.
    :param default_channel: channel used for deliveries that carry no
        channel name.
    :raises ValueError: if a channel has no formats, two formats share
        a version name, or the default channel is not configured.
    """

    channels: Mapping[str, tuple[ChannelFormat, ...]] = field(default_factory=dict)
    default_channel: str | None = None

    def __post_init__(self) -> None:
        """Freeze nested containers and validate the declaration."""
        normalized: dict[str, tuple[ChannelFormat, ...]] = {}
        for channel, formats in self.channels.items():
            if not isinstance(channel, str) or not channel:
                raise ValueError("Channel names must be non-empty strings.")
            entries = tuple(formats)
            if not entries:
                raise ValueError(
                    f"Channel '{channel}' must approve at least one format.",
                )
            for entry in entries:
                if not isinstance(entry, ChannelFormat):
                    raise ValueError(
                        f"Channel '{channel}' contains "
                        f"{type(entry).__name__}, expected ChannelFormat.",
                    )
            versions = [entry.version for entry in entries]
            if len(set(versions)) != len(versions):
                raise ValueError(
                    f"Channel '{channel}' declares duplicate format versions: "
                    f"{sorted(versions)}.",
                )
            normalized[channel] = entries

        if self.default_channel is not None and self.default_channel not in normalized:
            raise ValueError(
                f"Default channel '{self.default_channel}' is not configured. "
                f"Known channels: {sorted(normalized)}.",
            )
        object.__setattr__(self, "channels", MappingProxyType(normalized))

    def formats_for(self, channel: str | None) -> tuple[ChannelFormat, ...] | None:
        """
        Return formats approved for a channel.

        ``None`` is resolved through ``default_channel``.

        :param channel: channel name or None.
        :return: approved formats, or None if the channel is unknown.
        """
        resolved = self.default_channel if channel is None else channel
        if resolved is None:
            return None
        return self.channels.get(resolved)

    def resolve_channel(self, channel: str | None) -> str | None:
        """
        Resolve a delivery channel to a configured channel name.

        :param channel: channel name or None.
        :return: configured channel name, or None if it cannot be resolved.
        """
        resolved = self.default_channel if channel is None else channel
        if resolved is None or resolved not in self.channels:
            return None
        return resolved

    def versions_for(self, channel: str | None) -> tuple[str, ...]:
        """
        Return approved version names for a channel.

        :param channel: channel name or None.
        :return: version names, or an empty tuple for an unknown channel.
        """
        formats = self.formats_for(channel)
        if formats is None:
            return ()
        return tuple(entry.version for entry in formats)

    def with_channel(
        self,
        channel: str,
        *formats: ChannelFormat,
    ) -> "ChannelFormatPolicy":
        """
        Return a copy with one channel's formats replaced.

        This is the reload primitive: callers build a new policy from the
        old one and install it in one assignment, so in-flight deliveries
        keep their previous snapshot.

        :param channel: channel to update.
        :param formats: new approved formats for that channel.
        :return: new policy.
        """
        channels = dict(self.channels)
        channels[channel] = formats
        return ChannelFormatPolicy(
            channels=channels,
            default_channel=self.default_channel,
        )

    def without_channel(self, channel: str) -> "ChannelFormatPolicy":
        """
        Return a copy with one channel removed.

        :param channel: channel to remove.
        :raises ValueError: if removing it would leave the default channel
            configured.
        :return: new policy.
        """
        if channel == self.default_channel:
            raise ValueError(
                f"Cannot remove the default channel '{channel}'.",
            )
        channels = dict(self.channels)
        channels.pop(channel, None)
        return ChannelFormatPolicy(
            channels=channels,
            default_channel=self.default_channel,
        )


@dataclass(frozen=True, slots=True)
class FormatDecision:
    """
    The format selected for one delivery.

    The decision is captured before parsing and is carried through the
    whole lifecycle of that message, so a concurrent policy reload cannot
    change the formatter, the business target, or the acknowledgement.

    :param channel: managed channel the delivery came from.
    :param version: selected wire version.
    :param formatter: formatter selected for this delivery.
    :param generation: policy generation that produced the decision.
    :param reason: why this format was selected.
    :param allowed_versions: versions the channel approved at selection time.
    :param legacy: whether the selected format is a legacy format.
    """

    channel: str | None
    version: str
    formatter: TaskiqFormatter
    generation: int
    reason: str
    allowed_versions: tuple[str, ...] = ()
    legacy: bool = False


@dataclass(frozen=True, slots=True)
class FormatRejection:
    """
    A delivery that was terminated before business execution.

    Rejections are the diagnosable termination path: the message is not
    re-parsed with another formatter, no task or dependency is resolved,
    and an ackable delivery is acknowledged so the broker stops redelivery.

    :param channel: managed channel the delivery came from.
    :param allowed_versions: versions the channel approved at selection time.
    :param generation: policy generation that produced the rejection.
    :param reason: ``unknown-channel``, ``format-mismatch`` or ``parse-error``.
    :param version: selected version, present for ``parse-error``.
    :param formatter: selected formatter, present for ``parse-error``.
    :param error: underlying parse error, present for ``parse-error``.
    :param data_size: size of the rejected payload in bytes.
    """

    channel: str | None
    allowed_versions: tuple[str, ...]
    generation: int
    reason: str
    version: str | None = None
    formatter: TaskiqFormatter | None = None
    error: BaseException | None = None
    data_size: int = 0
