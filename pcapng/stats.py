"""
Helpers for interpreting Interface Statistics Block (ISB) observations.

An Interface Statistics Block
(:py:class:`pcapng.blocks.InterfaceStatistics`) is a point-in-time snapshot
of counters for one interface. A single capture can contain several such
blocks for the same interface. Their counters are cumulative and each one
measures a different stage of capture; this module turns a sequence of
snapshots into per-interval *deltas* without making assumptions the
pcap-ng format does not support.

Counter semantics (pcap-ng spec, section 4.6). Every counter is a 64-bit
cumulative value counted "from the beginning of the capture":

* ``isb_ifrecv`` -- packets received from the physical interface.
* ``isb_ifdrop`` -- packets dropped by the interface due to lack of
  resources.
* ``isb_filteraccept`` -- packets accepted by (passed) the capture filter.
* ``isb_osdrop`` -- packets dropped by the operating system.
* ``isb_usrdeliv`` -- packets delivered to the user/application. This can
  differ from ``isb_filteraccept - isb_osdrop`` because packets may still
  be sitting in OS buffers when the capture ends.

Rules enforced here:

* The counters are independent measurements of different capture stages.
  They are never added together to fabricate a "total packet count".
* A counter absent from an observation is *unknown*, not zero. Missing
  values are represented as ``None`` and any interval touching one is
  reported as inconclusive for that counter.
* Counter values are unsigned and cumulative. If a later value is smaller
  than an earlier one the counter wrapped around or was reset; the change
  over that interval cannot be computed and is reported as inconclusive
  rather than as a negative number.
* Deltas are only meaningful between consecutive observations *of the same
  interface*. Records belonging to different interfaces are never mixed.
* Statistics blocks and actual packet blocks can only be cross-checked on
  the same interface and over the same interval. See
  :py:func:`count_packets`.
"""

from collections import namedtuple

from pcapng.blocks import (
    EnhancedPacket,
    InterfaceStatistics,
    SimplePacket,
)


# ISB counter option names, in the order defined by the pcap-ng spec.
COUNTER_FIELDS = (
    "isb_ifrecv",
    "isb_ifdrop",
    "isb_filteraccept",
    "isb_osdrop",
    "isb_usrdeliv",
)

# Subset of counters that measure dropped (rather than seen/accepted) packets.
DROP_COUNTER_FIELDS = ("isb_ifdrop", "isb_osdrop")


CounterField = namedtuple("CounterField", ["name", "description"])


# What each counter actually means; keep these distinct and never sum them.
# Wording follows the pcap-ng spec, section 4.6. Every counter is cumulative
# "starting from the beginning of the capture".
COUNTER_DESCRIPTIONS = {
    "isb_ifrecv": CounterField(
        "isb_ifrecv",
        "Packets received from the physical interface, cumulative from the "
        "beginning of the capture.",
    ),
    "isb_ifdrop": CounterField(
        "isb_ifdrop",
        "Packets dropped by the interface due to lack of resources, "
        "cumulative from the beginning of the capture.",
    ),
    "isb_filteraccept": CounterField(
        "isb_filteraccept",
        "Packets accepted by the capture filter, cumulative from the "
        "beginning of the capture.",
    ),
    "isb_osdrop": CounterField(
        "isb_osdrop",
        "Packets dropped by the operating system, cumulative from the "
        "beginning of the capture.",
    ),
    "isb_usrdeliv": CounterField(
        "isb_usrdeliv",
        "Packets delivered to the user/application. Can differ from "
        "isb_filteraccept - isb_osdrop because packets may still sit in OS "
        "buffers when the capture ends.",
    ),
}


def get_counter(stats_block, name):
    """Return one counter value from an Interface Statistics Block.

    Returns ``None`` when the option is absent: a missing counter means the
    value is unknown and must not be treated as zero.
    """
    if not isinstance(stats_block, InterfaceStatistics):
        raise TypeError("expected an InterfaceStatistics block")
    if name not in COUNTER_DESCRIPTIONS:
        raise KeyError("unknown ISB counter: {0!r}".format(name))
    return stats_block.options.get(name)


def observation_counters(stats_block):
    """Return ``{counter_name: value}`` for one observation.

    Missing counters are included with a ``None`` value so that "absent"
    stays visibly distinct from an actual zero.
    """
    return {name: get_counter(stats_block, name) for name in COUNTER_FIELDS}


CounterDelta = namedtuple(
    "CounterDelta",
    ["name", "previous", "current", "delta", "conclusive", "reason"],
)


def counter_delta(previous, current, name):
    """Compute the change of one counter between two observations.

    ``previous`` and ``current`` are Interface Statistics Blocks of the
    same interface, in observation order.

    Returns a :py:class:`CounterDelta`. ``delta`` is ``None`` and
    ``conclusive`` is ``False`` when either observation lacks the counter
    (unknown, not zero) or when the value decreased (counter reset or
    wrap-around). A decrease never yields a negative delta.
    """
    prev_value = get_counter(previous, name)
    cur_value = get_counter(current, name)

    if prev_value is None or cur_value is None:
        return CounterDelta(
            name, prev_value, cur_value, None, False,
            "counter missing from an observation (unknown, not zero)",
        )

    if cur_value < prev_value:
        return CounterDelta(
            name, prev_value, cur_value, None, False,
            "counter decreased; reset or wrap-around, delta is not computable",
        )

    return CounterDelta(name, prev_value, cur_value, cur_value - prev_value,
                        True, None)


class StatsInterval(namedtuple("StatsInterval",
                              ["interface_id", "start", "end", "deltas"])):
    """Counter changes between two consecutive observations of one interface.

    ``start`` and ``end`` are the two Interface Statistics Blocks;
    ``deltas`` maps each :py:data:`COUNTER_FIELDS` name to a
    :py:class:`CounterDelta`.
    """

    __slots__ = ()

    @property
    def elapsed(self):
        """Wall-clock time between the two observations, in seconds."""
        return self.end.timestamp - self.start.timestamp

    def inconclusive_counters(self):
        """Names of counters whose delta could not be computed here."""
        return {
            name: delta
            for name, delta in self.deltas.items()
            if not delta.conclusive
        }


def compute_intervals(stats_blocks):
    """Yield a :py:class:`StatsInterval` for each consecutive pair.

    :param stats_blocks:
        Interface Statistics Blocks for a *single* interface, in observation
        (file) order. Passing records from more than one interface is a
        ``ValueError``: deltas across different interfaces are meaningless.

    A single observation yields no interval. Each yielded interval reports
    a conclusive delta per counter or explains why it cannot be concluded.
    """
    stats_blocks = list(stats_blocks)
    for block in stats_blocks:
        if not isinstance(block, InterfaceStatistics):
            raise TypeError("expected InterfaceStatistics blocks")

    interface_ids = {block.interface_id for block in stats_blocks}
    if len(interface_ids) > 1:
        raise ValueError(
            "intervals can only be computed within one interface; got "
            "interface ids {0!r}".format(sorted(interface_ids))
        )

    previous = None
    for current in stats_blocks:
        if previous is not None:
            deltas = {
                name: counter_delta(previous, current, name)
                for name in COUNTER_FIELDS
            }
            yield StatsInterval(
                interface_id=current.interface_id,
                start=previous,
                end=current,
                deltas=deltas,
            )
        previous = current


def count_packets(blocks, interface_id, start=None, end=None):
    """Count packet blocks for one interface, optionally within an interval.

    :param blocks:
        Iterable of blocks, e.g. the output of
        :py:class:`pcapng.scanner.FileScanner`.
    :param interface_id:
        Only packets recorded against this interface are counted.
    :param start:
        Optional Interface Statistics Block marking the beginning of the
        interval; counting starts at the block after it.
    :param end:
        Optional Interface Statistics Block marking the end; counting stops
        before it.

    Only Enhanced Packet Blocks and Simple Packet Blocks are counted
    (obsolete Packet Blocks are excluded). This is the number of packets
    actually stored in the file, which can only be compared against ISB
    counters for the same interface and over the same interval -- and even
    then the counters measure capture stages, not necessarily stored blocks.
    """
    if start is not None and not isinstance(start, InterfaceStatistics):
        raise TypeError("start must be an InterfaceStatistics block")
    if end is not None and not isinstance(end, InterfaceStatistics):
        raise TypeError("end must be an InterfaceStatistics block")

    count = 0
    inside = start is None
    for block in blocks:
        if not inside:
            if block is start:
                inside = True
            continue
        if end is not None and block is end:
            break
        if isinstance(block, (EnhancedPacket, SimplePacket)):
            if block.interface_id == interface_id:
                count += 1
    return count
