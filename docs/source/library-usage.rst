Library usage
#############

Use the :py:class:`~pcapng.scanner.FileScanner` class to iterate over blocks
in a pcap-ng archive file, like this:

.. code-block:: python

    from pcapng import FileScanner

    with open('/tmp/mycapture.pcap') as fp:
        scanner = FileScanner(fp)
        for block in scanner:
            pass  # do something with the block...

Block types can be checked against blocks in :py:mod:`pcapng.blocks`.

Interface statistics
====================

A capture can contain several Interface Statistics Blocks (ISBs) for the
same interface; each one is a point-in-time snapshot. All of them are kept,
in file order, on
:py:attr:`pcapng.blocks.SectionHeader.interface_statistics` and, grouped by
interface, on
:py:attr:`pcapng.blocks.SectionHeader.interface_stats_history`.

.. code-block:: python

    from pcapng import FileScanner

    with open('/tmp/mycapture.pcapng', 'rb') as fp:
        blocks = list(FileScanner(fp))

    section = blocks[0]
    for stats in section.iter_interface_stats(interface_id=0):
        print(stats.timestamp, stats.options)

For backwards compatibility, the legacy accessors still expose only the
*latest* snapshot:
:py:attr:`pcapng.blocks.InterfaceDescription.statistics` and
:py:attr:`pcapng.blocks.SectionHeader.interface_stats`. New code should use
:py:attr:`pcapng.blocks.InterfaceDescription.statistics_history` instead so
that earlier observations are not hidden by later ones.

Use :py:mod:`pcapng.stats` to turn a series of snapshots into per-interval
deltas. A counter missing from an observation is unknown (``None``), not
zero, and a counter that decreases is treated as a reset/wrap-around: the
delta is reported as inconclusive rather than as a negative number.

.. code-block:: python

    from pcapng.stats import compute_intervals

    history = list(section.iter_interface_stats(interface_id=0))
    for interval in compute_intervals(history):
        for name, delta in interval.deltas.items():
            if delta.conclusive:
                print(name, delta.delta)
            else:
                print(name, 'inconclusive:', delta.reason)

The counters (``isb_ifrecv``, ``isb_ifdrop``, ``isb_filteraccept``,
``isb_osdrop``, ``isb_usrdeliv``) measure different capture stages and are
never added together. They can only be cross-checked against the packets
stored in the file for the same interface and over the same interval; see
:py:func:`pcapng.stats.count_packets`.

A runnable demonstration, including synthetic captures for continuous
observations, missing counters and counter resets, is provided in
``examples/diagnose_interface_stats.py``.
