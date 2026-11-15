import pcapng.blocks as blocks
from pcapng import strictness as _strictness
from pcapng.exceptions import PcapngDumpError


def _first_policy(*values):
    for value in values:
        if value is not None:
            return value
    return None


class FileWriter(object):
    """
    pcap-ng file writer.
    """

    __slots__ = [
        "stream",
        "interfaces",
        "current_section",
        "_strictness_policy",
    ]

    def __init__(
        self,
        stream,
        shb,
        policy=None,
        strictness_policy=None,
        strictness=None,
        strictness_level=None,
    ):
        """
        Start writing a new pcap-ng section to the given stream. Writes the
        :py:class:`SectionHeader` immediately. Also writes any
        :py:class:`InterfaceDescription` blocks that have been created for
        the section.

        :param stream:
            a file-like object to which to write the data.

        :param shb:
            a :py:class:`pcapng.blocks.SectionHeader` to start the section.

        :param policy:
            optional :py:class:`pcapng.strictness.StrictnessPolicy` (or
            :py:class:`pcapng.strictness.Strictness`) owned by the task
            writing this stream.  Fixes and strictness diagnostics produced
            by writing blocks are attributed to this policy, not to whatever
            global setting is active or to the policy that was used to read
            the blocks.  When omitted, an active
            :py:func:`pcapng.strictness.strictness_scope` is captured;
            otherwise the legacy global setting is consulted dynamically.
        """
        self.stream = stream
        self.interfaces = set()
        if not isinstance(shb, blocks.SectionHeader):
            raise TypeError("not a SectionHeader")
        self.current_section = shb
        explicit = _first_policy(
            policy, strictness_policy, strictness_level, strictness
        )
        # Re-initialising (new section) keeps the policy of the writer task.
        if explicit is None:
            explicit = getattr(self, "_strictness_policy", None)
        self._strictness_policy = _strictness.capture_policy(explicit)
        shb._write(self.stream, policy=self._effective_policy(shb))
        for iface in sorted(shb.interfaces.keys()):
            self.interfaces.add(iface)
            shb.interfaces[iface]._write(
                stream, policy=self._effective_policy(shb.interfaces[iface])
            )

    @property
    def strictness_policy(self):
        """The task policy this writer belongs to (may be None)."""
        return self._strictness_policy

    @strictness_policy.setter
    def strictness_policy(self, policy):
        self._strictness_policy = _strictness.capture_policy(policy)

    @property
    def policy(self):
        """The effective policy used for diagnostics from this writer."""
        return _strictness.operation_policy(self)

    @policy.setter
    def policy(self, policy):
        self._strictness_policy = _strictness.capture_policy(policy)

    def use_policy(self, policy):
        """Explicitly bind this writer to a task policy."""
        self._strictness_policy = _strictness.capture_policy(policy)
        return self

    def _effective_policy(self, blk):
        # The writing task owns automatic fixes and warning attribution.  A
        # writer created inside a task keeps that task's policy; otherwise the
        # task active at write time applies (which may be an enclosing scope,
        # or the legacy global setting).  The block's own read policy remains
        # inspectable but does not decide how another task writes it.
        if self._strictness_policy is not None:
            return self._strictness_policy
        return _strictness.get_strictness_policy()

    def write_block(self, blk):
        """
        Write the given block to this stream.

        If the block is a :py:class:`pcapng.blocks.SectionHeader`, then a new
        section will be started in the same output stream, along with any
        :py:class:`InterfaceDescription` blocks that have been created for the section.

        :param blk:
            a :py:class:`pcapng.blocks.Block` to write.
        """
        if not isinstance(blk, blocks.Block):
            raise TypeError("not a pcapng block")

        if type(blk) is blocks.SectionHeader:
            # Starting a new section, so re-initialize (keeping our policy)
            self.__init__(self.stream, blk, policy=self._strictness_policy)
            return

        if blk.section is not self.current_section:
            raise PcapngDumpError("block not from current section")

        if type(blk) is blocks.InterfaceDescription:
            # Have we already written this interface?
            if blk.interface_id in self.interfaces:
                # We have. Should this be an error?
                raise PcapngDumpError(
                    "duplicate interface_id {}".format(blk.interface_id)
                )
            # No, so add it
            self.interfaces.add(blk.interface_id)
        elif isinstance(blk, blocks.BlockWithInterfaceMixin):
            # Check that we've written the interface for this block
            if blk.interface.interface_id not in self.interfaces:
                raise PcapngDumpError("no matching interface written for block")

        blk._write(self.stream, policy=self._effective_policy(blk))
