import pcapng.blocks as blocks
from pcapng import strictness as strictness_module
from pcapng.exceptions import PcapngDumpError


class FileWriter(object):
    """
    pcap-ng file writer.
    """

    __slots__ = [
        "stream",
        "interfaces",
        "current_section",
        "_strictness",
        "_strictness_explicit",
    ]

    def __init__(self, stream, shb, strictness=None, **kwargs):
        """
        Start writing a new pcap-ng section to the given stream. Writes the
        :py:class:`SectionHeader` immediately. Also writes any
        :py:class:`InterfaceDescription` blocks that have been created for
        the section.

        :param stream:
            a file-like object to which to write the data.

        :param shb:
            a :py:class:`pcapng.blocks.SectionHeader` to start the section.

        :param strictness:
            a :py:class:`~pcapng.strictness.Strictness` value or
            :py:class:`~pcapng.strictness.StrictnessPolicy` to use for this
            writer.  When omitted, the policy active in the current task
            context is captured; if there is none, the compatibility global
            level is used dynamically.
        """
        explicit_flag = kwargs.pop("_strictness_explicit", None)
        if strictness is None:
            strictness = kwargs.pop(
                "strict_level", kwargs.pop("policy", kwargs.pop("strict", None))
            )
        if kwargs:
            raise TypeError(
                "unexpected keyword argument(s): {}".format(", ".join(sorted(kwargs)))
            )
        self._strictness_explicit = (
            strictness is not None
            if explicit_flag is None
            else explicit_flag
        )
        self.stream = stream
        self.interfaces = set()
        if not isinstance(shb, blocks.SectionHeader):
            raise TypeError("not a SectionHeader")
        self._strictness = strictness_module.capture_strictness(strictness)
        self.current_section = shb
        shb._write(self.stream, strictness=self._policy_for(shb))
        for iface in sorted(shb.interfaces.keys()):
            self.interfaces.add(iface)
            shb.interfaces[iface]._write(
                stream, strictness=self._policy_for(shb.interfaces[iface])
            )

    @property
    def strictness(self):
        """Return the policy this writer uses for writing."""
        return strictness_module.resolve_for_object(
            None, self._strictness, self._strictness_explicit
        )

    @property
    def strictness_policy(self):
        return self.strictness

    @property
    def strict_level(self):
        return self.strictness.level

    @property
    def policy(self):
        return self.strictness

    def _policy_for(self, blk):
        """
        Resolve the policy for a write.

        Explicit task scope wins, then this writer's captured policy.  If the
        writer has no policy of its own (legacy construction outside any
        scope), a policy captured by the block itself is used, so a block
        handed over from another processing stage remains interpretable.
        """
        if self._strictness_explicit:
            return strictness_module.resolve_for_object(
                None, self._strictness, True
            )
        if self._strictness is not None:
            return strictness_module.resolve_for_object(
                None, self._strictness, False
            )
        # Legacy writer with no policy of its own: use the block's own
        # policy, including whether it was explicitly configured.
        return strictness_module.resolve_for_object(
            None,
            getattr(blk, "_strictness", None),
            getattr(blk, "_strictness_explicit", False),
        )

    def write_block(self, blk, strictness=None):
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
            # Starting a new section, so re-initialize.  Preserve this
            # writer's captured policy rather than re-capturing from whatever
            # task happens to be active right now.
            self.__init__(
                self.stream,
                blk,
                strictness=self._policy_for(blk),
                _strictness_explicit=self._strictness_explicit,
            )
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

        if strictness is None:
            strictness = self._policy_for(blk)
        blk._write(self.stream, strictness=strictness)
