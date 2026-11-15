# ----------------------------------------------------------------------
# Library to parse pcap-ng file format
#
# See: http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
# ----------------------------------------------------------------------

from .scanner import FileScanner  # noqa
from .strictness import (  # noqa
    Strictness,
    StrictnessPolicy,
    get_strictness,
    get_strictness_policy,
    set_strictness,
    strictness_scope,
)
from .writer import FileWriter  # noqa
