# ----------------------------------------------------------------------
# Library to parse pcap-ng file format
#
# See: http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
# ----------------------------------------------------------------------

from .scanner import FileScanner  # noqa
from .strictness import (  # noqa
    Strictness,
    StrictnessPolicy,
    get_strict_level,
    get_strictness,
    set_strictness,
    strictness_scope,
)
from .writer import FileWriter  # noqa
