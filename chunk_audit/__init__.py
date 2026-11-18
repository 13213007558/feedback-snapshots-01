"""Static pre-check and finite witness matcher for windowed YARA scanning."""

from .analyzer import SAFE, AT_RISK, UNDECIDED, RuleVerdict, analyze_ruleset
from .hex_patterns import HexParseError, analyze_hex
from .matcher import compare_windows, windows_for

__all__ = [
    "SAFE",
    "AT_RISK",
    "UNDECIDED",
    "RuleVerdict",
    "analyze_ruleset",
    "analyze_hex",
    "HexParseError",
    "compare_windows",
    "windows_for",
]
