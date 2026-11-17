"""Bounded, assembly-free constant recovery over dncil method bodies.

This package performs *static* recovery of a small, explicitly bounded class of
expressions (constant integers/strings, locals, finite array writes and a
whitelisted set of string/char helpers) from CIL method bodies parsed by
:mod:`dncil`. It never loads assemblies, never resolves tokens through the CLR
and never executes unknown methods. When the analysis leaves the supported
class, two values merge to a conflict, or a configured budget is exhausted, the
affected result is reported as *pending* rather than guessed.
"""

from dncil.analysis.domain import (
    TOP,
    ArrayValue,
    CharValue,
    Confidence,
    IntValue,
    StringValue,
    Value,
    merge_values,
)
from dncil.analysis.metadata import AnalysisBudget, KnownOp, MethodBinding, Metadata
from dncil.analysis.recovery import RecoveredString, recover_strings
from dncil.analysis.interpreter import AnalysisLimits, analyze_body

__all__ = [
    "TOP",
    "ArrayValue",
    "CharValue",
    "Confidence",
    "IntValue",
    "StringValue",
    "Value",
    "merge_values",
    "AnalysisBudget",
    "KnownOp",
    "MethodBinding",
    "Metadata",
    "RecoveredString",
    "recover_strings",
    "AnalysisLimits",
    "analyze_body",
]
