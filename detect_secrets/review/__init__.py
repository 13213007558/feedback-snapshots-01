"""Structured-config review pipeline with source-faithful provenance.

Public entry points:

* :func:`review_config` runs the structured/fallback pipeline.
* :class:`ReviewResult` exposes :meth:`~ReviewResult.public_report` (safe to
  share) and :meth:`~ReviewResult.internal_record` (restricted, local only).
* :func:`write_internal_record` persists the restricted record on this machine.
"""
from .models import Finding
from .models import ParseDiagnostic
from .models import ParsePath
from .models import PublicFinding
from .models import PublicReport
from .models import Representation
from .models import ReviewResult
from .models import SourceLocation
from .pipeline import review_config
from .storage import read_internal_record
from .storage import write_internal_record

__all__ = [
    'Finding',
    'ParseDiagnostic',
    'ParsePath',
    'PublicFinding',
    'PublicReport',
    'Representation',
    'ReviewResult',
    'SourceLocation',
    'review_config',
    'read_internal_record',
    'write_internal_record',
]
