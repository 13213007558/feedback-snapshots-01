"""Stable fingerprints tied to the representation that produced a finding.

Normalization can re-order or merge fields, so a coordinate taken from the
normalized output cannot identify a finding in the original input. The
fingerprint therefore mixes in the parse path and the *original* coordinate,
keeping structured and text-path findings in separate identity spaces even when
their rule id and value coincide.
"""
import hashlib
from typing import Tuple

from .models import ParsePath
from .models import SourceLocation


def compute_fingerprint(
    rule_id: str,
    parse_path: ParsePath,
    original_location: SourceLocation,
    logical_path: Tuple[str, ...],
) -> str:
    payload = '|'.join(
        (
            parse_path.value,
            rule_id,
            str(original_location.line),
            str(original_location.column or ''),
            '.'.join(logical_path),
        ),
    )
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()
