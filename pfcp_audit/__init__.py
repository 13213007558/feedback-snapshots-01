"""Limited PFCP endpoint-allocation evidence checker built on pycrate.

The package never treats a parseable PFCP F-TEID as proof that a GTP-U tunnel
was installed.  It keeps the raw evidence (IE path, flags, request side and
response side) and separates three states for every endpoint reference:

* a specified endpoint (CH clear, TEID/address carried in the request),
* a requested allocation (CH set, optional CHID/CHOOSE_ID),
* a confirmed allocation (a matching CreatedPDR in an accepted response).

Nothing is inferred across sessions or across selection groups: a successful
allocation for one F-SEID can never satisfy a request under another F-SEID.
"""

from .fteid import (
    FTEIDLayout,
    FTEIDKind,
    LayoutAnomaly,
    inspect_fteid,
)
from .evidence import (
    EndpointEvidence,
    EndpointState,
    GroupEvidence,
    SessionEvidence,
    Verdict,
)
from .audit import AuditResult, EndpointAuditor, audit_messages, audit_transcript
from .transcript import Transcript, TranscriptMessage, load_transcript

__all__ = [
    'FTEIDLayout',
    'FTEIDKind',
    'LayoutAnomaly',
    'inspect_fteid',
    'EndpointEvidence',
    'EndpointState',
    'GroupEvidence',
    'SessionEvidence',
    'Verdict',
    'AuditResult',
    'EndpointAuditor',
    'audit_messages',
    'audit_transcript',
    'Transcript',
    'TranscriptMessage',
    'load_transcript',
]
