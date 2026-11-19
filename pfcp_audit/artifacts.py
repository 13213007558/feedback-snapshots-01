"""Build the self-contained evidence artifact for the endpoint audit.

The artifact is plain JSON so it can be reviewed without pycrate: it contains
the raw hexadecimal transcription of every message, the audit result for each
scenario and two single-bit flag mutations with the evidence they produce.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .audit import EndpointAuditor, audit_transcript
from .mutation import clear_flag, flip_flag
from .scenarios import (
    SESSION_A,
    all_transcripts,
    legal_transcript,
)


def _audit_one(transcript) -> Dict[str, Any]:
    return audit_transcript(transcript).to_dict()


def _mutation_section() -> List[Dict[str, Any]]:
    transcript = legal_transcript()
    baseline = audit_transcript(transcript)
    request_bytes = transcript.messages[0].bytes
    demonstrations: List[Dict[str, Any]] = []

    # 1) Clear CH on the choose F-TEID of PDR 20.
    choose_path = baseline.sessions[SESSION_A].endpoints[20].ie_path
    cleared, cleared_offset = clear_flag(request_bytes, choose_path, 'CH')
    auditor = EndpointAuditor()
    auditor.add_message(cleared, label='A-req CH-cleared')
    for message in transcript.messages[1:]:
        auditor.add_message(message.bytes, label=message.label)
    cleared_result = auditor.finalize()
    demonstrations.append({
        'name': 'ch_cleared_on_allocation_request',
        'target_ie': choose_path.render(),
        'changed_byte_offset': cleared_offset,
        'original_flags_byte': '%02x' % request_bytes[cleared_offset],
        'mutated_flags_byte': '%02x' % cleared[cleared_offset],
        'mutated_request_hex': cleared.hex(),
        'endpoint_state': cleared_result.sessions[SESSION_A].endpoints[20].state.value,
        'anomalies': [
            a.value for a in cleared_result.sessions[SESSION_A].endpoints[20].anomalies
        ],
        'interpreted_as_address': cleared_result.sessions[SESSION_A].endpoints[20]
        .layout.ipv4
        is not None,
    })

    # 2) Flip the V4 presence bit on the specified F-TEID of PDR 10.
    specified_path = baseline.sessions[SESSION_A].endpoints[10].ie_path
    flipped, flipped_offset = flip_flag(request_bytes, specified_path, 'V4')
    flip_result = EndpointAuditor()
    flip_result.add_message(flipped, label='A-req V4-flipped')
    flip_audit = flip_result.finalize()
    demonstrations.append({
        'name': 'v4_presence_flipped_on_specified_endpoint',
        'target_ie': specified_path.render(),
        'changed_byte_offset': flipped_offset,
        'original_flags_byte': '%02x' % request_bytes[flipped_offset],
        'mutated_flags_byte': '%02x' % flipped[flipped_offset],
        'mutated_request_hex': flipped.hex(),
        'endpoint_state': flip_audit.sessions[SESSION_A].endpoints[10].state.value,
        'anomalies': [
            a.value for a in flip_audit.sessions[SESSION_A].endpoints[10].anomalies
        ],
        'interpreted_as_address': flip_audit.sessions[SESSION_A].endpoints[10]
        .layout.ipv4
        is not None,
    })
    return demonstrations


def build_artifact() -> Dict[str, Any]:
    transcripts = all_transcripts()
    return {
        'title': 'PFCP endpoint-allocation evidence artifact',
        'scenarios': [
            {
                'name': transcript.name,
                'description': transcript.description,
                'transcript': transcript.to_dict(),
                'audit': _audit_one(transcript),
            }
            for transcript in transcripts
        ],
        'flag_mutations': _mutation_section(),
    }
